/*
  Copyright 2015 Google LLC All rights reserved.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at:

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

/*
   american fuzzy lop - LLVM instrumentation bootstrap
   ---------------------------------------------------

   Written by Laszlo Szekeres <lszekeres@google.com> and
              Michal Zalewski <lcamtuf@google.com>

   LLVM integration design comes from Laszlo Szekeres.

   This code is the rewrite of afl-as.h's main_payload.
*/

#include "afl/config.h"
#include "afl/types.h"
#include "afl.h"

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <sys/types.h>
#include "qemu/queue.h"
#include "tcg/tcg-op.h"

/* This is a somewhat ugly hack for the experimental 'trace-pc-guard' mode.
   Basically, we need to make sure that the forkserver is initialized after
   the LLVM-generated runtime initialization pass, not before. */

#ifdef USE_TRACE_PC
#  define CONST_PRIO 5
#else
#  define CONST_PRIO 0
#endif /* ^USE_TRACE_PC */


/* Globals needed by the injected instrumentation. The __afl_area_initial region
   is used for instrumentation output before __afl_map_shm() has a chance to run.
   It will end up as .comm, so it shouldn't be too wasteful. */

u8  __afl_area_initial[MAP_SIZE];
u8* __afl_area_ptr = __afl_area_initial;

#define GUARD_VALUE     (0xffffffffffffffUL)
__thread u64 __afl_prev_loc;
__thread u64 __x_prev_loc = GUARD_VALUE;
__thread u64 __x_prev_end = GUARD_VALUE;
__thread u64 __x_guard = GUARD_VALUE;
__thread u64 __x_int = GUARD_VALUE;
__thread u64 __x_thread_id = GUARD_VALUE;
FILE *afl_log_file = NULL;

typedef struct afl_range {
    uint64_t start;
    uint64_t end;
    QTAILQ_ENTRY(afl_range) entry;
} afl_range;

static QTAILQ_HEAD(, afl_range) ranges = QTAILQ_HEAD_INITIALIZER(ranges);

/* Running in persistent mode? */

static u8 is_persistent;


/* SHM setup. */

static void __afl_map_shm(void) {

  char *id_str = getenv(SHM_ENV_VAR);

  /* If we're running under AFL, attach to the appropriate region, replacing the
     early-stage __afl_area_initial region that is needed to allow some really
     hacky .init code to work correctly in projects such as OpenSSL. */

  if (id_str) {

    u32 shm_id = atoi(id_str);

    __afl_area_ptr = shmat(shm_id, NULL, 0);

    /* Whooooops. */

    if (__afl_area_ptr == (void *)-1) _exit(1);

    /* Write something into the bitmap so that even with low AFL_INST_RATIO,
       our parent doesn't give up on us. */

    __afl_area_ptr[0] = 1;

  }

}


/* Fork server logic. */

static void __afl_start_forkserver(void) {

  static u8 tmp[4];
  s32 child_pid;

  u8  child_stopped = 0;

  /* Phone home and tell the parent that we're OK. If parent isn't there,
     assume we're not running in forkserver mode and just execute program. */

  if (write(FORKSRV_FD + 1, tmp, 4) != 4) return;

  while (1) {

    u32 was_killed;
    int status;

    /* Wait for parent by reading from the pipe. Abort if read fails. */

    if (read(FORKSRV_FD, &was_killed, 4) != 4) _exit(1);

    /* If we stopped the child in persistent mode, but there was a race
       condition and afl-fuzz already issued SIGKILL, write off the old
       process. */

    if (child_stopped && was_killed) {
      child_stopped = 0;
      if (waitpid(child_pid, &status, 0) < 0) _exit(1);
    }

    if (!child_stopped) {

      /* Once woken up, create a clone of our process. */

      child_pid = fork();
      if (child_pid < 0) _exit(1);

      /* In child process: close fds, resume execution. */

      if (!child_pid) {

        close(FORKSRV_FD);
        close(FORKSRV_FD + 1);
        return;

      }

    } else {

      /* Special handling for persistent mode: if the child is alive but
         currently stopped, simply restart it with SIGCONT. */

      kill(child_pid, SIGCONT);
      child_stopped = 0;

    }

    /* In parent process: write PID to pipe, then wait for child. */

    if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) _exit(1);

    if (waitpid(child_pid, &status, is_persistent ? WUNTRACED : 0) < 0)
      _exit(1);

    /* In persistent mode, the child stops itself with SIGSTOP to indicate
       a successful run. In this case, we want to wake it up without forking
       again. */

    if (WIFSTOPPED(status)) child_stopped = 1;

    /* Relay wait status to pipe, then loop back. */

    if (write(FORKSRV_FD + 1, &status, 4) != 4) _exit(1);

  }

}


/* A simplified persistent mode handler, used as explained in README.llvm. */

int __afl_persistent_loop(unsigned int max_cnt) {

  static u8  first_pass = 1;
  static u32 cycle_cnt;

  g_autofree char *filename = NULL;
  assert(asprintf(&filename, "output-%ld", clock()) > 0);
  if (afl_log_file) {
      fclose(afl_log_file);
  }
  #if 0
  afl_log_file = fopen(filename, "w");
  #endif
  //afl_log_file = stderr;
  if (first_pass) {

    /* Make sure that every iteration of __AFL_LOOP() starts with a clean slate.
       On subsequent calls, the parent will take care of that, but on the first
       iteration, it's our job to erase any trace of whatever happened
       before the loop. */

    if (is_persistent) {

      memset(__afl_area_ptr, 0, MAP_SIZE);
      __afl_area_ptr[0] = 1;
      __afl_prev_loc = 0;
      __x_prev_loc = GUARD_VALUE;
      __x_prev_end = GUARD_VALUE;
      __x_guard = GUARD_VALUE;
      __x_thread_id = GUARD_VALUE;
      __x_int = GUARD_VALUE;
    }

    cycle_cnt  = max_cnt;
    first_pass = 0;
    return 1;

  }

  if (is_persistent) {

    if (cycle_cnt && --cycle_cnt) {

      kill(getpid(), SIGSTOP);

      __afl_area_ptr[0] = 1;
      __afl_prev_loc = 0;
      __x_prev_loc = GUARD_VALUE;
      __x_prev_end = GUARD_VALUE;
      __x_guard = GUARD_VALUE;
      __x_thread_id = GUARD_VALUE;
      __x_int = GUARD_VALUE;

      return 1;

    } else {

      /* When exiting __AFL_LOOP(), make sure that the subsequent code that
         follows the loop is not traced. We do that by pivoting back to the
         dummy output region. */

      __afl_area_ptr = __afl_area_initial;

    }

  }

  return 0;

}


/* This one can be called from user code when deferred forkserver mode
    is enabled. */

void __afl_manual_init(void) {

  static u8 init_done;

  if (!init_done) {

    __afl_map_shm();
    __afl_start_forkserver();
    init_done = 1;
  }

}


/* Proper initialization routine. */

static __attribute__((constructor)) void __afl_auto_init(void) {

  is_persistent = !!getenv(PERSIST_ENV_VAR);

  if (getenv(DEFER_ENV_VAR)) return;

  __afl_manual_init();

}

void afl_add_range(uint64_t start, uint64_t size)
{
    afl_range *range = g_new0(afl_range, 1);
    range->start = start;
    range->end = start + size;
    QTAILQ_INSERT_TAIL(&ranges, range, entry);
}

bool afl_addr_in_ranges(uint64_t addr)
{
    afl_range *range;
    QTAILQ_FOREACH(range, &ranges, entry) {
        if (range->start <= addr && addr < range->end) {
            return true;
        }
    }
    return false;
}

bool afl_maybe_log(uint64_t cur_loc, uint64_t cur_end, uint64_t tid, const char *prefix)
{
    if (__x_thread_id != tid && __x_thread_id) {
        return 0;
    }

    if (!afl_addr_in_ranges(cur_loc)) {
        __x_guard = GUARD_VALUE;
        return 0;
    }

    if (__x_int == cur_loc) {
        __x_int = GUARD_VALUE;
        return 0;
    }

    if (__x_prev_loc <= cur_loc && cur_loc < __x_prev_end) {
        return 0;
    }

    if (afl_log_file) {
        fprintf(afl_log_file, "%s(0x%lx, 0x%lx)\n", __func__, cur_loc, cur_end);
    }

    __x_prev_loc = cur_loc;
    __x_prev_end = cur_end;
    cur_loc = (cur_loc >> 4) ^ (cur_loc << 8);
    cur_loc &= MAP_SIZE - 1;

    __x_guard = cur_loc ^ __afl_prev_loc;
    __afl_area_ptr[__x_guard]++;
    __afl_prev_loc = cur_loc >> 1;
    return 1;
}

void afl_filter_tid(uint64_t tid)
{
    __x_thread_id = tid;
}

bool  afl_cancel_log(const char *prefix)
{
    if (__x_guard == GUARD_VALUE) {
        return 0;
    }
    if (afl_log_file) {
        fprintf(afl_log_file, "%s()\n", __func__);
    }
    __afl_area_ptr[__x_guard]--;
    __x_guard = GUARD_VALUE;
    __x_prev_loc = GUARD_VALUE;
    __x_prev_end = GUARD_VALUE;
    return 1;
}

void afl_interrupt(uint64_t pc)
{
    if (!afl_addr_in_ranges(pc)) {
        return;
    }
    __x_int = pc;
    if (afl_log_file) {
        fprintf(afl_log_file, "%s(0x%lx)\n", __func__, pc);
    }
}

void afl_link(uint64_t from, uint64_t to)
{
    if (afl_log_file) {
        fprintf(afl_log_file, "%s(0x%lx, 0x%lx)\n", __func__, from, to);
    }
}

void afl_log(uint64_t addr)
{
    if (!afl_addr_in_ranges(addr)) {
        return;
    }

    if (afl_log_file) {
        fprintf(afl_log_file, "%s(0x%lx)\n", __func__, addr);
    }
}

void HELPER(afl_trace)(CPUArchState *env)
{
    target_ulong cs_base, pc;
    uint32_t flags;

    cpu_get_tb_cpu_state(env, &pc, &cs_base, &flags);
    if (!afl_addr_in_ranges(pc)) {
        return;
    }

    if (afl_log_file) {
        fprintf(afl_log_file, "%s(0x%lx)\n", __func__, pc);
    }
}

void afl_gen_trace(uint64_t cur_loc)
{
    TCGv index, count, new_prev_loc;
    TCGv_ptr prev_loc_ptr, count_ptr;

    if (!afl_addr_in_ranges(cur_loc)) {
        return;
    }

    cur_loc = (cur_loc >> 4) ^ (cur_loc << 8);
    cur_loc &= MAP_SIZE - 1;
    /* index = prev_loc ^ cur_loc */
    prev_loc_ptr = tcg_const_ptr(&__afl_prev_loc);
    index = tcg_temp_new();
    tcg_gen_ld_tl(index, prev_loc_ptr, 0);
    tcg_gen_xori_tl(index, index, cur_loc);

    /* afl_area_ptr[index]++ */
    count_ptr = tcg_const_ptr(__afl_area_ptr);
    tcg_gen_add_ptr(count_ptr, count_ptr, (TCGv_ptr)index);
    count = tcg_temp_new();
    tcg_gen_ld8u_tl(count, count_ptr, 0);
    tcg_gen_addi_tl(count, count, 1);
    tcg_gen_st8_tl(count, count_ptr, 0);
    tcg_temp_free(index);
    tcg_temp_free(count);

    /* __afl_prev_loc = cur_loc >> 1 */
    new_prev_loc = tcg_const_tl(cur_loc >> 1);
    tcg_gen_st_tl(new_prev_loc, prev_loc_ptr, 0);
    tcg_temp_free(new_prev_loc);
    tcg_temp_free_ptr(count_ptr);
    tcg_temp_free_ptr(prev_loc_ptr);
    
    gen_helper_afl_trace(cpu_env);
    return;
}
