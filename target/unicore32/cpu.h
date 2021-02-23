/*
 * UniCore32 virtual CPU header
 *
 * Copyright (C) 2010-2012 Guan Xuetao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation, or (at your option) any
 * later version. See the COPYING file in the top-level directory.
 */

#ifndef UNICORE32_CPU_H
#define UNICORE32_CPU_H

#include "cpu-qom.h"
#include "exec/cpu-defs.h"

typedef struct CPUUniCore32State {
    /* Regs for current mode.  */
    uint32_t regs[32];
    /* Frequently accessed ASR bits are stored separately for efficiently.
       This contains all the other bits.  Use asr_{read,write} to access
       the whole ASR.  */
    uint32_t uncached_asr;
    uint32_t bsr;

    /* Banked registers.  */
    uint32_t banked_bsr[6];
    uint32_t banked_r29[6];
    uint32_t banked_r30[6];

    /* asr flag cache for faster execution */
    uint32_t CF; /* 0 or 1 */
    uint32_t VF; /* V is the bit 31. All other bits are undefined */
    uint32_t NF; /* N is bit 31. All other bits are undefined.  */
    uint32_t ZF; /* Z set if zero.  */

    /* System control coprocessor (cp0) */
    struct {
        uint32_t c0_cpuid;
        uint32_t c0_cachetype;
        uint32_t c1_sys; /* System control register.  */
        uint32_t c2_base; /* MMU translation table base.  */
        uint32_t c3_faultstatus; /* Fault status registers.  */
        uint32_t c4_faultaddr; /* Fault address registers.  */
        uint32_t c5_cacheop; /* Cache operation registers.  */
        uint32_t c6_tlbop; /* TLB operation registers. */
    } cp0;

    /* UniCore-F64 coprocessor state.  */
    struct {
        float64 regs[16];
        uint32_t xregs[32];
        float_status fp_status;
    } ucf64;

    /* Internal CPU feature flags.  */
    uint32_t features;

} CPUUniCore32State;

/**
 * UniCore32CPU:
 * @env: #CPUUniCore32State
 *
 * A UniCore32 CPU.
 */
struct UniCore32CPU {
    /*< private >*/
    CPUState parent_obj;
    /*< public >*/

    CPUNegativeOffsetState neg;
    CPUUniCore32State env;
};


void uc32_cpu_do_interrupt(CPUState *cpu);
bool uc32_cpu_exec_interrupt(CPUState *cpu, int int_req);
void uc32_cpu_dump_state(CPUState *cpu, FILE *f, int flags);
hwaddr uc32_cpu_get_phys_page_debug(CPUState *cpu, vaddr addr);

#define ASR_M                   (0x1f)
#define ASR_MODE_USER           (0x10)
#define ASR_MODE_INTR           (0x12)
#define ASR_MODE_PRIV           (0x13)
#define ASR_MODE_TRAP           (0x17)
#define ASR_MODE_EXTN           (0x1b)
#define ASR_MODE_SUSR           (0x1f)
#define ASR_I                   (1 << 7)
#define ASR_V                   (1 << 28)
#define ASR_C                   (1 << 29)
#define ASR_Z                   (1 << 30)
#define ASR_N                   (1 << 31)
#define ASR_NZCV                (ASR_N | ASR_Z | ASR_C | ASR_V)
#define ASR_RESERVED            (~(ASR_M | ASR_I | ASR_NZCV))

#define UC32_EXCP_PRIV          (1)
#define UC32_EXCP_ITRAP         (2)
#define UC32_EXCP_DTRAP         (3)
#define UC32_EXCP_INTR          (4)

/* Return the current ASR value.  */
target_ulong cpu_asr_read(CPUUniCore32State *env1);
/* Set the ASR.  Note that some bits of mask must be all-set or all-clear.  */
void cpu_asr_write(CPUUniCore32State *env1, target_ulong val, target_ulong mask);

/* UniCore-F64 system registers.  */
#define UC32_UCF64_FPSCR                (31)
#define UCF64_FPSCR_MASK                (0x27ffffff)
#define UCF64_FPSCR_RND_MASK            (0x7)
#define UCF64_FPSCR_RND(r)              (((r) >>  0) & UCF64_FPSCR_RND_MASK)
#define UCF64_FPSCR_TRAPEN_MASK         (0x7f)
#define UCF64_FPSCR_TRAPEN(r)           (((r) >> 10) & UCF64_FPSCR_TRAPEN_MASK)
#define UCF64_FPSCR_FLAG_MASK           (0x3ff)
#define UCF64_FPSCR_FLAG(r)             (((r) >> 17) & UCF64_FPSCR_FLAG_MASK)
#define UCF64_FPSCR_FLAG_ZERO           (1 << 17)
#define UCF64_FPSCR_FLAG_INFINITY       (1 << 18)
#define UCF64_FPSCR_FLAG_INVALID        (1 << 19)
#define UCF64_FPSCR_FLAG_UNDERFLOW      (1 << 20)
#define UCF64_FPSCR_FLAG_OVERFLOW       (1 << 21)
#define UCF64_FPSCR_FLAG_INEXACT        (1 << 22)
#define UCF64_FPSCR_FLAG_HUGEINT        (1 << 23)
#define UCF64_FPSCR_FLAG_DENORMAL       (1 << 24)
#define UCF64_FPSCR_FLAG_UNIMP          (1 << 25)
#define UCF64_FPSCR_FLAG_DIVZERO        (1 << 26)

#define UC32_HWCAP_CMOV                 4 /* 1 << 2 */
#define UC32_HWCAP_UCF64                8 /* 1 << 3 */

#define cpu_signal_handler              uc32_cpu_signal_handler

int uc32_cpu_signal_handler(int host_signum, void *pinfo, void *puc);

/* MMU modes definitions */
#define MMU_USER_IDX 1
static inline int cpu_mmu_index(CPUUniCore32State *env, bool ifetch)
{
    return (env->uncached_asr & ASR_M) == ASR_MODE_USER ? 1 : 0;
}

typedef CPUUniCore32State CPUArchState;
typedef UniCore32CPU ArchCPU;

#include "exec/cpu-all.h"

#define UNICORE32_CPU_TYPE_SUFFIX "-" TYPE_UNICORE32_CPU
#define UNICORE32_CPU_TYPE_NAME(model) model UNICORE32_CPU_TYPE_SUFFIX
#define CPU_RESOLVING_TYPE TYPE_UNICORE32_CPU

static inline void cpu_get_tb_cpu_state(CPUUniCore32State *env, target_ulong *pc,
                                        target_ulong *cs_base, uint64_t *flags)
{
    *pc = env->regs[31];
    *cs_base = 0;
    *flags = 0;
    if ((env->uncached_asr & ASR_M) != ASR_MODE_USER) {
        *flags |= (1 << 6);
    }
}

bool uc32_cpu_tlb_fill(CPUState *cs, vaddr address, int size,
                       MMUAccessType access_type, int mmu_idx,
                       bool probe, uintptr_t retaddr);
void uc32_translate_init(void);
void switch_mode(CPUUniCore32State *, int);

#endif /* UNICORE32_CPU_H */
