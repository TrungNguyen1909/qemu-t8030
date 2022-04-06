/*
 * QEMU System Emulator
 *
 * Copyright (c) 2003-2020 Fabrice Bellard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "qemu/osdep.h"
#include "qemu-common.h"
#include "sysemu/sysemu.h"

#if 1
#include "afl.h"
#include "sysemu/runstate.h"
#include "migration/snapshot.h"
#endif

#ifdef CONFIG_SDL
#if defined(__APPLE__) || defined(main)
#include <SDL.h>
static int qemu_main(int argc, char **argv, char **envp);
int main(int argc, char **argv)
{
    return qemu_main(argc, argv, NULL);
}
#undef main
#define main qemu_main
#endif
#endif /* CONFIG_SDL */

#ifdef CONFIG_COCOA
#undef main
#define main qemu_main
#endif /* CONFIG_COCOA */

#define AFL_NUM_SUB_LOOP    (1)
#define AFL_NUM_LOOP        (AFL_NUM_SUB_LOOP * 1000)

int main(int argc, char **argv, char **envp)
{
    if (getenv(SHM_ENV_VAR)) {
        /* XXX: Use FD 9 for input */
        dup2(0, 9);
        int dev_null_fd = open("/dev/null", O_RDONLY);
        dup2(dev_null_fd, 0);
        close(dev_null_fd);
    }
    qemu_init(argc, argv, envp);

    if (getenv(SHM_ENV_VAR) == NULL) {
        qemu_main_loop();
    } else {
        const char *name = "fuzz-user-snap";
        Error *err = NULL;
        int saved_vm_running  = runstate_is_running();
        clock_t start, end, start2, end2;

        printf("Loading snapshot: %s\n", name);
        start = clock();
        vm_stop(RUN_STATE_RESTORE_VM);
        if (load_snapshot(name, NULL, false, NULL, &err) /* reset */
            /* check if panic detected at machine reset */
            && !runstate_check(RUN_STATE_GUEST_PANICKED)
            && saved_vm_running) {
            puts("Starting VM");
            vm_start();
        } else {
            printf("Failed to load snapshot %s\n", name);
            g_assert_not_reached();
            return -1;
        }
        end = clock();
        printf("Snapshot restore took %f seconds\n",
                ((double)end - start) / CLOCKS_PER_SEC);

        while (__AFL_LOOP(AFL_NUM_LOOP)) {
            /*
            for (int _ = 0; _ < AFL_NUM_SUB_LOOP
                            && (_ == 0 || __AFL_LOOP(AFL_NUM_LOOP)); _++) {
            */
                start2 = clock();
                qemu_main_loop();
                end2 = clock();
                printf("Test took %f seconds\n", ((double)end2 - start2) / CLOCKS_PER_SEC);
                /* TODO: Check for Panic */
            /*
            }
            */
            printf("Loading snapshot: %s\n", name);
            start = clock();
            vm_stop(RUN_STATE_RESTORE_VM);
            if (load_snapshot(name, NULL, false, NULL, &err) /* reset */
                /* check if panic detected at machine reset */
                && !runstate_check(RUN_STATE_GUEST_PANICKED)
                && saved_vm_running) {
                puts("Restarting VM");
                vm_start();
            }

            if (runstate_check(RUN_STATE_GUEST_PANICKED)) {
                qemu_cleanup();
                kill(getpid(), SIGQUIT);
            }
            assert(runstate_check(RUN_STATE_RUNNING));
            if (err) {
                break;
            }
            end = clock();
            printf("Snapshot restore took %f seconds\n",
                    ((double)end - start) / CLOCKS_PER_SEC);
        }
    }
    qemu_cleanup();

    return 0;
}
