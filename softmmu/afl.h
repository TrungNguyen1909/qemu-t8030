#ifndef AFL_H
#define AFL_H
#include "qemu/osdep.h"
#include "afl/config.h"
#include "afl/trace.h"

#define __AFL_HAVE_MANUAL_CONTROL 1
#define FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION 1

#define __AFL_LOOP(_A) ({ static volatile char *_B __attribute__((used)); \
    _B = (char*)PERSIST_SIG; \
    __afl_persistent_loop(_A); })

#define __AFL_INIT() do { static volatile char *_A __attribute__((used)); \
    _A = (char*)DEFER_SIG; \
    __afl_manual_init(); } while (0)


int __afl_persistent_loop(unsigned int max_cnt);
void __afl_manual_init(void);

#endif /* AFL_H */
