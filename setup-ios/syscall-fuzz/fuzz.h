#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

bool fuzz_is_in_afl(void);
void fuzz_set_thread(void);
void fuzz_vm_stop(void);
ssize_t fuzzread(int fd, void *buf, size_t nbyte);
