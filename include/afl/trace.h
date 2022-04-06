#ifndef AFL_TRACE_H
#define AFL_TRACE_H
#include "qemu/osdep.h"
#include "qemu-common.h"

extern FILE *afl_log_file;
bool afl_addr_in_ranges(uint64_t addr);
bool afl_maybe_log(uint64_t addr, uint64_t end, uint64_t tid, const char *prefix);
bool afl_cancel_log(const char *prefix);
void afl_log(uint64_t addr);
void afl_add_range(uint64_t start, uint64_t size);
void afl_link(uint64_t from, uint64_t to);
void afl_gen_trace(uint64_t cur_loc);
void afl_interrupt(uint64_t pc);
void afl_filter_tid(uint64_t tid);
#endif /* AFL_TRACE_H */
