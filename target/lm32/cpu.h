/*
 *  LatticeMico32 virtual CPU header.
 *
 *  Copyright (c) 2010 Michael Walle <michael@walle.cc>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef LM32_CPU_H
#define LM32_CPU_H

#include "cpu-qom.h"
#include "exec/cpu-defs.h"

typedef struct CPULM32State CPULM32State;

static inline int cpu_mmu_index(CPULM32State *env, bool ifetch)
{
    return 0;
}

/* Exceptions indices */
enum {
    EXCP_RESET = 0,
    EXCP_BREAKPOINT,
    EXCP_INSN_BUS_ERROR,
    EXCP_WATCHPOINT,
    EXCP_DATA_BUS_ERROR,
    EXCP_DIVIDE_BY_ZERO,
    EXCP_IRQ,
    EXCP_SYSTEMCALL
};

/* Registers */
enum {
    R_R0 = 0, R_R1, R_R2, R_R3, R_R4, R_R5, R_R6, R_R7, R_R8, R_R9, R_R10,
    R_R11, R_R12, R_R13, R_R14, R_R15, R_R16, R_R17, R_R18, R_R19, R_R20,
    R_R21, R_R22, R_R23, R_R24, R_R25, R_R26, R_R27, R_R28, R_R29, R_R30,
    R_R31
};

/* Register aliases */
enum {
    R_GP = R_R26,
    R_FP = R_R27,
    R_SP = R_R28,
    R_RA = R_R29,
    R_EA = R_R30,
    R_BA = R_R31
};

/* IE flags */
enum {
    IE_IE  = (1<<0),
    IE_EIE = (1<<1),
    IE_BIE = (1<<2),
};

/* DC flags */
enum {
    DC_SS  = (1<<0),
    DC_RE  = (1<<1),
    DC_C0  = (1<<2),
    DC_C1  = (1<<3),
    DC_C2  = (1<<4),
    DC_C3  = (1<<5),
};

/* CFG mask */
enum {
    CFG_M         = (1<<0),
    CFG_D         = (1<<1),
    CFG_S         = (1<<2),
    CFG_U         = (1<<3),
    CFG_X         = (1<<4),
    CFG_CC        = (1<<5),
    CFG_IC        = (1<<6),
    CFG_DC        = (1<<7),
    CFG_G         = (1<<8),
    CFG_H         = (1<<9),
    CFG_R         = (1<<10),
    CFG_J         = (1<<11),
    CFG_INT_SHIFT = 12,
    CFG_BP_SHIFT  = 18,
    CFG_WP_SHIFT  = 22,
    CFG_REV_SHIFT = 26,
};

/* CSRs */
enum {
    CSR_IE   = 0x00,
    CSR_IM   = 0x01,
    CSR_IP   = 0x02,
    CSR_ICC  = 0x03,
    CSR_DCC  = 0x04,
    CSR_CC   = 0x05,
    CSR_CFG  = 0x06,
    CSR_EBA  = 0x07,
    CSR_DC   = 0x08,
    CSR_DEBA = 0x09,
    CSR_JTX  = 0x0e,
    CSR_JRX  = 0x0f,
    CSR_BP0  = 0x10,
    CSR_BP1  = 0x11,
    CSR_BP2  = 0x12,
    CSR_BP3  = 0x13,
    CSR_WP0  = 0x18,
    CSR_WP1  = 0x19,
    CSR_WP2  = 0x1a,
    CSR_WP3  = 0x1b,
};

enum {
    LM32_FEATURE_MULTIPLY     =  1,
    LM32_FEATURE_DIVIDE       =  2,
    LM32_FEATURE_SHIFT        =  4,
    LM32_FEATURE_SIGN_EXTEND  =  8,
    LM32_FEATURE_I_CACHE      = 16,
    LM32_FEATURE_D_CACHE      = 32,
    LM32_FEATURE_CYCLE_COUNT  = 64,
};

enum {
    LM32_FLAG_IGNORE_MSB = 1,
};

struct CPULM32State {
    /* general registers */
    uint32_t regs[32];

    /* special registers */
    uint32_t pc;        /* program counter */
    uint32_t ie;        /* interrupt enable */
    uint32_t icc;       /* instruction cache control */
    uint32_t dcc;       /* data cache control */
    uint32_t cc;        /* cycle counter */
    uint32_t cfg;       /* configuration */

    /* debug registers */
    uint32_t dc;        /* debug control */
    uint32_t bp[4];     /* breakpoints */
    uint32_t wp[4];     /* watchpoints */

    struct CPUBreakpoint *cpu_breakpoint[4];
    struct CPUWatchpoint *cpu_watchpoint[4];

    /* Fields up to this point are cleared by a CPU reset */
    struct {} end_reset_fields;

    /* Fields from here on are preserved across CPU reset. */
    uint32_t eba;       /* exception base address */
    uint32_t deba;      /* debug exception base address */

    /* interrupt controller handle for callbacks */
    DeviceState *pic_state;
    /* JTAG UART handle for callbacks */
    DeviceState *juart_state;

    /* processor core features */
    uint32_t flags;

};

/**
 * LM32CPU:
 * @env: #CPULM32State
 *
 * A LatticeMico32 CPU.
 */
struct LM32CPU {
    /*< private >*/
    CPUState parent_obj;
    /*< public >*/

    CPUNegativeOffsetState neg;
    CPULM32State env;

    uint32_t revision;
    uint8_t num_interrupts;
    uint8_t num_breakpoints;
    uint8_t num_watchpoints;
    uint32_t features;
};


#ifndef CONFIG_USER_ONLY
extern const VMStateDescription vmstate_lm32_cpu;
#endif

void lm32_cpu_do_interrupt(CPUState *cpu);
bool lm32_cpu_exec_interrupt(CPUState *cs, int int_req);
void lm32_cpu_dump_state(CPUState *cpu, FILE *f, int flags);
hwaddr lm32_cpu_get_phys_page_debug(CPUState *cpu, vaddr addr);
int lm32_cpu_gdb_read_register(CPUState *cpu, GByteArray *buf, int reg);
int lm32_cpu_gdb_write_register(CPUState *cpu, uint8_t *buf, int reg);

typedef enum {
    LM32_WP_DISABLED = 0,
    LM32_WP_READ,
    LM32_WP_WRITE,
    LM32_WP_READ_WRITE,
} lm32_wp_t;

static inline lm32_wp_t lm32_wp_type(uint32_t dc, int idx)
{
    assert(idx < 4);
    return (dc >> (idx+1)*2) & 0x3;
}

/* you can call this signal handler from your SIGBUS and SIGSEGV
   signal handlers to inform the virtual CPU of exceptions. non zero
   is returned if the signal was handled by the virtual CPU.  */
int cpu_lm32_signal_handler(int host_signum, void *pinfo,
                          void *puc);
void lm32_cpu_list(void);
void lm32_translate_init(void);
void cpu_lm32_set_phys_msb_ignore(CPULM32State *env, int value);
void QEMU_NORETURN raise_exception(CPULM32State *env, int index);
void lm32_debug_excp_handler(CPUState *cs);
void lm32_breakpoint_insert(CPULM32State *env, int index, target_ulong address);
void lm32_breakpoint_remove(CPULM32State *env, int index);
void lm32_watchpoint_insert(CPULM32State *env, int index, target_ulong address,
        lm32_wp_t wp_type);
void lm32_watchpoint_remove(CPULM32State *env, int index);
bool lm32_cpu_do_semihosting(CPUState *cs);

#define LM32_CPU_TYPE_SUFFIX "-" TYPE_LM32_CPU
#define LM32_CPU_TYPE_NAME(model) model LM32_CPU_TYPE_SUFFIX
#define CPU_RESOLVING_TYPE TYPE_LM32_CPU

#define cpu_list lm32_cpu_list
#define cpu_signal_handler cpu_lm32_signal_handler

bool lm32_cpu_tlb_fill(CPUState *cs, vaddr address, int size,
                       MMUAccessType access_type, int mmu_idx,
                       bool probe, uintptr_t retaddr);

typedef CPULM32State CPUArchState;
typedef LM32CPU ArchCPU;

#include "exec/cpu-all.h"

static inline void cpu_get_tb_cpu_state(CPULM32State *env, target_ulong *pc,
                                        target_ulong *cs_base, uint64_t *flags)
{
    *pc = env->pc;
    *cs_base = 0;
    *flags = 0;
}

#endif
