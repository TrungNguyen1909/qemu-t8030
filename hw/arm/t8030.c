/*
 * iPhone 11 - T8030
 *
 * Copyright (c) 2019 Johnathan Afek <jonyafek@me.com>
 * Copyright (c) 2021 Nguyen Hoang Trung (TrungNguyen1909)
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
#include "qemu/log.h"
#include "qapi/error.h"
#include "qemu-common.h"
#include "hw/arm/boot.h"
#include "exec/address-spaces.h"
#include "hw/misc/unimp.h"
#include "sysemu/block-backend.h"
#include "sysemu/sysemu.h"
#include "sysemu/reset.h"
#include "qemu/error-report.h"
#include "hw/platform-bus.h"
#include "arm-powerctl.h"

#include "hw/arm/t8030.h"

#include "hw/irq.h"
#include "hw/or-irq.h"
#include "hw/intc/apple_aic.h"
#include "hw/block/apple_ans.h"
#include "hw/gpio/apple_gpio.h"
#include "hw/i2c/apple_i2c.h"

#include "hw/arm/exynos4210.h"

#define T8030_PHYS_BASE (0x800000000)
#define CPU_IMPL_REG_BASE (0x210050000)
#define CPM_IMPL_REG_BASE (0x210e40000)
#define T8030_MAX_DEVICETREE_SIZE (0x40000)
#define T8030_NVRAM_SIZE (0x2000)
#define NOP_INST (0xd503201f)
#define MOV_W0_01_INST (0x52800020)
#define MOV_X13_0_INST (0xd280000d)
#define RET_INST (0xd65f03c0)
#define RETAB_INST (0xd65f0fff)

#define T8030_CPREG_FUNCS(name)                                                    \
    static uint64_t T8030_cpreg_read_##name(CPUARMState *env,                      \
                                            const ARMCPRegInfo *ri)                \
    {                                                                              \
        T8030CPUState *tcpu = T8030_cs_from_env(env);                  \
        return tcpu->T8030_CPREG_VAR_NAME(name);                                    \
    }                                                                              \
    static void T8030_cpreg_write_##name(CPUARMState *env, const ARMCPRegInfo *ri, \
                                         uint64_t value)                           \
    {                                                                              \
        T8030CPUState *tcpu = T8030_cs_from_env(env);                  \
        tcpu->T8030_CPREG_VAR_NAME(name) = value;                                   \
        /* if (value != 0) fprintf(stderr, "T8030CPUState REG WRITE " #name " = 0x%llx at PC 0x%llx\n", value, env->pc); */ \
    }

#define T8030_CPREG_DEF(p_name, p_op0, p_op1, p_crn, p_crm, p_op2, p_access) \
    {                                                                        \
        .cp = CP_REG_ARM64_SYSREG_CP,                                        \
        .name = #p_name, .opc0 = p_op0, .crn = p_crn, .crm = p_crm,          \
        .opc1 = p_op1, .opc2 = p_op2, .access = p_access, .type = ARM_CP_IO, \
        .state = ARM_CP_STATE_AA64, .readfn = T8030_cpreg_read_##p_name,     \
        .writefn = T8030_cpreg_write_##p_name                                \
    }

static T8030CPUState *T8030_cs_from_env(CPUARMState *env);

T8030_CPREG_FUNCS(ARM64_REG_HID11)
T8030_CPREG_FUNCS(ARM64_REG_HID13)
T8030_CPREG_FUNCS(ARM64_REG_HID14)
T8030_CPREG_FUNCS(ARM64_REG_HID3)
T8030_CPREG_FUNCS(ARM64_REG_HID5)
T8030_CPREG_FUNCS(ARM64_REG_HID4)
T8030_CPREG_FUNCS(ARM64_REG_HID8)
T8030_CPREG_FUNCS(ARM64_REG_HID7)
T8030_CPREG_FUNCS(ARM64_REG_LSU_ERR_STS)
T8030_CPREG_FUNCS(PMC0)
T8030_CPREG_FUNCS(PMC1)
T8030_CPREG_FUNCS(PMCR1)
T8030_CPREG_FUNCS(PMSR)
T8030_CPREG_FUNCS(ARM64_REG_APCTL_EL1)
T8030_CPREG_FUNCS(ARM64_REG_KERNELKEYLO_EL1)
T8030_CPREG_FUNCS(ARM64_REG_KERNELKEYHI_EL1)
T8030_CPREG_FUNCS(ARM64_REG_EHID4)
T8030_CPREG_FUNCS(S3_4_c15_c0_5)
T8030_CPREG_FUNCS(S3_4_c15_c1_3)
T8030_CPREG_FUNCS(S3_4_c15_c1_4)
T8030_CPREG_FUNCS(ARM64_REG_CYC_OVRD)
T8030_CPREG_FUNCS(ARM64_REG_ACC_CFG)
T8030_CPREG_FUNCS(S3_6_c15_c1_0)
T8030_CPREG_FUNCS(S3_6_c15_c1_1)
T8030_CPREG_FUNCS(S3_6_c15_c1_2)
T8030_CPREG_FUNCS(S3_6_c15_c1_5)
T8030_CPREG_FUNCS(S3_6_c15_c1_6)
T8030_CPREG_FUNCS(S3_6_c15_c1_7)
T8030_CPREG_FUNCS(S3_6_c15_c3_0)
T8030_CPREG_FUNCS(S3_6_c15_c3_1)
T8030_CPREG_FUNCS(S3_6_c15_c8_0)
T8030_CPREG_FUNCS(S3_6_c15_c8_2)
T8030_CPREG_FUNCS(S3_6_c15_c8_3)
T8030_CPREG_FUNCS(UPMPCM)
T8030_CPREG_FUNCS(UPMCR0)
T8030_CPREG_FUNCS(UPMSR)
T8030_CPREG_FUNCS(ARM64_REG_CTRR_A_LWR_EL1)
T8030_CPREG_FUNCS(ARM64_REG_CTRR_A_UPR_EL1)
T8030_CPREG_FUNCS(ARM64_REG_CTRR_CTL_EL1)
T8030_CPREG_FUNCS(ARM64_REG_CTRR_LOCK_EL1)

static void T8030_set_cs(CPUState *cpu, T8030CPUState *s)
{
    ARMCPU *arm_cpu = ARM_CPU(cpu);
    CPUARMState *env = &arm_cpu->env;

    env->t8030state = (void *)s;
};

static T8030CPUState *T8030_cs_from_env(CPUARMState *env)
{
    return env->t8030state;
}

static inline bool T8030CPU_is_sleep(T8030CPUState* tcpu)
{
    return CPU(tcpu->cpu)->halted;
}

// Wake up cpus, call with machine mutex unlocked
static void T8030_wake_up_cpus(MachineState* machine, uint32_t cpu_mask)
{
    T8030MachineState* tms = T8030_MACHINE(machine);

    WITH_QEMU_LOCK_GUARD(&tms->mutex) {
        int i;

        for(i = 0; i < machine->smp.cpus; i++) {
            if (test_bit(i, (unsigned long*)&cpu_mask) && T8030CPU_is_sleep(tms->cpus[i])) {
                int ret = QEMU_ARM_POWERCTL_RET_SUCCESS;

                if (tms->cpus[i]->cpu->power_state != PSCI_ON) {
                    ret = arm_set_cpu_on_and_reset(tms->cpus[i]->mpidr);
                }

                if (ret != QEMU_ARM_POWERCTL_RET_SUCCESS) {
                    error_report("%s: failed to bring up CPU %d: err %d",
                            __func__, i, ret);
                }
            }
        }
    }
}

static void T8030_wake_up_cpu(MachineState* machine, uint32_t cpu_id)
{
    T8030_wake_up_cpus(machine, 1 << cpu_id);
}

//Deliver IPI, call with cluster mutex locked
static void T8030_cluster_deliver_ipi(cluster* c, uint64_t cpu_id, uint64_t src_cpu, uint64_t flag)
{
    T8030MachineState *tms;

    T8030_wake_up_cpu(c->machine, cpu_id);

    tms = T8030_MACHINE(c->machine);
    if (tms->cpus[cpu_id]->ipi_sr)
        return;

    // fprintf(stderr, "Cluster %u delivering Fast IPI from CPU %x to CPU %x\n", c->id, src_cpu, cpu_id);
    tms->cpus[cpu_id]->ipi_sr = 1LL | (src_cpu << IPI_SR_SRC_CPU_SHIFT) | flag;
    qemu_irq_raise(tms->cpus[cpu_id]->fast_ipi);
}

//Deliver intercluster IPI
static void T8030_ipi_rr_local(CPUARMState *env, const ARMCPRegInfo *ri, uint64_t value)
{
    T8030CPUState *tcpu = T8030_cs_from_env(env);
    T8030MachineState *tms = T8030_MACHINE(tcpu->machine);

    WITH_QEMU_LOCK_GUARD(&tms->clusters[tcpu->cluster_id]->mutex) {
        uint32_t phys_id = MPIDR_CPU_ID(value) | (tcpu->cluster_id << 8);
        cluster *c = tms->clusters[tcpu->cluster_id];
        uint32_t cpu_id = -1;
        int i;

        for(i = 0; i < MAX_CPU; i++) {
            if (c->cpus[i]!=NULL) {
                if (c->cpus[i]->phys_id==phys_id) {
                    cpu_id = i;
                    break;
                }
            }
        }

        // fprintf(stderr, "CPU %x sending fast IPI to local CPU %x: value: 0x%llx\n", tcpu->phys_id, phys_id, value);
        if (cpu_id == -1 || c->cpus[cpu_id] == NULL) {
            qemu_log_mask(LOG_GUEST_ERROR, "CPU %x failed to send fast IPI to local CPU %x: value: 0x" TARGET_FMT_lx "\n", tcpu->phys_id, phys_id, value);
            return;
        }

        if ((value & ARM64_REG_IPI_RR_TYPE_NOWAKE) == ARM64_REG_IPI_RR_TYPE_NOWAKE) {
            // fprintf(stderr, "...nowake ipi\n");
            if (T8030CPU_is_sleep(c->cpus[cpu_id])) {
                c->noWakeIPI[tcpu->cpu_id][cpu_id] = 1;
            } else {
                T8030_cluster_deliver_ipi(c, cpu_id, tcpu->cpu_id, ARM64_REG_IPI_RR_TYPE_IMMEDIATE);
            }
        } else if ((value & ARM64_REG_IPI_RR_TYPE_DEFERRED) == ARM64_REG_IPI_RR_TYPE_DEFERRED) {
            // fprintf(stderr, "...deferred ipi\n");
            c->deferredIPI[tcpu->cpu_id][cpu_id] = 1;
        } else if ((value & ARM64_REG_IPI_RR_TYPE_RETRACT) == ARM64_REG_IPI_RR_TYPE_RETRACT) {
            // fprintf(stderr, "...retract ipi\n");
            c->deferredIPI[tcpu->cpu_id][cpu_id] = 0;
            c->noWakeIPI[tcpu->cpu_id][cpu_id] = 0;
        } else if ((value & ARM64_REG_IPI_RR_TYPE_IMMEDIATE) == ARM64_REG_IPI_RR_TYPE_IMMEDIATE) {
            // fprintf(stderr, "...immediate ipi\n");
            T8030_cluster_deliver_ipi(c, cpu_id, tcpu->cpu_id, ARM64_REG_IPI_RR_TYPE_IMMEDIATE);
        }
    }
}

// Deliver intracluster IPI
static void T8030_ipi_rr_global(CPUARMState *env, const ARMCPRegInfo *ri, uint64_t value)
{
    T8030CPUState *tcpu = T8030_cs_from_env(env);
    T8030MachineState *tms = T8030_MACHINE(tcpu->machine);
    uint32_t cluster_id = MPIDR_CLUSTER_ID(value >> IPI_RR_TARGET_CLUSTER_SHIFT);

    if (cluster_id >= MAX_CLUSTER || tms->clusters[cluster_id] == 0)
        return;

    WITH_QEMU_LOCK_GUARD(&tms->clusters[cluster_id]->mutex) {
        uint32_t phys_id = MPIDR_CPU_ID(value) | cluster_id << 8;
        cluster *c = tms->clusters[cluster_id];
        uint32_t cpu_id = -1;
        int i;

        for(i = 0; i < MAX_CPU; i++) {
            if (c->cpus[i] != NULL) {
                if (c->cpus[i]->phys_id == phys_id) {
                    cpu_id = i;
                    break;
                }
            }
        }

        // fprintf(stderr, "CPU %x sending fast IPI to global CPU %x: value: 0x%llx\n", tcpu->phys_id, phys_id, value);
        if (cpu_id == -1 || c->cpus[cpu_id] == NULL) {
            fprintf(stderr, "CPU %x failed to send fast IPI to global CPU %x: value: 0x" TARGET_FMT_lx "\n", tcpu->phys_id, phys_id, value);
            return;
        }

        if ((value & ARM64_REG_IPI_RR_TYPE_NOWAKE) == ARM64_REG_IPI_RR_TYPE_NOWAKE) {
            if (T8030CPU_is_sleep(c->cpus[cpu_id])) {
                c->noWakeIPI[tcpu->cpu_id][cpu_id] = 1;
            } else {
                T8030_cluster_deliver_ipi(c, cpu_id, tcpu->cpu_id, ARM64_REG_IPI_RR_TYPE_IMMEDIATE);
            }
        } else if ((value & ARM64_REG_IPI_RR_TYPE_DEFERRED) == ARM64_REG_IPI_RR_TYPE_DEFERRED) {
            c->deferredIPI[tcpu->cpu_id][cpu_id] = 1;
        } else if ((value & ARM64_REG_IPI_RR_TYPE_RETRACT) == ARM64_REG_IPI_RR_TYPE_RETRACT) {
            c->deferredIPI[tcpu->cpu_id][cpu_id] = 0;
            c->noWakeIPI[tcpu->cpu_id][cpu_id] = 0;
        } else if ((value & ARM64_REG_IPI_RR_TYPE_IMMEDIATE) == ARM64_REG_IPI_RR_TYPE_IMMEDIATE) {
            T8030_cluster_deliver_ipi(c, cpu_id, tcpu->cpu_id, ARM64_REG_IPI_RR_TYPE_IMMEDIATE);
        } 
    }
}

//Receiving IPI
static uint64_t T8030_ipi_read_sr(CPUARMState *env, const ARMCPRegInfo *ri)
{
    T8030CPUState *tcpu = T8030_cs_from_env(env);

    assert(env_archcpu(env)->mp_affinity == tcpu->mpidr);
    return tcpu->ipi_sr;
}

// Acknowledge received IPI
static void T8030_ipi_write_sr(CPUARMState *env, const ARMCPRegInfo *ri,
                               uint64_t value)
{
    T8030CPUState *tcpu = T8030_cs_from_env(env);
    T8030MachineState *tms = T8030_MACHINE(tcpu->machine);
    cluster *c = tms->clusters[tcpu->cluster_id];
    uint64_t src_cpu = IPI_SR_SRC_CPU(value);

    tcpu->ipi_sr = 0;
    qemu_irq_lower(tcpu->fast_ipi);

    WITH_QEMU_LOCK_GUARD(&c->mutex) {
        if ((value & ARM64_REG_IPI_RR_TYPE_NOWAKE) == ARM64_REG_IPI_RR_TYPE_NOWAKE) {
            c->noWakeIPI[src_cpu][tcpu->cpu_id] = 0;
        } else if ((value & ARM64_REG_IPI_RR_TYPE_DEFERRED) == ARM64_REG_IPI_RR_TYPE_DEFERRED) {
            c->deferredIPI[src_cpu][tcpu->cpu_id] = 0;
        }
    }
    // fprintf(stderr, "CPU %x ack fast IPI from CPU %llu: 0x%llx\n", tcpu->cpu_id, src_cpu, value);
}

// Read deferred interrupt timeout (global)
static uint64_t T8030_ipi_read_cr(CPUARMState *env, const ARMCPRegInfo *ri)
{
    T8030CPUState *tcpu = T8030_cs_from_env(env);
    T8030MachineState *tms = T8030_MACHINE(tcpu->machine);
    uint64_t abstime;

    nanoseconds_to_absolutetime(tms->ipi_cr, &abstime);
    return abstime;
}

//Set deferred interrupt timeout (global)
static void T8030_ipi_write_cr(CPUARMState *env, const ARMCPRegInfo *ri,
                               uint64_t value)
{
    uint64_t nanosec = 0;
    T8030CPUState *tcpu = T8030_cs_from_env(env);
    T8030MachineState *tms = T8030_MACHINE(tcpu->machine);

    absolutetime_to_nanoseconds(value, &nanosec);
    // fprintf(stderr, "T8030 adjusting deferred IPI timeout to " TARGET_FMT_lu "ns\n", nanosec);

    WITH_QEMU_LOCK_GUARD(&tms->mutex) {
        uint64_t ct;

        if (value == 0)
            value = kDeferredIPITimerDefault;

        ct = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
        timer_mod_ns(tms->ipicr_timer, (ct / tms->ipi_cr) * tms->ipi_cr + nanosec);
        tms->ipi_cr = nanosec;
    }
}

// This is the same as the array for kvm, but without
// the L2ACTLR_EL1, which is already defined in TCG.
// Duplicating this list isn't a perfect solution,
// but it's quick and reliable.
static const ARMCPRegInfo T8030_cp_reginfo_tcg[] = {
    // Apple-specific registers
    T8030_CPREG_DEF(ARM64_REG_HID11, 3, 0, 15, 13, 0, PL1_RW),
    T8030_CPREG_DEF(ARM64_REG_HID13, 3, 0, 15, 14, 0, PL1_RW),
    T8030_CPREG_DEF(ARM64_REG_HID14, 3, 0, 15, 15, 0, PL1_RW),
    T8030_CPREG_DEF(ARM64_REG_HID3, 3, 0, 15, 3, 0, PL1_RW),
    T8030_CPREG_DEF(ARM64_REG_HID5, 3, 0, 15, 5, 0, PL1_RW),
    T8030_CPREG_DEF(ARM64_REG_HID4, 3, 0, 15, 4, 0, PL1_RW),
    T8030_CPREG_DEF(ARM64_REG_EHID4, 3, 0, 15, 4, 1, PL1_RW),
    T8030_CPREG_DEF(ARM64_REG_HID8, 3, 0, 15, 8, 0, PL1_RW),
    T8030_CPREG_DEF(ARM64_REG_HID7, 3, 0, 15, 7, 0, PL1_RW),
    T8030_CPREG_DEF(ARM64_REG_LSU_ERR_STS, 3, 3, 15, 0, 0, PL1_RW),
    T8030_CPREG_DEF(PMC0, 3, 2, 15, 0, 0, PL1_RW),
    T8030_CPREG_DEF(PMC1, 3, 2, 15, 1, 0, PL1_RW),
    T8030_CPREG_DEF(PMCR1, 3, 1, 15, 1, 0, PL1_RW),
    T8030_CPREG_DEF(PMSR, 3, 1, 15, 13, 0, PL1_RW),
    T8030_CPREG_DEF(ARM64_REG_APCTL_EL1, 3, 4, 15, 0, 4, PL1_RW),
    T8030_CPREG_DEF(ARM64_REG_KERNELKEYLO_EL1, 3, 4, 15, 1, 0, PL1_RW),
    T8030_CPREG_DEF(ARM64_REG_KERNELKEYHI_EL1, 3, 4, 15, 1, 1, PL1_RW),
    T8030_CPREG_DEF(S3_4_c15_c0_5, 3, 4, 15, 0, 5, PL1_RW),
    T8030_CPREG_DEF(S3_4_c15_c1_3, 3, 4, 15, 1, 3, PL1_RW),
    T8030_CPREG_DEF(S3_4_c15_c1_4, 3, 4, 15, 1, 4, PL1_RW),
    T8030_CPREG_DEF(ARM64_REG_CYC_OVRD, 3, 5, 15, 5, 0, PL1_RW),
    T8030_CPREG_DEF(ARM64_REG_ACC_CFG, 3, 5, 15, 4, 0, PL1_RW),
    T8030_CPREG_DEF(S3_6_c15_c1_0, 3, 6, 15, 1, 0, PL1_RW),
    T8030_CPREG_DEF(S3_6_c15_c1_1, 3, 6, 15, 1, 1, PL1_RW),
    T8030_CPREG_DEF(S3_6_c15_c1_2, 3, 6, 15, 1, 2, PL1_RW),
    T8030_CPREG_DEF(S3_6_c15_c1_5, 3, 6, 15, 1, 5, PL1_RW),
    T8030_CPREG_DEF(S3_6_c15_c1_6, 3, 6, 15, 1, 6, PL1_RW),
    T8030_CPREG_DEF(S3_6_c15_c1_7, 3, 6, 15, 1, 7, PL1_RW),
    T8030_CPREG_DEF(S3_6_c15_c3_0, 3, 6, 15, 3, 0, PL1_RW),
    T8030_CPREG_DEF(S3_6_c15_c3_1, 3, 6, 15, 3, 1, PL1_RW),
    T8030_CPREG_DEF(S3_6_c15_c8_0, 3, 6, 15, 8, 0, PL1_RW),
    T8030_CPREG_DEF(S3_6_c15_c8_2, 3, 6, 15, 8, 2, PL1_RW),
    T8030_CPREG_DEF(S3_6_c15_c8_3, 3, 6, 15, 8, 3, PL1_RW),
    T8030_CPREG_DEF(UPMPCM, 3, 7, 15, 5, 4, PL1_RW),
    T8030_CPREG_DEF(UPMCR0, 3, 7, 15, 0, 4, PL1_RW),
    T8030_CPREG_DEF(UPMSR, 3, 7, 15, 6, 4, PL1_RW),
    T8030_CPREG_DEF(ARM64_REG_CTRR_A_LWR_EL1, 3, 4, 15, 2, 3, PL1_RW),
    T8030_CPREG_DEF(ARM64_REG_CTRR_A_UPR_EL1, 3, 4, 15, 2, 4, PL1_RW),
    T8030_CPREG_DEF(ARM64_REG_CTRR_CTL_EL1, 3, 4, 15, 2, 5, PL1_RW),
    T8030_CPREG_DEF(ARM64_REG_CTRR_LOCK_EL1, 3, 4, 15, 2, 2, PL1_RW),
    
    //Cluster
    {                                                                        
        .cp = CP_REG_ARM64_SYSREG_CP,                                        
        .name = "ARM64_REG_IPI_RR_LOCAL",
        .opc0 = 3, .opc1 = 5, .crn = 15, .crm = 0, .opc2 = 0,
        .access = PL1_W, .type = ARM_CP_IO | ARM_CP_NO_RAW,
        .state = ARM_CP_STATE_AA64,
        .readfn = arm_cp_read_zero,
        .writefn = T8030_ipi_rr_local
    },
    {                                                                        
        .cp = CP_REG_ARM64_SYSREG_CP,                                        
        .name = "ARM64_REG_IPI_RR_GLOBAL",
        .opc0 = 3, .opc1 = 5, .crn = 15, .crm = 0, .opc2 = 1,
        .access = PL1_W, .type = ARM_CP_IO | ARM_CP_NO_RAW,
        .state = ARM_CP_STATE_AA64,
        .readfn = arm_cp_read_zero,
        .writefn = T8030_ipi_rr_global
    },
    {                                                                        
        .cp = CP_REG_ARM64_SYSREG_CP,                                        
        .name = "ARM64_REG_IPI_SR",
        .opc0 = 3, .opc1 = 5, .crn = 15, .crm = 1, .opc2 = 1,
        .access = PL1_RW, .type = ARM_CP_IO | ARM_CP_NO_RAW,
        .state = ARM_CP_STATE_AA64,
        .readfn = T8030_ipi_read_sr,
        .writefn = T8030_ipi_write_sr
    },
    {                                                                        
        .cp = CP_REG_ARM64_SYSREG_CP,                                        
        .name = "ARM64_REG_IPI_CR",
        .opc0 = 3, .opc1 = 5, .crn = 15, .crm = 3, .opc2 = 1,
        .access = PL1_RW, .type = ARM_CP_IO,
        .state = ARM_CP_STATE_AA64,
        .readfn = T8030_ipi_read_cr,
        .writefn = T8030_ipi_write_cr
    },
    //GXF
    {                                                                        
        .cp = CP_REG_ARM64_SYSREG_CP,                                        
        .name = "GXF_ENTER_EL1",
        .opc0 = 3, .opc1 = 6, .crn = 15, .crm = 8, .opc2 = 1,
        .access = PL1_RW, .resetvalue = 0,
        .state = ARM_CP_STATE_AA64,
        .fieldoffset = offsetof(CPUARMState, gxf.gxf_enter_el[1])
    },  
    {                                                                        
        .cp = CP_REG_ARM64_SYSREG_CP,                                        
        .name = "TPIDR_GL11",
        .opc0 = 3, .opc1 = 6, .crn = 15, .crm = 9, .opc2 = 1,
        .access = PL1_RW, .resetvalue = 0,
        .state = ARM_CP_STATE_AA64,
        .fieldoffset = offsetof(CPUARMState, cp15.tpidr_el[1])
    },
    {                                                                        
        .cp = CP_REG_ARM64_SYSREG_CP,                                        
        .name = "ESR_GL11",
        .opc0 = 3, .opc1 = 6, .crn = 15, .crm = 9, .opc2 = 5,
        .access = PL1_RW, .resetvalue = 0,
        .state = ARM_CP_STATE_AA64,
        .fieldoffset = offsetof(CPUARMState, cp15.esr_el[1])
    },
    {                                                                        
        .cp = CP_REG_ARM64_SYSREG_CP,                                        
        .name = "FAR_GL11",
        .opc0 = 3, .opc1 = 6, .crn = 15, .crm = 9, .opc2 = 7,
        .access = PL1_RW, .resetvalue = 0,
        .state = ARM_CP_STATE_AA64,
        .fieldoffset = offsetof(CPUARMState, cp15.far_el[1])
    },
    REGINFO_SENTINEL,
};

static void T8030_add_cpregs(T8030CPUState* tcpu)
{
    ARMCPU *cpu = tcpu->cpu;

    tcpu->T8030_CPREG_VAR_NAME(ARM64_REG_HID11) = 0;
    tcpu->T8030_CPREG_VAR_NAME(ARM64_REG_HID3) = 0;
    tcpu->T8030_CPREG_VAR_NAME(ARM64_REG_HID5) = 0;
    tcpu->T8030_CPREG_VAR_NAME(ARM64_REG_HID8) = 0;
    tcpu->T8030_CPREG_VAR_NAME(ARM64_REG_HID7) = 0;
    tcpu->T8030_CPREG_VAR_NAME(ARM64_REG_LSU_ERR_STS) = 0;
    tcpu->T8030_CPREG_VAR_NAME(PMC0) = 0;
    tcpu->T8030_CPREG_VAR_NAME(PMC1) = 0;
    tcpu->T8030_CPREG_VAR_NAME(PMCR1) = 0;
    tcpu->T8030_CPREG_VAR_NAME(PMSR) = 0;
    tcpu->T8030_CPREG_VAR_NAME(ARM64_REG_APCTL_EL1) = 2;
    tcpu->T8030_CPREG_VAR_NAME(ARM64_REG_KERNELKEYLO_EL1) = 0;
    tcpu->T8030_CPREG_VAR_NAME(ARM64_REG_KERNELKEYHI_EL1) = 0;

    /* Note that we can't just use the T8030CPUState as an opaque pointer
     * in define_arm_cp_regs_with_opaque(), because when we're called back
     * it might be with code translated by CPU 0 but run by CPU 1, in
     * which case we'd get the wrong value.
     * So instead we define the regs with no ri->opaque info, and
     * get back to the T8030CPUState from the CPUARMState.
     */
    T8030_set_cs(CPU(cpu), tcpu);
    define_arm_cp_regs(cpu, T8030_cp_reginfo_tcg);
}

static void T8030_create_s3c_uart(const T8030MachineState *tms, Chardev *chr)
{
    DeviceState *dev;
    hwaddr base;
    //first fetch the uart mmio address
    int vector;
    DTBProp *prop;
    hwaddr *uart_offset;
    DTBNode *child = get_dtb_child_node_by_name(tms->device_tree, "arm-io");

    assert(child != NULL);

    child = get_dtb_child_node_by_name(child, "uart0");
    assert(child != NULL);

    //make sure this node has the boot-console prop
    prop = get_dtb_prop(child, "boot-console");
    assert(prop != NULL);

    prop = get_dtb_prop(child, "reg");
    assert(prop != NULL);

    uart_offset = (hwaddr *)prop->value;
    base = tms->soc_base_pa + uart_offset[0];

    prop = get_dtb_prop(child, "interrupts");
    assert(prop);

    vector = *(uint32_t*)prop->value;
    dev = exynos4210_uart_create(base, 256, 0, chr, qdev_get_gpio_in(DEVICE(tms->aic), vector));
    assert(dev);
}

static void T8030_patch_kernel(AddressSpace *nsas)
{
    // uint32_t value = 0;
    // //disable_kprintf_output = 0
    // address_space_rw(nsas, vtop_static(0xFFFFFFF0077142C8),
    //                  MEMTXATTRS_UNSPECIFIED, (uint8_t *)&value,
    //                  sizeof(value), 1);
    //TODO: PMGR
    // value = RET_INST;
    // //AppleT8030PMGR::panicHW
    // address_space_rw(nsas, vtop_static(0xFFFFFFF008B2DBE4),
    //                  MEMTXATTRS_UNSPECIFIED, (uint8_t *)&value,
    //                  sizeof(value), 1);
    // //AppleImage4 _xnu_log 
    // value = NOP_INST;
    // address_space_rw(nsas, vtop_static(0xFFFFFFF008387A28),
    //                  MEMTXATTRS_UNSPECIFIED, (uint8_t *)&value,
    //                  sizeof(value), 1);
}

static void T8030_memory_setup(MachineState *machine)
{
    uint64_t used_ram_for_blobs = 0;
    hwaddr kernel_low;
    hwaddr kernel_high;
    hwaddr virt_base;
    hwaddr dtb_pa;
    hwaddr dtb_va;
    uint64_t dtb_size;
    hwaddr kbootargs_pa;
    hwaddr top_of_kernel_data_pa;
    hwaddr mem_size;
    hwaddr remaining_mem_size;
    hwaddr allocated_ram_pa;
    hwaddr phys_ptr;
    hwaddr phys_pc;
    video_boot_args v_bootargs = {0};
    T8030MachineState *tms = T8030_MACHINE(machine);
    MemoryRegion* sysmem = tms->sysmem;
    AddressSpace* nsas = tms->cpus[0]->nsas;
    uint64_t trustcache_size = 0;
    hwaddr trustcache_pa;
    void *nvram_data = NULL;
    NvmeNamespace* nvram;
    hwaddr ramdisk_size = 0;

    //setup the memory layout:

    //At the beginning of the non-secure ram we have the raw kernel file.
    //After that we have the static trust cache.
    //After that we have all the kernel sections.
    //After that we have ramdosk
    //After that we have the device tree
    //After that we have the kernel boot args
    //After that we have the rest of the RAM

    macho_file_highest_lowest(tms->kernel_filename, &kernel_low, &kernel_high);

    g_virt_base = virt_base = align_64k_low(kernel_low);
    g_phys_base = T8030_PHYS_BASE;
    phys_ptr = T8030_PHYS_BASE;
    fprintf(stderr, "g_virt_base: 0x" TARGET_FMT_lx "\ng_phys_base: 0x" TARGET_FMT_lx "\n", g_virt_base, g_phys_base);
    fprintf(stderr, "kernel_low: 0x" TARGET_FMT_lx "\nkernel_high: 0x" TARGET_FMT_lx "\n", kernel_low, kernel_high);

    // //now account for the trustcache
    phys_ptr += align_64k_high(0x2000000);
    trustcache_pa = phys_ptr;
    macho_load_trustcache(tms->trustcache_filename, nsas, sysmem, trustcache_pa, &trustcache_size);
    phys_ptr += align_64k_high(trustcache_size);

    used_ram_for_blobs += align_64k_high(trustcache_size);
    //now account for the loaded kernel
    arm_load_macho(tms->kernel_filename, nsas, sysmem, "Kernel",
                   T8030_PHYS_BASE, virt_base, &phys_pc);
    tms->kpc_pa = phys_pc;
    used_ram_for_blobs += (align_64k_high(kernel_high) - kernel_low);

    T8030_patch_kernel(nsas);

    phys_ptr = align_64k_high(vtop_static(kernel_high));

    //now account for device tree
    dtb_pa = phys_ptr;

    dtb_va = ptov_static(phys_ptr);
    phys_ptr += align_64k_high(T8030_MAX_DEVICETREE_SIZE);
    used_ram_for_blobs += align_64k_high(T8030_MAX_DEVICETREE_SIZE);
    //now account for the ramdisk
    tms->ramdisk_file_dev.pa = 0;

    if (tms->ramdisk_filename[0]) {
        tms->ramdisk_file_dev.pa = phys_ptr;
        macho_load_ramdisk(tms->ramdisk_filename, nsas, sysmem, phys_ptr, &tms->ramdisk_file_dev.size);
        tms->ramdisk_file_dev.size = align_64k_high(tms->ramdisk_file_dev.size);
        ramdisk_size = tms->ramdisk_file_dev.size;
        phys_ptr += tms->ramdisk_file_dev.size;
        used_ram_for_blobs += tms->ramdisk_file_dev.size;
    }
    
    //now account for kernel boot args
    used_ram_for_blobs += align_64k_high(sizeof(struct xnu_arm64_boot_args));
    kbootargs_pa = phys_ptr;
    tms->kbootargs_pa = kbootargs_pa;
    phys_ptr += align_64k_high(sizeof(struct xnu_arm64_boot_args));
    tms->extra_data_pa = phys_ptr;

    top_of_kernel_data_pa = phys_ptr;
    allocated_ram_pa = phys_ptr;
    
    remaining_mem_size = T8030_PHYS_BASE + machine->ram_size - allocated_ram_pa;
    mem_size = machine->ram_size;
    tms->dram_base = T8030_PHYS_BASE;
    tms->dram_size = machine->ram_size;

    nvram = NVME_NS(qdev_find_recursive(sysbus_get_default(), "nvram"));
    assert(nvram);

    nvram_data = g_malloc0(T8030_NVRAM_SIZE);
    blk_pread(nvram->blkconf.blk, 0, nvram_data, T8030_NVRAM_SIZE);
    
    macho_load_dtb(tms->device_tree, nsas, sysmem, "DeviceTree",
                   dtb_pa, &dtb_size,
                   tms->ramdisk_file_dev.pa, ramdisk_size,
                   trustcache_pa, trustcache_size,
                   kbootargs_pa,
                   tms->dram_base, tms->dram_size,
                   nvram_data, T8030_NVRAM_SIZE);
    g_free(nvram_data);
    assert(dtb_size <= T8030_MAX_DEVICETREE_SIZE);

    macho_setup_bootargs("BootArgs", nsas, sysmem, kbootargs_pa,
                         virt_base, T8030_PHYS_BASE, mem_size,
                         top_of_kernel_data_pa, dtb_va, dtb_size,
                         v_bootargs, tms->kern_args);

    allocate_ram(sysmem, "RAM", allocated_ram_pa, remaining_mem_size);
}

static void cpu_impl_reg_write(void *opaque, hwaddr addr, uint64_t data, unsigned size)
{
    T8030CPUState *cpu = (T8030CPUState*)opaque;
    fprintf(stderr, "CPU %x cpu-impl-reg WRITE @ 0x" TARGET_FMT_lx " value: 0x" TARGET_FMT_lx "\n", cpu->cpu_id, addr, data);
}

static uint64_t cpu_impl_reg_read(void *opaque, hwaddr addr, unsigned size)
{
    T8030CPUState *cpu = (T8030CPUState*) opaque;
    fprintf(stderr, "CPU %x cpu-impl-reg READ @ 0x" TARGET_FMT_lx "\n", cpu->cpu_id, addr);
    return 0;
}

static const MemoryRegionOps cpu_impl_reg_ops = {
    .write = cpu_impl_reg_write,
    .read = cpu_impl_reg_read,
};

static void cpu_coresight_reg_write(void *opaque, hwaddr addr, uint64_t data, unsigned size)
{
}

static uint64_t cpu_coresight_reg_read(void *opaque, hwaddr addr, unsigned size)
{
    return 0;
}

static const MemoryRegionOps cpu_coresight_reg_ops = {
    .write = cpu_coresight_reg_write,
    .read = cpu_coresight_reg_read,
};

static void cpm_impl_reg_write(void *opaque, hwaddr addr, uint64_t data, unsigned size)
{
    cluster* cpm = (cluster*) opaque;
    fprintf(stderr, "Cluster %u cpm-impl-reg WRITE @ 0x" TARGET_FMT_lx " value: 0x" TARGET_FMT_lx "\n", cpm->id, addr, data);
}

static uint64_t cpm_impl_reg_read(void *opaque, hwaddr addr, unsigned size)
{
    cluster* cpm = (cluster*) opaque;

    fprintf(stderr, "Cluster %u cpm-impl-reg READ @ 0x" TARGET_FMT_lx "\n", cpm->id, addr);

    return 0;
}

static const MemoryRegionOps cpm_impl_reg_ops = {
    .write = cpm_impl_reg_write,
    .read = cpm_impl_reg_read,
};

static void pmgr_unk_reg_write(void *opaque, hwaddr addr, uint64_t data, unsigned size)
{
    //hwaddr* base = (hwaddr*) opaque;
    //fprintf(stderr, "PMGR reg WRITE unk @ 0x" TARGET_FMT_lx " base: 0x" TARGET_FMT_lx " value: 0x" TARGET_FMT_lx "\n", base + addr, base, data);
}

static uint64_t pmgr_unk_reg_read(void *opaque, hwaddr addr, unsigned size)
{
    hwaddr* base = (hwaddr*) opaque;

    //fprintf(stderr, "PMGR reg READ unk @ 0x" TARGET_FMT_lx " base: 0x" TARGET_FMT_lx "\n", base + addr, base);
    if (((uint64_t)(base + addr) & 0x10e70000) == 0x10e70000) {
        return (108<<4) | 0x200000;
    }

    return 0;
}

static const MemoryRegionOps pmgr_unk_reg_ops = {
    .write = pmgr_unk_reg_write,
    .read = pmgr_unk_reg_read,
};

static void pmgr_reg_write(void *opaque, hwaddr addr, uint64_t data, unsigned size)
{
    MachineState *machine = MACHINE(opaque);

    // fprintf(stderr, "PMGR reg WRITE @ 0x" TARGET_FMT_lx " value: 0x" TARGET_FMT_lx "\n", addr, data);
    switch (addr) {
        case 0xd4004:
            T8030_wake_up_cpus(machine, data);
            return;
    }
}

static uint64_t pmgr_reg_read(void *opaque, hwaddr addr, unsigned size)
{
    // fprintf(stderr, "PMGR reg READ @ 0x" TARGET_FMT_lx "\n", addr);
    switch(addr) {
        case 0xf0010: /* AppleT8030PMGR::commonSramCheck */
            return 0x5000;
        case 0x802d8:
        case 0x80308:
        case 0x80310:
        case 0x80318:
        case 0x80320:
        case 0x80328:
        case 0x80330:
            return 0xf0;
    }
    return 0;
}

static const MemoryRegionOps pmgr_reg_ops = {
    .write = pmgr_reg_write,
    .read = pmgr_reg_read,
};

static void sart_reg_write(void *opaque, hwaddr addr, uint64_t data, unsigned size)
{
    qemu_log_mask(LOG_UNIMP, "SART reg WRITE @ 0x" TARGET_FMT_lx " value: 0x" TARGET_FMT_lx "\n", addr, data);
}

static uint64_t sart_reg_read(void *opaque, hwaddr addr, unsigned size)
{
    qemu_log_mask(LOG_UNIMP, "SART reg READ @ 0x" TARGET_FMT_lx "\n", addr);

    return 0;
}

static const MemoryRegionOps sart_reg_ops = {
    .write = sart_reg_write,
    .read = sart_reg_read,
};

static void T8030_cluster_setup(MachineState *machine)
{
    T8030MachineState *tms = T8030_MACHINE(machine);

    tms->clusters[0] = g_new0(cluster, 1);
    //TODO: find base through device tree
    tms->clusters[0]->base = CPM_IMPL_REG_BASE;
    tms->clusters[0]->type = '0'; // E-CORE
    tms->clusters[0]->id = 0;
    tms->clusters[0]->mr = g_new(MemoryRegion, 1);
    tms->clusters[0]->machine = machine;
    qemu_mutex_init(&tms->clusters[0]->mutex);
    memory_region_init_io(tms->clusters[0]->mr, OBJECT(machine), &cpm_impl_reg_ops, tms->clusters[0], "cpm-impl-reg", 0x10000);
    memory_region_add_subregion(tms->sysmem, tms->clusters[0]->base, tms->clusters[0]->mr);
    tms->clusters[1] = g_new0(cluster, 1);
    //TODO: find base through device tree
    tms->clusters[1]->base = CPM_IMPL_REG_BASE + 0x10000;
    tms->clusters[1]->type = '1'; // P-CORE
    tms->clusters[1]->id = 1;
    tms->clusters[1]->mr = g_new(MemoryRegion, 1);
    tms->clusters[1]->machine = machine;

    qemu_mutex_init(&tms->clusters[1]->mutex);
    memory_region_init_io(tms->clusters[1]->mr, OBJECT(machine), &cpm_impl_reg_ops, tms->clusters[1], "cpm-impl-reg", 0x10000);
    memory_region_add_subregion(tms->sysmem, tms->clusters[1]->base,tms->clusters[1]->mr);
}

static void T8030_cpu_setup(MachineState *machine)
{
    unsigned int i;
    DTBNode *root;
    T8030MachineState *tms = T8030_MACHINE(machine);

    T8030_cluster_setup(machine);

    root = get_dtb_child_node_by_name(tms->device_tree, "cpus");

    for(i = 0; i<MAX_CPU; i++) {
        char cpu_name[8];
        unsigned int cpu_id, phys_id, cluster_id, mpidr;
        uint64_t freq;
        uint64_t *reg;
        DeviceState *fiq_or;
        DTBNode *node;
        DTBProp* prop = NULL;
        Object *cpuobj;
        CPUState *cs;

        snprintf(cpu_name, 8, "cpu%u", i);
        node = get_dtb_child_node_by_name(root, cpu_name);
        assert(node);

        if (i >= machine->smp.cpus) {
            remove_dtb_node(root, node);
            continue;
        }

        cpuobj = object_new(machine->cpu_type);
        tms->cpus[i] = g_new(T8030CPUState, 1);
        tms->cpus[i]->cpu = ARM_CPU(cpuobj);
        tms->cpus[i]->machine = machine;
        cs = CPU(tms->cpus[i]->cpu);

        //MPIDR_EL1
        prop = get_dtb_prop(node, "cpu-id");
        assert(prop->length == 4);
        cpu_id = *(unsigned int*)prop->value;

        prop = get_dtb_prop(node, "reg");
        assert(prop->length == 4);
        phys_id = *(unsigned int*)prop->value;

        prop = get_dtb_prop(node, "cluster-id");
        assert(prop->length == 4);
        cluster_id = *(unsigned int*)prop->value;

        mpidr = 0LL | phys_id | (tms->clusters[cluster_id]->type << MPIDR_AFF2_SHIFT) | (1LL << 31);
        object_property_set_uint(cpuobj, "mp-affinity", mpidr, &error_fatal);
        object_property_set_uint(cpuobj, "cntfrq", 24000000, &error_fatal);
        tms->cpus[i]->mpidr = mpidr;
        tms->cpus[i]->cpu_id = cpu_id;
        tms->cpus[i]->phys_id = phys_id;
        tms->cpus[i]->cluster_id = cluster_id;
        tms->clusters[cluster_id]->cpus[cpu_id] = tms->cpus[i];

        //remove debug regs from device tree
        prop = get_dtb_prop(node, "reg-private");
        if (prop != NULL) {
            remove_dtb_prop(node, prop);
        }

        prop = get_dtb_prop(node, "cpu-uttdbg-reg");
        if (prop != NULL) {
            remove_dtb_prop(node, prop);
        }

        //need to set the cpu freqs instead of iboot
        freq = 24000000;

        if (i == 0) {
            prop = get_dtb_prop(node, "state");
            if (prop != NULL) {
                remove_dtb_prop(node, prop);
            }
            add_dtb_prop(node, "state", 8, (uint8_t*)"running");
        }

        prop = get_dtb_prop(node, "timebase-frequency");
        if (prop != NULL) {
            remove_dtb_prop(node, prop);
        }
        add_dtb_prop(node, "timebase-frequency", sizeof(uint64_t), (uint8_t *)&freq);

        prop = get_dtb_prop(node, "fixed-frequency");
        if (prop != NULL) {
            remove_dtb_prop(node, prop);
        }
        add_dtb_prop(node, "fixed-frequency", sizeof(uint64_t), (uint8_t *)&freq);

        //per cpu memory region
        tms->cpus[i]->memory = g_new(MemoryRegion, 1);
        memory_region_init(tms->cpus[i]->memory, OBJECT(machine), "cpu-memory", UINT64_MAX);
        tms->cpus[i]->sysmem = g_new(MemoryRegion, 1);
        memory_region_init_alias(tms->cpus[i]->sysmem, OBJECT(tms->cpus[i]->memory), "sysmem", tms->sysmem, 0, UINT64_MAX);
        memory_region_add_subregion_overlap(tms->cpus[i]->memory, 0, tms->cpus[i]->sysmem, -2);
        object_property_set_link(cpuobj, "memory", OBJECT(tms->cpus[i]->memory), &error_abort);
        //set secure monitor to false
        object_property_set_bool(cpuobj, "has_el3", false, NULL);

        object_property_set_bool(cpuobj, "has_el2", false, NULL);

        if (i > 0) {
            object_property_set_bool(cpuobj, "start-powered-off", true, NULL);
        }

        qdev_realize(DEVICE(cpuobj), NULL, &error_fatal);
        
        tms->cpus[i]->nsas = cpu_get_address_space(cs, ARMASIdx_NS);

        prop = get_dtb_prop(node, "cpu-impl-reg");
        assert(prop);
        assert(prop->length == 16);

        reg = (uint64_t*)prop->value;
        tms->cpus[i]->impl_reg = g_new(MemoryRegion, 1);
        memory_region_init_io(tms->cpus[i]->impl_reg, cpuobj, &cpu_impl_reg_ops, tms->cpus[i], "cpu-impl-reg", reg[1]);

        hwaddr cpu_impl_reg_addr = reg[0];

        memory_region_add_subregion(tms->sysmem, cpu_impl_reg_addr, tms->cpus[i]->impl_reg);

        prop = get_dtb_prop(node, "coresight-reg");
        assert(prop);
        assert(prop->length == 16);

        reg = (uint64_t*)prop->value;
        tms->cpus[i]->coresight_reg = g_new(MemoryRegion, 1);
        memory_region_init_io(tms->cpus[i]->coresight_reg, cpuobj, &cpu_coresight_reg_ops, tms->cpus[i], "coresight-reg", reg[1]);

        hwaddr cpu_coresight_reg_addr = reg[0];

        memory_region_add_subregion(tms->sysmem, cpu_coresight_reg_addr, tms->cpus[i]->coresight_reg);

        fiq_or = qdev_new(TYPE_OR_IRQ);
        object_property_add_child(cpuobj, "fiq-or", OBJECT(fiq_or));
        qdev_prop_set_uint16(fiq_or, "num-lines", 16);
        qdev_realize_and_unref(fiq_or, NULL, &error_fatal);

        qdev_connect_gpio_out(fiq_or, 0, qdev_get_gpio_in(DEVICE(cpuobj), ARM_CPU_FIQ));

        qdev_connect_gpio_out(DEVICE(cpuobj), GTIMER_VIRT, qdev_get_gpio_in(fiq_or, 0));
        tms->cpus[i]->fast_ipi = qdev_get_gpio_in(fiq_or, 1);

        T8030_add_cpregs(tms->cpus[i]);
    }
}

static void T8030_bootargs_setup(MachineState *machine)
{
    T8030MachineState *tms = T8030_MACHINE(machine);
    tms->bootinfo.firmware_loaded = true;
}

static void T8030_create_aic(MachineState *machine)
{
    unsigned int i;
    hwaddr *reg;
    DTBProp *prop;
    T8030MachineState *tms = T8030_MACHINE(machine);
    DTBNode *child = get_dtb_child_node_by_name(tms->device_tree, "arm-io");

    assert(child != NULL);
    child = get_dtb_child_node_by_name(child, "aic");
    assert(child != NULL);

    tms->aic = apple_aic_create(machine->smp.cpus, child);
    object_property_add_child(OBJECT(machine), "aic", OBJECT(tms->aic));
    assert(tms->aic);

    prop = get_dtb_prop(child, "reg");
    assert(prop != NULL);

    reg = (hwaddr*)prop->value;

    for(i = 0; i < machine->smp.cpus; i++) {
        memory_region_add_subregion_overlap(tms->cpus[i]->memory, tms->soc_base_pa + reg[0], sysbus_mmio_get_region(SYS_BUS_DEVICE(tms->aic), i), 0);
        sysbus_connect_irq(SYS_BUS_DEVICE(tms->aic), i, qdev_get_gpio_in(DEVICE(tms->cpus[i]->cpu), ARM_CPU_IRQ));
    }

    sysbus_realize(SYS_BUS_DEVICE(tms->aic), &error_fatal);
}

static void T8030_pmgr_setup(MachineState* machine)
{
    uint64_t *reg;
    int i;
    char name[32];
    DTBProp *prop;
    T8030MachineState *tms = T8030_MACHINE(machine);
    DTBNode *child = get_dtb_child_node_by_name(tms->device_tree, "arm-io");

    assert(child != NULL);
    child = get_dtb_child_node_by_name(child, "pmgr");
    assert(child != NULL);

    prop = get_dtb_prop(child, "reg");
    assert(prop);

    reg = (uint64_t*)prop->value;

    for(i = 0; i < prop->length / 8; i+=2) {
        MemoryRegion* mem = g_new(MemoryRegion, 1);
        if (i > 0) {
            snprintf(name, 32, "pmgr-unk-reg-%d", i);
            memory_region_init_io(mem, OBJECT(machine), &pmgr_unk_reg_ops, (void*)reg[i], name, reg[i+1]);
        } else {
            memory_region_init_io(mem, OBJECT(machine), &pmgr_reg_ops, tms, "pmgr-reg", reg[i+1]);
        }
        memory_region_add_subregion(tms->sysmem, reg[i] + reg[i+1] < tms->soc_size ? tms->soc_base_pa + reg[i] : reg[i], mem);
    }

    {
        MemoryRegion *mem = g_new(MemoryRegion, 1);

        snprintf(name, 32, "pmp-reg");
        memory_region_init_io(mem, OBJECT(machine), &pmgr_unk_reg_ops, (void*)0x3BC00000, name, 0x60000);
        memory_region_add_subregion(tms->sysmem, tms->soc_base_pa + 0x3BC00000, mem);
    }

    add_dtb_prop(child, "voltage-states0", 24, (uint8_t*)"\x01\x00\x00\x00\x71\x02\x00\x00\x01\x00\x00\x00\xa9\x02\x00\x00\x01\x00\x00\x00\xe4\x02\x00\x00");
    add_dtb_prop(child, "voltage-states1", 40, (uint8_t*)"\x71\xbc\x01\x00\x38\x02\x00\x00\x4b\x28\x01\x00\x83\x02\x00\x00\x38\xde\x00\x00\xde\x02\x00\x00\xc7\xb1\x00\x00\x42\x03\x00\x00\x25\x94\x00\x00\xaf\x03\x00\x00");
    add_dtb_prop(child, "voltage-states2", 24, (uint8_t*)"\x01\x00\x00\x00\x74\x02\x00\x00\x01\x00\x00\x00\xb8\x02\x00\x00\x01\x00\x00\x00\x42\x03\x00\x00");
    add_dtb_prop(child, "voltage-states5", 64, (uint8_t*)"\x12\xda\x01\x00\x38\x02\x00\x00\xb3\x18\x01\x00\x71\x02\x00\x00\x87\xc5\x00\x00\xb8\x02\x00\x00\xa2\x89\x00\x00\x20\x03\x00\x00\x37\x75\x00\x00\x87\x03\x00\x00\xaa\x6a\x00\x00\xe8\x03\x00\x00\xc3\x62\x00\x00\x48\x04\x00\x00\x18\x60\x00\x00\x65\x04\x00\x00");
    add_dtb_prop(child, "voltage-states8", 96, (uint8_t*)"\x00\xf4\x06\x14\xff\xff\xff\xff\x00\x2a\x75\x15\xff\xff\xff\xff\x00\x6e\x0a\x1e\xff\xff\xff\xff\x00\xbf\x2f\x20\xff\xff\xff\xff\x00\x1e\x7c\x29\xff\xff\xff\xff\x00\xa5\x0f\x2d\xff\xff\xff\xff\x00\x55\x81\x38\xff\xff\xff\xff\x00\x7e\x5f\x40\xff\xff\xff\xff\x00\xb4\xcd\x41\xff\xff\xff\xff\x00\x8c\x86\x47\xff\xff\xff\xff\x00\x64\x3f\x4d\xff\xff\xff\xff\x80\xc9\x53\x53\xff\xff\xff\xff");
    add_dtb_prop(child, "voltage-states9", 56, (uint8_t*)"\x00\x00\x00\x00\x90\x01\x00\x00\x00\x2a\x75\x15\x3f\x02\x00\x00\xc0\x4f\xef\x1e\x7a\x02\x00\x00\x00\xcd\x56\x27\x90\x02\x00\x00\x00\x11\xec\x2f\xc8\x02\x00\x00\x00\x55\x81\x38\x16\x03\x00\x00\x80\xfe\x2a\x47\x96\x03\x00\x00");
    add_dtb_prop(child, "voltage-states10", 24, (uint8_t*)"\x01\x00\x00\x00\x67\x02\x00\x00\x01\x00\x00\x00\x90\x02\x00\x00\x01\x00\x00\x00\xc2\x02\x00\x00");
    add_dtb_prop(child, "voltage-states11", 24, (uint8_t*)"\x01\x00\x00\x00\x29\x02\x00\x00\x01\x00\x00\x00\x71\x02\x00\x00\x01\x00\x00\x00\xf4\x02\x00\x00");
    add_dtb_prop(child, "bridge-settings-12", 192, (uint8_t*)"\x00\x00\x00\x00\x11\x00\x00\x00\x0c\x00\x00\x00\xe8\x7c\x18\x03\x54\x00\x00\x00\x12\x00\x00\x00\x00\x09\x00\x00\x01\x00\x01\x40\x24\x09\x00\x00\x18\x08\x08\x00\x28\x09\x00\x00\x01\x00\x00\x00\x48\x09\x00\x00\x01\x00\x00\x00\x64\x09\x00\x00\x18\x08\x08\x00\x88\x09\x00\x00\x01\x00\x00\x00\x00\x0a\x00\x00\x7f\x00\x00\x00\x00\x10\x00\x00\x01\x01\x00\x00\x00\x40\x00\x00\x03\x00\x00\x00\x04\x40\x00\x00\x03\x00\x00\x00\x08\x40\x00\x00\x03\x00\x00\x00\x0c\x40\x00\x00\x03\x00\x00\x00\x04\x41\x00\x00\x01\x00\x00\x00\x00\x43\x00\x00\x01\x00\x01\xc0\x38\x43\x00\x00\x01\x00\x00\x00\x48\x43\x00\x00\x01\x00\x00\x00\x00\x80\x00\x00\x0f\x00\x00\x00\x00\x82\x00\x00\x01\x00\x01\xc0\x28\x82\x00\x00\x01\x00\x00\x00\x38\x82\x00\x00\x01\x00\x00\x00\x48\x82\x00\x00\x01\x00\x00\x00");
    add_dtb_prop(child, "bridge-settings-13", 64, (uint8_t*)"\x00\x00\x00\x00\x03\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x08\x00\x00\x00\x03\x00\x00\x00\x0c\x00\x00\x00\x03\x00\x00\x00\x04\x01\x00\x00\x01\x00\x00\x00\x00\x03\x00\x00\x01\x00\x01\xc0\x38\x03\x00\x00\x01\x00\x00\x00\x48\x03\x00\x00\x01\x00\x00\x00");
    add_dtb_prop(child, "bridge-settings-14", 40, (uint8_t*)"\x00\x00\x00\x00\x0f\x00\x00\x00\x00\x02\x00\x00\x01\x00\x01\xc0\x28\x02\x00\x00\x01\x00\x00\x00\x38\x02\x00\x00\x01\x00\x00\x00\x48\x02\x00\x00\x01\x00\x00\x00");
    add_dtb_prop(child, "bridge-settings-15", 144, (uint8_t*)"\x00\x00\x00\x00\x01\x00\x00\x00\x0c\x00\x00\x00\x98\x7e\x68\x01\x00\x0a\x00\x00\x01\x00\x01\x40\x24\x0a\x00\x00\x18\x08\x08\x00\x44\x0a\x00\x00\x18\x08\x08\x00\x64\x0a\x00\x00\x18\x08\x08\x00\x84\x0a\x00\x00\x18\x08\x08\x00\x00\x0b\x00\x00\x7f\x00\x00\x00\x00\x11\x00\x00\x01\x01\x00\x00\x00\x40\x00\x00\x03\x00\x00\x00\x04\x40\x00\x00\x03\x00\x00\x00\x08\x40\x00\x00\x03\x00\x00\x00\x0c\x40\x00\x00\x03\x00\x00\x00\x10\x40\x00\x00\x03\x00\x00\x00\x04\x41\x00\x00\x01\x00\x00\x00\x00\x43\x00\x00\x01\x00\x01\xc0\x00\x80\x00\x00\x0f\x00\x00\x00\x00\x82\x00\x00\x01\x00\x01\xc0");
    add_dtb_prop(child, "bridge-settings-16", 56, (uint8_t*)"\x00\x00\x00\x00\x03\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x08\x00\x00\x00\x03\x00\x00\x00\x0c\x00\x00\x00\x03\x00\x00\x00\x10\x00\x00\x00\x03\x00\x00\x00\x04\x01\x00\x00\x01\x00\x00\x00\x00\x03\x00\x00\x01\x00\x01\xc0");
    add_dtb_prop(child, "bridge-settings-17", 16, (uint8_t*)"\x00\x00\x00\x00\x0f\x00\x00\x00\x00\x02\x00\x00\x01\x00\x01\xc0");
    add_dtb_prop(child, "bridge-settings-6", 128, (uint8_t*)"\x00\x00\x00\x00\x10\x04\x00\x00\x00\x04\x00\x00\x01\x00\x01\x40\x00\x06\x00\x00\xff\xff\xff\x01\x08\x07\x00\x00\x00\x00\x00\x02\x0c\x07\x00\x00\x80\x00\x40\x00\x10\x07\x00\x00\x80\x00\x40\x00\x14\x07\x00\x00\x80\x00\x40\x00\x18\x07\x00\x00\x80\x00\x40\x00\x1c\x07\x00\x00\x10\x00\x10\x00\x44\x07\x00\x00\x12\x00\x29\x00\x48\x07\x00\x00\x0a\x00\x40\x00\x4c\x07\x00\x00\x0a\x00\x40\x00\x50\x07\x00\x00\x0a\x00\x40\x00\x54\x07\x00\x00\x0a\x00\x40\x00\x58\x07\x00\x00\x10\x00\x40\x00\x00\x08\x00\x00\x01\x01\x00\x00");
    add_dtb_prop(child, "bridge-settings-1", 128, (uint8_t*)"\x00\x00\x00\x00\x10\x04\x00\x00\x00\x04\x00\x00\x01\x00\x01\x40\x00\x06\x00\x00\xff\xff\xff\x01\x08\x07\x00\x00\x00\x00\x00\x02\x0c\x07\x00\x00\x80\x00\x40\x00\x10\x07\x00\x00\x80\x00\x40\x00\x14\x07\x00\x00\x80\x00\x40\x00\x18\x07\x00\x00\x80\x00\x40\x00\x1c\x07\x00\x00\x10\x00\x40\x00\x44\x07\x00\x00\x00\x00\x00\x02\x48\x07\x00\x00\x80\x00\x40\x00\x4c\x07\x00\x00\x80\x00\x40\x00\x50\x07\x00\x00\x80\x00\x40\x00\x54\x07\x00\x00\x80\x00\x40\x00\x58\x07\x00\x00\x10\x00\x40\x00\x00\x08\x00\x00\x01\x01\x00\x00");
    add_dtb_prop(child, "bridge-settings-0", 128, (uint8_t*)"\x00\x00\x00\x00\x10\x04\x00\x00\x00\x04\x00\x00\x01\x00\x01\x40\x00\x06\x00\x00\xff\xff\xff\x01\x08\x07\x00\x00\x00\x00\x00\x02\x0c\x07\x00\x00\x80\x00\x40\x00\x10\x07\x00\x00\x80\x00\x40\x00\x14\x07\x00\x00\x80\x00\x40\x00\x18\x07\x00\x00\x80\x00\x40\x00\x1c\x07\x00\x00\x10\x00\x20\x00\x44\x07\x00\x00\x00\x00\x00\x02\x48\x07\x00\x00\x80\x00\x40\x00\x4c\x07\x00\x00\x80\x00\x40\x00\x50\x07\x00\x00\x80\x00\x40\x00\x54\x07\x00\x00\x80\x00\x40\x00\x58\x07\x00\x00\x10\x00\x40\x00\x00\x08\x00\x00\x01\x01\x00\x00");
    add_dtb_prop(child, "bridge-settings-8", 128, (uint8_t*)"\x00\x00\x00\x00\x10\x04\x00\x00\x00\x04\x00\x00\x01\x00\x01\x40\x00\x06\x00\x00\xff\xff\xff\x01\x08\x07\x00\x00\x00\x00\x00\x02\x0c\x07\x00\x00\x80\x00\x40\x00\x10\x07\x00\x00\x80\x00\x40\x00\x14\x07\x00\x00\x80\x00\x40\x00\x18\x07\x00\x00\x80\x00\x40\x00\x1c\x07\x00\x00\x20\x00\x20\x00\x44\x07\x00\x00\x00\x00\x00\x02\x48\x07\x00\x00\x80\x00\x40\x00\x4c\x07\x00\x00\x80\x00\x40\x00\x50\x07\x00\x00\x80\x00\x40\x00\x54\x07\x00\x00\x80\x00\x40\x00\x58\x07\x00\x00\x10\x00\x80\x00\x00\x08\x00\x00\x01\x01\x00\x00");
    add_dtb_prop(child, "bridge-settings-7", 80, (uint8_t*)"\x00\x00\x00\x00\x10\x04\x00\x00\x00\x04\x00\x00\x01\x00\x01\x40\x00\x06\x00\x00\xff\xff\xff\x01\x08\x07\x00\x00\x00\x00\x00\x02\x0c\x07\x00\x00\x80\x00\x40\x00\x10\x07\x00\x00\x80\x00\x40\x00\x14\x07\x00\x00\x80\x00\x40\x00\x18\x07\x00\x00\x80\x00\x40\x00\x1c\x07\x00\x00\x10\x00\x10\x00\x00\x08\x00\x00\x01\x01\x00\x00");
    add_dtb_prop(child, "bridge-settings-5", 176, (uint8_t*)"\x00\x00\x00\x00\x10\x04\x00\x00\x00\x04\x00\x00\x01\x00\x00\x40\x00\x06\x00\x00\xff\xff\xff\x01\x08\x07\x00\x00\x00\x00\x00\x02\x0c\x07\x00\x00\x13\x00\xc7\x00\x10\x07\x00\x00\x13\x00\xc7\x00\x14\x07\x00\x00\x13\x00\xc7\x00\x18\x07\x00\x00\x13\x00\xc7\x00\x1c\x07\x00\x00\x10\x00\x20\x00\x44\x07\x00\x00\x00\x00\x00\x02\x48\x07\x00\x00\x80\x00\x40\x00\x4c\x07\x00\x00\x80\x00\x40\x00\x50\x07\x00\x00\x80\x00\x40\x00\x54\x07\x00\x00\x80\x00\x40\x00\x58\x07\x00\x00\x10\x00\x40\x00\x80\x07\x00\x00\x12\x00\x29\x00\x84\x07\x00\x00\x0a\x00\x40\x00\x88\x07\x00\x00\x0a\x00\x40\x00\x8c\x07\x00\x00\x0a\x00\x40\x00\x90\x07\x00\x00\x0a\x00\x40\x00\x94\x07\x00\x00\x10\x00\x30\x00\x00\x08\x00\x00\x01\x01\x00\x00");
    add_dtb_prop(child, "bridge-settings-2", 128, (uint8_t*)"\x00\x00\x00\x00\x10\x04\x00\x00\x00\x04\x00\x00\x01\x00\x01\x40\x00\x06\x00\x00\xff\xff\xff\x01\x08\x07\x00\x00\x00\x00\x00\x02\x0c\x07\x00\x00\x80\x00\x40\x00\x10\x07\x00\x00\x80\x00\x40\x00\x14\x07\x00\x00\x80\x00\x40\x00\x18\x07\x00\x00\x80\x00\x40\x00\x1c\x07\x00\x00\x10\x00\x10\x00\x44\x07\x00\x00\x00\x00\x00\x02\x48\x07\x00\x00\x80\x00\x40\x00\x4c\x07\x00\x00\x80\x00\x40\x00\x50\x07\x00\x00\x80\x00\x40\x00\x54\x07\x00\x00\x80\x00\x40\x00\x58\x07\x00\x00\x10\x00\x39\x00\x00\x08\x00\x00\x01\x01\x00\x00");
    add_dtb_prop(child, "bridge-settings-3", 128, (uint8_t*)"\x00\x00\x00\x00\x10\x04\x00\x00\x00\x04\x00\x00\x01\x00\x01\x40\x00\x06\x00\x00\xff\xff\xff\x01\x08\x07\x00\x00\x00\x00\x00\x02\x0c\x07\x00\x00\x80\x00\x40\x00\x10\x07\x00\x00\x80\x00\x40\x00\x14\x07\x00\x00\x80\x00\x40\x00\x18\x07\x00\x00\x80\x00\x40\x00\x1c\x07\x00\x00\x10\x00\x30\x00\x44\x07\x00\x00\x00\x00\x00\x02\x48\x07\x00\x00\x80\x00\x40\x00\x4c\x07\x00\x00\x80\x00\x40\x00\x50\x07\x00\x00\x80\x00\x40\x00\x54\x07\x00\x00\x80\x00\x40\x00\x58\x07\x00\x00\x10\x00\x37\x00\x00\x08\x00\x00\x01\x01\x00\x00");
    add_dtb_prop(child, "bridge-settings-4", 128, (uint8_t*)"\x00\x00\x00\x00\x10\x04\x00\x00\x00\x04\x00\x00\x01\x00\x00\x40\x00\x06\x00\x00\xff\xff\xff\x01\x08\x07\x00\x00\x00\x00\x00\x02\x0c\x07\x00\x00\x10\x00\xa6\x00\x10\x07\x00\x00\x10\x00\xa6\x00\x14\x07\x00\x00\x10\x00\xa6\x00\x18\x07\x00\x00\x10\x00\xa6\x00\x1c\x07\x00\x00\x10\x00\x10\x00\x44\x07\x00\x00\x00\x00\x00\x02\x48\x07\x00\x00\x80\x00\x40\x00\x4c\x07\x00\x00\x80\x00\x40\x00\x50\x07\x00\x00\x80\x00\x40\x00\x54\x07\x00\x00\x80\x00\x40\x00\x58\x07\x00\x00\x10\x00\x80\x00\x00\x08\x00\x00\x01\x01\x00\x00");
    add_dtb_prop(child, "voltage-states5-sram", 64, (uint8_t*)"\x00\xbf\x2f\x20\xf1\x02\x00\x00\x00\x04\x5c\x36\xf1\x02\x00\x00\x00\x64\x3f\x4d\xf1\x02\x00\x00\x00\x59\xdd\x6e\x20\x03\x00\x00\x00\x32\x2d\x82\x87\x03\x00\x00\x00\x18\x0d\x8f\xe8\x03\x00\x00\x00\xc8\x7e\x9a\x48\x04\x00\x00\x00\x6a\xc9\x9e\x65\x04\x00\x00");
    add_dtb_prop(child, "voltage-states1-sram", 40, (uint8_t*)"\x00\x10\x55\x22\xf1\x02\x00\x00\x00\x98\x7f\x33\xf1\x02\x00\x00\x00\x20\xaa\x44\xf1\x02\x00\x00\x00\xa8\xd4\x55\x42\x03\x00\x00\x00\x30\xff\x66\xaf\x03\x00\x00");
    add_dtb_prop(child, "voltage-states9-sram", 56, (uint8_t*)"\x00\x00\x00\x00\xf1\x02\x00\x00\x00\x2a\x75\x15\xf1\x02\x00\x00\xc0\x4f\xef\x1e\xf1\x02\x00\x00\x00\xcd\x56\x27\xf1\x02\x00\x00\x00\x11\xec\x2f\xf1\x02\x00\x00\x00\x55\x81\x38\x16\x03\x00\x00\x80\xfe\x2a\x47\x96\x03\x00\x00");
}

static void T8030_sart_setup(MachineState* machine)
{
    uint64_t *reg;
    T8030MachineState *tms = T8030_MACHINE(machine);
    DTBNode *child = get_dtb_child_node_by_name(tms->device_tree, "arm-io");
    DTBProp *prop;
    MemoryRegion *sart;

    assert(child != NULL);
    child = get_dtb_child_node_by_name(child, "sart-ans");
    assert(child != NULL);

    prop = get_dtb_prop(child, "reg");
    assert(prop);
    reg = (uint64_t*)prop->value;

    sart = g_new(MemoryRegion, 1);
    memory_region_init_io(sart, OBJECT(machine), &sart_reg_ops, tms, "sart-reg", reg[1]);
    memory_region_add_subregion(tms->sysmem, tms->soc_base_pa + reg[0], sart);
}

static void T8030_create_ans(MachineState* machine)
{
    int i;
    uint32_t *ints;
    DTBProp *prop;
    uint64_t *reg;
    T8030MachineState *tms = T8030_MACHINE(machine);
    DTBNode *child = get_dtb_child_node_by_name(tms->device_tree, "arm-io");

    assert(child != NULL);
    child = get_dtb_child_node_by_name(child, "ans");
    assert(child != NULL);

    tms->ans = apple_ans_create(child);
    assert(tms->ans);

    object_property_add_child(OBJECT(machine), "ans", OBJECT(tms->ans));
    prop = get_dtb_prop(child, "reg");
    assert(prop);
    reg = (uint64_t*)prop->value;

    /*
    0: AppleA7IOP akfRegMap
    1: AppleASCWrapV2 coreRegisterMap
    2: AppleA7IOP autoBootRegMap
    3: NVMe BAR
    */
    sysbus_mmio_map(tms->ans, 0, tms->soc_base_pa + reg[0]);
    sysbus_mmio_map(tms->ans, 1, tms->soc_base_pa + reg[2]);
    sysbus_mmio_map(tms->ans, 2, tms->soc_base_pa + reg[4]);
    sysbus_mmio_map(tms->ans, 3, tms->soc_base_pa + reg[6]);

    prop = get_dtb_prop(child, "interrupts");
    assert(prop);
    assert(prop->length == 20);
    ints = (uint32_t*)prop->value;

    for(i = 0; i < prop->length / sizeof(uint32_t); i++) {
        sysbus_connect_irq(tms->ans, i, qdev_get_gpio_in(DEVICE(tms->aic), ints[i]));
    }

    sysbus_realize(tms->ans, &error_fatal);
}

static void T8030_create_gpio(MachineState *machine, const char *name)
{
    DeviceState *gpio = NULL;
    DTBProp *prop;
    uint64_t *reg;
    uint32_t *ints;
    int i;
    T8030MachineState *tms = T8030_MACHINE(machine);
    DTBNode *child = get_dtb_child_node_by_name(tms->device_tree, "arm-io");

    child = get_dtb_child_node_by_name(child, name);
    assert(child);
    gpio = apple_gpio_create(child);
    assert(gpio);
    object_property_add_child(OBJECT(machine), name, OBJECT(gpio));

    prop = get_dtb_prop(child, "reg");
    assert(prop);
    reg = (uint64_t*)prop->value;
    sysbus_mmio_map(SYS_BUS_DEVICE(gpio), 0, tms->soc_base_pa + reg[0]);
    prop = get_dtb_prop(child, "interrupts");
    assert(prop);

    ints = (uint32_t*)prop->value;

    for(i = 0; i < prop->length / sizeof(uint32_t); i++) {
        sysbus_connect_irq(SYS_BUS_DEVICE(gpio), i, qdev_get_gpio_in(DEVICE(tms->aic), ints[i]));
    }

    sysbus_realize_and_unref(SYS_BUS_DEVICE(gpio), &error_fatal);
}

static DeviceState *T8030_get_gpio_with_role(MachineState *machine, uint32_t role)
{
    switch (role) {
        case 0x00005041: /* AP */
            return DEVICE(object_property_get_link(OBJECT(machine), "gpio", &error_fatal));
            break;
        case 0x00434d53: /* SMC */
            return DEVICE(object_property_get_link(OBJECT(machine), "smc-gpio", &error_fatal));
            break;
        case 0x0042554e: /* NUB */
            return DEVICE(object_property_get_link(OBJECT(machine), "nub-gpio", &error_fatal));
            break;
        default:
            qemu_log_mask(LOG_GUEST_ERROR, "%s: invalid gpio role %s\n", __func__, (const char*)&role);
    }
    return NULL;
}

static void T8030_create_i2c(MachineState *machine, const char *name)
{
    uint32_t line = 0;
    uint32_t opts = 0;
    uint32_t role = 0;
    DeviceState *gpio;
    DeviceState *i2c = NULL;
    DTBProp *prop;
    uint64_t *reg;
    uint32_t* ints;
    int i;
    T8030MachineState *tms = T8030_MACHINE(machine);
    DTBNode *child = get_dtb_child_node_by_name(tms->device_tree, "arm-io");

    child = get_dtb_child_node_by_name(child, name);
    assert(child);

    i2c = apple_i2c_create(child);
    assert(i2c);
    object_property_add_child(OBJECT(machine), name, OBJECT(i2c));

    prop = get_dtb_prop(child, "reg");
    assert(prop);

    reg = (uint64_t*)prop->value;
    sysbus_mmio_map(SYS_BUS_DEVICE(i2c), 0, tms->soc_base_pa + reg[0]);

    prop = get_dtb_prop(child, "interrupts");
    assert(prop);
    ints = (uint32_t*)prop->value;
    for(i = 0; i < prop->length / sizeof(uint32_t); i++) {
        sysbus_connect_irq(SYS_BUS_DEVICE(i2c), i, qdev_get_gpio_in(DEVICE(tms->aic), ints[i]));
    }

    prop = get_dtb_prop(child, "gpio-iic_scl");
    assert(prop);
    line = ((uint32_t*)prop->value)[0];
    opts = ((uint32_t*)prop->value)[1];
    role = ((uint32_t*)prop->value)[2];

    gpio = T8030_get_gpio_with_role(machine, role);
    if (gpio) {
        if (!get_dtb_prop(child, "function-iic_scl")) {
            uint32_t func[] = {
                APPLE_GPIO(gpio)->phandle,
                0x4750494F, /* GPIO */
                line,
                opts
            };
            prop = add_dtb_prop(child, "function-iic_scl", sizeof(func), (uint8_t*)func);
        }
        qdev_connect_gpio_out(gpio, line, qdev_get_gpio_in(i2c, BITBANG_I2C_SCL));
    }

    prop = get_dtb_prop(child, "gpio-iic_sda");
    assert(prop);
    line = ((uint32_t*)prop->value)[0];
    opts = ((uint32_t*)prop->value)[1];
    role = ((uint32_t*)prop->value)[2];

    gpio = T8030_get_gpio_with_role(machine, role);
    if (gpio) {
        if (!get_dtb_prop(child, "function-iic_sda")) {
            uint32_t func[] = {
                APPLE_GPIO(gpio)->phandle,
                0x4750494F, /* GPIO */
                line,
                opts
            };
            prop = add_dtb_prop(child, "function-iic_sda", sizeof(func), (uint8_t*)func);
        }
        qdev_connect_gpio_out(gpio, line, qdev_get_gpio_in(i2c, BITBANG_I2C_SDA));
        qdev_connect_gpio_out(i2c, BITBANG_I2C_SDA, qdev_get_gpio_in(gpio, line));
    }

    sysbus_realize_and_unref(SYS_BUS_DEVICE(i2c), &error_fatal);
}

static void T8030_cpu_reset(void *opaque)
{
    MachineState *machine = MACHINE(opaque);
    T8030MachineState *tms = T8030_MACHINE(machine);
    CPUState *cpu;
    CPUState *cs;
    CPUARMState *env;

    CPU_FOREACH(cpu) {
        ARM_CPU(cpu)->rvbar = tms->kpc_pa & ~0xfff;
    }
    
    cs = CPU(first_cpu);
    env = &ARM_CPU(cs)->env;
    cpu_reset(cs);
    env->xregs[0] = tms->kbootargs_pa;
    env->pc = tms->kpc_pa;
}

static void T8030_cluster_tick(cluster* c)
{
    WITH_QEMU_LOCK_GUARD(&c->mutex) {
        int i, j;

        for(i = 0; i < MAX_CPU; i++) { /* source */
            for(j = 0; j < MAX_CPU; j++) { /* target */
                if (c->cpus[j] != NULL && c->deferredIPI[i][j]) {
                    T8030_cluster_deliver_ipi(c, j, i, ARM64_REG_IPI_RR_TYPE_DEFERRED);
                    break;
                }
            }
        }

        for(i = 0; i < MAX_CPU; i++) { /* source */
            for(j = 0; j < MAX_CPU; j++) { /* target */
                if (c->cpus[j] != NULL && c->noWakeIPI[i][j] && !T8030CPU_is_sleep(c->cpus[j])) {
                    T8030_cluster_deliver_ipi(c, j, i, ARM64_REG_IPI_RR_TYPE_NOWAKE);
                    break;
                }
            }
        }
    }
}

static void T8030_machine_ipicr_tick(void* opaque)
{
    int i;
    T8030MachineState *tms = T8030_MACHINE((MachineState *)opaque);

    for(i = 0; i < MAX_CLUSTER; i++) {
        T8030_cluster_tick(tms->clusters[i]);
    }

    timer_mod_ns(tms->ipicr_timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + tms->ipi_cr);
}

static void T8030_machine_reset(void* opaque)
{
    MachineState *machine = MACHINE(opaque);
    T8030MachineState *tms = T8030_MACHINE(opaque);

    tms->ipicr_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, T8030_machine_ipicr_tick, machine);
    timer_mod_ns(tms->ipicr_timer, kDeferredIPITimerDefault);
    T8030_memory_setup(machine);
    T8030_cpu_reset(tms);
}

static void T8030_machine_init(MachineState *machine)
{
    T8030MachineState *tms = T8030_MACHINE(machine);
    DTBNode *child;
    DTBProp *prop;
    hwaddr *ranges;

    qemu_mutex_init(&tms->mutex);
    tms->sysmem = get_system_memory();
    
    tms->device_tree = load_dtb_from_file(tms->dtb_filename);
    child = get_dtb_child_node_by_name(tms->device_tree, "arm-io");
    assert(child != NULL);

    prop = get_dtb_prop(child, "ranges");
    assert(prop != NULL);

    ranges = (hwaddr *)prop->value;
    tms->soc_base_pa = ranges[1];
    tms->soc_size = ranges[2];

    T8030_cpu_setup(machine);

    tms->ipi_cr = kDeferredIPITimerDefault;

    T8030_create_aic(machine);
    
    T8030_create_s3c_uart(tms, serial_hd(0));

    T8030_pmgr_setup(machine);

    T8030_sart_setup(machine);

    T8030_create_ans(machine);

    T8030_create_gpio(machine, "gpio");
    T8030_create_gpio(machine, "smc-gpio");
    T8030_create_gpio(machine, "nub-gpio");
    
    T8030_create_i2c(machine, "i2c0");
    T8030_create_i2c(machine, "i2c1");
    T8030_create_i2c(machine, "i2c2");
    T8030_create_i2c(machine, "i2c3");
    T8030_create_i2c(machine, "smc-i2c0");
    T8030_create_i2c(machine, "smc-i2c1");

    T8030_bootargs_setup(machine);

    qemu_register_reset(T8030_machine_reset, tms);
}

static void T8030_set_ramdisk_filename(Object *obj, const char *value, Error **errp)
{
    T8030MachineState *tms = T8030_MACHINE(obj);

    g_strlcpy(tms->ramdisk_filename, value, sizeof(tms->ramdisk_filename));
}

static char *T8030_get_ramdisk_filename(Object *obj, Error **errp)
{
    T8030MachineState *tms = T8030_MACHINE(obj);
    return g_strdup(tms->ramdisk_filename);
}

static void T8030_set_kernel_filename(Object *obj, const char *value, Error **errp)
{
    T8030MachineState *tms = T8030_MACHINE(obj);

    g_strlcpy(tms->kernel_filename, value, sizeof(tms->kernel_filename));
}

static char *T8030_get_kernel_filename(Object *obj, Error **errp)
{
    T8030MachineState *tms = T8030_MACHINE(obj);
    return g_strdup(tms->kernel_filename);
}

static void T8030_set_dtb_filename(Object *obj, const char *value, Error **errp)
{
    T8030MachineState *tms = T8030_MACHINE(obj);

    g_strlcpy(tms->dtb_filename, value, sizeof(tms->dtb_filename));
}

static char *T8030_get_dtb_filename(Object *obj, Error **errp)
{
    T8030MachineState *tms = T8030_MACHINE(obj);
    return g_strdup(tms->dtb_filename);
}

static void T8030_set_trustcache_filename(Object *obj, const char *value, Error **errp)
{
    T8030MachineState *tms = T8030_MACHINE(obj);

    g_strlcpy(tms->trustcache_filename, value, sizeof(tms->trustcache_filename));
}

static char *T8030_get_trustcache_filename(Object *obj, Error **errp)
{
    T8030MachineState *tms = T8030_MACHINE(obj);

    return g_strdup(tms->trustcache_filename);
}

static void T8030_set_kern_args(Object *obj, const char *value, Error **errp)
{
    T8030MachineState *tms = T8030_MACHINE(obj);

    g_strlcpy(tms->kern_args, value, sizeof(tms->kern_args));
}

static char *T8030_get_kern_args(Object *obj, Error **errp)
{
    T8030MachineState *tms = T8030_MACHINE(obj);

    return g_strdup(tms->kern_args);
}

static void T8030_set_xnu_ramfb(Object *obj, const char *value, Error **errp)
{
    T8030MachineState *tms = T8030_MACHINE(obj);

    if (strcmp(value, "on") == 0)
        tms->use_ramfb = true;
    else {
        if (strcmp(value, "off") != 0)
            fprintf(stderr, "NOTE: the value of xnu-ramfb is not valid,\
                            the framebuffer will be disabled.\n");
        tms->use_ramfb = false;
    }
}

static char *T8030_get_xnu_ramfb(Object *obj, Error **errp)
{
    T8030MachineState *tms = T8030_MACHINE(obj);

    if (tms->use_ramfb)
        return g_strdup("on");
    else
        return g_strdup("off");
}

static void T8030_instance_init(Object *obj)
{
    object_property_add_str(obj, "ramdisk-filename", T8030_get_ramdisk_filename,
                            T8030_set_ramdisk_filename);
    object_property_set_description(obj, "ramdisk-filename",
                                    "Set the ramdisk filename to be loaded");

    object_property_add_str(obj, "kernel-filename", T8030_get_kernel_filename,
                            T8030_set_kernel_filename);
    object_property_set_description(obj, "kernel-filename",
                                    "Set the kernel filename to be loaded");

    object_property_add_str(obj, "dtb-filename", T8030_get_dtb_filename, T8030_set_dtb_filename);
    object_property_set_description(obj, "dtb-filename",
                                    "Set the dev tree filename to be loaded");

    object_property_add_str(obj, "trustcache-filename", T8030_get_trustcache_filename, T8030_set_trustcache_filename);
    object_property_set_description(obj, "trustcache-filename",
                                    "Set the trustcache filename to be loaded");

    object_property_add_str(obj, "kern-cmd-args", T8030_get_kern_args,
                            T8030_set_kern_args);
    object_property_set_description(obj, "kern-cmd-args",
                                    "Set the XNU kernel cmd args");

    object_property_add_str(obj, "xnu-ramfb",
                            T8030_get_xnu_ramfb,
                            T8030_set_xnu_ramfb);

    object_property_set_description(obj, "xnu-ramfb",
                                    "Turn on the display framebuffer");
}

static void T8030_machine_class_init(ObjectClass *klass, void *data)
{
    MachineClass *mc = MACHINE_CLASS(klass);

    mc->desc = "T8030";
    mc->init = T8030_machine_init;
    mc->max_cpus = MAX_CPU;
    // this disables the error message "Failed to query for block devices!"
    // when starting qemu - must keep at least one device
    mc->no_sdcard = 1;
    mc->no_floppy = 1;
    mc->no_cdrom = 1;
    mc->no_parallel = 1;
    mc->default_cpu_type = ARM_CPU_TYPE_NAME("cortex-a72");
    mc->minimum_page_bits = 14;
}

static const TypeInfo T8030_machine_info = {
    .name = TYPE_T8030_MACHINE,
    .parent = TYPE_MACHINE,
    .instance_size = sizeof(T8030MachineState),
    .class_size = sizeof(T8030MachineClass),
    .class_init = T8030_machine_class_init,
    .instance_init = T8030_instance_init,
};

static void T8030_machine_types(void)
{
    type_register_static(&T8030_machine_info);
}

type_init(T8030_machine_types)
