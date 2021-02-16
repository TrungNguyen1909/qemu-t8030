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
#include "qapi/error.h"
#include "qemu-common.h"
#include "hw/arm/boot.h"
#include "exec/address-spaces.h"
#include "hw/misc/unimp.h"
#include "sysemu/sysemu.h"
#include "sysemu/reset.h"
#include "qemu/error-report.h"
#include "hw/platform-bus.h"

#include "hw/arm/t8030.h"

#include "hw/irq.h"
#include "hw/intc/apple-aic.h"

#include "hw/arm/exynos4210.h"

#define T8030_SECURE_RAM_SIZE (0x100000)
#define T8030_PHYS_BASE (0x40000000)
#define CPU_IMPL_REG_BASE (0x210050000)
#define CPM_IMPL_REG_BASE (0x210e40000)
#define T8030_MAX_DEVICETREE_SIZE (0x40000)
#define NOP_INST (0xd503201f)
#define MOV_W0_01_INST (0x52800020)
#define MOV_X13_0_INST (0xd280000d)
#define RET_INST (0xd65f03c0)
#define RETAB_INST (0xd65f0fff)

#define T8030_CPREG_FUNCS(name)                                                    \
    static uint64_t T8030_cpreg_read_##name(CPUARMState *env,                      \
                                            const ARMCPRegInfo *ri)                \
    {                                                                              \
        T8030CPU *tcpu = (T8030CPU *)ri->opaque;                  \
        return tcpu->T8030_CPREG_VAR_NAME(name);                                    \
    }                                                                              \
    static void T8030_cpreg_write_##name(CPUARMState *env, const ARMCPRegInfo *ri, \
                                         uint64_t value)                           \
    {                                                                              \
        T8030CPU *tcpu = (T8030CPU *)ri->opaque;                  \
        tcpu->T8030_CPREG_VAR_NAME(name) = value;                                   \
        /* if(value != 0) fprintf(stderr, "T8030CPU REG WRITE " #name " = 0x%llx\n", value);*/ \
    }

#define T8030_CPREG_DEF(p_name, p_op0, p_op1, p_crn, p_crm, p_op2, p_access) \
    {                                                                        \
        .cp = CP_REG_ARM64_SYSREG_CP,                                        \
        .name = #p_name, .opc0 = p_op0, .crn = p_crn, .crm = p_crm,          \
        .opc1 = p_op1, .opc2 = p_op2, .access = p_access, .type = ARM_CP_IO, \
        .state = ARM_CP_STATE_AA64, .readfn = T8030_cpreg_read_##p_name,     \
        .writefn = T8030_cpreg_write_##p_name                                \
    }

T8030_CPREG_FUNCS(ARM64_REG_HID11)
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
T8030_CPREG_FUNCS(L2ACTLR_EL1)
T8030_CPREG_FUNCS(ARM64_REG_APCTL_EL1)
T8030_CPREG_FUNCS(ARM64_REG_KERNELKEYLO_EL1)
T8030_CPREG_FUNCS(ARM64_REG_KERNELKEYHI_EL1)
T8030_CPREG_FUNCS(ARM64_REG_EHID4)
T8030_CPREG_FUNCS(S3_4_c15_c0_5)
T8030_CPREG_FUNCS(S3_4_c15_c1_3)
T8030_CPREG_FUNCS(S3_4_c15_c1_4)
T8030_CPREG_FUNCS(ARM64_REG_CYC_OVRD)
T8030_CPREG_FUNCS(ARM64_REG_ACC_CFG)
T8030_CPREG_FUNCS(ARM64_REG_VMSA_LOCK_EL1)
T8030_CPREG_FUNCS(S3_6_c15_c1_0)
T8030_CPREG_FUNCS(S3_6_c15_c1_1)
T8030_CPREG_FUNCS(S3_6_c15_c1_2)
T8030_CPREG_FUNCS(S3_6_c15_c1_5)
T8030_CPREG_FUNCS(S3_6_c15_c1_6)
T8030_CPREG_FUNCS(S3_6_c15_c1_7)
T8030_CPREG_FUNCS(S3_6_c15_c3_0)
T8030_CPREG_FUNCS(S3_6_c15_c3_1)
T8030_CPREG_FUNCS(S3_6_c15_c8_0)
T8030_CPREG_FUNCS(S3_6_c15_c8_1)
T8030_CPREG_FUNCS(S3_6_c15_c8_2)
T8030_CPREG_FUNCS(S3_6_c15_c8_3)
T8030_CPREG_FUNCS(S3_6_c15_c9_1)
T8030_CPREG_FUNCS(UPMPCM)
T8030_CPREG_FUNCS(UPMCR0)
T8030_CPREG_FUNCS(UPMSR)
T8030_CPREG_FUNCS(ARM64_REG_CTRR_A_LWR_EL1)
T8030_CPREG_FUNCS(ARM64_REG_CTRR_A_UPR_EL1)
T8030_CPREG_FUNCS(ARM64_REG_CTRR_CTL_EL1)
T8030_CPREG_FUNCS(ARM64_REG_CTRR_LOCK_EL1)

//Deliver IPI, call with cluster mutex locked
static void T8030_cluster_deliver_ipi(cluster* c, uint32_t cpu_id){
    if(c->cpus[cpu_id]->is_sleep){
        //TODO: Wake up this one
    }
    for(int k = 0; k < MAX_CPU; k++){
        //clear all pending IPIs
        c->deferredIPI[k][cpu_id] = 0;
        c->noWakeIPI[k][cpu_id] = 0;
    }
    assert(c->cpus[cpu_id]->is_in_ipi == false);
    c->cpus[cpu_id]->is_in_ipi = true;

    fprintf(stderr, "Cluster %u delivering Fast IPI to CPU %u\n", c->id, cpu_id);

    T8030MachineState *tms = T8030_MACHINE(c->machine);
    WITH_QEMU_LOCK_GUARD(&tms->mutex){
        tms->pendingIPI[cpu_id] = true;
        timer_mod_ns(tms->ipi_deliver_timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + 1);
    }
}

//Deliver intercluster IPI
static void T8030_ipi_rr_local(CPUARMState *env, const ARMCPRegInfo *ri,
                                         uint64_t value)
{
    T8030CPU *tcpu = (T8030CPU *)ri->opaque;
    T8030MachineState *tms = T8030_MACHINE(tcpu->machine);
    WITH_QEMU_LOCK_GUARD(&tms->clusters[tcpu->cluster_id]->mutex){
        uint32_t cpu_id = MPIDR_CPU_ID(value);
        cluster *c = tms->clusters[tcpu->cluster_id];
        if(c->cpus[cpu_id] == NULL) return;
        fprintf(stderr, "CPU %u sending fast IPI to local CPU %u: value: 0x%llx\n", tcpu->cpu_id, cpu_id, value);
        if ((value & ARM64_REG_IPI_RR_TYPE_NOWAKE) == ARM64_REG_IPI_RR_TYPE_NOWAKE){
            fprintf(stderr, "...nowake ipi\n");
            if(c->cpus[cpu_id]->is_sleep){
                c->noWakeIPI[tcpu->cpu_id][cpu_id] = 1;
            } else {
                T8030_cluster_deliver_ipi(c, cpu_id);
            }
        } else if ((value & ARM64_REG_IPI_RR_TYPE_DEFERRED) == ARM64_REG_IPI_RR_TYPE_DEFERRED){
            fprintf(stderr, "...deferred ipi\n");
            c->deferredIPI[tcpu->cpu_id][cpu_id] = 1;
        } else if ((value & ARM64_REG_IPI_RR_TYPE_RETRACT) == ARM64_REG_IPI_RR_TYPE_RETRACT){
            fprintf(stderr, "...retract ipi\n");
            c->deferredIPI[tcpu->cpu_id][cpu_id] = 0;
            c->noWakeIPI[tcpu->cpu_id][cpu_id] = 0;
        } else if((value & ARM64_REG_IPI_RR_TYPE_IMMEDIATE) == ARM64_REG_IPI_RR_TYPE_IMMEDIATE){
            fprintf(stderr, "...immediate ipi\n");
            T8030_cluster_deliver_ipi(c, cpu_id);
        }
    }
}
//Deliver intracluster IPI
static void T8030_ipi_rr_global(CPUARMState *env, const ARMCPRegInfo *ri,
                                         uint64_t value)
{
    T8030CPU *tcpu = (T8030CPU *)ri->opaque;
    T8030MachineState *tms = T8030_MACHINE(tcpu->machine);
    uint32_t cluster_id = MPIDR_CLUSTER_ID(value >> IPI_RR_TARGET_CLUSTER_SHIFT);
    if(cluster_id >= MAX_CLUSTER || tms->clusters[cluster_id] == 0) return;
    WITH_QEMU_LOCK_GUARD(&tms->clusters[cluster_id]->mutex){
        uint32_t cpu_id = MPIDR_CPU_ID(value);
        cluster *c = tms->clusters[cluster_id];
        if(c->cpus[cpu_id] == NULL) return;
        if ((value & ARM64_REG_IPI_RR_TYPE_NOWAKE) == ARM64_REG_IPI_RR_TYPE_NOWAKE){
            if(c->cpus[cpu_id]->is_sleep){
                c->noWakeIPI[tcpu->cpu_id][cpu_id] = 1;
            } else {
                T8030_cluster_deliver_ipi(c, cpu_id);
            }
        } else if ((value & ARM64_REG_IPI_RR_TYPE_DEFERRED) == ARM64_REG_IPI_RR_TYPE_DEFERRED){
            c->deferredIPI[tcpu->cpu_id][cpu_id] = 1;
        } else if ((value & ARM64_REG_IPI_RR_TYPE_RETRACT) == ARM64_REG_IPI_RR_TYPE_RETRACT){
            c->deferredIPI[tcpu->cpu_id][cpu_id] = 0;
            c->noWakeIPI[tcpu->cpu_id][cpu_id] = 0;
        } else if((value & ARM64_REG_IPI_RR_TYPE_IMMEDIATE) == ARM64_REG_IPI_RR_TYPE_IMMEDIATE){
            T8030_cluster_deliver_ipi(c, cpu_id);
        } 
    }
}
//Receiving IPI
static uint64_t T8030_ipi_read_sr(CPUARMState *env, const ARMCPRegInfo *ri)
{
    T8030CPU *tcpu = (T8030CPU *)ri->opaque;
    return tcpu->is_in_ipi;
}
//Acknowledge received IPI
static void T8030_ipi_write_sr(CPUARMState *env, const ARMCPRegInfo *ri,
                                         uint64_t value)
{
    T8030CPU *tcpu = (T8030CPU *)ri->opaque;
    tcpu->is_in_ipi = false;
    qemu_irq_lower(qdev_get_gpio_in(DEVICE(tcpu->cpu), ARM_CPU_FIQ));
    fprintf(stderr, "CPU %u ack fast IPI\n", tcpu->cpu_id);
}
//Read deferred interrupt timeout (global)
static uint64_t T8030_ipi_read_cr(CPUARMState *env, const ARMCPRegInfo *ri)
{
    T8030CPU *tcpu = (T8030CPU *)ri->opaque;
    T8030MachineState *tms = T8030_MACHINE(tcpu->machine);
    WITH_QEMU_LOCK_GUARD(&tms->mutex){
        return tms->ipi_cr;
    }
}
//Set deferred interrupt timeout (global)
static void T8030_ipi_write_cr(CPUARMState *env, const ARMCPRegInfo *ri,
                                         uint64_t value)
{
    fprintf(stderr, "T8030 adjusting deferred IPI timeout to %llu\n", value);
    T8030CPU *tcpu = (T8030CPU *)ri->opaque;
    T8030MachineState *tms = T8030_MACHINE(tcpu->machine);
    WITH_QEMU_LOCK_GUARD(&tms->mutex){
        if(value == 0) value = kDeferredIPITimerDefault;
        if(tms->ipi_cr == value) return;

        uint64_t ct = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
        timer_mod_ns(tms->ipicr_timer, (ct / tms->ipi_cr) * tms->ipi_cr + value);
        tms->ipi_cr = value;
    }
}

// This is the same as the array for kvm, but without
// the L2ACTLR_EL1, which is already defined in TCG.
// Duplicating this list isn't a perfect solution,
// but it's quick and reliable.
static const ARMCPRegInfo T8030_cp_reginfo_tcg[] = {
    // Apple-specific registers
    T8030_CPREG_DEF(ARM64_REG_HID11, 3, 0, 15, 13, 0, PL1_RW),
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
    T8030_CPREG_DEF(ARM64_REG_VMSA_LOCK_EL1, 3, 4, 15, 1, 2, PL1_RW),
    T8030_CPREG_DEF(S3_6_c15_c1_0, 3, 6, 15, 1, 0, PL1_RW),
    T8030_CPREG_DEF(S3_6_c15_c1_1, 3, 6, 15, 1, 1, PL1_RW),
    T8030_CPREG_DEF(S3_6_c15_c1_2, 3, 6, 15, 1, 2, PL1_RW),
    T8030_CPREG_DEF(S3_6_c15_c1_5, 3, 6, 15, 1, 5, PL1_RW),
    T8030_CPREG_DEF(S3_6_c15_c1_6, 3, 6, 15, 1, 6, PL1_RW),
    T8030_CPREG_DEF(S3_6_c15_c1_7, 3, 6, 15, 1, 7, PL1_RW),
    T8030_CPREG_DEF(S3_6_c15_c3_0, 3, 6, 15, 3, 0, PL1_RW),
    T8030_CPREG_DEF(S3_6_c15_c3_1, 3, 6, 15, 3, 1, PL1_RW),
    T8030_CPREG_DEF(S3_6_c15_c8_0, 3, 6, 15, 8, 0, PL1_RW),
    T8030_CPREG_DEF(S3_6_c15_c8_1, 3, 6, 15, 8, 1, PL1_RW),
    T8030_CPREG_DEF(S3_6_c15_c8_2, 3, 6, 15, 8, 2, PL1_RW),
    T8030_CPREG_DEF(S3_6_c15_c8_3, 3, 6, 15, 8, 3, PL1_RW),
    T8030_CPREG_DEF(S3_6_c15_c9_1, 3, 6, 15, 9, 1, PL1_RW),
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
        .name = "ARM64_REG_IPI_RR_LOCAL", .opc0 = 3, .crn = 15, .crm = 0,
        .opc1 = 5, .opc2 = 0, .access = PL1_W, .type = ARM_CP_NO_RAW | ARM_CP_RAISES_EXC,
        .state = ARM_CP_STATE_AA64,
        .writefn = T8030_ipi_rr_local
    },
    {                                                                        
        .cp = CP_REG_ARM64_SYSREG_CP,                                        
        .name = "ARM64_REG_IPI_RR_GLOBAL", .opc0 = 3, .crn = 15, .crm = 0,
        .opc1 = 5, .opc2 = 1, .access = PL1_W, .type = ARM_CP_NO_RAW | ARM_CP_RAISES_EXC,
        .state = ARM_CP_STATE_AA64,
        .writefn = T8030_ipi_rr_global
    },
    {                                                                        
        .cp = CP_REG_ARM64_SYSREG_CP,                                        
        .name = "ARM64_REG_IPI_SR", .opc0 = 3, .crn = 15, .crm = 1,
        .opc1 = 5, .opc2 = 1, .access = PL1_RW, .type = ARM_CP_IO,
        .state = ARM_CP_STATE_AA64,
        .readfn = T8030_ipi_read_sr,
        .writefn = T8030_ipi_write_sr
    },
    {                                                                        
        .cp = CP_REG_ARM64_SYSREG_CP,                                        
        .name = "ARM64_REG_IPI_CR", .opc0 = 3, .crn = 15, .crm = 3,
        .opc1 = 5, .opc2 = 1, .access = PL1_RW, .type = ARM_CP_IO,
        .state = ARM_CP_STATE_AA64,
        .readfn = T8030_ipi_read_cr,
        .writefn = T8030_ipi_write_cr
    },
    REGINFO_SENTINEL,
};

static uint32_t g_nop_inst = NOP_INST;
static uint32_t g_mov_w0_01_inst = MOV_W0_01_INST;
static uint32_t g_mov_x13_0_inst = MOV_X13_0_INST;
static uint32_t g_ret_inst = RET_INST;
static uint32_t g_retab_inst = RETAB_INST;

static void T8030_add_cpregs(T8030CPU* tcpu)
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
    tcpu->T8030_CPREG_VAR_NAME(L2ACTLR_EL1) = 0;
    tcpu->T8030_CPREG_VAR_NAME(ARM64_REG_APCTL_EL1) = 2;
    tcpu->T8030_CPREG_VAR_NAME(ARM64_REG_KERNELKEYLO_EL1) = 0;
    tcpu->T8030_CPREG_VAR_NAME(ARM64_REG_KERNELKEYHI_EL1) = 0;
    define_arm_cp_regs_with_opaque(cpu, T8030_cp_reginfo_tcg, tcpu);
}

static void T8030_create_s3c_uart(const T8030MachineState *tms, Chardev *chr)
{
    qemu_irq irq;
    DeviceState *d;
    SysBusDevice *s;
    hwaddr base;
    //first fetch the uart mmio address
    DTBNode *child = get_dtb_child_node_by_name(tms->device_tree, "arm-io");
    assert(child != NULL);
    child = get_dtb_child_node_by_name(child, "uart0");
    assert(child != NULL);
    //make sure this node has the boot-console prop
    DTBProp* prop = get_dtb_prop(child, "boot-console");
    assert(prop != NULL);
    prop = get_dtb_prop(child, "reg");
    assert(prop != NULL);
    hwaddr *uart_offset = (hwaddr *)prop->value;
    base = tms->soc_base_pa + uart_offset[0];

    //hack for now. create a device that is not used just to have a dummy
    //unused interrupt
    d = qdev_new(TYPE_PLATFORM_BUS_DEVICE);
    s = SYS_BUS_DEVICE(d);
    sysbus_init_irq(s, &irq);
    //pass a dummy irq as we don't need nor want interrupts for this UART
    DeviceState *dev = exynos4210_uart_create(base, 256, 0, chr, irq);
    assert(dev!=NULL);
}

static void T8030_patch_kernel(AddressSpace *nsas)
{
    //gxf_enable
    address_space_rw(nsas, vtop_static(0xFFFFFFF00811CE98),
                     MEMTXATTRS_UNSPECIFIED, (uint8_t *)&g_nop_inst,
                     sizeof(g_nop_inst), 1);
    //pmap_ppl_locked_down = 1
    address_space_rw(nsas, vtop_static(0xFFFFFFF007B5A5A8),
                     MEMTXATTRS_UNSPECIFIED, (uint8_t *)&g_nop_inst,
                     sizeof(g_nop_inst), 1);
    uint32_t value = 0;
    //disable_kprintf_output = 0
    address_space_rw(nsas, vtop_static(0xFFFFFFF0077142C8),
                     MEMTXATTRS_UNSPECIFIED, (uint8_t *)&value,
                     sizeof(value), 1);
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
    hwaddr ramfb_pa = 0;
    video_boot_args v_bootargs = {0};
    T8030MachineState *tms = T8030_MACHINE(machine);
    MemoryRegion* sysmem = tms->sysmem;
    AddressSpace* nsas = tms->cpus[0]->nsas;

    //setup the memory layout:

    //At the beginning of the non-secure ram we have the raw kernel file.
    //After that we have the static trust cache.
    //After that we have all the kernel sections.
    //After that we have ramdosk
    //After that we have the device tree
    //After that we have the kernel boot args
    //After that we have the rest of the RAM

    macho_file_highest_lowest_base(tms->kernel_filename, T8030_PHYS_BASE,
                                   &virt_base, &kernel_low, &kernel_high);

    g_virt_base = virt_base;
    g_phys_base = T8030_PHYS_BASE;
    phys_ptr = T8030_PHYS_BASE;
    fprintf(stderr, "g_virt_base: 0x" TARGET_FMT_lx "\ng_phys_base: 0x" TARGET_FMT_lx "\n", g_virt_base, g_phys_base);
    fprintf(stderr, "kernel_low: 0x" TARGET_FMT_lx "\nkernel_high: 0x" TARGET_FMT_lx "\n", kernel_low, kernel_high);

    // //now account for the trustcache
    phys_ptr += align_64k_high(0x2000000);
    hwaddr trustcache_pa = phys_ptr;
    hwaddr trustcache_size = 0;
    macho_load_raw_file("static_tc", nsas, sysmem,
                        "trustcache.T8030", trustcache_pa,
                        &trustcache_size);
    fprintf(stderr, "trustcache_addr: 0x%llx\ntrustcache_size: 0x%llx\n", trustcache_pa, trustcache_size);
    phys_ptr += align_64k_high(trustcache_size);

    //now account for the loaded kernel
    arm_load_macho(tms->kernel_filename, nsas, sysmem, "kernel.T8030",
                   T8030_PHYS_BASE, virt_base, kernel_low,
                   kernel_high, &phys_pc);
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
    hwaddr ramdisk_size = 0;
    if (0 != tms->ramdisk_filename[0])
    {
        tms->ramdisk_file_dev.pa = phys_ptr;
        macho_map_raw_file(tms->ramdisk_filename, nsas, sysmem,
                           "ramdisk_raw_file.T8030", tms->ramdisk_file_dev.pa,
                           &tms->ramdisk_file_dev.size);
        tms->ramdisk_file_dev.size = align_64k_high(tms->ramdisk_file_dev.size);
        ramdisk_size = tms->ramdisk_file_dev.size;
        phys_ptr += tms->ramdisk_file_dev.size;
        fprintf(stderr, "ramdisk addr: 0x" TARGET_FMT_lx "\n", tms->ramdisk_file_dev.pa);
        fprintf(stderr, "ramdisk size: 0x" TARGET_FMT_lx "\n", tms->ramdisk_file_dev.size);
    }
    
    //now account for kernel boot args
    used_ram_for_blobs += align_64k_high(sizeof(struct xnu_arm64_boot_args));
    kbootargs_pa = phys_ptr;
    tms->kbootargs_pa = kbootargs_pa;
    phys_ptr += align_64k_high(sizeof(struct xnu_arm64_boot_args));
    tms->extra_data_pa = phys_ptr;
    allocated_ram_pa = phys_ptr;
    
    if (tms->use_ramfb)
    {
        ramfb_pa = ((hwaddr) & ((AllocatedData *)tms->extra_data_pa)->ramfb[0]);
        xnu_define_ramfb_device(nsas, ramfb_pa);
        xnu_get_video_bootargs(&v_bootargs, ramfb_pa);
    }

    phys_ptr += align_64k_high(sizeof(AllocatedData));
    top_of_kernel_data_pa = phys_ptr;
    remaining_mem_size = machine->ram_size - used_ram_for_blobs;
    mem_size = allocated_ram_pa - T8030_PHYS_BASE + remaining_mem_size;
    tms->dram_base = T8030_PHYS_BASE;
    tms->dram_size = mem_size;

    fprintf(stderr, "mem_size: 0x" TARGET_FMT_lx "\n", mem_size);
    fprintf(stderr, "dram-base: 0x" TARGET_FMT_lx "\n", tms->dram_base);
    fprintf(stderr, "dram-size: 0x" TARGET_FMT_lx "\n", tms->dram_size);

    macho_load_dtb(tms->device_tree, nsas, sysmem, "dtb.T8030",
                   dtb_pa, &dtb_size,
                   tms->ramdisk_file_dev.pa, ramdisk_size,
                   trustcache_pa, trustcache_size,
                   tms->dram_base, tms->dram_size);
    assert(dtb_size <= T8030_MAX_DEVICETREE_SIZE);

    macho_setup_bootargs("k_bootargs.T8030", nsas, sysmem, kbootargs_pa,
                         virt_base, T8030_PHYS_BASE, mem_size,
                         top_of_kernel_data_pa, dtb_va, dtb_size,
                         v_bootargs, tms->kern_args);

    allocate_ram(sysmem, "T8030.ram", allocated_ram_pa, remaining_mem_size);
}

static void cpu_impl_reg_write(void *opaque,
                  hwaddr addr,
                  uint64_t data,
                  unsigned size){
    T8030CPU* cpu = (T8030CPU*) opaque;
    fprintf(stderr, "CPU %u cpu-impl-reg WRITE @ 0x" TARGET_FMT_lx " value: 0x" TARGET_FMT_lx "\n", cpu->cpu_id, addr, data);
}
static uint64_t cpu_impl_reg_read(void *opaque,
                     hwaddr addr,
                     unsigned size){
    T8030CPU* cpu = (T8030CPU*) opaque;
    fprintf(stderr, "CPU %u cpu-impl-reg READ @ 0x" TARGET_FMT_lx "\n", cpu->cpu_id, addr);
    return 0;
}

static const MemoryRegionOps cpu_impl_reg_ops = {
    .write = cpu_impl_reg_write,
    .read = cpu_impl_reg_read,
};

static void cpu_coresight_reg_write(void *opaque,
                  hwaddr addr,
                  uint64_t data,
                  unsigned size){
    T8030CPU* cpu = (T8030CPU*) opaque;
}
static uint64_t cpu_coresight_reg_read(void *opaque,
                     hwaddr addr,
                     unsigned size){
    T8030CPU* cpu = (T8030CPU*) opaque;
    return 0;
}
static const MemoryRegionOps cpu_coresight_reg_ops = {
    .write = cpu_coresight_reg_write,
    .read = cpu_coresight_reg_read,
};

static void cpm_impl_reg_write(void *opaque,
                  hwaddr addr,
                  uint64_t data,
                  unsigned size){
    cluster* cpm = (cluster*) opaque;
    fprintf(stderr, "Cluster %u cpm-impl-reg WRITE @ 0x" TARGET_FMT_lx " value: 0x" TARGET_FMT_lx "\n", cpm->id, addr, data);
}
static uint64_t cpm_impl_reg_read(void *opaque,
                     hwaddr addr,
                     unsigned size){
    cluster* cpm = (cluster*) opaque;
    fprintf(stderr, "Cluster %u cpm-impl-reg READ @ 0x" TARGET_FMT_lx "\n", cpm->id, addr);
    return 0;
}
static const MemoryRegionOps cpm_impl_reg_ops = {
    .write = cpm_impl_reg_write,
    .read = cpm_impl_reg_read,
};

static void T8030_cluster_setup(MachineState *machine){

    T8030MachineState *tms = T8030_MACHINE(machine);
    tms->clusters[0] = g_new0(cluster, 1);
    tms->clusters[0]->base = CPM_IMPL_REG_BASE;
    tms->clusters[0]->type = '0'; // E-CORE
    tms->clusters[0]->id = 0;
    tms->clusters[0]->mr = g_new(MemoryRegion, 1);
    tms->clusters[0]->machine = machine;
    qemu_mutex_init(&tms->clusters[0]->mutex);
    memory_region_init_io(tms->clusters[0]->mr, OBJECT(machine), &cpm_impl_reg_ops, tms->clusters[0], "cpm-impl-reg", 0x10000);
    memory_region_add_subregion(tms->sysmem, tms->clusters[0]->base, tms->clusters[0]->mr);
    tms->clusters[1] = g_new0(cluster, 1);
    tms->clusters[1]->base = CPM_IMPL_REG_BASE + 0x10000;
    tms->clusters[1]->type = '1'; // P-CORE
    tms->clusters[1]->id = 1;
    tms->clusters[1]->mr = g_new(MemoryRegion, 1);
    tms->clusters[1]->machine = machine;
    for(int i = 0;i < MAX_CPU; i++){
        for(int j = 0;j < MAX_CPU; j++){
            tms->clusters[1]->deferredIPI[i][j] = -1;
        }
    }
    qemu_mutex_init(&tms->clusters[1]->mutex);
    memory_region_init_io(tms->clusters[1]->mr, OBJECT(machine), &cpm_impl_reg_ops, tms->clusters[1], "cpm-impl-reg", 0x10000);
    memory_region_add_subregion(tms->sysmem, tms->clusters[1]->base,tms->clusters[1]->mr);
}

static void T8030_cpu_setup(MachineState *machine)
{
    T8030MachineState *tms = T8030_MACHINE(machine);

    T8030_cluster_setup(machine);

    DTBNode* root = get_dtb_child_node_by_name(tms->device_tree, "cpus");
    for(unsigned int i=0;i<machine->smp.cpus;i++){

        char* cpu_name = g_malloc0(8);
        snprintf(cpu_name, 8, "cpu%u", i);
        DTBNode* node = get_dtb_child_node_by_name(root, cpu_name);
        assert(node);
        DTBProp* prop = NULL;
        Object *cpuobj = object_new(machine->cpu_type);
        tms->cpus[i] = g_new(T8030CPU, 1);
        tms->cpus[i]->cpu = ARM_CPU(cpuobj);
        tms->cpus[i]->machine = machine;
        CPUState *cs = CPU(tms->cpus[i]->cpu);

        //MPIDR_EL1
        prop = get_dtb_prop(node, "cpu-id");
        assert(prop->length == 4);
        unsigned int cpu_id = *(unsigned int*)prop->value;
        prop = get_dtb_prop(node, "reg");
        assert(prop->length == 4);
        unsigned int phys_id = *(unsigned int*)prop->value;
        prop = get_dtb_prop(node, "cluster-id");
        assert(prop->length == 4);
        unsigned int cluster_id = *(unsigned int*)prop->value;
        uint64_t mpidr = 0LL | phys_id | (cluster_id << MPIDR_AFF1_SHIFT) | (tms->clusters[cluster_id]->type << MPIDR_AFF2_SHIFT) | (1LL << 31);
        tms->cpus[i]->cpu->mp_affinity = mpidr;
        tms->cpus[i]->mpidr = mpidr;
        tms->cpus[cpu_id] = tms->cpus[i];
        tms->clusters[cluster_id]->cpus[cpu_id] = tms->cpus[i];
        //remove debug regs from device tree
        prop = get_dtb_prop(node, "reg-private");
        if(prop != NULL){
            remove_dtb_prop(node, prop);
        }
        prop = get_dtb_prop(node, "cpu-uttdbg-reg");
        if(prop != NULL){
            remove_dtb_prop(node, prop);
        }
        //need to set the cpu freqs instead of iboot
        uint64_t freq = 24000000;
        if (i == 0){
            prop = get_dtb_prop(node, "state");
            if(prop != NULL) {
                remove_dtb_prop(node, prop);
            }
            add_dtb_prop(node, "state", 8, "running");
        }
        prop = get_dtb_prop(node, "timebase-frequency");
        if(prop != NULL){
            remove_dtb_prop(node, prop);
        }
        add_dtb_prop(node, "timebase-frequency", sizeof(uint64_t),
                        (uint8_t *)&freq);
        prop = get_dtb_prop(node, "fixed-frequency");
        if(prop != NULL){
            remove_dtb_prop(node, prop);
        }
        add_dtb_prop(node, "fixed-frequency", sizeof(uint64_t),
                        (uint8_t *)&freq);
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

        if(i > 0){
            object_property_set_bool(cpuobj, "start-powered-off", true, NULL);
            tms->cpus[i]->is_sleep = true;
        }

        qdev_realize(DEVICE(cpuobj), NULL, &error_fatal);
        
        tms->cpus[i]->cpu_id = cpu_id;
        tms->cpus[i]->phys_id = phys_id;
        tms->cpus[i]->cluster_id = cluster_id;
        tms->cpus[i]->nsas = cpu_get_address_space(cs, ARMASIdx_NS);

        prop = get_dtb_prop(node, "cpu-impl-reg");
        assert(prop);
        assert(prop->length == 16);
        uint64_t* reg = (uint64_t*)prop->value;
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
        
        qdev_connect_gpio_out(DEVICE(cpuobj), GTIMER_VIRT,
                          qdev_get_gpio_in(DEVICE(cpuobj), ARM_CPU_FIQ));
        T8030_add_cpregs(tms->cpus[i]);
        
        object_unref(cpuobj);
    }
    //currently support only a single CPU and thus
    //use no interrupt controller and wire IRQs from devices directly to the CPU
}

static void T8030_bootargs_setup(MachineState *machine)
{
    T8030MachineState *tms = T8030_MACHINE(machine);
    tms->bootinfo.firmware_loaded = true;
}

static void T8030_create_aic(MachineState *machine){
    T8030MachineState *tms = T8030_MACHINE(machine);
    DTBNode *child = get_dtb_child_node_by_name(tms->device_tree, "arm-io");
    assert(child != NULL);
    child = get_dtb_child_node_by_name(child, "aic");
    assert(child != NULL);
    tms->aic = apple_aic_create(tms->soc_base_pa, machine->smp.cpus, child);
    assert(tms->aic);
    for(int i = 0; i < machine->smp.cpus; i++)
    {
        memory_region_add_subregion_overlap(tms->cpus[i]->memory, tms->aic->base, tms->aic->iomems[i], 0);
        qdev_connect_gpio_out(DEVICE(tms->aic), i, qdev_get_gpio_in(DEVICE(tms->cpus[i]->cpu), ARM_CPU_FIQ));
    }
}

static void T8030_cpu_reset(void *opaque)
{
    T8030MachineState *tms = T8030_MACHINE((MachineState *)opaque);
    ARMCPU *cpu = ARM_CPU(first_cpu);
    CPUState *cs = CPU(cpu);
    CPUARMState *env = &cpu->env;

    cpu_reset(cs);

    env->xregs[0] = tms->kbootargs_pa;
    env->pc = tms->kpc_pa;
}

static void T8030_cluster_tick(cluster* c){
    WITH_QEMU_LOCK_GUARD(&c->mutex){
        for(int i = 0; i < MAX_CPU; i++) /* target */
        if(c->cpus[i] != NULL){
            for(int j = 0; j < MAX_CPU; j++){ /* source */
                if(c->deferredIPI[j][i]){
                    T8030_cluster_deliver_ipi(c, i);
                    break;
                }
            }
        }
    }
}

static void T8030_machine_deliver_ipi(void* opaque){
    T8030MachineState *tms = T8030_MACHINE((MachineState *)opaque);
    WITH_QEMU_LOCK_GUARD(&tms->mutex){
        for(int i = 0; i < MAX_CPU; i++)
        if(tms->pendingIPI[i]){

            fprintf(stderr, "T8030 delivering Fast IPI to CPU %u\n", i);
            qemu_irq_raise(qdev_get_gpio_in(DEVICE(tms->cpus[i]->cpu), ARM_CPU_FIQ));
        }
    }
}
static void T8030_machine_ipicr_tick(void* opaque){
    T8030MachineState *tms = T8030_MACHINE((MachineState *)opaque);
    for(int i = 0; i < MAX_CLUSTER; i++){
        T8030_cluster_tick(tms->clusters[i]);
    }
    timer_mod_ns(tms->ipicr_timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + tms->ipi_cr);
}

static void T8030_machine_reset(void* opaque){
    MachineState* machine = MACHINE(opaque);
    T8030MachineState *tms = T8030_MACHINE(opaque);
    tms->ipi_deliver_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, T8030_machine_deliver_ipi, machine);
    tms->ipicr_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, T8030_machine_ipicr_tick, machine);
    timer_mod_ns(tms->ipicr_timer, kDeferredIPITimerDefault);
    T8030_cpu_reset(tms);
}

static void T8030_machine_init(MachineState *machine)
{
    T8030MachineState *tms = T8030_MACHINE(machine);
    qemu_mutex_init(&tms->mutex);
    tms->sysmem = get_system_memory();
    
    tms->device_tree = load_dtb_from_file(tms->dtb_filename);
    DTBNode *child = get_dtb_child_node_by_name(tms->device_tree, "arm-io");
    assert(child != NULL);
    DTBProp *prop = get_dtb_prop(child, "ranges");
    assert(prop != NULL);
    hwaddr *ranges = (hwaddr *)prop->value;
    tms->soc_base_pa = ranges[1];

    T8030_cpu_setup(machine);

    T8030_memory_setup(machine);

    tms->ipi_cr = kDeferredIPITimerDefault;

    T8030_create_aic(machine);
    
    T8030_create_s3c_uart(tms, serial_hd(0));

    T8030_bootargs_setup(machine);

    qemu_register_reset(T8030_machine_reset, tms);
}

static void T8030_set_ramdisk_filename(Object *obj, const char *value,
                                       Error **errp)
{
    T8030MachineState *tms = T8030_MACHINE(obj);

    g_strlcpy(tms->ramdisk_filename, value, sizeof(tms->ramdisk_filename));
}

static char *T8030_get_ramdisk_filename(Object *obj, Error **errp)
{
    T8030MachineState *tms = T8030_MACHINE(obj);
    return g_strdup(tms->ramdisk_filename);
}

static void T8030_set_kernel_filename(Object *obj, const char *value,
                                      Error **errp)
{
    T8030MachineState *tms = T8030_MACHINE(obj);

    g_strlcpy(tms->kernel_filename, value, sizeof(tms->kernel_filename));
}

static char *T8030_get_kernel_filename(Object *obj, Error **errp)
{
    T8030MachineState *tms = T8030_MACHINE(obj);
    return g_strdup(tms->kernel_filename);
}

static void T8030_set_dtb_filename(Object *obj, const char *value,
                                   Error **errp)
{
    T8030MachineState *tms = T8030_MACHINE(obj);

    g_strlcpy(tms->dtb_filename, value, sizeof(tms->dtb_filename));
}

static char *T8030_get_dtb_filename(Object *obj, Error **errp)
{
    T8030MachineState *tms = T8030_MACHINE(obj);
    return g_strdup(tms->dtb_filename);
}

static void T8030_set_kern_args(Object *obj, const char *value,
                                Error **errp)
{
    T8030MachineState *tms = T8030_MACHINE(obj);

    g_strlcpy(tms->kern_args, value, sizeof(tms->kern_args));
}

static char *T8030_get_kern_args(Object *obj, Error **errp)
{
    T8030MachineState *tms = T8030_MACHINE(obj);
    return g_strdup(tms->kern_args);
}

static void T8030_set_xnu_ramfb(Object *obj, const char *value,
                                Error **errp)
{
    T8030MachineState *tms = T8030_MACHINE(obj);
    if (strcmp(value, "on") == 0)
        tms->use_ramfb = true;
    else
    {
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
    //this disables the error message "Failed to query for block devices!"
    //when starting qemu - must keep at least one device
    //mc->no_sdcard = 1;
    mc->no_floppy = 1;
    mc->no_cdrom = 1;
    mc->no_parallel = 1;
    mc->default_cpu_type = ARM_CPU_TYPE_NAME("cortex-a72");
    mc->minimum_page_bits = 12;
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
