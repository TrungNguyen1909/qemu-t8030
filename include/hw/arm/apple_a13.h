#ifndef HW_ARM_APPLE_A13_H
#define HW_ARM_APPLE_A13_H

#include "qemu-common.h"
#include "cpu.h"
#include "exec/hwaddr.h"
#include "qemu/queue.h"
#include "hw/arm/xnu_dtb.h"
#include "hw/cpu/cluster.h"

#define A13_MAX_CPU 6
#define A13_MAX_CLUSTER 2
#define A13_NUM_ECORE 2
#define A13_NUM_PCORE 4

#define TYPE_APPLE_A13 "apple-a13-cpu"
OBJECT_DECLARE_TYPE(AppleA13State, AppleA13Class, APPLE_A13)

#define TYPE_APPLE_A13_CLUSTER "apple-a13-cluster"
OBJECT_DECLARE_SIMPLE_TYPE(AppleA13Cluster, APPLE_A13_CLUSTER)

#define A13_CPREG_VAR_NAME(name) cpreg_##name
#define A13_CPREG_VAR_DEF(name) uint64_t A13_CPREG_VAR_NAME(name)

#define kDeferredIPITimerDefault 64000

typedef struct AppleA13Class {
    /*< private >*/
    ARMCPUClass base_class;
    /*< public >*/

    DeviceRealize parent_realize;
    DeviceUnrealize parent_unrealize;
    DeviceReset   parent_reset;
} AppleA13Class;

typedef struct AppleA13State {
    ARMCPU parent_obj;
    MemoryRegion impl_reg;
    MemoryRegion coresight_reg;
    MemoryRegion memory;
    MemoryRegion sysmem;
    uint32_t cpu_id;
    uint32_t phys_id;
    uint32_t cluster_id;
    uint64_t mpidr;
    uint64_t ipi_sr;
    hwaddr cluster_reg[2];
    qemu_irq fast_ipi;
    A13_CPREG_VAR_DEF(ARM64_REG_EHID4);
    A13_CPREG_VAR_DEF(ARM64_REG_EHID10);
    A13_CPREG_VAR_DEF(ARM64_REG_HID0);
    A13_CPREG_VAR_DEF(ARM64_REG_HID1);
    A13_CPREG_VAR_DEF(ARM64_REG_HID3);
    A13_CPREG_VAR_DEF(ARM64_REG_HID4);
    A13_CPREG_VAR_DEF(ARM64_REG_HID5);
    A13_CPREG_VAR_DEF(ARM64_REG_HID7);
    A13_CPREG_VAR_DEF(ARM64_REG_HID8);
    A13_CPREG_VAR_DEF(ARM64_REG_HID9);
    A13_CPREG_VAR_DEF(ARM64_REG_HID11);
    A13_CPREG_VAR_DEF(ARM64_REG_HID13);
    A13_CPREG_VAR_DEF(ARM64_REG_HID14);
    A13_CPREG_VAR_DEF(ARM64_REG_HID16);
    A13_CPREG_VAR_DEF(ARM64_REG_LSU_ERR_STS);
    A13_CPREG_VAR_DEF(PMC0);
    A13_CPREG_VAR_DEF(PMC1);
    A13_CPREG_VAR_DEF(PMCR0);
    A13_CPREG_VAR_DEF(PMCR1);
    A13_CPREG_VAR_DEF(PMSR);
    A13_CPREG_VAR_DEF(S3_4_c15_c0_5);
    A13_CPREG_VAR_DEF(AMX_STATUS_EL1);
    A13_CPREG_VAR_DEF(AMX_CTL_EL1);
    A13_CPREG_VAR_DEF(ARM64_REG_CYC_OVRD);
    A13_CPREG_VAR_DEF(ARM64_REG_ACC_CFG);
    A13_CPREG_VAR_DEF(S3_5_c15_c10_1);
    /* uncore */
    A13_CPREG_VAR_DEF(UPMPCM);
    A13_CPREG_VAR_DEF(UPMCR0);
    A13_CPREG_VAR_DEF(UPMSR);
} AppleA13State;

typedef struct AppleA13Cluster {
    CPUClusterState parent_obj;
    hwaddr base;
    hwaddr size;
    uint32_t cluster_type;
    MemoryRegion mr;
    AppleA13State *cpus[A13_MAX_CPU];
    uint32_t deferredIPI[A13_MAX_CPU][A13_MAX_CPU];
    uint32_t noWakeIPI[A13_MAX_CPU][A13_MAX_CPU];
    uint64_t tick;
    uint64_t ipi_cr;
    QTAILQ_ENTRY(AppleA13Cluster) next;
    A13_CPREG_VAR_DEF(CTRR_A_LWR_EL1);
    A13_CPREG_VAR_DEF(CTRR_A_UPR_EL1);
    A13_CPREG_VAR_DEF(CTRR_CTL_EL1);
    A13_CPREG_VAR_DEF(CTRR_LOCK_EL1);
} AppleA13Cluster;

AppleA13State *apple_a13_cpu_create(DTBNode *node);
bool apple_a13_cpu_is_sleep(AppleA13State *tcpu);
bool apple_a13_cpu_is_powered_off(AppleA13State *tcpu);
void apple_a13_cpu_start(AppleA13State *tcpu);
void apple_a13_cpu_reset(AppleA13State *tcpu);
void apple_a13_cpu_off(AppleA13State *tcpu);
#endif /* HW_ARM_APPLE_A13_H */
