#ifndef HW_ARM_T8030_CPU_H
#define HW_ARM_T8030_CPU_H

#include "qemu-common.h"
#include "cpu.h"
#include "exec/hwaddr.h"
#include "qemu/queue.h"
#include "hw/arm/xnu_dtb.h"

#define T8030_MAX_CPU 6
#define T8030_MAX_CLUSTER 2
#define T8030_NUM_ECORE 2
#define T8030_NUM_PCORE 4

#define TYPE_T8030_CPU "t8030-cpu"
OBJECT_DECLARE_TYPE(T8030CPUState, T8030CPUClass, T8030_CPU)

#define TYPE_T8030_CPU_CLUSTER "t8030-cpu-cluster"
OBJECT_DECLARE_SIMPLE_TYPE(T8030CPUCluster, T8030_CPU_CLUSTER)

#define T8030_CPREG_VAR_NAME(name) cpreg_##name
#define T8030_CPREG_VAR_DEF(name) uint64_t T8030_CPREG_VAR_NAME(name)

#define kDeferredIPITimerDefault 64000

typedef struct T8030CPUClass {
    /*< private >*/
    ARMCPUClass base_class;
    /*< public >*/

    DeviceRealize parent_realize;
    DeviceUnrealize parent_unrealize;
    DeviceReset   parent_reset;
} T8030CPUClass;

typedef struct T8030CPUState {
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
    T8030_CPREG_VAR_DEF(ARM64_REG_EHID4);
    T8030_CPREG_VAR_DEF(ARM64_REG_EHID10);
    T8030_CPREG_VAR_DEF(ARM64_REG_HID0);
    T8030_CPREG_VAR_DEF(ARM64_REG_HID3);
    T8030_CPREG_VAR_DEF(ARM64_REG_HID4);
    T8030_CPREG_VAR_DEF(ARM64_REG_HID5);
    T8030_CPREG_VAR_DEF(ARM64_REG_HID7);
    T8030_CPREG_VAR_DEF(ARM64_REG_HID8);
    T8030_CPREG_VAR_DEF(ARM64_REG_HID9);
    T8030_CPREG_VAR_DEF(ARM64_REG_HID11);
    T8030_CPREG_VAR_DEF(ARM64_REG_HID13);
    T8030_CPREG_VAR_DEF(ARM64_REG_HID14);
    T8030_CPREG_VAR_DEF(ARM64_REG_HID16);
    T8030_CPREG_VAR_DEF(ARM64_REG_LSU_ERR_STS);
    T8030_CPREG_VAR_DEF(PMC0);
    T8030_CPREG_VAR_DEF(PMC1);
    T8030_CPREG_VAR_DEF(PMCR1);
    T8030_CPREG_VAR_DEF(PMSR);
    T8030_CPREG_VAR_DEF(ARM64_REG_APCTL_EL1);
    T8030_CPREG_VAR_DEF(ARM64_REG_KERNELKEYLO_EL1);
    T8030_CPREG_VAR_DEF(ARM64_REG_KERNELKEYHI_EL1);
    T8030_CPREG_VAR_DEF(S3_4_c15_c0_5);
    T8030_CPREG_VAR_DEF(AMX_STATUS_EL1);
    T8030_CPREG_VAR_DEF(AMX_CTL_EL1);
    T8030_CPREG_VAR_DEF(ARM64_REG_CYC_OVRD);
    T8030_CPREG_VAR_DEF(ARM64_REG_ACC_CFG);
    T8030_CPREG_VAR_DEF(S3_5_c15_c10_1);
    /* uncore */
    T8030_CPREG_VAR_DEF(UPMPCM);
    T8030_CPREG_VAR_DEF(UPMCR0);
    T8030_CPREG_VAR_DEF(UPMSR);
    /* ktrr */
    T8030_CPREG_VAR_DEF(ARM64_REG_CTRR_A_LWR_EL1);
    T8030_CPREG_VAR_DEF(ARM64_REG_CTRR_A_UPR_EL1);
    T8030_CPREG_VAR_DEF(ARM64_REG_CTRR_CTL_EL1);
    T8030_CPREG_VAR_DEF(ARM64_REG_CTRR_LOCK_EL1);
} T8030CPUState;

typedef struct T8030CPUCluster {
    DeviceState parent_obj;
    hwaddr base;
    hwaddr size;
    uint8_t id;
    uint8_t type;
    MemoryRegion mr;
    T8030CPUState *cpus[T8030_MAX_CPU];
    uint32_t deferredIPI[T8030_MAX_CPU][T8030_MAX_CPU];
    uint32_t noWakeIPI[T8030_MAX_CPU][T8030_MAX_CPU];
    uint64_t tick;
    uint64_t ipi_cr;
    QTAILQ_ENTRY(T8030CPUCluster) next; 
} T8030CPUCluster;

T8030CPUState *t8030_cpu_create(DTBNode *node);
bool t8030_cpu_is_sleep(T8030CPUState *tcpu);
void t8030_cpu_wakeup(T8030CPUState *tcpu);
#endif /* HW_ARM_T8030_CPU_H */
