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

#define MPIDR_AFF0_SHIFT 0
#define MPIDR_AFF0_WIDTH 8
#define MPIDR_AFF0_MASK  (((1 << MPIDR_AFF0_WIDTH) - 1) << MPIDR_AFF0_SHIFT)
#define MPIDR_AFF1_SHIFT 8
#define MPIDR_AFF1_WIDTH 8
#define MPIDR_AFF1_MASK  (((1 << MPIDR_AFF1_WIDTH) - 1) << MPIDR_AFF1_SHIFT)
#define MPIDR_AFF2_SHIFT 16
#define MPIDR_AFF2_WIDTH 8
#define MPIDR_AFF2_MASK  (((1 << MPIDR_AFF2_WIDTH) - 1) << MPIDR_AFF2_SHIFT)

#define MPIDR_CPU_ID(mpidr_el1_val)             (((mpidr_el1_val) & MPIDR_AFF0_MASK) >> MPIDR_AFF0_SHIFT)
#define MPIDR_CLUSTER_ID(mpidr_el1_val)         (((mpidr_el1_val) & MPIDR_AFF1_MASK) >> MPIDR_AFF1_SHIFT)

#define IPI_SR_SRC_CPU_SHIFT 8
#define IPI_SR_SRC_CPU_WIDTH 8
#define IPI_SR_SRC_CPU_MASK  (((1 << IPI_SR_SRC_CPU_WIDTH) - 1) << IPI_SR_SRC_CPU_SHIFT)
#define IPI_SR_SRC_CPU(ipi_sr_val)         (((ipi_sr_val) & IPI_SR_SRC_CPU_MASK) >> IPI_SR_SRC_CPU_SHIFT)

#define IPI_RR_TARGET_CLUSTER_SHIFT 16
#define ARM64_REG_IPI_RR_TYPE_IMMEDIATE (0 << 28)
#define ARM64_REG_IPI_RR_TYPE_RETRACT   (1 << 28)
#define ARM64_REG_IPI_RR_TYPE_DEFERRED  (2 << 28)
#define ARM64_REG_IPI_RR_TYPE_NOWAKE    (3 << 28)

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
    //uncore
    T8030_CPREG_VAR_DEF(UPMPCM);
    T8030_CPREG_VAR_DEF(UPMCR0);
    T8030_CPREG_VAR_DEF(UPMSR);
    //ktrr
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
T8030CPUState *t8030_cs_from_env(CPUARMState *env);
bool t8030_cpu_is_sleep(T8030CPUState *tcpu);
void t8030_cpu_wakeup(T8030CPUState *tcpu);
#endif /* HW_ARM_T8030_CPU_H */
