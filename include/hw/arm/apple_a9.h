#ifndef HW_ARM_APPLE_A9_H
#define HW_ARM_APPLE_A9_H

#include "qemu-common.h"
#include "cpu.h"
#include "exec/hwaddr.h"
#include "qemu/queue.h"
#include "hw/arm/xnu_dtb.h"
#include "hw/cpu/cluster.h"

#define A9_MAX_CPU 6
#define A9_MAX_CLUSTER 2
#define A9_NUM_ECORE 2
#define A9_NUM_PCORE 4

#define TYPE_APPLE_A9 "apple-a9-cpu"
OBJECT_DECLARE_TYPE(AppleA9State, AppleA9Class, APPLE_A9)

#define A9_CPREG_VAR_NAME(name) cpreg_##name
#define A9_CPREG_VAR_DEF(name) uint64_t A9_CPREG_VAR_NAME(name)

#define kDeferredIPITimerDefault 64000

typedef struct AppleA9Class {
    /*< private >*/
    ARMCPUClass base_class;
    /*< public >*/

    DeviceRealize parent_realize;
    DeviceUnrealize parent_unrealize;
    DeviceReset   parent_reset;
} AppleA9Class;

typedef struct AppleA9State {
    ARMCPU parent_obj;
    MemoryRegion impl_reg;
    MemoryRegion coresight_reg;
    MemoryRegion memory;
    MemoryRegion sysmem;
    uint32_t cpu_id;
    uint32_t phys_id;
    uint64_t mpidr;
    A9_CPREG_VAR_DEF(ARM64_REG_EHID4);
    A9_CPREG_VAR_DEF(ARM64_REG_EHID10);
    A9_CPREG_VAR_DEF(ARM64_REG_HID0);
    A9_CPREG_VAR_DEF(ARM64_REG_HID3);
    A9_CPREG_VAR_DEF(ARM64_REG_HID4);
    A9_CPREG_VAR_DEF(ARM64_REG_HID5);
    A9_CPREG_VAR_DEF(ARM64_REG_HID7);
    A9_CPREG_VAR_DEF(ARM64_REG_HID8);
    A9_CPREG_VAR_DEF(ARM64_REG_HID9);
    A9_CPREG_VAR_DEF(ARM64_REG_HID11);
    A9_CPREG_VAR_DEF(ARM64_REG_HID13);
    A9_CPREG_VAR_DEF(ARM64_REG_HID14);
    A9_CPREG_VAR_DEF(ARM64_REG_HID16);
    A9_CPREG_VAR_DEF(ARM64_REG_LSU_ERR_STS);
    A9_CPREG_VAR_DEF(PMC0);
    A9_CPREG_VAR_DEF(PMC1);
    A9_CPREG_VAR_DEF(PMCR1);
    A9_CPREG_VAR_DEF(PMSR);
    A9_CPREG_VAR_DEF(ARM64_REG_APCTL_EL1);
    A9_CPREG_VAR_DEF(S3_4_c15_c0_5);
    A9_CPREG_VAR_DEF(ARM64_REG_CYC_OVRD);
    A9_CPREG_VAR_DEF(ARM64_REG_ACC_CFG);
    A9_CPREG_VAR_DEF(S3_5_c15_c10_1);
    /* uncore */
    A9_CPREG_VAR_DEF(UPMPCM);
    A9_CPREG_VAR_DEF(UPMCR0);
    A9_CPREG_VAR_DEF(UPMSR);
} AppleA9State;

AppleA9State *apple_a9_create(DTBNode *node);
bool apple_a9_is_sleep(AppleA9State *tcpu);
void apple_a9_wakeup(AppleA9State *tcpu);
#endif /* HW_ARM_APPLE_A9_H */
