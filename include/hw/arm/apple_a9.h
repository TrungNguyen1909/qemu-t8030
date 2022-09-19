#ifndef HW_ARM_APPLE_A9_H
#define HW_ARM_APPLE_A9_H

#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/hwaddr.h"
#include "qemu/queue.h"
#include "hw/arm/xnu_dtb.h"
#include "hw/cpu/cluster.h"

#define A9_MAX_CPU 2

#define TYPE_APPLE_A9 "apple-a9-cpu"
OBJECT_DECLARE_TYPE(AppleA9State, AppleA9Class, APPLE_A9)

#define A9_CPREG_VAR_NAME(name) cpreg_##name
#define A9_CPREG_VAR_DEF(name) uint64_t A9_CPREG_VAR_NAME(name)

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
    A9_CPREG_VAR_DEF(HID11);
    A9_CPREG_VAR_DEF(HID4);
    A9_CPREG_VAR_DEF(HID5);
    A9_CPREG_VAR_DEF(HID7);
    A9_CPREG_VAR_DEF(HID8);
    A9_CPREG_VAR_DEF(PMCR0);
    A9_CPREG_VAR_DEF(PMCR1);
    A9_CPREG_VAR_DEF(PMCR2);
    A9_CPREG_VAR_DEF(PMCR3);
    A9_CPREG_VAR_DEF(PMCR4);
    A9_CPREG_VAR_DEF(PMESR0);
    A9_CPREG_VAR_DEF(PMESR1);
    A9_CPREG_VAR_DEF(OPMAT0);
    A9_CPREG_VAR_DEF(OPMAT1);
    A9_CPREG_VAR_DEF(OPMSK0);
    A9_CPREG_VAR_DEF(OPMSK1);
    A9_CPREG_VAR_DEF(PMSR);
    A9_CPREG_VAR_DEF(PMTRHLD6);
    A9_CPREG_VAR_DEF(PMTRHLD4);
    A9_CPREG_VAR_DEF(PMTRHLD2);
    A9_CPREG_VAR_DEF(PMMMAP);
    A9_CPREG_VAR_DEF(LSU_ERR_STS);
    A9_CPREG_VAR_DEF(LSU_ERR_ADR);
    A9_CPREG_VAR_DEF(L2C_ERR_INF);
    A9_CPREG_VAR_DEF(FED_ERR_STS);
    A9_CPREG_VAR_DEF(CYC_CFG);
    A9_CPREG_VAR_DEF(MMU_ERR_STS);
} AppleA9State;

AppleA9State *apple_a9_create(DTBNode *node);
bool apple_a9_is_sleep(AppleA9State *tcpu);
void apple_a9_wakeup(AppleA9State *tcpu);
#endif /* HW_ARM_APPLE_A9_H */
