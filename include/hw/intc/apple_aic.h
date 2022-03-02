#ifndef APPLE_AIC_H
#define APPLE_AIC_H

#include "hw/sysbus.h"
#include "qom/object.h"
#include "hw/arm/xnu_dtb.h"

#define TYPE_APPLE_AIC "apple.aic"
OBJECT_DECLARE_SIMPLE_TYPE(AppleAICState, APPLE_AIC)

#define AIC_DEBUG_NEW_IRQ

typedef struct AppleAICState AppleAICState;

typedef struct  {
    AppleAICState *aic;
    qemu_irq irq;
    MemoryRegion iomem;
    uint32_t cpu_id;
    uint32_t pendingIPI;
    uint32_t deferredIPI;
    uint32_t ipi_mask;
} AppleAICCPU;

struct AppleAICState {
    SysBusDevice parent_obj;
    QEMUTimer *timer;
    QemuMutex mutex;
    uint32_t phandle;
    uint32_t base_size;
    uint32_t numEIR;
    uint32_t numIRQ;
    uint32_t numCPU;
    uint32_t global_cfg;
    uint32_t time_base;
    uint32_t *eir_mask;
    uint32_t *eir_dest;
    AppleAICCPU *cpus;
    uint32_t *eir_state;
#ifdef AIC_DEBUG_NEW_IRQ
    uint32_t *eir_mask_once;
#endif
};


SysBusDevice *apple_aic_create(uint32_t numCPU, DTBNode *node,
                               DTBNode *timebase_node);

#endif /* APPLE_AIC_H */
