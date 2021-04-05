#ifndef APPLE_AIC_H
#define APPLE_AIC_H

#include "hw/sysbus.h"
#include "qom/object.h"
#include "hw/arm/xnu_dtb.h"

#define TYPE_APPLE_AIC "apple.aic"
OBJECT_DECLARE_SIMPLE_TYPE(AppleAICState, APPLE_AIC)

/*
AIC splits IRQs into domains (ipid)
In T8030 device tree, we have aic->ipid_length = 72
=> IRQ(extInts) max nr = ((len(ipid_mask)>>2)<<5) = 0x240 (interrupts)
-> num domains = (0x240 + 31)>>5 = 18 (domains)
0x240/18 = 32 (bits) of an uint32_t

Commands such as REG_IRQ_DISABLE/ENABLE assign each domain to a 32bit register.
When disable/enable-ing IRQ (i.e: n),
you write to (aic_base + command_reg_base + (n / 32)) a uint32_t which has (n % 32)-th bit set,
command_reg_base is 0x4100 for REG_IRQ_DISABLE, 0x4180 for REG_IRQ_ENABLE.

T8030 uses both fast IPI, and AIC IPIs.
AIC IPIs' vectors are right after IRQs' vectors.
num IRQ + (cpu_id * 2) -> self_ipi (cpuX->cpuX)
num IRQ + (cpu_id * 2) + 1 -> other_ipi (cpuX->cpuY)
*/ 

typedef enum {
    //CPU not in AppleInterruptController::handleInterrupt loop
    AIC_CPU_STATE_NONE = 0,
    //CPU is/will be in ::handleInterrupt loop
    AIC_CPU_STATE_PROCESSING,
} AICCpuState;

typedef struct  {
    void *aic;
    unsigned int cpu_id;
    unsigned int state;
    unsigned int ack;
    unsigned int is_ipi;
    unsigned int ipi_source;
    
    unsigned int irq_source;
} AppleAICOpaque;

struct AppleAICState {
    DeviceState parent_obj;
    //reg region per cpu
    MemoryRegion* iomems;
    //timer
    QEMUTimer* timer;
    //mutex
    QemuMutex mutex;
    //reg base address
    hwaddr base;
    unsigned long base_size;
    size_t numIPID;
    size_t numIRQ;
    size_t numCPU;
    //mask of IRQ in domains of 32
    uint32_t *ipid_mask;
    //whether IPI i is disabled (bit 31 set: self masked, bit 0 set: other masked)
    uint32_t *ipi_mask;
    //for IRQ i, if bit x is set, that IRQ should be sent to cpu x (there might be multiple bits set)
    uint32_t *irq_affinity;
    //cpu opaques
    AppleAICOpaque* cpus;
    //cpu irqs
    qemu_irq *cpu_irqs;
    //ext irqs state
    bool *ext_irq_state;
    //pending IPIs: 1: set; 0: unset
    bool **pendingIPI;
    //deferred IPIs: 1: set; 0: unset
    bool **deferredIPI;
    //global cfg
    uint32_t global_cfg;
    //tick counter
    unsigned long tick;
    
};


AppleAICState* apple_aic_create(hwaddr soc_base, unsigned int numCPU, DTBNode* node);

#endif /* APPLE_AIC_H */