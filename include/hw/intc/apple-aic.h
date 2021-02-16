#ifndef APPLE_AIC_H
#define APPLE_AIC_H

#include "hw/sysbus.h"
#include "qom/object.h"
#include "hw/arm/xnu_dtb.h"

#define TYPE_APPLE_AIC "apple.aic"
OBJECT_DECLARE_SIMPLE_TYPE(AppleAICState, APPLE_AIC)

#define REG_ID_REVISION                 0x0000
#define REG_ID_CONFIG                   0x0004
#define REG_GLOBAL_CFG                  0x0010
#define REG_TIME_LO                     0x0020
#define REG_TIME_HI                     0x0028
#define REG_ID_CPUID                    0x2000
#define REG_ACK                     0x2004
#define  REG_ACK_TYPE_MASK          (15 << 16)
#define   REG_ACK_TYPE_NONE         (0 << 16)
#define   REG_ACK_TYPE_IRQ          (1 << 16)
#define   REG_ACK_TYPE_IPI          (4 << 16)
#define    REG_ACK_IPI_OTHER        0x40001
#define    REG_ACK_IPI_SELF         0x40002
#define  REG_ACK_NUM_MASK           (4095)

#define REG_IPI_SET                     0x2008
#define   REG_IPI_FLAG_SELF             (1 << 31)
#define   REG_IPI_FLAG_OTHER            (1 << 0)
#define REG_IPI_CLEAR                   0x200C
#define REG_IPI_DEFER_SET               0x202C
#define REG_IPI_DEFER_CLEAR             0x2030

#define REG_IPI_DISABLE                 0x0024
#define REG_IPI_ENABLE                  0x0028

#define REG_TSTAMP_CTRL                 0x2040
#define REG_TSTAMP_LO                   0x2048
#define REG_TSTAMP_HI                   0x204C

#define REG_TSTAMP(i)					(0x6000 + ((i) << 4))

#define REG_IRQ_AFFINITY(i)             (0x3000 + ((i) << 2))
#define REG_IRQ_DISABLE(i)              (0x4100 + (((i) >> 5) << 2))
#define  REG_IRQ_xABLE_MASK(i)          (1 << ((i) & 31))
#define REG_IRQ_ENABLE(i)               (0x4180 + (((i) >> 5) << 2))
#define REG_IRQ_STAT(i)               	(0x4200 + (((i) >> 5) << 2))
#define REG_CPU_REGION                  0x5000
#define  REG_CPU_LOCAL                  0x2000
#define  REG_CPU_SHIFT                  7
#define  REG_PERCPU(r,c)                ((r)+REG_CPU_REGION+((c)<<REG_CPU_SHIFT))

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

#define kDeferredIPITimerDefault 1536

typedef struct  {
    void *aic;
    unsigned int cpu_id;
    unsigned int interrupted;
    unsigned int ack;
    unsigned int is_ipi;
    unsigned int ipi_source;
    
    unsigned int irq_source;
} AppleAICOpaque;

struct AppleAICState {
    SysBusDevice parent_obj;
    //reg region per cpu
    MemoryRegion** iomems;
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
    unsigned int *ipid_mask;
    //whether IPI i is disabled (bit 31 set: self masked, bit 0 set: other masked)
    unsigned int *ipi_mask;
    //for IRQ i, if bit x is set, that IRQ should be sent to cpu x (there might be multiple bits set)
    unsigned int *irq_affinity;
    //cpu opaques
    AppleAICOpaque** cpus;
    //cpu irqs
    qemu_irq *cpu_irqs;
    //ext irqs state
    bool *ext_irq_state;
    //pending IPIs: 1: set; 0: unset
    bool **pendingIPI;
    //deferred IPIs: 1: set; 0: unset
    bool **deferredIPI;
    //global cfg
    unsigned int global_cfg;
    //tick counter
    unsigned long tick;
    
};


AppleAICState* apple_aic_create(hwaddr soc_base, unsigned int numCPU, DTBNode* node);

#endif /* APPLE_AIC_H */