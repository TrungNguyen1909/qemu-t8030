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
AppleInterruptController::start
v22 = this->vtable->AppleInterruptController._readReg32(this, 4u) & 0x3FF;
this->AppleInterruptController._aicNumExtInts = v22;
v23 = (v22 + 31) >> 5;
this->AppleInterruptController._aicNumIPID = v23;
if ( v11 != 4 * v23 )
    panic(
    "\"AppleInterruptController::start: device tree ipid-mask property length is %d but should be %d\"",
    v11,
    (4 * v23));
}

In t8030, we have ipid_length = 72
=> IRQ(extInts) max nr = 0x240 -> max num IPID = (0x240 + 31)>>5 = 18 (domains)
conviniently, 0x240/18 = 32 (bits)
*/ 

// ((len(ipid_mask)>>2)<<5)
#define kDeferredIPITimerDefault 1536

/*
Apparently, t8030 uses fast IPI on p-core, which does not rely on AIC but cluster to do IPIs
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