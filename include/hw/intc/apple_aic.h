#ifndef APPLE_AIC_H
#define APPLE_AIC_H

#include "hw/sysbus.h"
#include "qom/object.h"
#include "hw/arm/xnu_dtb.h"

#define TYPE_APPLE_AIC "apple.aic"
OBJECT_DECLARE_SIMPLE_TYPE(AppleAICState, APPLE_AIC)

#define AIC_DEBUG_NEW_IRQ

/*
 * AIC splits IRQs into domains (ipid)
 * In T8030 device tree, we have aic->ipid_length = 72
 * => IRQ(extInts) max nr = ((len(ipid_mask)>>2)<<5) = 0x240 (interrupts)
 * -> num domains = (0x240 + 31)>>5 = 18 (domains)
 * 0x240/18 = 32 (bits) of an uint32_t
 *
 * Commands such as rAIC_EIR_MASK_SET/CLR assign each domain to a 32bit register.
 * When masking/unmasking-ing IRQ n,
 * write to (aic_base + command_reg_base + (n / 32) * 4)
 *          a uint32_t which has (n % 32)-th bit set,
 * command_reg_base is 0x4100 for rAIC_EIR_MASK_SET, 0x4180 for rAIC_EIR_MASK_CLR.
 *
 * T8030 uses both fast IPI, and AIC IPIs.
 * AIC IPIs' vectors are right after IRQs' vectors.
 * num IRQ + (X * 2) -> self_ipi (cpuX->cpuX)
 * num IRQ + (Y * 2) + 1 -> other_ipi (cpuX->cpuY)
 */

//TODO: this is hardcoded for T8030
#define AIC_INT_COUNT   (576)
#define AIC_CPU_COUNT   (6)
#define AIC_VERSION     (2)

#define rAIC_REV                    (0x0000)
#define rAIC_CAP0                   (0x0004)
#define rAIC_CAP1                   (0x0008)
#define rAIC_RST                    (0x000C)

#define rAIC_GLB_CFG                (0x0010)
#define     AIC_GLBCFG_IEN          (1 << 0)
#define     AIC_GLBCFG_AEWT(_t)     ((_t) << 4)
#define     AIC_GLBCFG_SEWT(_t)     ((_t) << 8)
#define     AIC_GLBCFG_AIWT(_t)     ((_t) << 12)
#define     AIC_GLBCFG_SIWT(_t)     ((_t) << 16)
#define     AIC_GLBCFG_SYNC_ACG     (1 << 29)
#define     AIC_GLBCFG_EIR_ACG      (1 << 30)
#define     AIC_GLBCFG_REG_ACG      (1 << 31)
#define     AIC_GLBCFG_WT_MASK      (15)
#define     AIC_GLBCFG_WT_64MICRO   (7)

#define rAIC_WHOAMI                 (0x2000)
#define rAIC_IACK                   (0x2004)
#define rAIC_IPI_SET                (0x2008)
#define rAIC_IPI_CLR                (0x200C)
#define     AIC_IPI_NORMAL          (1 << 0)
#define     AIC_IPI_SELF            (1 << 31)
#define rAIC_IPI_MASK_SET           (0x2024)
#define rAIC_IPI_MASK_CLR           (0x2028)
#define rAIC_IPI_DEFER_SET          (0x202C)
#define rAIC_IPI_DEFER_CLR          (0x2030)

#define rAIC_EIR_DEST(_n)           (0x3000 + ((_n) * 4))
#define rAIC_EIR_SW_SET(_n)         (0x4000 + ((_n) * 4))
#define rAIC_EIR_SW_CLR(_n)         (0x4080 + ((_n) * 4))
#define rAIC_EIR_MASK_SET(_n)       (0x4100 + ((_n) * 4))
#define rAIC_EIR_MASK_CLR(_n)       (0x4180 + ((_n) * 4))
#define rAIC_EIR_INT_RO(_n)         (0x4200 + ((_n) * 4))

#define rAIC_WHOAMI_Pn(_n)          (0x5000 + ((_n) * 0x80))
#define rAIC_IACK_Pn(_n)            (0x5004 + ((_n) * 0x80))
#define rAIC_IPI_SET_Pn(_n)         (0x5008 + ((_n) * 0x80))
#define rAIC_IPI_CLR_Pn(_n)         (0x500C + ((_n) * 0x80))
#define rAIC_IPI_MASK_SET_Pn(_n)    (0x5024 + ((_n) * 0x80))
#define rAIC_IPI_MASK_CLR_Pn(_n)    (0x5028 + ((_n) * 0x80))
#define rAIC_IPI_DEFER_SET_Pn(_n)   (0x502C + ((_n) * 0x80))
#define rAIC_IPI_DEFER_CLR_Pn(_n)   (0x5030 + ((_n) * 0x80))

#define kAIC_INT_SPURIOUS       (0x00000)
#define kAIC_INT_EXT            (0x10000)
#define kAIC_INT_IPI            (0x40000)
#define kAIC_INT_IPI_NORM       (0x40001)
#define kAIC_INT_IPI_SELF       (0x40002)

#define AIC_INT_EXT(_v)         (((_v) & 0x70000) == kAIC_INT_EXT)
#define AIC_INT_IPI(_v)         (((_v) & 0x70000) == kAIC_INT_IPI)

#define AIC_INT_EXTID(_v)       ((_v) & 0x3FF)

#define AIC_SRC_TO_EIR(_s)      ((_s) >> 5)
#define AIC_SRC_TO_MASK(_s)     (1 << ((_s) & 0x1F))
#define AIC_EIR_TO_SRC(_s, _v)  (((_s) << 5) + ((_v) & 0x1F))

#define kAIC_MAX_EXTID          (AIC_INT_COUNT)
#define kAIC_VEC_IPI            (kAIC_MAX_EXTID)
#define kAIC_NUM_INTS           (kAIC_VEC_IPI + 1)

#define kAIC_NUM_EIRS           AIC_SRC_TO_EIR(kAIC_MAX_EXTID)

#define kAICWT 64000

typedef struct  {
    void *aic;
    qemu_irq irq;
    MemoryRegion iomem;
    unsigned int cpu_id;
    uint32_t pendingIPI;
    uint32_t deferredIPI;
    uint32_t ipi_mask;
} AppleAICOpaque;

struct AppleAICState {
    SysBusDevice parent_obj;
    QEMUTimer *timer;
    QemuMutex mutex;
    uint32_t phandle;
    uint32_t base_size;
    size_t numEIR;
    size_t numIRQ;
    size_t numCPU;
    uint32_t *eir_mask;
    uint32_t *eir_dest;
    AppleAICOpaque *cpus;
    uint32_t *eir_state;
    uint32_t global_cfg;
#ifdef AIC_DEBUG_NEW_IRQ
    uint32_t *eir_mask_once;
#endif
};


SysBusDevice *apple_aic_create(unsigned int numCPU, DTBNode *node);

#endif /* APPLE_AIC_H */
