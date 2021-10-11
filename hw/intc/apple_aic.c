#include "qemu/osdep.h"
#include "hw/intc/apple_aic.h"
#include "trace.h"
#include "hw/irq.h"
#include "migration/vmstate.h"
#include "qemu/bitops.h"
#include "qemu/lockable.h"
#include "qemu/log.h"
#include "qemu/module.h"
#include "qemu/timer.h"
#include "hw/arm/xnu_dtb.h"
#include "hw/pci/msi.h"

/*
 * Check state and interrupt cpus, call with mutex locked
 */
static void apple_aic_update(AppleAICState *s)
{
    uint32_t intr = 0;
    uint32_t potential = 0;
    int i;

    for (i = 0; i < s->numCPU; i++) {
        s->cpus[i].pendingIPI |= s->cpus[i].deferredIPI;
        s->cpus[i].deferredIPI = 0;
    }

    for (i = 0; i < s->numCPU; i++) {
        if (s->cpus[i].pendingIPI & (~s->cpus[i].ipi_mask)) {
            intr |= (1 << i);
        }
    }

    i = -1;
    while ((i = find_next_bit((unsigned long *)s->eir_state, s->numIRQ, i+1))
            < s->numIRQ) {
        int dest;
        if ((test_bit(i, (unsigned long *)s->eir_mask) == 0)
            && (dest = s->eir_dest[i])) {
            if (((intr & dest) == 0)) {
                /* The interrupt doesn't have a cpu that can process it yet */
                uint32_t cpu = find_first_bit((unsigned long *)&s->eir_dest[i],
                                                s->numCPU);
                intr |= (1 << cpu);
                potential |= dest;
            } else {
                int k;
                for (k = 0; k < s->numCPU; k++) {
                    if (((intr & (1 << k)) == 0) && (potential & (1 << k))) {
                        /* 
                         * cpu K isn't in the interrupt list
                         * and can handle some of the previous interrupts
                         */
                        intr |= (1 << k);
                        break;
                    }
                }
            }
        }     
    }
    for (i = 0; i < s->numCPU; i++) {
        if (intr & (1 << i)) {
            qemu_irq_raise(s->cpus[i].irq);
        }
    }
}

static void apple_aic_set_irq(void *opaque, int irq, int level)
{
    AppleAICState *s = APPLE_AIC(opaque);

    WITH_QEMU_LOCK_GUARD(&s->mutex) {
        trace_aic_set_irq(irq, level);
        if (level) {
            set_bit(irq, (unsigned long *)s->eir_state);
        } else {
            clear_bit(irq, (unsigned long *)s->eir_state);
        }
    }
}

static void apple_aic_tick(void *opaque)
{
    AppleAICState *s = APPLE_AIC(opaque);

    WITH_QEMU_LOCK_GUARD(&s->mutex) {
        apple_aic_update(s);
    }

    timer_mod_ns(s->timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + kAICWT);
}

static void apple_aic_reset(DeviceState *dev)
{
    int i;
    AppleAICState *s = APPLE_AIC(dev);

    /* mask all IRQs */
    memset(s->eir_mask, 0xffff, sizeof(uint32_t) * s->numEIR);

#ifdef AIC_DEBUG_NEW_IRQ
    memset(s->eir_mask_once, 0xffff, sizeof(uint32_t) * s->numEIR);
#endif

    /* dest default to 0 */
    memset(s->eir_dest, 0, sizeof(uint32_t) * s->numIRQ);

    for (i = 0; i < s->numCPU; i++) {
        /* mask all IPI */
        s->cpus[i].ipi_mask = AIC_IPI_NORMAL | AIC_IPI_SELF;
        s->cpus[i].pendingIPI = 0;
        s->cpus[i].deferredIPI = 0;
    }
}

static void apple_aic_write(void *opaque, hwaddr addr, uint64_t data,
                            unsigned size)
{
    AppleAICCPU *o = (AppleAICCPU *)opaque;
    AppleAICState *s = APPLE_AIC(o->aic);
    uint32_t val = (uint32_t)data;

    WITH_QEMU_LOCK_GUARD(&s->mutex) {
        switch (addr) {
        case rAIC_RST:
            apple_aic_reset(DEVICE(s));
            break;

        case rAIC_GLB_CFG:
            s->global_cfg = data;
            break;

        case rAIC_IPI_SET:
            {
                int i;

                for (i = 0; i < s->numCPU; i++) {
                    if (val & (1 << i)) {
                        set_bit(o->cpu_id, (unsigned long *)&s->cpus[i].pendingIPI);
                        if (~s->cpus[i].ipi_mask & AIC_IPI_NORMAL) {
                            qemu_irq_raise(s->cpus[i].irq);
                        }
                    }
                }

                if (val & AIC_IPI_SELF) {
                    set_bit(AIC_IPI_SELF, (unsigned long *)&o->pendingIPI);
                    if (~o->ipi_mask & AIC_IPI_SELF) {
                        qemu_irq_raise(o->irq);
                    }
                }
            }
            break;

        case rAIC_IPI_CLR:
            {
                int i;

                for (i = 0; i < s->numCPU; i++) {
                    if (val & (1 << i)) {
                        clear_bit(o->cpu_id, (unsigned long *)&s->cpus[i].pendingIPI);
                    }
                }

                if (val & AIC_IPI_SELF) {
                    clear_bit(AIC_IPI_SELF, (unsigned long *)&o->pendingIPI);
                }
            }
            break;

        case rAIC_IPI_MASK_SET:
            o->ipi_mask |= (val & (AIC_IPI_NORMAL | AIC_IPI_SELF));
            break;

        case rAIC_IPI_MASK_CLR:
            o->ipi_mask &= ~(val & (AIC_IPI_NORMAL | AIC_IPI_SELF));
            break;

        case rAIC_IPI_DEFER_SET:
            {
                int i;

                for (i = 0; i < s->numCPU; i++) {
                    if (val & (1 << i)) {
                        set_bit(o->cpu_id, (unsigned long *)&s->cpus[i].deferredIPI);
                    }
                }

                if (val & AIC_IPI_SELF) {
                    set_bit(AIC_IPI_SELF, (unsigned long *)&o->deferredIPI);
                }
            }
            break;

        case rAIC_IPI_DEFER_CLR:
            {
                int i;

                for (i = 0; i < s->numCPU; i++) {
                    if (val & (1 << i)) {
                        clear_bit(o->cpu_id, (unsigned long *)&s->cpus[i].deferredIPI);
                    }
                }

                if (val & AIC_IPI_SELF) {
                    clear_bit(AIC_IPI_SELF, (unsigned long *)&o->deferredIPI);
                }
            }
            break;

        case rAIC_EIR_DEST(0) ... rAIC_EIR_DEST(AIC_INT_COUNT):
            {
                uint32_t vector = (addr - rAIC_EIR_DEST(0)) / 4;
                if (unlikely(vector >= s->numIRQ)) {
                    break;
                }
                s->eir_dest[vector] = val;
            }
            break;

        case rAIC_EIR_SW_SET(0) ... rAIC_EIR_SW_SET(kAIC_NUM_EIRS):
            {
                uint32_t eir = (addr - rAIC_EIR_SW_SET(0)) / 4;
                if (unlikely(eir >= s->numEIR)) {
                    break;
                }
                s->eir_state[eir] |= val;
            }
            break;

        case rAIC_EIR_SW_CLR(0) ... rAIC_EIR_SW_CLR(kAIC_NUM_EIRS):
            {
                uint32_t eir = (addr - rAIC_EIR_SW_CLR(0)) / 4;
                if (unlikely(eir >= s->numEIR)) {
                    break;
                }
                s->eir_state[eir] &= ~val;
            }
            break;

        case rAIC_EIR_MASK_SET(0) ... rAIC_EIR_MASK_SET(kAIC_NUM_EIRS):
            {
                uint32_t eir = (addr - rAIC_EIR_MASK_SET(0)) / 4;
                if (unlikely(eir >= s->numEIR)) {
                    break;
                }
                s->eir_mask[eir] |= val;
            }
            break;

        case rAIC_EIR_MASK_CLR(0) ... rAIC_EIR_MASK_CLR(kAIC_NUM_EIRS):
            {
                uint32_t eir = (addr - rAIC_EIR_MASK_CLR(0)) / 4;

                if (unlikely(eir >= s->numEIR)) {
                    break;
                }

                s->eir_mask[eir] &= ~val;

#ifdef AIC_DEBUG_NEW_IRQ
                if ((s->eir_mask[eir] | s->eir_mask_once[eir]) != s->eir_mask[eir]) {
                    for (int i = 0; i < 32; i++) {
                        if ((s->eir_mask[eir] & (1 << i)) == 0 && (s->eir_mask_once[eir] & (1 << i)) != 0) {
                            trace_aic_new_irq(AIC_EIR_TO_SRC(eir, i));
                        }
                    }
                }
                s->eir_mask_once[eir] = s->eir_mask[eir];
#endif
            }
            break;

        case rAIC_WHOAMI_Pn(0) ... rAIC_WHOAMI_Pn(AIC_CPU_COUNT) - 4:
            {
                uint32_t cpu = (addr - 0x5000) / 0x80;
                if (unlikely(cpu > s->numCPU)) {
                    break;
                }
                addr = addr - 0x5000 + 0x2000;
                qemu_mutex_unlock(&s->mutex);
                apple_aic_write(&s->cpus[cpu], addr, data, size);
                qemu_mutex_lock(&s->mutex);
            }
            break;

        default:
            qemu_log_mask(LOG_UNIMP, "AIC: Write to unspported reg 0x" TARGET_FMT_plx
                        " cpu %u\n", addr, o->cpu_id);
            break;
        }
    }
}

static uint64_t apple_aic_read(void *opaque, hwaddr addr, unsigned size)
{
    AppleAICCPU *o = (AppleAICCPU *)opaque;
    AppleAICState *s = APPLE_AIC(o->aic);

    WITH_QEMU_LOCK_GUARD(&s->mutex) {
        switch (addr) {
        case rAIC_REV:
            return 2;

        case rAIC_CAP0:
            return (((uint64_t)s->numCPU - 1) << 16) | (s->numIRQ);

        case rAIC_GLB_CFG:
            return s->global_cfg;

        case rAIC_WHOAMI:
            return o->cpu_id;

        case rAIC_IACK:
            {
                int i;

                qemu_irq_lower(o->irq);
                if (o->pendingIPI & AIC_IPI_SELF & ~o->ipi_mask) {
                    o->ipi_mask |= kAIC_INT_IPI_SELF;
                    return kAIC_INT_IPI | kAIC_INT_IPI_SELF;
                }

                if (~o->ipi_mask & AIC_IPI_NORMAL) {

                    for (i = 0; i < s->numCPU; i++) {
                        if (o->pendingIPI & (1 << i)) {
                            o->ipi_mask |= kAIC_INT_IPI_NORM;
                            return kAIC_INT_IPI | kAIC_INT_IPI_NORM;
                        }
                    }
                }

                i = -1;
                while ((i = find_next_bit((unsigned long *)s->eir_state,
                                         s->numIRQ, i+1)) < s->numIRQ) {
                    if (test_bit(i, (unsigned long *)s->eir_mask) == 0) {
                        if (s->eir_dest[i] & (1 << o->cpu_id)) {
                                set_bit(i, (unsigned long *)s->eir_mask);
                                return kAIC_INT_EXT | AIC_INT_EXTID(i);
                        }
                    }
                }
                return kAIC_INT_SPURIOUS;
            }

        case rAIC_EIR_DEST(0) ... rAIC_EIR_DEST(AIC_INT_COUNT):
            {
                uint32_t vector = (addr - rAIC_EIR_DEST(0)) / 4;

                if (unlikely(vector >= s->numIRQ)) {
                    break;
                }

                return s->eir_dest[vector];
            }

        case rAIC_EIR_MASK_SET(0) ... rAIC_EIR_MASK_SET(kAIC_NUM_EIRS):
            {
                uint32_t eir = (addr - rAIC_EIR_MASK_SET(0)) / 4;

                if (unlikely(eir >= s->numEIR)) {
                    break;
                }

                return s->eir_mask[eir];
            }

        case rAIC_EIR_MASK_CLR(0) ... rAIC_EIR_MASK_CLR(kAIC_NUM_EIRS):
            {
                uint32_t eir = (addr - rAIC_EIR_MASK_CLR(0)) / 4;

                if (unlikely(eir >= s->numEIR)) {
                    break;
                }

                return s->eir_mask[eir];
            }

        case rAIC_EIR_INT_RO(0) ... rAIC_EIR_INT_RO(kAIC_NUM_EIRS):
            {
                uint32_t eir = (addr - rAIC_EIR_INT_RO(0)) / 4;

                if (unlikely(eir >= s->numEIR)) {
                    break;
                }
                return s->eir_state[eir];
            }

        case rAIC_WHOAMI_Pn(0) ... rAIC_WHOAMI_Pn(AIC_CPU_COUNT) - 4:
            {
                uint32_t cpu = (addr - 0x5000) / 0x80;
                uint64_t val;

                if (unlikely(cpu > s->numCPU)) {
                    break;
                }

                addr = addr - 0x5000 + 0x2000;
                qemu_mutex_unlock(&s->mutex);

                val = apple_aic_read(&s->cpus[cpu], addr, size);
                qemu_mutex_lock(&s->mutex);
                return val;
            }
        default:
            qemu_log_mask(LOG_UNIMP,
                          "AIC: Read from unspported reg 0x" TARGET_FMT_plx
                          " cpu: %u\n", addr, o->cpu_id);
        }
    }
    return -1;
}

static const MemoryRegionOps apple_aic_ops = {
    .read = apple_aic_read,
    .write = apple_aic_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .impl.min_access_size = 4,
    .impl.max_access_size = 4,
    .valid.min_access_size = 4,
    .valid.max_access_size = 4,
    .valid.unaligned = false,
};

static void apple_aic_realize(DeviceState *dev, struct Error **errp)
{
    AppleAICState *s = APPLE_AIC(dev);
    SysBusDevice *sbd = SYS_BUS_DEVICE(dev);
    int i;

    qemu_mutex_init(&s->mutex);
    s->cpus = g_new0(AppleAICCPU, s->numCPU);

    for (i = 0; i < s->numCPU; i++) {
        AppleAICCPU *cpu = &s->cpus[i];

        cpu->aic = s;
        cpu->cpu_id = i;
        memory_region_init_io(&cpu->iomem, OBJECT(dev), &apple_aic_ops, cpu,
                              TYPE_APPLE_AIC, s->base_size);
        sysbus_init_mmio(sbd, &cpu->iomem);
        sysbus_init_irq(sbd, &cpu->irq);
    }

    qdev_init_gpio_in(dev, apple_aic_set_irq, s->numIRQ);

    assert(s->numCPU > 0);

    s->eir_mask = g_new0(uint32_t, s->numEIR);
    s->eir_dest = g_new0(uint32_t, s->numIRQ);
    s->eir_state = g_new0(uint32_t, s->numEIR);

#ifdef AIC_DEBUG_NEW_IRQ
    s->eir_mask_once = g_new0(uint32_t, s->numEIR);
#endif

    s->timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, apple_aic_tick, dev);
    timer_mod_ns(s->timer, kAICWT);
    msi_nonbroken = true;
}

static void apple_aic_unrealize(DeviceState *dev)
{
    AppleAICState *s = APPLE_AIC(dev);
    timer_free(s->timer);
}

SysBusDevice *apple_aic_create(uint32_t numCPU, DTBNode *node)
{
    DeviceState  *dev;
    AppleAICState *s;
    DTBProp *prop;
    hwaddr *reg;

    dev = qdev_new(TYPE_APPLE_AIC);
    s = APPLE_AIC(dev);
    prop = find_dtb_prop(node, "AAPL,phandle");
    assert(prop);
    s->phandle = *(uint32_t *)prop->value;
    prop = find_dtb_prop(node, "reg");
    assert(prop != NULL);
    reg = (hwaddr *)prop->value;
    s->base_size = reg[1];
    prop = find_dtb_prop(node, "ipid-mask");
    s->numEIR = prop->length / 4;
    s->numIRQ = s->numEIR * 32;

    s->numCPU = numCPU;
    set_dtb_prop(node, "#main-cpus", 4, (uint8_t *)&s->numCPU);

    prop = find_dtb_prop(node, "#shared-timestamps");
    assert(prop);
    assert(prop->length == 4);
    *(uint32_t *)prop->value = 0;

    return SYS_BUS_DEVICE(dev);
}

static const VMStateDescription vmstate_apple_aic_cpu = {
    .name = "apple_aic_cpu",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (VMStateField[]) {
        VMSTATE_UINT32(cpu_id, AppleAICCPU),
        VMSTATE_UINT32(pendingIPI, AppleAICCPU),
        VMSTATE_UINT32(deferredIPI, AppleAICCPU),
        VMSTATE_UINT32(ipi_mask, AppleAICCPU),
        VMSTATE_END_OF_LIST()
    }
};

static const VMStateDescription vmstate_apple_aic = {
    .name = "apple_aic",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (VMStateField[]) {
        VMSTATE_UINT32(numEIR, AppleAICState),
        VMSTATE_UINT32(numIRQ, AppleAICState),
        VMSTATE_UINT32(numCPU, AppleAICState),
        VMSTATE_UINT32(global_cfg, AppleAICState),
        VMSTATE_VARRAY_UINT32(eir_mask, AppleAICState, numEIR, 1,
                              vmstate_info_uint32, uint32_t),
        VMSTATE_VARRAY_UINT32(eir_dest, AppleAICState, numIRQ, 1,
                              vmstate_info_uint32, uint32_t),
        VMSTATE_VARRAY_UINT32(eir_state, AppleAICState, numEIR, 1,
                              vmstate_info_uint32, uint32_t),
#ifdef AIC_DEBUG_NEW_IRQ
        VMSTATE_VARRAY_UINT32(eir_mask_once, AppleAICState, numEIR, 1,
                              vmstate_info_uint32, uint32_t),
#endif
        VMSTATE_STRUCT_VARRAY_POINTER_UINT32(cpus, AppleAICState, numCPU,
                                             vmstate_apple_aic_cpu,
                                             AppleAICCPU),

        VMSTATE_END_OF_LIST()
    }
};

static void apple_aic_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->realize = apple_aic_realize;
    dc->unrealize = apple_aic_unrealize;
    dc->reset = apple_aic_reset;
    dc->desc = "Apple Interrupt Controller";
    dc->vmsd = &vmstate_apple_aic;
}

static const TypeInfo apple_aic_info = {
    .name = TYPE_APPLE_AIC,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(AppleAICState),
    .class_init = apple_aic_class_init,
};

static void apple_aic_register_types(void)
{
    type_register_static(&apple_aic_info);
}

type_init(apple_aic_register_types);
