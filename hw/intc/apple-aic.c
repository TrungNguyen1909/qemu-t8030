#include "qemu/osdep.h"
#include "hw/intc/apple-aic.h"
#include "hw/irq.h"
#include "migration/vmstate.h"
#include "qemu/bitops.h"
#include "qemu/lockable.h"
#include "qemu/log.h"
#include "qemu/module.h"
#include "qemu/timer.h"
#include "hw/arm/xnu_dtb.h"

//cpu is getting next interrupt to process, find one
static unsigned int apple_aic_find_irq_cpu(AppleAICState* s, unsigned int cpu_id){
    // check for IPI
    for(int i = 0; i < s->numCPU; i++){ /* source */
        int j = cpu_id; /* target */
        if(!s->cpus[j]->interrupted && s->pendingIPI[i][j]){
            bool isMasked = s->ipi_mask[j] & (i == j ?  REG_IPI_FLAG_SELF : REG_IPI_FLAG_OTHER);
            if(!isMasked){
                s->cpus[j]->interrupted = true;
                s->cpus[j]->is_ipi = true;
                s->cpus[j]->ipi_source = i;
                s->cpus[j]->ack = (i == j ? REG_ACK_IPI_SELF : REG_ACK_IPI_OTHER);
                s->pendingIPI[i][j] = 0;
                return s->cpus[j]->ack;
            }
        }
    }
    // check for IRQ
    for(int i = 0; i < s->numIRQ;i++)
    if(s->ext_irq_state[i]){
        if(!test_bit(i, (unsigned long*)s->ipid_mask)){
            //find a cpu to interrupt
            int cpu = -1;
            if(!s->cpus[cpu_id]->interrupted && test_bit(cpu_id, (unsigned long*)&s->irq_affinity[i])){
                cpu = cpu_id;
            }
            if(cpu == -1) continue;
            s->cpus[cpu]->interrupted = true;
            s->cpus[cpu]->is_ipi = false;
            s->cpus[cpu]->irq_source = i;
            s->cpus[cpu]->ack = i | REG_ACK_TYPE_IRQ;
            s->ext_irq_state[i] = 0;
            return s->cpus[cpu]->ack;
        }
    }
    return REG_ACK_TYPE_NONE;
}
//update aic and dispatch pendings, call with mutex locked
static void apple_aic_update(AppleAICState* s){
    // This is not the best way to handle this
    // Interrupts should be grouped in order for one CPU to handle it all at once

    // check for IPI
    for(int i = 0; i < s->numCPU; i++) /* source */
        for(int j = 0; j < s->numCPU; j++) /* target */
            if(!s->cpus[j]->interrupted && s->pendingIPI[i][j]){
                bool isMasked = s->ipi_mask[j] & (i == j ?  REG_IPI_FLAG_SELF : REG_IPI_FLAG_OTHER);
                if(!isMasked){
                    s->cpus[j]->interrupted = true;
                    s->cpus[j]->is_ipi = true;
                    s->cpus[j]->ipi_source = i;
                    s->cpus[j]->ack = (i == j ? REG_ACK_IPI_SELF : REG_ACK_IPI_OTHER);
                    s->pendingIPI[i][j] = 0;
                    qemu_irq_raise(s->cpu_irqs[j]);
                }
            }
    // check for IRQ
    for(int i = 0; i < s->numIRQ;i++)
    if(s->ext_irq_state[i]){
        if(!test_bit(i, (unsigned long*)s->ipid_mask)){
            //find a cpu to interrupt
            int cpu = -1;
            for(int j = 0; j < s->numCPU; j++)
            if(!s->cpus[j]->interrupted && test_bit(j, (unsigned long*)&s->irq_affinity[i])){
                cpu = j;
                break;
            }
            if(cpu == -1) continue;
            s->cpus[cpu]->interrupted = true;
            s->cpus[cpu]->is_ipi = false;
            s->cpus[cpu]->irq_source = i;
            s->cpus[cpu]->ack = i;
            s->ext_irq_state[i] = false;
            qemu_irq_raise(s->cpu_irqs[cpu]);
        }
    }
}
static void apple_aic_set_irq(void *opaque, int irq, int level){
    AppleAICState* s = APPLE_AIC(opaque);
    WITH_QEMU_LOCK_GUARD(&s->mutex){
        s->ext_irq_state[irq] = level & 1;
        if(level == 1) {
            apple_aic_update(s);
        }
    }
}
static void apple_aic_tick(void *opaque) {
    AppleAICState* s = APPLE_AIC(opaque);
    WITH_QEMU_LOCK_GUARD(&s->mutex){
        for(int i = 0; i < s->numCPU; i++){ /* source */
            for(int j = 0; j < s->numCPU; j++) /* target */
            if(s->deferredIPI[i][j]){
                s->pendingIPI[i][j] = 1;
                s->deferredIPI[i][j] = 0;
            }
        }
        apple_aic_update(s);
    }
    timer_mod_ns(s->timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) + kDeferredIPITimerDefault);
}
static void apple_aic_write(void *opaque,
                  hwaddr addr,
                  uint64_t data,
                  unsigned size){
    AppleAICOpaque* o = (AppleAICOpaque*)opaque;
    AppleAICState* s = APPLE_AIC(o->aic);
    unsigned int val = (unsigned int)data;
    WITH_QEMU_LOCK_GUARD(&s->mutex){
        if (addr >= 0x6000) { /* REG_TSTAMP */
            //TODO: implement
            // fprintf(stderr, "AIC: Write REG_TSTAMP\n");
            return;
        } else if (addr >= 0x5000) { /* REG_PERCPU(r,c) */
            unsigned int cpu_id = extract32(addr, 7, 5);
            unsigned int op = extract32(addr, 0, 7);
            switch (op){
                case REG_IPI_DISABLE:
                    s->ipi_mask[cpu_id] = (~val) & (REG_IPI_FLAG_SELF | REG_IPI_FLAG_OTHER);
                    return;
                case REG_IPI_ENABLE:
                    s->ipi_mask[cpu_id] = ((~val) & REG_IPI_FLAG_SELF) | ((~val) & REG_IPI_FLAG_OTHER);
                    return;
                case REG_IPI_DEFER_CLEAR:
                    s->deferredIPI[cpu_id][o->cpu_id] = 0;
                    return;
                default:
                    break;
            }
        } else if (addr >= 0x4280) {
            //Unknown
        } else if (addr >= 0x4100){ /* REG_IRQ_DISABLE; REG_IRQ_ENABLE, REG_IRQ_STAT */
            unsigned int ipid = extract32(addr, 2, 6);
            if(ipid < (s->numIRQ >> 5)){
                if (addr >= 0x4200) { /* REG_IRQ_STAT */
                    s->ipid_mask[ipid] = val;
                    return;
                } else if (addr >= 0x4180){ /* REG_IRQ_ENABLE */
                        for(int i = 0; i < 32; i++)
                        if(test_bit(i, (unsigned long*)&val)) {
                            s->ipid_mask[ipid] &= ~(1 << i);
                        }
                        return;
                } else { /* REG_IRQ_DISABLE */
                    for(int i = 0; i < 32; i++)
                        if(test_bit(i, (unsigned long*)&val)) {
                            s->ipid_mask[ipid] |= (1 << i);
                        }
                    return;
                }
            }
        } else if (addr >= 0x4080){
            //IRQ ACK
            //if the vector-th bit is set in ipid-mask, [0, 4) in most dtree, this will be sent
            //on t8030, only wdt (watch dog timer) is affected by this
            //for wdt device, when IRQ 0 is raised, the device panics
            if(!o->interrupted) return;
            o->interrupted = false;
            // fprintf(stderr, "AIC: Received IRQ ack\n");
            return;
        } else if (addr >= 0x3000) { /* REG_IRQ_AFFINITY */
            unsigned int vectorNumber = extract32(addr, 2, 10);
            val &= ~(-1 << s->numCPU);
            if (val == 0){
                val = ~(-1 << s->numCPU); //any CPU
            }
            s->irq_affinity[vectorNumber] = val;
            return;
        } else {
            bool set = false;
            switch (addr){
                case REG_GLOBAL_CFG:
                    s->global_cfg = val;
                    return;
                case REG_IPI_SET:
                    if (val & REG_IPI_FLAG_SELF){
                        val = 1 << o->cpu_id;
                    }
                    for (int i = 0; i < s->numCPU; i++)
                    if(test_bit(i, (unsigned long*)&val))
                    {
                        s->pendingIPI[o->cpu_id][i] = 1;
                        set = true;
                    }
                    if (!set){
                        fprintf(stderr, "AIC: Write REG_IPI_SET = 0x%x from CPU %u not set any IPI\n", val, o->cpu_id);
                        break;
                    }
                    apple_aic_update(s);
                    return;
                case REG_IPI_DEFER_SET:
                    if (val & REG_IPI_FLAG_SELF){
                        val = 1 << o->cpu_id;
                    }
                    set = false;
                    for (int i = 0; i < s->numCPU; i++)
                    if(test_bit(i, (unsigned long*)&val))
                    {
                        s->deferredIPI[o->cpu_id][i] = 1;
                        set = true;
                    }
                    if (!set){
                        fprintf(stderr, "AIC: Write REG_IPI_DEFER_SET = 0x%x not set any IPI\n", val);
                        break;
                    }
                    apple_aic_update(s);
                    return;
                case REG_IPI_CLEAR:
                    //TODO: Implement
                    return;
            }
        }
        fprintf(stderr, "AIC: Write to unspported reg 0x%llx\n", addr);
    }
}
static uint64_t apple_aic_read(void *opaque,
                     hwaddr addr,
                     unsigned size){
    AppleAICOpaque* o = (AppleAICOpaque*)opaque;
    AppleAICState* s = APPLE_AIC(o->aic);
    WITH_QEMU_LOCK_GUARD(&s->mutex){
        if (addr >= 0x6000) { /* REG_TSTAMP */
            //TODO: implement
            fprintf(stderr, "AIC: Read REG_TSTAMP\n");
            return 0;
        } else if (addr >= 0x5000) { /* REG_PERCPU(r,c) */
            unsigned int cpu_id = extract32(addr, 7, 5);
            unsigned int op = extract32(addr, 0, 7);
            switch (op){
                case REG_IPI_DISABLE:
                    return s->ipi_mask[cpu_id];
                case REG_IPI_ENABLE:
                    return ((~s->ipi_mask[cpu_id]) & REG_IPI_FLAG_SELF) | ((~s->ipi_mask[cpu_id]) & REG_IPI_FLAG_OTHER);
                default:
                    break;
            }
        } else if (addr >= 0x4280) {
            //Unknown
        } else if (addr >= 0x4100){ /* REG_IRQ_DISABLE; REG_IRQ_ENABLE, REG_IRQ_STAT */
            unsigned int ipid = extract32(addr, 2, 6);
            if(ipid < (s->numIRQ >> 5)){
                if (addr >= 0x4200) { /* REG_IRQ_STAT */
                    return s->ipid_mask[ipid];
                } else if (addr >= 0x4180){ /* REG_IRQ_ENABLE */
                        return ~s->ipid_mask[ipid];
                } else { /* REG_IRQ_DISABLE */
                    return s->ipid_mask[ipid];
                }
            }
        } else if (addr >= 0x3000) { /* REG_IRQ_AFFINITY */
            unsigned int vectorNumber = extract32(addr, 2, 10);
            return s->irq_affinity[vectorNumber];
        } else {
            switch (addr){
                case REG_ID_REVISION:
                    return 2;
                case REG_ID_CONFIG:
                    return (((uint64_t)s->numCPU - 1) << 16) | (s->numIRQ);
                case REG_GLOBAL_CFG:
                    return s->global_cfg;
                case REG_ID_CPUID:
                    return o->cpu_id;
                case REG_TSTAMP_LO:
                    return (uint32_t)s->tick;
                case REG_TSTAMP_HI:
                    return (uint32_t)((s->tick)>>32);
                case REG_ACK:
                    //TODO : implement
                    if(!o->interrupted){
                        int ack = apple_aic_find_irq_cpu(s, o->cpu_id);
                        if(o->interrupted){
                            if(!o->is_ipi && o->irq_source > 3){
                                o->interrupted = false;
                            }
                        }
                        return ack;
                    }
                    o->interrupted = false;
                    qemu_irq_lower(s->cpu_irqs[o->cpu_id]);
                    return o->ack;
                default:
                    break;
            }
        }
    }
    fprintf(stderr, "AIC: Read from unspported reg 0x%llx\n", addr);
    return -1;
}

static const MemoryRegionOps apple_aic_ops = {
    .read = apple_aic_read,
    .write = apple_aic_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid.min_access_size = 4,
    .valid.max_access_size = 4,
    .valid.unaligned = false,
};

static void apple_aic_init(Object *obj)
{
    SysBusDevice *sbd = SYS_BUS_DEVICE(obj);
    AppleAICState *s = APPLE_AIC(obj);
    qemu_mutex_init(&s->mutex);
    s->cpus = g_malloc0(sizeof(AppleAICOpaque*) * s->numCPU);
    s->iomems = g_malloc0(sizeof(MemoryRegion*) * s->numCPU);
    for(int i=0; i < s->numCPU; i++){
        s->iomems[i] = g_new(MemoryRegion, 1);
        AppleAICOpaque *opaque = g_new0(AppleAICOpaque, 1);
        opaque->aic = s;
        opaque->cpu_id = i;
        memory_region_init_io(s->iomems[i], obj, &apple_aic_ops, opaque,
                                TYPE_APPLE_AIC, s->base_size);
        s->cpus[i] = opaque;
    }

    qdev_init_gpio_in(DEVICE(obj), apple_aic_set_irq, s->numIRQ);
    assert(s->numCPU > 0);
    s->ipid_mask = g_malloc0(sizeof(unsigned int) * s->numIPID);
    s->ipi_mask = g_malloc0(sizeof(unsigned int) * s->numCPU);
    s->irq_affinity = g_malloc0(sizeof(unsigned int) * s->numIRQ);
    s->cpu_irqs = g_malloc0(sizeof(qemu_irq) * s->numCPU);
    qdev_init_gpio_out(DEVICE(obj), s->cpu_irqs, s->numCPU);
    s->pendingIPI = g_malloc0(sizeof(unsigned int*) * s->numCPU);
    s->deferredIPI = g_malloc0(sizeof(unsigned int*) * s->numCPU);
    for(int i = 0; i < s->numCPU; i++){
        sysbus_init_irq(sbd, &s->cpu_irqs[i]);
        s->pendingIPI[i] = g_malloc0(sizeof(bool) * s->numCPU);
        s->deferredIPI[i] = g_malloc0(sizeof(bool) * s->numCPU);
    }
    s->ext_irq_state = g_malloc0(sizeof(bool) * s->numIRQ);
}
static void apple_aic_realize(DeviceState *dev, Error **errp){
    AppleAICState *s = APPLE_AIC(dev);
    s->timer = timer_new_ns(QEMU_CLOCK_VIRTUAL,
                            apple_aic_tick, dev);
    timer_mod_ns(s->timer, kDeferredIPITimerDefault);
}
static void apple_aic_reset(DeviceState *dev){
    AppleAICState *s = APPLE_AIC(dev);
    //mask all IRQs
    memset(s->ipid_mask, 0xff, sizeof(unsigned int)*s->numIPID);
    //Affinity default to 0
    memset(s->irq_affinity, 0, sizeof(unsigned int)*s->numIRQ);
    for(int i=0;i < s->numCPU; i++)
    {
        // mask all IPI
        s->ipi_mask[i] = REG_IPI_FLAG_SELF | REG_IPI_FLAG_OTHER;
    }
}
AppleAICState* apple_aic_create(hwaddr soc_base, unsigned int numCPU, DTBNode* node){
    DeviceState  *dev;
    AppleAICState *s;

    dev = qdev_new(TYPE_APPLE_AIC);
    s = APPLE_AIC(dev);
    DTBProp* prop = get_dtb_prop(node, "reg");
    assert(prop != NULL);
    hwaddr* reg = (hwaddr*)prop->value;
    s->base = soc_base + reg[0];
    s->base_size = reg[1];
    prop = get_dtb_prop(node, "ipid-mask");
    s->numIPID = prop->length / 4;
    s->numIRQ = s->numIPID * 32;

    s->numCPU = numCPU;
    overwrite_dtb_prop(node, "#main-cpus", 4, (uint8_t*)&s->numCPU);

    prop = get_dtb_prop(node, "#shared-timestamps");
    assert(prop);
    assert(prop->length == 4);
    *(uint32_t*)prop->value = 0;
    apple_aic_init(OBJECT(dev));

    return s;
}
static void apple_aic_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    dc->realize = apple_aic_realize;
    dc->reset = apple_aic_reset;
    dc->desc = "Apple Interrupt Controller";
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