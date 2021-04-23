#include "qemu/osdep.h"
#include "qapi/error.h"
#include "hw/block/apple-ans.h"
#include "hw/irq.h"
#include "migration/vmstate.h"
#include "qemu/bitops.h"
#include "qemu/lockable.h"
#include "qemu/log.h"
#include "qemu/main-loop.h"
#include "qemu/module.h"
#include "qemu/timer.h"
#include "hw/arm/xnu_dtb.h"

//Push a message from AP to IOP, called with iothread locked
static inline void iop_inbox_push(AppleANSState* s, iop_message_t msg){
    QTAILQ_INSERT_TAIL(&s->inbox, msg, entry);
    qemu_irq_lower(s->irqs[IRQ_IOP_INBOX]);
    qemu_cond_broadcast(&s->iop_halt);
}
static inline iop_message_t iop_inbox_get(AppleANSState* s){
    iop_message_t msg = QTAILQ_FIRST(&s->inbox);
    QTAILQ_REMOVE(&s->inbox, msg, entry);
    return msg;
}
static inline bool iop_inbox_empty(AppleANSState* s){
    return QTAILQ_EMPTY(&s->inbox);
}
//Push a message from IOP to AP, called with iothread locked
static inline void iop_outbox_push_nolock(AppleANSState* s, iop_message_t msg){
    if(!s->outboxEnable){
        return;
    }
    QTAILQ_INSERT_TAIL(&s->outbox, msg, entry);
    qemu_irq_raise(s->irqs[IRQ_IOP_OUTBOX]);
}
//Push a message from IOP to AP, called with iothread unlocked
static inline void iop_outbox_push(AppleANSState* s, iop_message_t msg){
    qemu_mutex_unlock(&s->mutex);
    qemu_mutex_lock_iothread();
    iop_outbox_push_nolock(s, msg);
    qemu_mutex_unlock_iothread();
    qemu_mutex_lock(&s->mutex);
}
static inline bool iop_outbox_empty(AppleANSState* s){
    return QTAILQ_EMPTY(&s->outbox);
}
static inline uint32_t iop_outbox_flags(AppleANSState* s){
    uint32_t flags = 0;
    if(iop_outbox_empty(s)){
        flags |= A7V4_MSG_FLAG_LAST;
    } else {
        flags |= A7V4_MSG_FLAG_NOTLAST;
    }
    return flags;
}

static void iop_handle_mgmt_msg(AppleANSState* s, iop_message_t msg){
    switch(s->ep0_status){
        case EP0_WAIT_HELLO:
            if(msg->type == MSG_RECV_HELLO){
                iop_message_t m = g_new0(struct iop_message, 1);
                m->type = MSG_TYPE_ROLLCALL;
                m->rollcall.epMask = (1 << 0); //Register ANS2Endpoint1 ?
                m->rollcall.epBlock = 1;
                m->rollcall.epEnded = true;
                iop_outbox_push(s, m);
                s->ep0_status = EP0_WAIT_ROLLCALL;
                break;
            }
        case EP0_WAIT_ROLLCALL:
            if(msg->type == MSG_TYPE_ROLLCALL){
                iop_message_t m = g_new0(struct iop_message, 1);
                m->type = MSG_TYPE_POWER;
                m->power.state = 32;
                iop_outbox_push(s, m);
                s->ep0_status = EP0_WAIT_EPSTAT;
                break;
            }
        case EP0_WAIT_EPSTAT:
            if(msg->type == MSG_TYPE_EPSTAT) {
                iop_message_t m = g_new0(struct iop_message, 1);
                m->type = MSG_TYPE_POWER;
                m->power.state = 32;
                iop_outbox_push(s, m);
                s->ep0_status = EP0_WAIT_EPSTAT;
            }
        case EP0_WAIT_POWERACK:
            if(msg->type == MSG_TYPE_POWERACK) {
                iop_message_t m = g_new0(struct iop_message, 1);
                m->type = MSG_TYPE_POWERACK;
                m->power.state = msg->power.state;
                iop_outbox_push(s, m);
                s->ep0_status = EP0_DONE;
                
                qemu_mutex_lock_iothread();
                uint32_t config = pci_default_read_config(PCI_DEVICE(&s->nvme), PCI_COMMAND, 4);
                config |= 0x0002 | 0x0004; // memory | bus
                pci_default_write_config(PCI_DEVICE(&s->nvme), PCI_COMMAND, config, 4);
                assert(PCI_DEVICE(&s->nvme)->bus_master_enable_region.enabled);
                qemu_mutex_unlock_iothread();
                break;
            }
        default:
            qemu_log_mask(LOG_GUEST_ERROR, "ANS2: EP0: Skipping unexpected message\n");
    }
    g_free(msg);
}

static void* iop_thread_fn(void* opaque){
    AppleANSState* s = APPLE_ANS(opaque);
    while(1){
        bool has_work;
        bool stopped;
        WITH_QEMU_LOCK_GUARD(&s->mutex){
            stopped = s->stopping;
            has_work = !iop_inbox_empty(s);
            if(stopped){
                break;
            }
            if(has_work){
                iop_message_t msg = iop_inbox_get(s);
                // fprintf(stderr, "ANS2: Received msg type: %d endpoint: %d: 0x" TARGET_FMT_plx " 0x" TARGET_FMT_plx "\n", msg->type, msg->endpoint, msg->data[0], msg->data[1]);
                switch(msg->endpoint){
                    case 0:
                        iop_handle_mgmt_msg(s, msg);
                        break;
                    default:
                        qemu_log_mask(LOG_GUEST_ERROR, "ANS2: Skipping message to unknown endpoint: %d\n", msg->endpoint);
                        g_free(msg);
                }
                if(iop_inbox_empty(s)){
                    qemu_mutex_unlock(&s->mutex);
                    qemu_mutex_lock_iothread();
                    qemu_irq_raise(s->irqs[IRQ_IOP_INBOX]);
                    qemu_mutex_unlock_iothread();
                    qemu_mutex_lock(&s->mutex);
                }
            } else {
                qemu_cond_wait(&s->iop_halt, &s->mutex);
            }
        }
    }
    return NULL;
}

static void iop_akf_reg_write(void *opaque,
                  hwaddr addr,
                  uint64_t data,
                  unsigned size){
    AppleANSState* s = APPLE_ANS(opaque);
    WITH_QEMU_LOCK_GUARD(&s->mutex){
        switch (addr){
            case REG_AKF_CONFIG:
                s->config = data;
                return;
            case REG_A7V4_CPU_CTRL:
                if (data & REG_A7V4_CPU_CTRL_RUN){
                    s->cpu_ctrl = data;
                    iop_message_t msg = g_new0(struct iop_message, 1);
                    msg->type = MSG_SEND_HELLO;
                    msg->hello.major = 11;
                    msg->hello.minor = 11;
                    msg->endpoint = 0;
                    s->ep0_status = EP0_WAIT_HELLO;
                    iop_outbox_push_nolock(s, msg);
                }
                return;
            case REG_A7V4_A2I_MSG0:
                s->inboxBuffer[0] = data;
                return;
            case REG_A7V4_A2I_MSG1:
                s->inboxBuffer[1] = data;
                iop_message_t msg = g_new0(struct iop_message, 1);
                memcpy(msg->data, s->inboxBuffer, sizeof(s->inboxBuffer));
                iop_inbox_push(s, msg);
                return;
            case REG_A7V4_OUTBOX_CTRL:
                if(data & REG_A7V4_OUTBOX_CTRL_ENABLE){
                    s->outboxEnable = true;
                } else {
                    s->outboxEnable = false;
                }
                return;
        }
        qemu_log_mask(LOG_GUEST_ERROR, "ANS2: AppleA7IOP AKF unknown reg WRITE @ 0x" TARGET_FMT_plx " value: 0x" TARGET_FMT_plx "\n", addr, data);
    }
}
static uint64_t iop_akf_reg_read(void *opaque,
                     hwaddr addr,
                     unsigned size){
    AppleANSState* s = APPLE_ANS(opaque);
    WITH_QEMU_LOCK_GUARD(&s->mutex){
        iop_message_t m;
        uint64_t ret = 0;
        switch (addr){
            case REG_AKF_CONFIG:
                return s->config;
            case REG_A7V4_CPU_CTRL:
                return s->cpu_ctrl;
            case REG_A7V4_I2A_MSG0:
                m = QTAILQ_FIRST(&s->outbox);
                assert(m);
                return m->data[0];
            case REG_A7V4_I2A_MSG1:
                m = QTAILQ_FIRST(&s->outbox);
                assert(m);
                QTAILQ_REMOVE(&s->outbox, m, entry);
                m->flags = iop_outbox_flags(s);
                ret = m->data[1];
                if(iop_outbox_empty(s)) {
                    qemu_irq_lower(s->irqs[IRQ_IOP_OUTBOX]);
                }
                g_free(m);
                return ret;
            case REG_A7V4_INBOX_CTRL:
                if(iop_inbox_empty(s)){
                    ret |= REG_A7V4_INBOX_CTRL_EMPTY;
                }
                return ret;
            case REG_A7V4_OUTBOX_CTRL:
                if(iop_outbox_empty(s)){
                    ret |= REG_A7V4_OUTBOX_CTRL_EMPTY;
                } else {
                    ret |= REG_A7V4_OUTBOX_CTRL_HAS_MSG;
                }
                if (s->outboxEnable){
                    ret |= REG_A7V4_OUTBOX_CTRL_ENABLE;
                }
                return ret;
        }
        qemu_log_mask(LOG_UNIMP, "ANS2: AppleA7IOP AKF unknown reg READ @ 0x" TARGET_FMT_plx "\n", addr);
    }
    return 0;
}
static const MemoryRegionOps iop_akf_reg_ops = {
    .write = iop_akf_reg_write,
    .read = iop_akf_reg_read,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid.min_access_size = 4,
    .valid.max_access_size = 8,
    .impl.min_access_size = 4,
    .impl.max_access_size = 8,
    .valid.unaligned = false,
};
static void ascv2_core_reg_write(void *opaque,
                  hwaddr addr,
                  uint64_t data,
                  unsigned size){
    qemu_log_mask(LOG_UNIMP, "ANS2: AppleASCWrapV2 core reg WRITE @ 0x" TARGET_FMT_plx " value: 0x" TARGET_FMT_plx "\n", addr, data);
}
static uint64_t ascv2_core_reg_read(void *opaque,
                     hwaddr addr,
                     unsigned size){
    qemu_log_mask(LOG_UNIMP, "ANS2: AppleASCWrapV2 core reg READ @ 0x" TARGET_FMT_plx "\n", addr);
    return 0;
}
static const MemoryRegionOps ascv2_core_reg_ops = {
    .write = ascv2_core_reg_write,
    .read = ascv2_core_reg_read,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .impl.min_access_size = 8,
    .impl.max_access_size = 8,
    .valid.min_access_size = 8,
    .valid.max_access_size = 8,
    .valid.unaligned = false,
};
static void iop_autoboot_reg_write(void *opaque,
                  hwaddr addr,
                  uint64_t data,
                  unsigned size){
    qemu_log_mask(LOG_UNIMP, "ANS2: AppleA7IOP autoboot reg WRITE @ 0x" TARGET_FMT_plx " value: 0x" TARGET_FMT_plx "\n", addr, data);
}
static uint64_t iop_autoboot_reg_read(void *opaque,
                     hwaddr addr,
                     unsigned size){
    qemu_log_mask(LOG_UNIMP, "ANS2: AppleA7IOP autoboot reg READ @ 0x" TARGET_FMT_plx "\n", addr);
    return 0;
}
static const MemoryRegionOps iop_autoboot_reg_ops = {
    .write = iop_autoboot_reg_write,
    .read = iop_autoboot_reg_read,
};

static void apple_ans_set_irq(void *opaque, int irq_num, int level){
    AppleANSState* s = APPLE_ANS(opaque);
    qemu_set_irq(s->irqs[s->nvme_interrupt_idx], level);
}

SysBusDevice* apple_ans_create(DTBNode* node) {
    DeviceState  *dev;
    AppleANSState *s;
    PCIHostState *pci;
    SysBusDevice *sbd;
    PCIExpressHost *pex;

    dev = qdev_new(TYPE_APPLE_ANS);
    s = APPLE_ANS(dev);
    pci = PCI_HOST_BRIDGE(dev);
    sbd = SYS_BUS_DEVICE(dev);
    pex = PCIE_HOST_BRIDGE(dev);

    qemu_mutex_init(&s->mutex);
    DTBProp *prop = get_dtb_prop(node, "reg");
    assert(prop);
    uint64_t* reg = (uint64_t*)prop->value;
    /*
    0: AppleA7IOP akfRegMap
    1: AppleASCWrapV2 coreRegisterMap
    2: AppleA7IOP autoBootRegMap
    */
    s->iomems[0] = g_new(MemoryRegion, 1);
    memory_region_init_io(s->iomems[0], OBJECT(dev), &iop_akf_reg_ops, s, TYPE_APPLE_ANS ".akf-reg", reg[1]);
    sysbus_init_mmio(sbd, s->iomems[0]);
    s->iomems[1] = g_new(MemoryRegion, 1);
    memory_region_init_io(s->iomems[1], OBJECT(dev), &ascv2_core_reg_ops, s, TYPE_APPLE_ANS ".ascv2-core-reg", reg[3]);
    sysbus_init_mmio(sbd, s->iomems[1]);
    s->iomems[2] = g_new(MemoryRegion, 1);
    memory_region_init_io(s->iomems[2], OBJECT(dev), &iop_autoboot_reg_ops, s, TYPE_APPLE_ANS ".iop-autoboot-reg", reg[5]);
    sysbus_init_mmio(sbd, s->iomems[2]);
    for(int i = 0; i < 5; i++) {
        sysbus_init_irq(sbd, &s->irqs[i]);
    }
    QTAILQ_INIT(&s->inbox);
    QTAILQ_INIT(&s->outbox);
    qemu_cond_init(&s->iop_halt);

    DTBNode* child = get_dtb_child_node_by_name(node, "iop-ans-nub");
    assert(child);
    uint32_t data = 1;
    add_dtb_prop(child, "pre-loaded", 4, (uint8_t*)&data);
    add_dtb_prop(child, "running", 4, (uint8_t*)&data);
    prop = get_dtb_prop(child, "region-base");
    *(uint64_t*)prop->value = 0x8fc400000;
    prop = get_dtb_prop(child, "region-size");
    *(uint64_t*)prop->value = 0x3c00000;
    add_dtb_prop(child, "segment-names", 14, (uint8_t*)"__TEXT;__DATA");
    struct segment_range {
        uint64_t phys;
        uint64_t virt;
        uint64_t remap;
        uint32_t size;
        uint32_t flag;
    };
    struct segment_range segrange[2] = { 0 };
    segrange[0].phys = 0x800024000;
    segrange[0].virt = 0x0;
    segrange[0].remap = 0x800024000;
    segrange[0].size = 0x124000;
    segrange[0].flag = 0x1;

    segrange[1].phys = 0x8fc400000;
    segrange[1].virt = 0x124000;
    segrange[1].remap = 0x8fc400000;
    segrange[1].size = 0x3c00000;
    segrange[1].flag = 0x0;
    add_dtb_prop(child, "segment-ranges", 64, (uint8_t*)segrange);

    prop = get_dtb_prop(node, "nvme-interrupt-idx");
    assert(prop);
    s->nvme_interrupt_idx = *(uint32_t*)prop->value;
    object_initialize_child(OBJECT(dev), "nvme", &s->nvme, TYPE_NVME);
    
    object_property_set_str(OBJECT(&s->nvme), "serial", "QEMUT8030ANS", &error_fatal);
    object_property_set_bool(OBJECT(&s->nvme), "is-apple-ans", true, &error_fatal);
    object_property_set_uint(OBJECT(&s->nvme), "max_ioqpairs", 8, &error_fatal);
    object_property_set_uint(OBJECT(&s->nvme), "mdts", 8, &error_fatal);
    prop = get_dtb_prop(node, "namespaces");
    assert(prop);
    // NVMeCreateNamespacesEntryStruct* namespaces = (NVMeCreateNamespacesEntryStruct*)prop->value;
    // for (int i=0; i < prop->length / 12; i++){
    //     DeviceState* ns = qdev_new(TYPE_NVME_NS);
    //     object_property_set_uint(OBJECT(ns), "nsid", namespaces[i].unk0, &error_fatal);
           
    // }
    pcie_host_mmcfg_init(pex, PCIE_MMCFG_SIZE_MAX);
    memory_region_init(&s->io_mmio, OBJECT(s), "ans_pci_mmio", UINT64_MAX);
    memory_region_init(&s->io_ioport, OBJECT(s), "ans_pci_ioport", 64 * 1024);

    pci->bus = pci_register_root_bus(dev, "anspcie.0", apple_ans_set_irq,
                                     pci_swizzle_map_irq_fn, s, &s->io_mmio,
                                     &s->io_ioport, 0, 4, TYPE_PCIE_BUS);
    pci_realize_and_unref(PCI_DEVICE(&s->nvme), pci->bus, &error_fatal);
    sysbus_init_mmio(sbd, &s->nvme.iomem);
    return sbd;
}
static void apple_ans_realize(DeviceState *dev, Error **errp){
    AppleANSState* s = APPLE_ANS(dev);

    if(iop_inbox_empty(s)){
        qemu_irq_raise(s->irqs[IRQ_IOP_INBOX]);
    }
    qemu_thread_create(&s->iop_thread, "ans-iop", iop_thread_fn, (void*)s, QEMU_THREAD_JOINABLE);
}
static void apple_ans_unrealize(DeviceState *dev){
    AppleANSState* s = APPLE_ANS(dev);
    WITH_QEMU_LOCK_GUARD(&s->mutex){
        s->stopping = true;
    }
    qemu_cond_broadcast(&s->iop_halt);
}
static void apple_ans_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    dc->realize = apple_ans_realize;
    dc->unrealize = apple_ans_unrealize;
    // dc->reset = apple_ans_reset;
    dc->desc = "Apple ANS NVMe";
    set_bit(DEVICE_CATEGORY_BRIDGE, dc->categories);
    dc->fw_name = "pci";
}

static const TypeInfo apple_ans_info = {
    .name = TYPE_APPLE_ANS,
    .parent = TYPE_PCIE_HOST_BRIDGE,
    .instance_size = sizeof(AppleANSState),
    .class_init = apple_ans_class_init,
};

static void apple_ans_register_types(void)
{
    type_register_static(&apple_ans_info);
}

type_init(apple_ans_register_types);
