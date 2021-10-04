#include "qemu/osdep.h"
#include "qapi/error.h"
#include "hw/irq.h"
#include "migration/vmstate.h"
#include "qemu/bitops.h"
#include "qemu/log.h"
#include "qemu/module.h"
#include "sysemu/dma.h"
#include "hw/arm/xnu.h"
#include "hw/arm/xnu_dtb.h"
#include "hw/spmi/apple_spmi.h"

//#define DEBUG_SPMI

#define APPLE_SPMI_RESP_IRQ                 "apple-spmi-resp"

#define SPMI_QUEUE_DEPTH                    (0x100)

#define SPMI_QUEUE_STATUS                   (0x0)
#define  SPMI_QUEUE_STATUS_REQ_EMPTY        (1 << 8)
#define  SPMI_QUEUE_STATUS_RSP_EMPTY        (1 << 24)

#define SPMI_REQ_QUEUE_PUSH                 (0x4)
#define  SPMI_REQ_ADDR_SHIFT                 (16)
#define  SPMI_REQ_SID_SHIFT                  (8)
#define  SPMI_REQ_SID(_x)                    (((_x) >> 8) & 0xf)
#define  SPMI_OPCODE_SHIFT                   (0)
#define  SPMI_REQ_FINAL                      (1 << 15)

#define SPMI_RSP_QUEUE_POP                  (0x8)
#define  SPMI_RSP_ACK_MASK                  (0xff)
#define  SPMI_RSP_ACK_SHIFT                 (16)

#define SPMI_NUM_IRQ_BANK                   (9)
#define SPMI_NUM_IRQ                        (9 * 32)
#define SPMI_INT_STATUS_V0(_b)              (0x40 + (_b) * 4)
#define SPMI_INT_STATUS_V1(_b)              (0x60 + (_b) * 4)
#define SPMI_INT_ENAB(_b)                   (0x20 + (_b) * 4)

static inline int spmi_opcode(uint32_t spmi_request)
{
    switch ((spmi_request >> 4) & 0xf) {
    case 1:
        return spmi_request & 0xff;
    default:
        return spmi_request & 0xf8;
    }
}

static inline int spmi_data_length(uint32_t spmi_request)
{
    switch ((spmi_request >> 4) & 0xf) {
    case 1:
        return 0;
    default:
        return (spmi_request & 0x7) + 1;
    }
}

static inline int spmi_address(uint32_t spmi_request)
{
    switch (spmi_opcode(spmi_request)) {
    case SPMI_CMD_EXT_WRITE:
    case SPMI_CMD_EXT_READ:
    case SPMI_CMD_EXT_WRITEL:
    case SPMI_CMD_EXT_READL:
        return (spmi_request >> SPMI_REQ_ADDR_SHIFT) & 0xffff;
    default:
        return (spmi_request >> SPMI_REQ_ADDR_SHIFT) & 0xff;
    }
}

static void apple_spmi_set_irq(void *opaque, int irq, int level)
{
    AppleSPMIState *s = APPLE_SPMI(opaque);
    uint32_t *status = NULL;
    switch (s->reg_vers) {
    case 0:
        status = &s->base_reg[SPMI_INT_STATUS_V0(irq >> 5) >> 2];
        break;
    case 1:
        status = &s->base_reg[SPMI_INT_STATUS_V1(irq >> 5) >> 2];
        break;
    default:
        g_assert_not_reached();
        break;
    }
    if (level) {
        *status |= (1 << (irq & 31));
    } else {
        *status &= ~(1 << (irq & 31));
    }
}

static void apple_spmi_update_queues_status(AppleSPMIState *s)
{
    if (!fifo32_is_empty(&s->resp_fifo)) {
        s->base_reg[SPMI_QUEUE_STATUS >> 2] &= ~(SPMI_QUEUE_STATUS_RSP_EMPTY);
        qemu_irq_raise(s->resp_irq);
    } else {
        s->base_reg[SPMI_QUEUE_STATUS >> 2] |= (SPMI_QUEUE_STATUS_RSP_EMPTY);
        qemu_irq_lower(s->resp_irq);
    }
}

static void apple_spmi_update_irq(AppleSPMIState *s)
{
    int level = false;
    for (int i = 0; i < SPMI_NUM_IRQ_BANK && !level; i++) {
        uint32_t status = 0;
        switch (s->reg_vers) {
        case 0:
            status = s->base_reg[SPMI_INT_STATUS_V0(i) >> 2];
            break;
        case 1:
            status = s->base_reg[SPMI_INT_STATUS_V1(i) >> 2];
            break;
        default:
            g_assert_not_reached();
            break;
        }
        if (status & s->base_reg[SPMI_INT_ENAB(i) >> 2]) {
            level = 1;
        }
    }

    qemu_set_irq(s->irq, level);
}

static void apple_spmi_base_reg_write(void *opaque, hwaddr addr,
                                      uint64_t data,
                                      unsigned size)
{
    AppleSPMIState *s = APPLE_SPMI(opaque);
    uint32_t value = data;
    bool iflg = false;
    bool qflg = false;
#ifdef DEBUG_SPMI
    qemu_log_mask(LOG_UNIMP, "spmi: %s @ 0x"
    TARGET_FMT_plx " value: 0x" TARGET_FMT_plx "\n", __func__, addr, data);
#endif

    switch (addr) {
    case SPMI_REQ_QUEUE_PUSH: {
        if (s->data == NULL) {
            uint8_t sid = SPMI_REQ_SID(value);
            uint8_t opc = spmi_opcode(value);
            uint32_t addr = spmi_address(value);
            bool parity = !(value & SPMI_REQ_FINAL);
            uint32_t len = spmi_data_length(value);

            s->command = value;
            #ifdef DEBUG_SPMI
            qemu_log_mask(LOG_UNIMP, "%s: sid: 0x%x opc: 0x%x addr: 0x%x len: 0x%x\n",
                                     __func__, sid, opc, addr, len);
            #endif

            if (opc == SPMI_CMD_EXT_WRITE || opc == SPMI_CMD_EXT_WRITEL) {
                s->data_length = (len + 3) / 4;
                s->data_filled = 0;
                s->data = g_new0(uint32_t, s->data_length);
            }
            if (spmi_start_transfer(s->bus, sid, opc, addr)) {
                return;
            }
            if (s->data == NULL && len) {
                assert(opc == SPMI_CMD_EXT_READ || opc == SPMI_CMD_EXT_READL);
                g_autofree uint32_t *data = g_malloc0(len + 3);
                int count = spmi_recv(s->bus, (uint8_t *)data, len);
                uint8_t ack = 0;
                value &= 0xFFF;
                if (count > 0) {
                    ack = ~(-1 << count);
                }
                value |= (ack << SPMI_RSP_ACK_SHIFT);
                fifo32_push(&s->resp_fifo, value);
                for (int i = 0; i < (len + 3) / 4; i++) {
                    fifo32_push(&s->resp_fifo, data[i]);
                }
            }
            if (s->data == NULL && !parity) {
                spmi_end_transfer(s->bus);
                qflg = 1;
                iflg = 1;
            }
        } else {
            s->data[s->data_filled++] = value;
            if (s->data_filled >= s->data_length) {
                uint32_t requested_len = spmi_data_length(s->command);
                uint32_t count = spmi_send(s->bus, (uint8_t *)s->data,
                                           requested_len);
                fifo32_push(&s->resp_fifo, (s->command & 0xFFF)
                                           | ((count == requested_len) << 15));
                g_free(s->data);
                s->data = NULL;
                s->data_length = 0;
                if (s->command & SPMI_REQ_FINAL) {
                    spmi_end_transfer(s->bus);
                    qflg = 1;
                    iflg = 1;
                }
            }
        }
        break;
    }
    case SPMI_INT_ENAB(0) ... SPMI_INT_ENAB(SPMI_NUM_IRQ_BANK - 1):
        iflg = true;
        break;
    case SPMI_INT_STATUS_V1(0) ... SPMI_INT_STATUS_V1(SPMI_NUM_IRQ_BANK - 1):
        value = s->base_reg[addr >> 2] & (~value);
        iflg = true;
        break;
    default:
        break;
    }
    s->base_reg[addr >> 2] = value;
    if (qflg) {
        apple_spmi_update_queues_status(s);
    }
    if (iflg) {
        apple_spmi_update_irq(s);
    }
}

static uint64_t apple_spmi_base_reg_read(void *opaque,
                                         hwaddr addr,
                                         unsigned size)
{
    AppleSPMIState *s = APPLE_SPMI(opaque);
    bool qflg = false;
    bool iflg = false;
    uint32_t value = 0;
#ifdef DEBUG_SPMI
    qemu_log_mask(LOG_UNIMP, "spmi: %s @ 0x" TARGET_FMT_plx "\n", __func__,
                            addr);
#endif
    value = s->base_reg[addr >> 2];

    switch (addr) {
    case SPMI_RSP_QUEUE_POP:
        if (fifo32_is_empty(&s->resp_fifo)) {
            qemu_log_mask(LOG_GUEST_ERROR, "spmi: rsp queue empty\n");
            value = 0;
        } else {
            value = fifo32_pop(&s->resp_fifo);
        }
        qflg = true;
        iflg = true;
        break;
    default:
        break;
    }

    if (qflg) {
        apple_spmi_update_queues_status(s);
    }
    if (iflg) {
        apple_spmi_update_irq(s);
    }
    return value;
}

static const MemoryRegionOps apple_spmi_base_reg_ops = {
        .write = apple_spmi_base_reg_write,
        .read = apple_spmi_base_reg_read,
        .endianness = DEVICE_NATIVE_ENDIAN,
        .impl.min_access_size = 4,
        .impl.max_access_size = 4,
        .valid.min_access_size = 4,
        .valid.max_access_size = 4,
        .valid.unaligned = false,
};

static void apple_spmi_reset(DeviceState *dev)
{
    AppleSPMIState *s = APPLE_SPMI(dev);
    memset(s->base_reg, 0, sizeof(s->base_reg));
    memset(s->fault_reg, 0, sizeof(s->fault_reg));
    memset(s->fault_counter_reg, 0, sizeof(s->fault_counter_reg));
    s->base_reg[SPMI_QUEUE_STATUS >> 2] = SPMI_QUEUE_STATUS_REQ_EMPTY
                                          | SPMI_QUEUE_STATUS_RSP_EMPTY;
    s->fault_reg[SPMI_QUEUE_STATUS >> 2] = SPMI_QUEUE_STATUS_REQ_EMPTY
                                          | SPMI_QUEUE_STATUS_RSP_EMPTY;
    fifo32_reset(&s->resp_fifo);
    s->data = NULL;
    s->data_length = 0;
}

static void apple_spmi_realize(DeviceState *dev, Error **errp)
{
    AppleSPMIState *s = APPLE_SPMI(dev);

    qdev_connect_gpio_out_named(dev, APPLE_SPMI_RESP_IRQ, 0,
                                qdev_get_gpio_in(dev, s->resp_intr_index));
}

SysBusDevice *apple_spmi_create(DTBNode *node)
{
    DeviceState  *dev;
    AppleSPMIState *s;
    SysBusDevice *sbd;
    DTBProp *prop;
    uint64_t *reg;
    char bus_name[32] = { 0 };

    dev = qdev_new(TYPE_APPLE_SPMI);
    s = APPLE_SPMI(dev);
    sbd = SYS_BUS_DEVICE(dev);

    prop = find_dtb_prop(node, "name");
    dev->id = g_strdup((const char *)prop->value);

    snprintf(bus_name, sizeof(bus_name), "%s.bus", (const char *)prop->value);
    s->bus = spmi_init_bus(dev, (const char *)bus_name);

    prop = find_dtb_prop(node, "reg-vers");
    if (prop) {
        s->reg_vers = *(uint32_t *)prop->value;
    }

    /* XXX: There is a register overlapping issue (STS and ENAB) with reg v0 */
    assert(s->reg_vers != 0);

    prop = find_dtb_prop(node, "reg");
    assert(prop);

    reg = (uint64_t *)prop->value;

    memory_region_init_io(&s->iomems[0], OBJECT(dev), &apple_spmi_base_reg_ops,
                          s, TYPE_APPLE_SPMI ".base_reg", reg[1]);
    sysbus_init_mmio(sbd, &s->iomems[0]);

    memory_region_init_ram_device_ptr(&s->iomems[1], OBJECT(dev),
                                      TYPE_APPLE_SPMI ".fault_reg",
                                      sizeof(s->fault_reg), &s->fault_reg);
    sysbus_init_mmio(sbd, &s->iomems[1]);

    memory_region_init_ram_device_ptr(&s->iomems[2], OBJECT(dev),
                                      TYPE_APPLE_SPMI ".fault_counter_reg",
                                      sizeof(s->fault_counter_reg),
                                      &s->fault_counter_reg);
    sysbus_init_mmio(sbd, &s->iomems[2]);

    sysbus_init_irq(sbd, &s->irq);

    qdev_init_gpio_in(dev, apple_spmi_set_irq, SPMI_NUM_IRQ);

    prop = find_dtb_prop(node, "AAPL,phandle");

    s->phandle = *(uint32_t *)prop->value;

    prop = find_dtb_prop(node, "interrupts");

    s->resp_intr_index = *(uint32_t *)prop->value;

    prop = find_dtb_prop(node, "interrupt-parent");
    /* The first interrupt in list (response) should be self-wired */
    assert(*(uint32_t *)prop->value == s->phandle);

    qdev_init_gpio_out_named(dev, &s->resp_irq, APPLE_SPMI_RESP_IRQ, 1);

    fifo32_create(&s->resp_fifo, SPMI_QUEUE_DEPTH);
    return sbd;
}

static const VMStateDescription vmstate_apple_spmi = {
    .name = "apple_spmi",
    .fields = (VMStateField[]) {
        VMSTATE_FIFO32(resp_fifo, AppleSPMIState),
        VMSTATE_UINT32_ARRAY(base_reg, AppleSPMIState,
                             0x1000 / sizeof(uint32_t)),
        VMSTATE_UINT32_ARRAY(fault_reg, AppleSPMIState,
                             0x1000 / sizeof(uint32_t)),
        VMSTATE_UINT32_ARRAY(fault_counter_reg, AppleSPMIState,
                             0x64 / sizeof(uint32_t)),
        VMSTATE_UINT32(data_length, AppleSPMIState),
        VMSTATE_UINT32(data_filled, AppleSPMIState),
        VMSTATE_UINT32(command, AppleSPMIState),
        VMSTATE_VARRAY_UINT32_ALLOC(data, AppleSPMIState, data_length, 0,
                                    vmstate_info_uint32, uint32_t),

        VMSTATE_END_OF_LIST()
    }
};

static void apple_spmi_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->realize = apple_spmi_realize;
    /* dc->unrealize = apple_spmi_unrealize; */
    dc->reset = apple_spmi_reset;
    dc->desc = "Apple SPMI Controller";
    dc->vmsd = &vmstate_apple_spmi;
    set_bit(DEVICE_CATEGORY_BRIDGE, dc->categories);
}

static const TypeInfo apple_spmi_info = {
        .name = TYPE_APPLE_SPMI,
        .parent = TYPE_SYS_BUS_DEVICE,
        .instance_size = sizeof(AppleSPMIState),
        .class_init = apple_spmi_class_init,
};

static void apple_spmi_register_types(void)
{
    type_register_static(&apple_spmi_info);
}

type_init(apple_spmi_register_types);

