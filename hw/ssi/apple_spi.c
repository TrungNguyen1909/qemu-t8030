#include "qemu/osdep.h"
#include "hw/ssi/apple_spi.h"
#include "hw/irq.h"
#include "migration/vmstate.h"
#include "qemu/bitops.h"
#include "qemu/lockable.h"
#include "qemu/log.h"
#include "qemu/module.h"
#include "qemu/timer.h"
#include "hw/arm/xnu_dtb.h"
#include "qemu/fifo8.h"

/* XXX: Based on linux/drivers/spi/spi-apple.c */

#define R_CTRL                  0x000
#define  R_CTRL_RUN              (1 << 0)
#define  R_CTRL_TX_RESET         (1 << 2)
#define  R_CTRL_RX_RESET         (1 << 3)

#define R_CFG                   0x004
#define  R_CFG_AGD               (1 << 0)
#define  R_CFG_CPHA              (1 << 1)
#define  R_CFG_CPOL              (1 << 2)
#define  R_CFG_MODE(_x)          (((_x) >> 5) & 0x3)
#define  R_CFG_MODE_POLLED       0
#define  R_CFG_MODE_IRQ          1
#define  R_CFG_MODE_DMA          2
#define  R_CFG_IE_RXREADY        (1 << 7)
#define  R_CFG_IE_TXEMPTY        (1 << 8)
#define  R_CFG_LSB_FIRST	     (1 << 13)
#define  R_CFG_WORD_SIZE(_x)     (((_x) >> 15) & 0x3)
#define  R_CFG_WORD_SIZE_8B      0
#define  R_CFG_WORD_SIZE_16B     1
#define  R_CFG_WORD_SIZE_32B     2
#define  R_CFG_IE_COMPLETE       (1 << 21)

#define R_STATUS                0x008
#define  R_STATUS_RXREADY	     (1 << 0)
#define  R_STATUS_TXEMPTY        (1 << 1)
#define  R_STATUS_RXOVERFLOW     (1 << 3)
#define  R_STATUS_COMPLETE       (1 << 22)
#define  R_STATUS_TXFIFO_SHIFT   (6)
#define  R_STATUS_TXFIFO_MASK    (31 << R_STATUS_TXFIFO_SHIFT)
#define  R_STATUS_RXFIFO_SHIFT   (11)
#define  R_STATUS_RXFIFO_MASK    (31 << R_STATUS_RXFIFO_SHIFT)

#define R_PIN                   0x00c
#define  R_PIN_CS                (1 << 1)

#define R_TXDATA                0x010
#define R_RXDATA                0x020
#define R_CLKDIV                0x030
#define  R_CLKDIV_MAX            0x7ff
#define R_RXCNT                 0x034
#define R_WORD_DELAY            0x038
#define R_TXCNT                 0x04c
#define R_MAX                   (0x50)

#define R_FIFO_DEPTH            16
#define R_FIFO_MAX_DEPTH        (16 * 8)

#define REG(_s,_v)             ((_s)->regs[(_v)>>2])
#define MMIO_SIZE              (0x4000)

struct AppleSPIState {
    SysBusDevice parent_obj;

    MemoryRegion iomem;
    SSIBus *spi;

    qemu_irq irq;
    uint32_t last_irq;
    qemu_irq cs_line;

    Fifo8 rx_fifo;
    Fifo8 tx_fifo;
    uint32_t regs[MMIO_SIZE >> 2];
    uint32_t mmio_size;
};

static int apple_spi_word_size(AppleSPIState *s)
{
    switch (R_CFG_WORD_SIZE(REG(s, R_CFG))) {
    case R_CFG_WORD_SIZE_8B:
        return 1;
    case R_CFG_WORD_SIZE_16B:
        return 2;
    case R_CFG_WORD_SIZE_32B:
        return 4;
    default:
        break;
    }
    g_assert_not_reached();
}

static void apple_spi_update_xfer_tx(AppleSPIState *s)
{
    if (fifo8_is_empty(&s->tx_fifo)) {
        REG(s, R_STATUS) |= R_STATUS_TXEMPTY;
    }
}

static void apple_spi_update_xfer_rx(AppleSPIState *s)
{
    if (!fifo8_is_empty(&s->rx_fifo)) {
        REG(s, R_STATUS) |= R_STATUS_RXREADY;
    }
}

static void apple_spi_update_irq(AppleSPIState *s)
{
    uint32_t irq = 0;
    uint32_t mask = 0;

    if (REG(s, R_CFG) & R_CFG_IE_RXREADY) {
        mask |= R_STATUS_RXREADY;
    }
    if (REG(s, R_CFG) & R_CFG_IE_TXEMPTY) {
        mask |= R_STATUS_TXEMPTY;
    }
    if (REG(s, R_CFG) & R_CFG_IE_COMPLETE) {
        mask |= R_STATUS_COMPLETE;
    }

    if (REG(s, R_STATUS) & mask) {
        irq = 1;
    }
    if (irq != s->last_irq) {
        s->last_irq = irq;
        qemu_set_irq(s->irq, irq);
    }
}

static void apple_spi_update_cs(AppleSPIState *s)
{
    BusState *b = BUS(s->spi);
    BusChild *kid = QTAILQ_FIRST(&b->children);
    if (kid) {
        qemu_set_irq(qdev_get_gpio_in_named(kid->child, SSI_GPIO_CS, 0),
                     (REG(s, R_PIN) & R_PIN_CS) != 0);
    }
}

static void apple_spi_cs_set(void *opaque, int pin, int level)
{
    AppleSPIState *s = APPLE_SPI(opaque);
    if (level) {
        REG(s, R_PIN) |= R_PIN_CS;
    } else {
        REG(s, R_PIN) &= ~R_PIN_CS;
    }
    apple_spi_update_cs(s);
}

static void apple_spi_run(AppleSPIState *s)
{
    uint32_t tx;
    uint32_t rx;

    if (!(REG(s, R_CTRL) & R_CTRL_RUN)) {
        return;
    }

    while (REG(s, R_TXCNT) && !fifo8_is_empty(&s->tx_fifo)) {
        tx = (uint32_t)fifo8_pop(&s->tx_fifo);
        rx = ssi_transfer(s->spi, tx);
        REG(s, R_TXCNT)--;
        apple_spi_update_xfer_tx(s);
        if (REG(s, R_RXCNT) > 0) {
            if (fifo8_is_full(&s->rx_fifo)) {
                qemu_log_mask(LOG_GUEST_ERROR, "%s: rx overflow\n", __func__);
                REG(s, R_STATUS) |= R_STATUS_RXOVERFLOW;
            } else {
                fifo8_push(&s->rx_fifo, (uint8_t)rx);
                REG(s, R_RXCNT)--;
                apple_spi_update_xfer_rx(s);
            }
        }
    }
    while (!fifo8_is_full(&s->rx_fifo)
           && (REG(s, R_RXCNT) > 0)
           && (REG(s, R_CFG) & R_CFG_AGD)) {
        rx = ssi_transfer(s->spi, 0xff);
        if (fifo8_is_full(&s->rx_fifo)) {
            qemu_log_mask(LOG_GUEST_ERROR, "%s: rx overflow\n", __func__);
            REG(s, R_STATUS) |= R_STATUS_RXOVERFLOW;
            break;
        } else {
            fifo8_push(&s->rx_fifo, (uint8_t)rx);
            REG(s, R_RXCNT)--;
            apple_spi_update_xfer_rx(s);
        }
    }
    if (REG(s, R_RXCNT) == 0 && REG(s, R_TXCNT) == 0) {
        REG(s, R_STATUS) |= R_STATUS_COMPLETE;
        REG(s, R_CTRL) &= ~R_CTRL_RUN;
    }
}

static void apple_spi_reg_write(void *opaque,
                                hwaddr addr,
                                uint64_t data,
                                unsigned size)
{
    AppleSPIState *s = APPLE_SPI(opaque);
    uint32_t r = data;
    uint32_t *mmio = &REG(s, addr);
    uint32_t old = *mmio;
    bool cs_flg = false;
    bool run = false;

    if (addr >= R_MAX) {
        qemu_log_mask(LOG_UNIMP, "%s: reg WRITE @ 0x" TARGET_FMT_plx
                      " value: 0x" TARGET_FMT_plx "\n", __func__, addr, data);
        return;
    }

    switch (addr) {
    case R_CTRL:
        if (r & R_CTRL_TX_RESET) {
            fifo8_reset(&s->tx_fifo);
        }
        if (r & R_CTRL_RX_RESET) {
            fifo8_reset(&s->rx_fifo);
        }
        if (r & R_CTRL_RUN) {
            run = true;
        }
        break;
    case R_STATUS:
        r = old & (~r);
        break;
    case R_PIN:
        cs_flg = true;
        break;
    case R_TXDATA: {
        int word_size = apple_spi_word_size(s);
        if ((fifo8_is_full(&s->tx_fifo))
            || (fifo8_num_free(&s->tx_fifo) < word_size)) {
            qemu_log_mask(LOG_GUEST_ERROR, "%s: tx overflow\n", __func__);
            r = 0;
            break;
        }
        fifo8_push_all(&s->tx_fifo, (uint8_t *)&r, word_size);
        break;
    case R_CFG:
        run = true;
        break;
    }
    default:
        break;
    }

    *mmio = r;
    if (cs_flg) {
        apple_spi_update_cs(s);
    }
    if (run) {
        apple_spi_run(s);
    }
    apple_spi_update_irq(s);
}

static uint64_t apple_spi_reg_read(void *opaque,
                                   hwaddr addr,
                                   unsigned size)
{
    AppleSPIState *s = APPLE_SPI(opaque);
    uint32_t r;
    bool run = false;

    if (addr >= R_MAX) {
        qemu_log_mask(LOG_UNIMP, "%s: reg READ @ 0x" TARGET_FMT_plx "\n",
                                __func__, addr);
        return 0;
    }

    r = s->regs[addr >> 2];
    switch (addr) {
    case R_RXDATA: {
        const uint8_t *buf = NULL;
        int word_size = apple_spi_word_size(s);
        uint32_t num = 0;
        if (fifo8_is_empty(&s->rx_fifo)) {
            qemu_log_mask(LOG_GUEST_ERROR, "%s: rx underflow\n", __func__);
            r = 0;
            break;
        }
        buf = fifo8_pop_buf(&s->rx_fifo, word_size, &num);
        memcpy(&r, buf, num);
        if (fifo8_is_empty(&s->rx_fifo)) {
            run = true;
        }
        break;
    }
    case R_STATUS: {
        int val = 0;
        val |= fifo8_num_used(&s->tx_fifo) << R_STATUS_TXFIFO_SHIFT;
        val |= fifo8_num_used(&s->rx_fifo) << R_STATUS_RXFIFO_SHIFT;
        val &= (R_STATUS_TXFIFO_MASK | R_STATUS_RXFIFO_MASK);
        r &= ~(R_STATUS_TXFIFO_MASK | R_STATUS_RXFIFO_MASK);
        r |= val;
        break;
    }
    default:
        break;
    }

    if (run) {
        apple_spi_run(s);
    }
    apple_spi_update_irq(s);
    return r;
}

static const MemoryRegionOps apple_spi_reg_ops = {
    .write = apple_spi_reg_write,
    .read = apple_spi_reg_read,
    .valid.min_access_size = 4,
    .valid.max_access_size = 4,
    .endianness = DEVICE_NATIVE_ENDIAN,
};

static void apple_spi_reset(DeviceState *dev)
{
    AppleSPIState *s = APPLE_SPI(dev);

    memset(s->regs, 0, sizeof(s->regs));
    fifo8_reset(&s->tx_fifo);
    fifo8_reset(&s->rx_fifo);
}

static void apple_spi_realize(DeviceState *dev, struct Error **errp)
{
    AppleSPIState *s = APPLE_SPI(dev);
    SysBusDevice *sbd = SYS_BUS_DEVICE(dev);
    char mmio_name[32] = { 0 };
    char bus_name[32] = { 0 };

    snprintf(bus_name, sizeof(bus_name), "%s.bus", dev->id);
    s->spi = ssi_create_bus(dev, (const char *)bus_name);

    snprintf(mmio_name, sizeof(mmio_name), "%s.mmio", dev->id);
    memory_region_init_io(&s->iomem, OBJECT(dev), &apple_spi_reg_ops, s,
                          mmio_name, s->mmio_size);

    sysbus_init_mmio(sbd, &s->iomem);
    sysbus_init_irq(sbd, &s->irq);
    sysbus_init_irq(sbd, &s->cs_line);
    qdev_init_gpio_in_named(dev, apple_spi_cs_set, SSI_GPIO_CS, 1);

    fifo8_create(&s->tx_fifo, R_FIFO_DEPTH);
    fifo8_create(&s->rx_fifo, R_FIFO_DEPTH);
}

SysBusDevice *apple_spi_create(DTBNode *node)
{
    DeviceState *dev = qdev_new(TYPE_APPLE_SPI);
    SysBusDevice *sbd = SYS_BUS_DEVICE(dev);
    AppleSPIState *s = APPLE_SPI(dev);
    DTBProp *prop = find_dtb_prop(node, "reg");
    uint64_t mmio_size = ((hwaddr *)prop->value)[1];
    uint32_t data = 0;

    prop = find_dtb_prop(node, "name");
    dev->id = g_strdup((const char *)prop->value);
    s->mmio_size = mmio_size;

    data = 0;
    /* TODO: SIO */
    set_dtb_prop(node, "dma-capable", sizeof(data), (uint8_t *)&data);
    if ((prop = find_dtb_prop(node, "dma-channels")) != NULL) {
        remove_dtb_prop(node, prop);
    }
    if ((prop = find_dtb_prop(node, "dma-parent")) != NULL) {
        remove_dtb_prop(node, prop);
    }
    return sbd;
}

static void apple_spi_init(Object *obj)
{
    AppleSPIState *s = APPLE_SPI(obj);
    s->mmio_size = MMIO_SIZE;
}

static const VMStateDescription vmstate_apple_spi = {
    .name = "apple_spi",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (VMStateField[]) {
        VMSTATE_UINT32_ARRAY(regs, AppleSPIState, MMIO_SIZE >> 2),
        VMSTATE_FIFO8(rx_fifo, AppleSPIState),
        VMSTATE_FIFO8(tx_fifo, AppleSPIState),
        VMSTATE_UINT32(last_irq, AppleSPIState),
        VMSTATE_UINT32(mmio_size, AppleSPIState),
        VMSTATE_END_OF_LIST()
    }
};

static void apple_spi_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->desc = "Apple Samsung SPI Controller";

    dc->reset = apple_spi_reset;
    dc->realize = apple_spi_realize;
    dc->vmsd = &vmstate_apple_spi;
}

static const TypeInfo apple_spi_type_info = {
    .name = TYPE_APPLE_SPI,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(AppleSPIState),
    .instance_init = apple_spi_init,
    .class_init = apple_spi_class_init,
};

static void apple_spi_register_types(void)
{
    type_register_static(&apple_spi_type_info);
}

type_init(apple_spi_register_types)
