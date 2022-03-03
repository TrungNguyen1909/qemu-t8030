#include "qemu/osdep.h"
#include "hw/ssi/apple_spi.h"
#include "hw/ssi/ssi.h"
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
#define  R_CFG_CPHA              (1 << 1)
#define  R_CFG_CPOL              (1 << 2)
#define  R_CFG_MODE(_x)          (((_x) >> 5) & 0x3)
#define  R_CFG_MODE_POLLED       0
#define  R_CFG_MODE_IRQ          1
#define  R_CFG_MODE_DMA          2
#define  R_CFG_IE_RXCOMPLETE     (1 << 7)
#define  R_CFG_IE_TXRXTHRESH     (1 << 8)
#define  R_CFG_LSB_FIRST	     (1 << 13)
#define  R_CFG_WORD_SIZE(_x)     (((_x) >> 15) & 0x3)
#define  R_CFG_WORD_SIZE_8B      0
#define  R_CFG_WORD_SIZE_16B     1
#define  R_CFG_WORD_SIZE_32B     2
#define  R_CFG_FIFO_THRESH(_x)   (((_x) >> 17) & 0x3)
#define  R_CFG_FIFO_THRESH_8B    0
#define  R_CFG_FIFO_THRESH_4B    1
#define  R_CFG_FIFO_THRESH_1B    2
#define  R_CFG_IE_TXCOMPLETE     (1 << 21)

#define R_STATUS                0x008
#define  R_STATUS_RXCOMPLETE	 (1 << 0)
#define  R_STATUS_TXRXTHRESH     (1 << 1)
#define  R_STATUS_TXCOMPLETE     (1 << 2)

#define R_PIN                   0x00c
#define  R_PIN_KEEP_MOSI         (1 << 0)
#define  R_PIN_CS                (1 << 1)

#define R_TXDATA                0x010
#define R_RXDATA                0x020
#define R_CLKDIV                0x030
#define  R_CLKDIV_MAX            0x7ff
#define R_RXCNT                 0x034
#define R_WORD_DELAY            0x038
#define R_TXCNT                 0x04c

#define R_FIFOSTAT              0x10c
#define  R_FIFOSTAT_TXFULL       (1 << 4)
#define  R_FIFOSTAT_LEVEL_TX(_x) (((_x) & 0xff) << 8)
#define  R_FIFOSTAT_RXEMPTY      (1 << 20)
#define  R_FIFOSTAT_LEVEL_RX(_x) (((_x) & 0xff) << 24)

#define R_IE_XFER               0x130
#define R_IF_XFER               0x134
#define  R_XFER_RXCOMPLETE       (1 << 0)
#define  R_XFER_TXCOMPLETE       (1 << 1)

#define R_IE_FIFO               0x138
#define R_IF_FIFO               0x13c
#define  R_FIFO_RXTHRESH         (1 << 4)
#define  R_FIFO_TXTHRESH         (1 << 5)
#define  R_FIFO_RXFULL           (1 << 8)
#define  R_FIFO_TXEMPTY          (1 << 9)
#define  R_FIFO_RXUNDERRUN       (1 << 16)
#define  R_FIFO_TXOVERFLOW       (1 << 17)

#define R_SHIFTCFG              0x150
#define  R_SHIFTCFG_CLK_ENABLE   (1 << 0)
#define  R_SHIFTCFG_CS_ENABLE    (1 << 1)
#define  R_SHIFTCFG_AND_CLK_DATA (1 << 8)
#define  R_SHIFTCFG_CS_AS_DATA   (1 << 9)
#define  R_SHIFTCFG_TX_ENABLE    (1 << 10)
#define  R_SHIFTCFG_RX_ENABLE    (1 << 11)
#define  R_SHIFTCFG_BITS(_x)     (((_x) >> 16) & 0x3f)
#define  R_SHIFTCFG_OVERRIDE_CS  (1 << 24)

#define R_PINCFG                0x154
#define  R_PINCFG_KEEP_CLK       (1 << 0)
#define  R_PINCFG_KEEP_CS        (1 << 1)
#define  R_PINCFG_KEEP_MOSI      (1 << 2)
#define  R_PINCFG_CLK_IDLE_VAL   (1 << 8)
#define  R_PINCFG_CS_IDLE_VAL    (1 << 9)
#define  R_PINCFG_MOSI_IDLE_VAL  (1 << 10)

#define R_DELAY_PRE             0x160
#define R_DELAY_POST            0x168
#define  R_DELAY_ENABLE          (1 << 0)
#define  R_DELAY_NO_INTERBYTE    (1 << 1)
#define  R_DELAY_SET_SCK         (1 << 4)
#define  R_DELAY_SET_MOSI        (1 << 6)
#define  R_DELAY_SCK_VAL         (1 << 8)
#define  R_DELAY_MOSI_VAL        (1 << 12)
#define R_MAX                   (0x170)

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

static int apple_spi_thresh_size(AppleSPIState *s)
{
    /* XXX: These are in bits, but we are transferring by bytes anyway */
    switch (R_CFG_FIFO_THRESH(REG(s, R_CFG))) {
    case R_CFG_FIFO_THRESH_8B:
        return 1;
        break;
    case R_CFG_FIFO_THRESH_4B:
    case R_CFG_FIFO_THRESH_1B:
    default:
        return 0;
        break;
    }
    g_assert_not_reached();
}

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

static void apple_spi_update_fifo(AppleSPIState *s)
{
    uint32_t r = REG(s, R_IF_FIFO);
    r &= ~(R_FIFO_TXTHRESH | R_FIFO_RXTHRESH);
    if (REG(s, R_CFG) & R_CFG_IE_TXRXTHRESH) {
        if (fifo8_num_used(&s->tx_fifo) <= apple_spi_thresh_size(s)) {
            r |= R_FIFO_TXTHRESH;
        }
        if (fifo8_num_free(&s->rx_fifo) <= apple_spi_thresh_size(s)) {
            r |= R_FIFO_RXTHRESH;
        }
    }
    if (fifo8_is_empty(&s->tx_fifo)) {
        r |= R_FIFO_TXEMPTY;
    } else {
        r &= ~R_FIFO_TXEMPTY;
    }
    if (fifo8_is_full(&s->rx_fifo)) {
        r |= R_FIFO_RXFULL;
    } else {
        r &= ~R_FIFO_RXFULL;
    }

    REG(s, R_IF_FIFO) = r;
}

static void apple_spi_update_xfer(AppleSPIState *s)
{
    uint32_t r = REG(s, R_IF_XFER);

    if (REG(s, R_TXCNT) == 0) {
        REG(s, R_STATUS) |= R_STATUS_TXCOMPLETE;
        if (REG(s, R_CFG) & R_CFG_IE_TXCOMPLETE) {
            r |= R_XFER_TXCOMPLETE;
        }
    }

    if (REG(s, R_RXCNT) == 0) {
        REG(s, R_STATUS) |= R_STATUS_RXCOMPLETE;
        r |= R_XFER_RXCOMPLETE;
    }

    REG(s, R_IF_XFER) = r;
}

static void apple_spi_update_irq(AppleSPIState *s)
{
    uint32_t irq = 0;

    apple_spi_update_fifo(s);

    if (REG(s, R_IE_XFER) & REG(s, R_IF_XFER)) {
        irq = 1;
    }
    if (REG(s, R_IE_FIFO) & REG(s, R_IF_FIFO)) {
        irq = 1;
    }
    if (irq != s->last_irq) {
        s->last_irq = irq;
        qemu_set_irq(s->irq, irq);
    }
}

static void apple_spi_update_cs(AppleSPIState *s)
{
    qemu_set_irq(s->cs_line, (REG(s, R_PIN) & R_PIN_CS) != 0);
}

static void apple_spi_flush_txfifo(AppleSPIState *s)
{
    uint32_t tx;
    uint32_t rx;

    if (!(REG(s, R_CTRL) & R_CTRL_RUN)) {
        return;
    }

    while (!fifo8_is_empty(&s->tx_fifo)) {
        tx = (uint32_t)fifo8_pop(&s->tx_fifo);
        rx = ssi_transfer(s->spi, tx);
        REG(s, R_TXCNT)--;
        REG(s, R_RXCNT)--;
        if (fifo8_is_full(&s->rx_fifo)) {
            REG(s, R_IF_FIFO) |= R_FIFO_RXUNDERRUN;
        } else {
            fifo8_push(&s->rx_fifo, (uint8_t)rx);
            apple_spi_update_fifo(s);
        }
        apple_spi_update_xfer(s);
    }
}

static void apple_spi_reg_write(void *opaque,
                                hwaddr addr,
                                uint64_t data,
                                unsigned size)
{
    AppleSPIState *s = APPLE_SPI(opaque);
    uint32_t r = data;

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
        break;
    case R_PIN:
        apple_spi_update_cs(s);
        break;
    case R_TXDATA: {
        int word_size = apple_spi_word_size(s);
        if ((fifo8_is_full(&s->tx_fifo))
            || (fifo8_num_free(&s->tx_fifo) < word_size)) {
            REG(s, R_IF_FIFO) |= R_FIFO_TXOVERFLOW;
            r = 0;
            break;
        }
        fifo8_push_all(&s->tx_fifo, (uint8_t *)&r, word_size);
        apple_spi_flush_txfifo(s);
        break;
    }
    default:
        qemu_log_mask(LOG_UNIMP, "%s: reg WRITE @ 0x" TARGET_FMT_plx
                      " value: 0x" TARGET_FMT_plx "\n", __func__, addr, data);
        break;
    }

    s->regs[addr >> 2] = r;
    apple_spi_update_irq(s);
}

static uint64_t apple_spi_reg_read(void *opaque,
                                   hwaddr addr,
                                   unsigned size)
{
    AppleSPIState *s = APPLE_SPI(opaque);
    uint32_t r;

    if (addr >= R_MAX) {
        qemu_log_mask(LOG_UNIMP, "%s: reg READ @ 0x" TARGET_FMT_plx "\n",
                                __func__, addr);
        return 0;
    }

    r = s->regs[addr >> 2];
    switch (addr) {
    case R_FIFOSTAT: {
        int word_size = apple_spi_word_size(s);
        r = 0;
        r |= R_FIFOSTAT_LEVEL_TX(fifo8_num_used(&s->tx_fifo) / word_size);
        if (fifo8_is_full(&s->tx_fifo)) {
            r |= R_FIFOSTAT_TXFULL;
        }
        r |= R_FIFOSTAT_LEVEL_RX(fifo8_num_used(&s->rx_fifo) / word_size);
        if (fifo8_is_empty(&s->rx_fifo)) {
            r |= R_FIFOSTAT_RXEMPTY;
        }
        break;
    }
    case R_RXDATA: {
        const uint8_t *buf = NULL;
        int word_size = apple_spi_word_size(s);
        uint32_t num = 0;
        if (fifo8_is_empty(&s->rx_fifo)) {
            REG(s, R_IF_FIFO) |= R_FIFO_RXUNDERRUN;
            r = 0;
            break;
        }
        buf = fifo8_pop_buf(&s->rx_fifo, word_size, &num);
        memcpy(&r, buf, num);
        break;
    }
    default:
        qemu_log_mask(LOG_UNIMP, "%s: reg READ @ 0x" TARGET_FMT_plx "\n",
                                __func__, addr);
        break;
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

    fifo8_create(&s->tx_fifo, R_FIFO_MAX_DEPTH);
    fifo8_create(&s->rx_fifo, R_FIFO_MAX_DEPTH);

    data = 0;
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
