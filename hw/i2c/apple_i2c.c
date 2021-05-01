#include "qemu/osdep.h"
#include "hw/i2c/apple_i2c.h"
#include "hw/i2c/i2c.h"
#include "hw/i2c/bitbang_i2c.h"
#include "hw/irq.h"
#include "migration/vmstate.h"
#include "qemu/bitops.h"
#include "qemu/lockable.h"
#include "qemu/log.h"
#include "qemu/module.h"
#include "qemu/timer.h"
#include "hw/arm/xnu_dtb.h"

#define rMTXFIFO    0x00
#define rMRXFIFO	0x04
#define rMCNT		0x08
#define rXFSTA		0x0C
#define rSMSTA		0x14
#define rIMASK		0x18
#define rCTL		0x1C
#define rVERSION	0x28
#define rFILTER		0x38

#define kMTXFIFOWrite		(0 << 10)
#define kMTXFIFORead		(1 << 10)
#define kMTXFIFOStop		(1 << 9)
#define kMTXFIFOStart		(1 << 8)
#define kMTXFIFOData(_d)	(((_d) & 0xff) << 0)

#define kMRXFIFOEmpty		(1 << 8)
#define kMRXFIFOData(_v)	(((_v) >> 0) & 0xff)

#define kMCNTRxCnt(_v)		(((_v) >> 8) & 0xff)
#define kMCNTTxCnt(_v)		(((_v) >> 0) & 0xff)

#define kXFSTAmst(_v)		(((_v) >> 28) & 0xf)
#define kIDLE	0
#define kXFSTAxfifo(_v)		(((_v) >> 21) & 0x3)
#define kXFSTAxcnt(_v)		(((_v) >> 0) & 0xfffff)

/* Transaction in progress */
#define kSMSTAxip			(1 << 28)

/* Transaction ended */
#define kSMSTAxen			(1 << 27)

/* Unjam failed */
#define kSMSTAujf			(1 << 26)
#define kSMSTAjmd			(1 << 25)

/* Bus jammed */
#define kSMSTAjam			(1 << 24)

/* IO error */
#define kSMSTAmto			(1 << 23)

/* NAK */
#define kSMSTAmtn			(1 << 21)

/* RX finished */
#define kSMSTAmrf			(1 << 20)
#define kSMSTAmrne			(1 << 19)
#define kSMSTAmtr			(1 << 18)

/* TX finished */
#define kSMSTAmtf			(1 << 17)
#define kSMSTAmte			(1 << 16)

/* IO error */
#define kSMSTAtom			(1 << 6)

/* reset RX */
#define kCTLMRR			    (1 << 10)

/* reset TX */
#define kCTLMTR			    (1 << 9)

/* unjam */
#define kCTLUJM			    (1 << 8)

#define kCTLCLK(_c)		    (((_c) & 0xff) << 0)

#define kMIXDIV			    4

static void apple_i2c_gpio_set(void *opaque, int line, int level)
{
    AppleI2CState *s = APPLE_I2C(opaque);
    level = bitbang_i2c_set(&s->bitbang, line, level);
    if (level != s->last_level) {
        s->last_level = level;
        qemu_set_irq(s->out, level);
    }
}

static void i2c_reg_write(void *opaque,
                  hwaddr addr,
                  uint64_t data,
                  unsigned size){
    qemu_log_mask(LOG_UNIMP, "I2C: reg WRITE @ 0x" TARGET_FMT_plx " value: 0x" TARGET_FMT_plx "\n", addr, data);    
}
static uint64_t i2c_reg_read(void *opaque,
                     hwaddr addr,
                     unsigned size){
    qemu_log_mask(LOG_UNIMP, "I2C: reg READ @ 0x" TARGET_FMT_plx "\n", addr);
    return 0;
}
static const MemoryRegionOps i2c_reg_ops = {
    .write = i2c_reg_write,
    .read = i2c_reg_read,
    .valid.min_access_size = 4,
    .valid.max_access_size = 4,
    .endianness = DEVICE_NATIVE_ENDIAN,
};

DeviceState *apple_i2c_create(DTBNode *node)
{
    DeviceState *dev = qdev_new(TYPE_APPLE_I2C);
    SysBusDevice *sbd = SYS_BUS_DEVICE(dev);
    AppleI2CState *s = APPLE_I2C(dev);
    DTBProp *prop = get_dtb_prop(node, "reg");
    uint64_t mmio_size = ((hwaddr*)prop->value)[1];
    prop = get_dtb_prop(node, "name");
    dev->id = g_strdup((const char*)prop->value);
    memory_region_init_io(&s->iomem, OBJECT(dev), &i2c_reg_ops, s, (const char*)prop->value, mmio_size);
    char bus_name[32] = { 0 };
    snprintf(bus_name, sizeof(bus_name), "%s.bus", (const char*)prop->value);
    s->bus = i2c_init_bus(dev, (const char*)bus_name);
    sysbus_init_mmio(sbd, &s->iomem);
    prop = get_dtb_prop(node, "compatible");
    g_free(prop->value);
    // Force soft I2C as we haven't support multi-master yet.
    // TODO: I2C multi-master
    prop->value = (uint8_t*)g_strdup("iic,soft");
    prop->length = 9;
    qdev_init_gpio_in(dev, apple_i2c_gpio_set, 2);
    qdev_init_gpio_out(dev, &s->out, 1);
    sysbus_init_irq(sbd, &s->irq);

    bitbang_i2c_init(&s->bitbang, s->bus);
    return dev;
}

static void apple_i2c_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->desc = "Apple I2C Controller";
}

static const TypeInfo apple_i2c_type_info = {
    .name = TYPE_APPLE_I2C,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(AppleI2CState),
    .class_init = apple_i2c_class_init,
};

static void apple_i2c_register_types(void)
{
    type_register_static(&apple_i2c_type_info);
}

type_init(apple_i2c_register_types)