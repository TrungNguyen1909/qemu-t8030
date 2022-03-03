#include "qemu/osdep.h"
#include "hw/i2c/apple_hw_i2c.h"
#include "hw/i2c/i2c.h"
#include "hw/irq.h"
#include "migration/vmstate.h"
#include "qemu/bitops.h"
#include "qemu/lockable.h"
#include "qemu/log.h"
#include "qemu/module.h"
#include "qemu/timer.h"
#include "hw/arm/xnu_dtb.h"

//#define DEBUG_APPLE_HW_I2C

#define MMIO_SIZE   (0x10000)

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
#define kMTXFIFOData(_v)	(((_v) >> 0) & 0xff)

#define kMRXFIFOEmpty		(1 << 8)
#define kMRXFIFOData(_d)	(((_d) & 0xff) << 0)

#define kMCNTRxCnt(_v)		(((_v) & 0xff) << 8)
#define kMCNTTxCnt(_v)		(((_v) & 0xff) << 0)

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

#define REG(_s,_x) *(uint32_t *)&_s->reg[_x]

static void apple_hw_i2c_update_irq(AppleHWI2CState *s)
{
    bool level = false;
    if (REG(s, rSMSTA) & REG(s, rIMASK)) {
        level = true;
    } else {
        level = false;
    }
    if (level != s->last_irq) {
        qemu_set_irq(s->irq, level);
    }
}

static void apple_hw_i2c_reg_write(void *opaque,
                  hwaddr addr,
                  uint64_t data,
                  unsigned size)
{
    AppleHWI2CState *s = APPLE_HW_I2C(opaque);
    #ifdef DEBUG_APPLE_HW_I2C
    qemu_log_mask(LOG_UNIMP, "I2C: reg WRITE @ 0x" TARGET_FMT_plx
                             " value: 0x" TARGET_FMT_plx "\n", addr, data);
    #endif

    uint32_t *mmio = (uint32_t *)&s->reg[addr];
    uint32_t value = data;
    uint32_t orig = *mmio;
    bool iflg = false;

    switch (addr) {
    case rMTXFIFO: {
        uint8_t addr = kMTXFIFOData(value) >> 1;
        iflg = true;
        if ((value & kMTXFIFOStart)) {

            if (kMTXFIFOData(value) & 1) {
                s->is_recv = true;
                s->read_head = s->read_tail = 0;
                //assert(kMTXFIFOData(value) & 1);
            } else {
                s->is_recv = false;
                //assert((kMTXFIFOData(value) & 1) == 0);
            }
            if (i2c_start_transfer(s->bus, addr, s->is_recv) != 0) {
                qemu_log_mask(LOG_GUEST_ERROR,
                              "I2C: can't find device @ 0x%x\n", addr);
                REG(s, rSMSTA) |= kSMSTAmtn;
                break;
            }

            if (s->is_recv) {
                REG(s, rSMSTA) |= kSMSTAmrne;
            }
            s->xip = true;
            REG(s, rSMSTA) |= kSMSTAxip;
        } else if (s->xip) {
            if (value & kMTXFIFORead) {
                uint8_t len = kMTXFIFOData(value);
                //printf("I2C: Receiving 0x%x bytes\n", len);
                if (!s->is_recv) {
                    s->is_recv = 1;
                    if (i2c_start_transfer(s->bus, addr, s->is_recv) != 0) {
                        REG(s, rSMSTA) |= kSMSTAmtn;
                        break;
                    }
                }
                while (len--) {
                    s->read_buffer[s->read_tail++] = i2c_recv(s->bus);
                }
            } else {
                if (s->is_recv) {
                    s->is_recv = 0;
                    if (i2c_start_transfer(s->bus, addr, s->is_recv) != 0) {
                        REG(s, rSMSTA) |= kSMSTAmtn;
                        break;
                    }
                }
                if (i2c_send(s->bus, kMTXFIFOData(value))) {
                    REG(s, rSMSTA) |= kSMSTAmtn;
                    /* XXX: Should we end it here? */
                }
            }
        }
        if (value & kMTXFIFOStop) {
            if (s->xip) {
                if (!s->is_recv && i2c_send(s->bus, kMTXFIFOData(value))) {
                    REG(s, rSMSTA) |= kSMSTAmtn;
                }
                i2c_end_transfer(s->bus);
                REG(s, rSMSTA) |= kSMSTAxen;
            }
        }
        break;
    }
    case rSMSTA:
        value = orig & (~value);
        break;
    case rCTL:
        if (value & kCTLMRR) {
            s->read_head = s->read_tail = 0;
        }
        value = 0;
        break;
    default:
        break;
    }

    if (iflg) {
        apple_hw_i2c_update_irq(s);
    }
    *mmio = value;
}

static uint64_t apple_hw_i2c_reg_read(void *opaque,
                     hwaddr addr,
                     unsigned size)
{
    AppleHWI2CState *s = APPLE_HW_I2C(opaque);
    uint32_t *mmio = (uint32_t *)&s->reg[addr];
    uint32_t value = *mmio;

    switch (addr) {
    case rMRXFIFO:
        if (s->read_head >= s->read_tail) {
            value = kMRXFIFOEmpty;
            break;
        }
        value = kMRXFIFOData(s->read_buffer[s->read_head++]);
        break;
    case rMCNT:
        value = kMCNTRxCnt(s->read_tail - s->read_head);
        break;
    default:
        break;
    }

    #ifdef DEBUG_APPLE_HW_I2C
    qemu_log_mask(LOG_UNIMP, "I2C: reg READ @ 0x" TARGET_FMT_plx
                             " value: 0x%x\n", addr, value);
    #endif
    return value;
}

static const MemoryRegionOps i2c_reg_ops = {
    .write = apple_hw_i2c_reg_write,
    .read = apple_hw_i2c_reg_read,
    .valid.min_access_size = 4,
    .valid.max_access_size = 4,
    .endianness = DEVICE_NATIVE_ENDIAN,
};

SysBusDevice *apple_hw_i2c_create(const char *name)
{
    DeviceState *dev = qdev_new(TYPE_APPLE_HW_I2C);
    SysBusDevice *sbd = SYS_BUS_DEVICE(dev);
    AppleHWI2CState *s = APPLE_HW_I2C(dev);
    char bus_name[32] = { 0 };

    dev->id = g_strdup(name);
    snprintf(bus_name, sizeof(bus_name), "%s.bus", name);
    s->bus = i2c_init_bus(dev, bus_name);
    memory_region_init_io(&s->iomem, OBJECT(dev),
                          &i2c_reg_ops, s, dev->id, MMIO_SIZE);
    sysbus_init_mmio(sbd, &s->iomem);
    sysbus_init_irq(sbd, &s->irq);

    s->last_irq = 0;

    return sbd;
}

static const VMStateDescription vmstate_apple_hw_i2c = {
    .name = "apple_hw_i2c",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (VMStateField[]) {
        VMSTATE_UINT8_ARRAY(reg, AppleHWI2CState, APPLE_HW_I2C_MMIO_SIZE),
        VMSTATE_UINT8_ARRAY(read_buffer, AppleHWI2CState, 0xff),
        VMSTATE_UINT8(read_head, AppleHWI2CState),
        VMSTATE_UINT8(read_tail, AppleHWI2CState),
        VMSTATE_BOOL(last_irq, AppleHWI2CState),
        VMSTATE_BOOL(nak, AppleHWI2CState),
        VMSTATE_BOOL(xip, AppleHWI2CState),
        VMSTATE_BOOL(is_recv, AppleHWI2CState),
        VMSTATE_END_OF_LIST()
    }
};

static void apple_hw_i2c_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->desc = "Apple HW I2C Controller";
    dc->vmsd = &vmstate_apple_hw_i2c;
}

static const TypeInfo apple_hw_i2c_type_info = {
    .name = TYPE_APPLE_HW_I2C,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(AppleHWI2CState),
    .class_init = apple_hw_i2c_class_init,
};

static void apple_hw_i2c_register_types(void)
{
    type_register_static(&apple_hw_i2c_type_info);
}

type_init(apple_hw_i2c_register_types)
