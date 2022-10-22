#ifndef APPLE_I2C_H
#define APPLE_I2C_H

#include "hw/sysbus.h"
#include "qom/object.h"
#include "qemu/fifo8.h"
#include "hw/arm/xnu_dtb.h"

#define TYPE_APPLE_I2C "apple.i2c"
OBJECT_DECLARE_TYPE(AppleI2CState, AppleHWI2CClass, APPLE_I2C)

#define APPLE_I2C_MMIO_SIZE  (0x10000)
#define APPLE_I2C_SDA        "i2c.sda"
#define APPLE_I2C_SCL        "i2c.scl"

typedef struct AppleHWI2CClass {
    /*< private >*/
    SysBusDeviceClass parent_class;
    ResettablePhases parent_phases;

    /*< public >*/
} AppleHWI2CClass;

typedef struct AppleI2CState {
    /*< private >*/
    SysBusDevice parent_obj;

    /*< public >*/
    MemoryRegion iomem;
    I2CBus *bus;
    qemu_irq irq;
    qemu_irq sda, scl;
    uint8_t reg[APPLE_I2C_MMIO_SIZE];
    Fifo8 rx_fifo;
    bool last_irq;
    bool nak;
    bool xip;
    bool is_recv;
} AppleI2CState;

SysBusDevice *apple_i2c_create(const char *name);
#endif /* APPLE_I2C_H */
