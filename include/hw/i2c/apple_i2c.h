#ifndef APPLE_I2C_H
#define APPLE_I2C_H

#include "hw/sysbus.h"
#include "qom/object.h"
#include "hw/arm/xnu_dtb.h"
#include "hw/i2c/bitbang_i2c.h"

#define TYPE_APPLE_I2C "apple.i2c"
OBJECT_DECLARE_SIMPLE_TYPE(AppleI2CState, APPLE_I2C)

struct AppleI2CState {
    /*< private >*/
    SysBusDevice parent_obj;
    bitbang_i2c_interface bitbang;
    int last_level;

    /*< public >*/
    MemoryRegion iomem;
    I2CBus *bus;
    qemu_irq irq;
    qemu_irq out;
};

DeviceState *apple_i2c_create(DTBNode *node);
#endif /* APPLE_I2C_H */
