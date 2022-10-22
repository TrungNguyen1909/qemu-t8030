#ifndef APPLE_SOFT_I2C_H
#define APPLE_SOFT_I2C_H

#include "hw/sysbus.h"
#include "qom/object.h"
#include "hw/arm/xnu_dtb.h"
#include "hw/i2c/bitbang_i2c.h"

#define TYPE_APPLE_SOFT_I2C "apple.i2c.soft"
OBJECT_DECLARE_SIMPLE_TYPE(AppleSoftI2CState, APPLE_SOFT_I2C)

struct AppleSoftI2CState {
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

DeviceState *apple_soft_i2c_create(DTBNode *node);
#endif /* APPLE_SOFT_I2C_H */
