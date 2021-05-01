#ifndef APPLE_TRISTAR_H
#define APPLE_TRISTAR_H

#include "hw/sysbus.h"
#include "qom/object.h"
#include "hw/arm/xnu_dtb.h"
#include "hw/i2c/i2c.h"

#define TYPE_APPLE_TRISTAR "apple.tristar"
OBJECT_DECLARE_SIMPLE_TYPE(AppleTristarState, APPLE_TRISTAR)

struct AppleTristarState {
    /*< private >*/
    SysBusDevice parent_obj;

    /*< public >*/
    qemu_irq irq[2];

    uint32_t address;
    uint32_t mode;

    uint8_t mask;
    uint8_t key_esn[8];
    uint8_t enonce_m[8];
    uint8_t esn[8];
};

DeviceState *apple_tristar_create(DTBNode *node);
#endif /* APPLE_I2C_H */
