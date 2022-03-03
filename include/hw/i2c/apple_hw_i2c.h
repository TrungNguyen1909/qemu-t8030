#ifndef APPLE_HW_I2C_H
#define APPLE_HW_I2C_H

#include "hw/sysbus.h"
#include "qom/object.h"
#include "hw/arm/xnu_dtb.h"

#define TYPE_APPLE_HW_I2C "apple.hw-i2c"
OBJECT_DECLARE_SIMPLE_TYPE(AppleHWI2CState, APPLE_HW_I2C)

#define APPLE_HW_I2C_MMIO_SIZE  (0x10000)

typedef struct AppleHWI2CState {
    /*< private >*/
    SysBusDevice parent_obj;

    /*< public >*/
    MemoryRegion iomem;
    I2CBus *bus;
    qemu_irq irq;
    uint8_t reg[APPLE_HW_I2C_MMIO_SIZE];
    uint8_t read_buffer[0xff];
    uint8_t read_head;
    uint8_t read_tail;
    bool last_irq;
    bool nak;
    bool xip;
    bool is_recv;
} AppleHWI2CState;

SysBusDevice *apple_hw_i2c_create(const char *name);
#endif /* APPLE_I2C_H */
