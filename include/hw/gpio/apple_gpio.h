#ifndef APPLE_GPIO_H
#define APPLE_GPIO_H

#include "hw/sysbus.h"
#include "qom/object.h"
#include "hw/arm/xnu_dtb.h"

#define TYPE_APPLE_GPIO "apple.gpio"
OBJECT_DECLARE_SIMPLE_TYPE(AppleGPIOState, APPLE_GPIO)

typedef struct {
    uint32_t value;
    bool interrupted;
} AppleGPIOPinState;

struct AppleGPIOState {
    SysBusDevice parent_obj;
    MemoryRegion *iomem;
    uint64_t npins, nirqgrps;
    qemu_irq *irqs;
    qemu_irq *out;

    uint32_t *gpio_cfg;
    uint32_t **int_cfg;
    uint32_t *in;
    uint32_t *old_in;
    uint32_t npl;
    uint32_t phandle;
};

DeviceState *apple_gpio_create(DTBNode* node);
#endif
