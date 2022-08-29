#ifndef HW_SPMI_APPLE_SPMI_H
#define HW_SPMI_APPLE_SPMI_H

#include "qemu/osdep.h"
#include "qemu/queue.h"
#include "hw/sysbus.h"
#include "qom/object.h"
#include "qemu/fifo32.h"
#include "hw/spmi/spmi.h"
#include "hw/arm/xnu_dtb.h"

#define TYPE_APPLE_SPMI     "apple.spmi"
OBJECT_DECLARE_TYPE(AppleSPMIState, AppleSPMIClass, APPLE_SPMI)
#define APPLE_SPMI_MMIO_SIZE    (0x4000)

typedef struct AppleSPMIClass {
    /*< private >*/
    SysBusDeviceClass parent_class;
    ResettablePhases parent_phases;

    /*< public >*/
} AppleSPMIClass;

struct AppleSPMIState {
    SysBusDevice parent_obj;
    MemoryRegion container;
    MemoryRegion iomems[4];
    SPMIBus *bus;
    qemu_irq irq;
    qemu_irq resp_irq;
    Fifo32 resp_fifo;
    uint32_t control_reg[0x100 / sizeof(uint32_t)];
    uint32_t queue_reg[0x100 / sizeof(uint32_t)];
    uint32_t fault_reg[0x100 / sizeof(uint32_t)];
    uint32_t fault_counter_reg[0x64 / sizeof(uint32_t)];
    uint32_t resp_intr_index;
    uint32_t reg_vers;
    uint32_t *data;
    uint32_t data_length;
    uint32_t data_filled;
    uint32_t command;
};

SysBusDevice *apple_spmi_create(DTBNode *node);

#endif /* HW_SPMI_APPLE_SPMI_H */
