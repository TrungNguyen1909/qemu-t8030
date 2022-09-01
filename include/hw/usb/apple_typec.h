#ifndef APPLE_TYPEC_H
#define APPLE_TYPEC_H

#include "hw/sysbus.h"
#include "qom/object.h"
#include "hw/arm/xnu_dtb.h"
#include "hw/usb/hcd-dwc2.h"
#include "hw/usb/hcd-dwc3.h"
#include "hw/usb/hcd-tcp.h"

#define TYPE_APPLE_TYPEC "apple.typec"
OBJECT_DECLARE_SIMPLE_TYPE(AppleTypeCState, APPLE_TYPEC)

#define ATC_USB_MMIO_SIZE   (0x200000)

typedef struct AppleTypeCState {
    SysBusDevice parent_obj;
    MemoryRegion phy;
    MemoryRegion config;
    uint8_t      phy_reg[0x100];
    uint8_t      config_reg[0x4000];
    MemoryRegion container;
    MemoryRegion dwc3_mr;
    MemoryRegion dma_container_mr;
    MemoryRegion *dma_mr;
    DWC2State    dwc2;
    DWC3State    dwc3;
    SysBusDevice *host;
} AppleTypeCState;

DeviceState *apple_typec_create(DTBNode *node);
#endif
