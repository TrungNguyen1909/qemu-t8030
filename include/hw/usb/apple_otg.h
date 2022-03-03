#ifndef APPLE_OTG_H
#define APPLE_OTG_H

#include "hw/sysbus.h"
#include "qom/object.h"
#include "hw/arm/xnu_dtb.h"
#include "hw/usb/hcd-dwc2.h"
#include "hw/usb/hcd-tcp.h"

#define TYPE_APPLE_OTG "apple.otg"
OBJECT_DECLARE_SIMPLE_TYPE(AppleOTGState, APPLE_OTG)

struct AppleOTGState {
    SysBusDevice parent_obj;
    MemoryRegion phy;
    uint8_t      phy_reg[0x20];
    MemoryRegion usbctl;
    uint8_t      usbctl_reg[0x1000];
    MemoryRegion widget;
    uint8_t      widget_reg[0x100];
    MemoryRegion dwc2_mr;
    MemoryRegion dma_container_mr;
    MemoryRegion *dma_mr;
    DWC2State    dwc2;
    uint64_t high_addr;
    union {
        struct USBTCPHostState usbtcp;
        DeviceState usbhcd;
    };
    char *fuzz_input;
    bool dart;
};

DeviceState *apple_otg_create(DTBNode *node);
#endif
