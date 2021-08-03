#ifndef HW_USB_HCD_TCP_H
#define HW_USB_HCD_TCP_H

#include "qemu/osdep.h"
#include "hw/sysbus.h"
#include "qom/object.h"
#include "hw/usb.h"
#include "io/channel.h"
#include "qemu/coroutine.h"

#define TYPE_USB_TCP_HOST "usb-tcp-host"
OBJECT_DECLARE_SIMPLE_TYPE(USBTCPHostState, USB_TCP_HOST)

typedef struct USBTCPPacket {
    USBPacket p;
    void *buffer;
    USBDevice *dev;
    USBTCPHostState *s;
    uint8_t addr;
} USBTCPPacket;

struct USBTCPHostState {
    SysBusDevice parent_obj;

    USBBus bus;
    USBPort uport;
    USBPort uport2;
    QIOChannel *ioc;
    CoMutex write_mutex;
    bool closed;
    bool stopped;
};

#endif //HW_USB_HCD_TCP_H
