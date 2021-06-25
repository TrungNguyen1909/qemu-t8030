#ifndef HW_USB_HCD_TCP_H
#define HW_USB_HCD_TCP_H

#include "qemu/osdep.h"
#include "hw/sysbus.h"
#include "qom/object.h"
#include "hw/usb.h"

#define TYPE_USB_TCP_HOST "usb-tcp-host"
OBJECT_DECLARE_SIMPLE_TYPE(USBTCPHostState, USB_TCP_HOST)

typedef struct USBTCPPacket {
    USBPacket p;
    void *buffer;
    USBDevice *dev;
    QTAILQ_ENTRY(USBTCPPacket) queue;
} USBTCPPacket;

struct USBTCPHostState {
    SysBusDevice parent_obj;

    USBBus bus;
    USBPort uport;
    USBPort uport2;
    QemuThread read_thread;
    QemuMutex mutex;
    QemuMutex write_mutex;
    QemuCond cond;
    QemuMutex queue_mutex;
    QTAILQ_HEAD(, USBTCPPacket) queue;
    QEMUBH *bh;
    int socket;
    char *host;
    uint32_t port;
    bool closed;
    bool stopped;
};

#endif //HW_USB_HCD_TCP_H
