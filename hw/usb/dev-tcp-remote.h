#ifndef HW_USB_DEV_TCP_REMOTE_H
#define HW_USB_DEV_TCP_REMOTE_H

#include "qemu/osdep.h"
#include "hw/usb.h"
#include "qom/object.h"
#include "tcp-usb.h"
#include "qemu/main-loop.h"

typedef struct USBTCPInflightPacket {
    USBPacket *p;
    uint32_t handled;
    QemuCond c;
    QemuMutex m;

    QTAILQ_ENTRY(USBTCPInflightPacket) queue;

    uint8_t addr;
} USBTCPInflightPacket;

typedef struct USBTCPCompletedPacket {
    USBPacket *p;
    QTAILQ_ENTRY(USBTCPCompletedPacket) queue;
    uint8_t addr;
} USBTCPCompletedPacket;


typedef struct USBTCPRemoteState {
    USBDevice parent_obj;

    QemuThread thread;
    QemuThread read_thread;
    QemuCond cond;
    QemuMutex mutex;
    QemuMutex request_mutex;

    QemuMutex queue_mutex;
    QTAILQ_HEAD(, USBTCPInflightPacket) queue;

    QemuMutex completed_queue_mutex;
    QTAILQ_HEAD(, USBTCPCompletedPacket) completed_queue;
    QEMUBH *completed_bh;

    int socket;
    int fd;
    uint8_t addr;
    bool closed;
    bool stopped;
} USBTCPRemoteState;

#define TYPE_USB_TCP_REMOTE "usb-tcp-remote"
OBJECT_DECLARE_SIMPLE_TYPE(USBTCPRemoteState, USB_TCP_REMOTE)

#endif //HW_USB_DEV_TCP_REMOTE_H
