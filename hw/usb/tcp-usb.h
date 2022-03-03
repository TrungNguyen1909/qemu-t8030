#ifndef HW_USB_TCP_USB_H
#define HW_USB_TCP_USB_H

#include "qemu/osdep.h"
#include "hw/usb.h"

static const char *socket_path = "/tmp/usbqemu";

enum {
    TCP_USB_REQUEST  = (1 << 0),
    TCP_USB_RESPONSE = (1 << 1),
    TCP_USB_RESET    = (1 << 2),
    TCP_USB_CANCEL   = (1 << 3)
};

typedef struct QEMU_PACKED tcp_usb_header {
    uint8_t type;
} tcp_usb_header_t;

typedef struct QEMU_PACKED tcp_usb_request_header {
    uint8_t addr;
    int pid;
    uint8_t ep;
    unsigned int stream;
    uint64_t id;
    uint8_t short_not_ok;
    uint8_t int_req;
    uint16_t length;
} tcp_usb_request_header;

typedef struct QEMU_PACKED tcp_usb_response_header {
    uint8_t addr;
    int pid;
    uint8_t ep;
    uint64_t id;
    uint32_t status;
    uint16_t length;
} tcp_usb_response_header;

typedef struct QEMU_PACKED tcp_usb_cancel_header {
    uint8_t addr;
    int pid;
    uint8_t ep;
    uint64_t id;

} tcp_usb_cancel_header;

#endif //HW_USB_TCP_USB_H
