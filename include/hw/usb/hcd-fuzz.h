#ifndef HW_USB_HCD_FUZZ_H
#define HW_USB_HCD_FUZZ_H

#include "qemu/osdep.h"
#include "hw/sysbus.h"
#include "qom/object.h"
#include "hw/usb.h"
#include "io/channel.h"
#include "qemu/coroutine.h"
#include "qapi/error.h"
#include "qemu/main-loop.h"

#define TYPE_USB_FUZZ_HOST "usb-fuzz-host"
OBJECT_DECLARE_SIMPLE_TYPE(USBFuzzHostState, USB_FUZZ_HOST)

struct fuzz_packet {
    USBPacket p;
    void *buffer;
    int nakcnt;
    int setup_state;
    int setup_index;
    struct usb_control_packet setup;
    bool zlp;
};

enum dev_state {
    STATE_NONE = 0,
    STATE_GET_DESC_64,
    STATE_SET_ADDR,
    STATE_GET_DESC_18,
    STATE_SET_CONFIG_1,
    STATE_SET_CONFIG_0,
    STATE_SET_CONFIG_4,
    STATE_GET_CONFIG,
    STATE_SET_INTERFACE,
    STATE_GET_INTERFACE,
    STATE_GET_MAC,
    STATE_VERSION,
    STATE_VERSION_IN,
    STATE_SETUP,
    STATE_INPUT,
    STATE_OUTPUT,
    STATE_END,
};

struct USBFuzzHostState {
    SysBusDevice parent_obj;

    USBBus bus;
    USBPort uport;
    USBPort uport2;
    char *input_file;
    int fd;
    Error *migration_blocker;
    QEMUBH *bh;
    bool closed;
    bool stopped;
    QEMUTimer *timer;
    struct fuzz_packet *pkt;
    enum dev_state state;
    unsigned char host_mac[6];
    unsigned char device_mac[6];
    int mux_version;
    int mps;
    uint16_t sport, dport;
    uint32_t tx_seq, tx_ack, tx_win;
    uint32_t rx_seq, rx_ack, rx_win;
    uint32_t max_payload;
    uint16_t dev_tx_seq, dev_rx_seq;


};

#endif /* HW_USB_HCD_FUZZ_H */
