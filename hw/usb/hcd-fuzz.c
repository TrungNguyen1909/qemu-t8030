#include "qemu/osdep.h"
#include "qom/object.h"
#include "qemu/lockable.h"
#include "hw/usb.h"
#include "hw/usb/hcd-fuzz.h"
#include "qemu-common.h"
#include "hw/qdev-properties.h"
#include "qemu/main-loop.h"
#include "qemu/coroutine.h"
#include "io/channel.h"
#include "io/channel-util.h"
#include "qapi/error.h"
#include "sysemu/iothread.h"
#include "qemu/error-report.h"
#include "migration/blocker.h"
#include "migration/vmstate.h"
#include "sysemu/runstate.h"
#include "afl/trace.h"

#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>

#define PACKET_DELAY            (100 * SCALE_US)
#define PACKET_RETRY_DELAY      (50 * SCALE_MS)
#define END_DELAY               (50 * SCALE_MS)

#define DEBUG_PRINT

#define USB_TOKEN_RESET          (0)
#define END_PACKET               ((struct fuzz_packet *)0xdeadbeef)
#define NEXT_PACKET              ((struct fuzz_packet *)NULL)

#define SETUP_STATE_IDLE  0
#define SETUP_STATE_SETUP 1
#define SETUP_STATE_DATA  2
#define SETUP_STATE_ACK   3
#define SETUP_STATE_PARAM 4
#define SETUP_STATE_COMPLETE  5

struct QEMU_PACKED packet_req {
    int pid;
    uint8_t ep;
    uint16_t len;
};

enum mux_protocol {
    MUX_PROTO_VERSION = 0,
    MUX_PROTO_CONTROL = 1,
    MUX_PROTO_SETUP = 2,
    MUX_PROTO_TCP = 6,
};

struct mux_header_v0 {
    uint32_t protocol;
    uint32_t length;
};

struct mux_header {
    uint32_t protocol;
    uint32_t length;
    uint32_t magic;
    uint16_t tx_seq;
    uint16_t rx_seq;
};

struct version_header {
    uint32_t major;
    uint32_t minor;
    uint32_t padding;
};

struct frame_t {
    struct ether_header header;
    unsigned char payload[ETHER_MAX_LEN - ETHER_HDR_LEN];
    ssize_t len;
    ssize_t payload_len;
};

static void usb_fuzz_host_reset(DeviceState *dev);

#define GET_EP(_pid, _nr) usb_ep_get(s->uport.dev, \
                                     _pid == USB_TOKEN_SETUP ? \
                                     USB_TOKEN_OUT : _pid, _nr)

#define INIT_PACKET(_p, _pid, _ep) do { \
        usb_packet_init(&_p); \
        usb_packet_setup(&_p, _pid, GET_EP(_pid, _ep), 0, 0, 0, 0); } while(0)

static void read_fail(USBFuzzHostState *s)
{
    if (s->fd != -1 && s->input_file) {
        close(s->fd);
    }
    s->fd = -1;
}

static struct fuzz_packet *get_zlp(USBFuzzHostState *s, int ep)
{
    struct fuzz_packet *pkt = g_new0(struct fuzz_packet, 1);
    INIT_PACKET(pkt->p, USB_TOKEN_OUT, 0);
    return pkt;
}

#if 0
static struct fuzz_packet *get_next_packet(USBFuzzHostState *s,
                                           struct fuzz_packet *pkt)
{
    if (pkt->p.pid == USB_TOKEN_SETUP && pkt->buffer) {
        pkt->setup_state = SETUP_STATE_SETUP;
    }
    struct usb_control_packet *setup = (struct usb_control_packet *)pkt->buffer;
    struct fuzz_packet *next_pkt = g_new0(struct fuzz_packet, 1);
    void *buffer = NULL;
    int ep = pkt->p.ep->nr;
    switch (pkt->setup_state) {
    case SETUP_STATE_SETUP: {
        pkt->p.actual_length = 8;
        next_pkt->setup = *setup;
        if (setup->bmRequestType & USB_DIR_IN) {
            next_pkt->setup_state = SETUP_STATE_DATA;
            buffer = g_malloc0(setup->wLength);
            INIT_PACKET(next_pkt->p, USB_TOKEN_IN, ep);
            usb_packet_addbuf(&next_pkt->p, buffer, setup->wLength);
            next_pkt->buffer = buffer;
        } else {
            next_pkt->setup_state = (setup->wLength == 0 ?
                                        SETUP_STATE_COMPLETE : SETUP_STATE_DATA);
            if (setup->wLength) {
                /* XXX: This rarely happens so I'm not sure what to do yet */
                INIT_PACKET(next_pkt->p, USB_TOKEN_OUT, ep);
                buffer = g_malloc0(setup->wLength);
                memcpy(buffer, setup + 1, setup->wLength);
                usb_packet_addbuf(&next_pkt->p, buffer, setup->wLength);
                next_pkt->buffer = buffer;
            } else {
                INIT_PACKET(next_pkt->p, USB_TOKEN_IN, ep);
            }
        }
        break;
    }
    case SETUP_STATE_DATA: {
        int len = pkt->p.actual_length;
        setup = &pkt->setup;
        pkt->setup_index += len;
        next_pkt->setup = *setup;
        if (pkt->setup_index >= pkt->setup.wLength || len < 64 /* mps */) {
            INIT_PACKET(next_pkt->p, (setup->bmRequestType & USB_DIR_IN) ?
                                      USB_TOKEN_OUT : USB_TOKEN_IN, ep);
            next_pkt->setup_state = SETUP_STATE_COMPLETE;
            next_pkt->buffer = pkt->buffer;
            pkt->buffer = NULL;
        } else {
            INIT_PACKET(next_pkt->p, (setup->bmRequestType & USB_DIR_IN) ?
                                      USB_TOKEN_IN : USB_TOKEN_OUT, ep);
            next_pkt->setup_index = pkt->setup_index;
            next_pkt->setup_state = SETUP_STATE_DATA;
            next_pkt->buffer = pkt->buffer;
            pkt->buffer = NULL;
            usb_packet_addbuf(&next_pkt->p,
                              (char *)next_pkt->buffer + next_pkt->setup_index,
                              setup->wLength - next_pkt->setup_index);

        }
        break;
    }
    default:
        g_free(next_pkt);
        next_pkt = NULL;
        break;
    }
    if (pkt->zlp) {
        return get_zlp(s, pkt->p.ep->nr);
    }
    return next_pkt;
}

static void send_packet(USBFuzzHostState *s, struct fuzz_packet *pkt,
                        uint32_t proto, const void *data, size_t length)
{
    size_t sz = 0;
    char *buffer = NULL;

    if (s->mux_version >= 2) {
        struct mux_header *mh = NULL;
        sz = sizeof(*mh) + length;
        assert(sz < 3 * 16384);
        buffer = g_malloc0(sz);
        mh = (struct mux_header *)buffer;
        mh->protocol = htonl(proto);
        mh->length = htonl(sz);
        mh->magic = htonl(0xfeadface);
        mh->tx_seq = htons(s->dev_tx_seq);
        mh->rx_seq = htons(s->dev_rx_seq);
        s->dev_tx_seq++;
        memcpy(buffer + sizeof(struct mux_header), data, length);

    } else {
        struct mux_header_v0 *mh = NULL;
        sz = sizeof(*mh) + length;
        assert(sz < 3 * 16384);
        buffer = g_malloc0(sz);
        mh = (struct mux_header_v0 *)buffer;
        mh->protocol = htonl(proto);
        mh->length = htonl(sz);
        memcpy(buffer + sizeof(*mh), data, length);
    }

    INIT_PACKET(pkt->p, USB_TOKEN_OUT, 2);
    usb_packet_addbuf(&pkt->p, buffer, sz);
    pkt->buffer = buffer;
}

static void send_tcp(USBFuzzHostState *s, struct fuzz_packet *pkt,
                     uint8_t flags, const void *data, size_t length)
{
    size_t sz = sizeof(struct tcphdr) + length;
    g_autofree char *buffer = g_malloc0(sz);
    struct tcphdr *th = (struct tcphdr *)buffer;

    th->th_sport = htons(s->sport);
    th->th_dport = htons(s->dport);
    th->th_seq = htonl(s->tx_seq);
    th->th_ack = htonl(s->tx_ack);
    th->th_flags = flags;
    th->th_off = sizeof(*th) / 4;
    th->th_win = htons(s->tx_win >> 8);

    memcpy(buffer + sizeof(*th), data, length);
    send_packet(s, pkt, MUX_PROTO_TCP, buffer, sz);
    if (flags != TH_SYN) {
        s->tx_seq += length;
    }
}

static void receive_packet(USBFuzzHostState *s, struct fuzz_packet *pkt)
{
    void *buffer = NULL;
    INIT_PACKET(pkt->p, USB_TOKEN_IN, 1);
    buffer = g_malloc0(16384);
    usb_packet_addbuf(&pkt->p, buffer, 16384);
    pkt->buffer = buffer;
}

static struct fuzz_packet *get_packet(USBFuzzHostState *s)
{
    struct packet_req r = { 0 };
    void *buffer = NULL;
    g_autofree struct fuzz_packet *pkt = g_new0(struct fuzz_packet, 1);
    bool ended = s->fd == -1;

    if (ended) {
        return END_PACKET;
    }
    {
        switch (s->state) {
        case STATE_NONE: {
            INIT_PACKET(pkt->p, USB_TOKEN_SETUP, 0);
            buffer = g_malloc0(8);
            struct usb_control_packet *setup =
                                        (struct usb_control_packet *)buffer;
            setup->request = cpu_to_be16(DeviceRequest | USB_REQ_GET_DESCRIPTOR);
            setup->value = USB_DT_DEVICE << 8;
            setup->index = cpu_to_be16(0);
            setup->length = 64;
            usb_packet_addbuf(&pkt->p, buffer, 8);
            pkt->buffer = buffer;
            s->state = STATE_GET_DESC_64;
            break;
        }
        case STATE_SET_ADDR: {
            INIT_PACKET(pkt->p, USB_TOKEN_SETUP, 0);
            buffer = g_malloc0(8);
            struct usb_control_packet *setup =
                                        (struct usb_control_packet *)buffer;
            setup->request = cpu_to_be16(DeviceOutRequest | USB_REQ_SET_ADDRESS);
            setup->value = 4;
            setup->index = 0;
            setup->length = 0;
            usb_packet_addbuf(&pkt->p, buffer, 8);
            pkt->buffer = buffer;
            break;
        }
        case STATE_GET_DESC_18: {
            INIT_PACKET(pkt->p, USB_TOKEN_SETUP, 0);
            buffer = g_malloc0(8);
            struct usb_control_packet *setup =
                                        (struct usb_control_packet *)buffer;
            setup->request = cpu_to_be16(DeviceRequest | USB_REQ_GET_DESCRIPTOR);
            setup->value = USB_DT_DEVICE << 8;
            setup->index = 0;
            setup->length = USB_DT_DEVICE_SIZE;
            usb_packet_addbuf(&pkt->p, buffer, 8);
            pkt->buffer = buffer;
            break;
        }
        case STATE_SET_CONFIG_1: {
            INIT_PACKET(pkt->p, USB_TOKEN_SETUP, 0);
            buffer = g_malloc0(8);
            struct usb_control_packet *setup =
                                        (struct usb_control_packet *)buffer;
            setup->request = cpu_to_be16(DeviceOutRequest | USB_REQ_SET_CONFIGURATION);
            setup->value = 1;
            setup->index = 0;
            setup->length = 0;
            usb_packet_addbuf(&pkt->p, buffer, 8);
            pkt->buffer = buffer;
            break;
        }
        case STATE_SET_CONFIG_0: {
            INIT_PACKET(pkt->p, USB_TOKEN_SETUP, 0);
            buffer = g_malloc0(8);
            struct usb_control_packet *setup =
                                        (struct usb_control_packet *)buffer;
            setup->request = cpu_to_be16(DeviceOutRequest | USB_REQ_SET_CONFIGURATION);
            setup->value = 0;
            setup->index = 0;
            setup->length = 0;
            usb_packet_addbuf(&pkt->p, buffer, 8);
            pkt->buffer = buffer;
            break;
        }
        case STATE_SET_CONFIG_4: {
            INIT_PACKET(pkt->p, USB_TOKEN_SETUP, 0);
            buffer = g_malloc0(8);
            struct usb_control_packet *setup =
                                        (struct usb_control_packet *)buffer;
            setup->request = cpu_to_be16(DeviceOutRequest | USB_REQ_SET_CONFIGURATION);
            setup->value = 4;
            setup->index = 0;
            setup->length = 0;
            usb_packet_addbuf(&pkt->p, buffer, 8);
            pkt->buffer = buffer;
            break;
        }
        case STATE_GET_CONFIG: {
            INIT_PACKET(pkt->p, USB_TOKEN_SETUP, 0);
            buffer = g_malloc0(8);
            struct usb_control_packet *setup =
                                        (struct usb_control_packet *)buffer;
            setup->request = cpu_to_be16(DeviceRequest | USB_REQ_GET_CONFIGURATION);
            setup->value = 0;
            setup->index = 0;
            setup->length = 1;
            usb_packet_addbuf(&pkt->p, buffer, 8);
            pkt->buffer = buffer;
            break;
        }
        case STATE_SET_INTERFACE: {
            INIT_PACKET(pkt->p, USB_TOKEN_SETUP, 0);
            buffer = g_malloc0(8);
            struct usb_control_packet *setup =
                                        (struct usb_control_packet *)buffer;
            setup->request = cpu_to_be16(InterfaceOutRequest | USB_REQ_SET_INTERFACE);
            setup->value = 1;
            setup->index = 4;
            setup->length = 0;
            usb_packet_addbuf(&pkt->p, buffer, 8);
            pkt->buffer = buffer;
            break;
        }
        case STATE_GET_INTERFACE: {
            INIT_PACKET(pkt->p, USB_TOKEN_SETUP, 0);
            buffer = g_malloc0(8);
            struct usb_control_packet *setup =
                                        (struct usb_control_packet *)buffer;
            setup->request = cpu_to_be16(InterfaceRequest | USB_REQ_GET_INTERFACE);
            setup->value = 0;
            setup->index = 1;
            setup->length = 1;
            usb_packet_addbuf(&pkt->p, buffer, 8);
            pkt->buffer = buffer;
            break;
        }
        case STATE_GET_MAC: {
            INIT_PACKET(pkt->p, USB_TOKEN_SETUP, 0);
            buffer = g_malloc0(8);
            struct usb_control_packet *setup =
                                        (struct usb_control_packet *)buffer;
            setup->request = cpu_to_be16(ClassInterfaceRequest | 0);
            setup->value = 0;
            setup->index = 1;
            setup->length = 6;
            usb_packet_addbuf(&pkt->p, buffer, 8);
            pkt->buffer = buffer;
            break;
        }
        case STATE_VERSION: {
            struct version_header vh = { 0 };
            vh.major = htonl(2);
            send_packet(s, pkt, MUX_PROTO_VERSION, &vh, sizeof(vh));
            break;
        }
        case STATE_VERSION_IN: {
            receive_packet(s, pkt);
            break;
        }
        case STATE_SETUP: {
            s->dev_tx_seq = 0;
            s->dev_rx_seq = 0xffff;
            send_packet(s, pkt, MUX_PROTO_SETUP, "\x07", 1);
            break;
        }
        case STATE_INPUT: {
            /* TODO */
            uint8_t flags =  0;
            uint16_t len = 0;
            g_autofree void *data = NULL;
            if (read(s->fd, &flags, sizeof(flags)) != sizeof(flags) ||
                read(s->fd, &len, sizeof(len)) != sizeof(len)) {
                ended = true;
                read_fail(s);
                goto end;
            } else {
                data = g_malloc0(len);
                if (read(s->fd, data, len) != len) {
                    ended = true;
                    read_fail(s);
                    goto end;
                }
                send_tcp(s, pkt, flags, data, len);
            }
            break;
        }
        case STATE_OUTPUT: {
            receive_packet(s, pkt);
            break;
        }
        /* AppleUSBEthernetDevice configures EP 3 IN, EP 4 OUT */
        default: {
            ended = true;
            goto end;
            break;
        }
        }
    }
    return g_steal_pointer(&pkt);
end:
    if (ended) {
        return END_PACKET;
    } else {
        return NEXT_PACKET;
    }
}

#undef INIT_PACKET
#undef GET_EP

static void usb_fuzz_packet_complete(USBFuzzHostState *s, USBPacket *p)
{
    struct fuzz_packet *pkt = container_of(p, struct fuzz_packet, p);
    puts(__func__);
    if (pkt->buffer) {
        if (p->pid == USB_TOKEN_IN && pkt->buffer) {
            qemu_hexdump(stderr, __func__, pkt->buffer, pkt->p.actual_length);
        } else if (pkt->setup_state == SETUP_STATE_COMPLETE) {
            qemu_hexdump(stderr, __func__, pkt->buffer, pkt->setup.wLength);
        }
    }
    switch (s->state) {
    case STATE_GET_DESC_64:
        s->state = STATE_SET_ADDR;
        break;
    case STATE_SET_ADDR:
        s->state = STATE_GET_DESC_18;
        break;
    case STATE_GET_DESC_18:
        s->state = STATE_SET_CONFIG_1;
        break;
    case STATE_SET_CONFIG_1:
        s->state = STATE_SET_CONFIG_0;
        break;
    case STATE_SET_CONFIG_0:
        s->state = STATE_SET_CONFIG_4;
        break;
    case STATE_SET_CONFIG_4:
        s->state = STATE_GET_CONFIG;
        break;
    case STATE_GET_CONFIG:
        s->state = STATE_VERSION;
        break;
    case STATE_SET_INTERFACE:
        s->state = STATE_GET_INTERFACE;
        break;
    case STATE_GET_INTERFACE:
        s->state = STATE_VERSION;
        break;
    case STATE_GET_MAC:
        memcpy(s->device_mac, pkt->buffer, sizeof(s->device_mac));
        //memcpy(s->device_mac, "\xbe\xde\x48\x00\x11\x22", sizeof(s->device_mac));
        qemu_hexdump(stderr, "device_mac", s->device_mac,
                                           sizeof(s->device_mac));
        s->state = STATE_VERSION;
        break;
    case STATE_VERSION:
        s->state = STATE_VERSION_IN;
        break;
    case STATE_VERSION_IN: {
        struct version_packet {
            struct mux_header_v0 mh;
            struct version_header vh;
        } *vp = (struct version_packet *)pkt->buffer;
        s->mux_version = ntohl(vp->vh.major);
        s->state = STATE_SETUP;
        break;
    }
    case STATE_SETUP:
        s->state = STATE_INPUT;
        break;
    case STATE_INPUT:
        s->state = STATE_OUTPUT;
        break;
    case STATE_OUTPUT: {
        struct mux_header *mh = (struct mux_header *)pkt->buffer;
        s->dev_rx_seq = ntohs(mh->rx_seq);
        if (ntohl(mh->protocol) == MUX_PROTO_TCP) {
            struct tcphdr *th = (struct tcphdr *)(mh + 1);
            if (pkt->p.actual_length >= (sizeof(*mh) + sizeof(*th))) {
                uint32_t len = pkt->p.actual_length - sizeof(struct tcphdr)
                              - sizeof(struct mux_header);

                if (th->th_flags == (TH_SYN|TH_ACK)) {
                    s->tx_seq++;
                    s->tx_ack++;
                } else {
                    s->tx_ack += len;
                }

                s->rx_seq = ntohl(th->th_seq);
                s->rx_ack = ntohl(th->th_ack);
                s->rx_win = ntohs(th->th_win) << 8;
                /* TODO: update tx_seq/ack */
            }

        }
        s->state = STATE_INPUT;
        break;
    }
    default:
        break;
    }
}

#else

static struct fuzz_packet *get_next_packet(USBFuzzHostState *s,
                                           struct fuzz_packet *pkt)
{
    return NULL;
}

static struct fuzz_packet *get_packet(USBFuzzHostState *s)
{
    struct packet_req r = { 0 };
    void *buffer = NULL;
    g_autofree struct fuzz_packet *pkt = g_new0(struct fuzz_packet, 1);
    USBEndpoint *ep = NULL;
    bool ended = s->fd == -1;

    if (ended) {
        return END_PACKET;
    }
    if (read(s->fd, &r, sizeof(r)) != sizeof(r)) {
        if (s->fd != -1 && s->input_file) {
            close(s->fd);
        }
        s->fd = -1;
        ended = true;
        return END_PACKET;
    } else {
        r.ep &= 0xf;

        switch (r.pid) {
        case USB_TOKEN_RESET:
            #ifdef DEBUG_PRINT
            fprintf(stderr, "%s:%d ======= usb_device_reset ======\n", __func__,
                            __LINE__);
            #endif
            usb_device_reset(s->uport.dev);
            goto end;
        case USB_TOKEN_OUT:
        case USB_TOKEN_SETUP:
        case USB_TOKEN_IN:
            break;
        default: {
            switch (r.pid & 3) {
            case 0:
                r.pid = USB_TOKEN_SETUP;
                break;
            case 1:
                r.pid = USB_TOKEN_IN;
                break;
            case 2:
                r.pid = USB_TOKEN_OUT;
                break;
            case 3:
                #ifdef DEBUG_PRINT
                fprintf(stderr, "%s: ======= usb_device_reset ======\n", __func__);
                #endif
                usb_device_reset(s->uport.dev);
                goto end;
            default:
                break;
            }
            break;
        }
        }

        /* XXX: Forcing EP */
        switch (r.pid) {
        case USB_TOKEN_SETUP:
        case USB_TOKEN_OUT:
            r.ep = 2;
            break;
        case USB_TOKEN_IN:
            r.ep = 1;
            break;
        default:
            break;
        }

        ep = usb_ep_get(s->uport.dev,
                        r.pid == USB_TOKEN_SETUP ? USB_TOKEN_OUT : r.pid,
                        r.ep);
        assert(ep);
        usb_packet_init(&pkt->p);
        usb_packet_setup(&pkt->p, r.pid, ep, 0, 0, 0, 0);
        if (r.len > 0) {
            buffer = g_malloc0(r.len);
            if (r.pid != USB_TOKEN_IN) {
                if (read(s->fd, buffer, r.len) < r.len) {
                    if (s->fd != -1 && s->input_file) {
                        close(s->fd);
                    }
                    s->fd = -1;
                }
            }
            usb_packet_addbuf(&pkt->p, buffer, r.len);
            pkt->buffer = buffer;
        }
    }
    return g_steal_pointer(&pkt);
end:
    if (ended) {
        return END_PACKET;
    } else {
        return NEXT_PACKET;
    }
}

static void usb_fuzz_packet_complete(USBFuzzHostState *s, USBPacket *p)
{
    struct fuzz_packet *pkt = container_of(p, struct fuzz_packet, p);
    if (pkt->buffer) {
        if (p->pid == USB_TOKEN_IN && pkt->buffer) {
        #ifdef DEBUG_PRINT
            qemu_hexdump(stderr, "OUTPUT: ", pkt->buffer, pkt->p.actual_length);
        #endif
        }
    }
}
#endif

static void usb_fuzz_bh(void *opaque)
{
    USBFuzzHostState *s = USB_FUZZ_HOST(opaque);
    bool ended = s->fd == -1;

    if (s->pkt) {
        struct fuzz_packet *pkt = s->pkt;
        if (usb_packet_is_inflight(&pkt->p)) {
            return;
        }
        #ifdef DEBUG_PRINT
        fprintf(stderr, "%s:%d ======= usb_handle_packet ======\n", __func__,
                        __LINE__);
        fprintf(stderr, "%s: pid: 0x%x ep: %d\n", __func__, pkt->p.pid,
                        pkt->p.ep->nr);
        #endif
        if (pkt->nakcnt == 0 && pkt->p.pid != USB_TOKEN_IN && pkt->buffer) {
            qemu_hexdump(stderr, __func__, pkt->buffer, 8);
        }
        usb_handle_packet(s->uport.dev, &pkt->p);
        if (pkt->p.status == USB_RET_ASYNC) {
            return;
        }
        timer_mod_ns(s->timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL)
                               + PACKET_RETRY_DELAY);
        #ifdef DEBUG_PRINT
        fprintf(stderr, "%s: p->status: %d\n", __func__, pkt->p.status);
        #endif
        if (pkt->p.status == USB_RET_NAK) {
            pkt->nakcnt++;
            if (pkt->nakcnt > 10) {
                fprintf(stderr, "%s: Dropping packet as NAK-ed over 10 times\n",
                                __func__);
            } else {
                return;
            }
        }
        s->pkt = get_next_packet(s, s->pkt);
        if (s->pkt == NULL) {
            usb_fuzz_packet_complete(s, &pkt->p);
        }
        usb_packet_cleanup(&pkt->p);
        g_free(pkt->buffer);
        g_free(pkt);
        return;
    }

    if (s->fd < 0) {
        usb_fuzz_host_reset(DEVICE(s));
        /* This will stop the main loop once so we can load_snapshot */
        if (getenv(SHM_ENV_VAR)) {
            qemu_system_exit_request();
            timer_mod_ns(s->timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL)
                                   + PACKET_RETRY_DELAY);
        } else {
            vm_stop(RUN_STATE_DEBUG);
            migrate_del_blocker(s->migration_blocker);
        }
        return;
    }

    if (!ended) {
        struct fuzz_packet *pkt = get_packet(s);
        if (pkt == NEXT_PACKET) {
            timer_mod_ns(s->timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL)
                                   + PACKET_RETRY_DELAY);
            goto end;
        } else if (pkt == END_PACKET) {
            s->pkt = NULL;
            ended = true;
            goto end;
        }
        s->pkt = pkt;
        if (s->uport.dev->state != USB_STATE_DEFAULT) {
            #ifdef DEBUG_PRINT
            fprintf(stderr, "%s:%d ======= usb_device_reset ======\n", __func__,
                            __LINE__);
            #endif
            usb_device_reset(s->uport.dev);
            timer_mod_ns(s->timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL)
                                   + PACKET_RETRY_DELAY);
            goto end;
        }
        #ifdef DEBUG_PRINT
        fprintf(stderr, "%s:%d ======= usb_handle_packet ======\n", __func__,
                        __LINE__);
        fprintf(stderr, "%s: pid: 0x%x ep: %d\n", __func__, pkt->p.pid, pkt->p.ep->nr);
        #endif
        if (pkt->p.pid != USB_TOKEN_IN && pkt->buffer) {
        #ifdef DEBUG_PRINT
            qemu_hexdump(stderr, "INPUT: ", pkt->buffer, pkt->p.iov.size);
        #endif
        }
        usb_handle_packet(s->uport.dev, &pkt->p);
        #ifdef DEBUG_PRINT
        fprintf(stderr, "%s: p->status: %d\n", __func__, pkt->p.status);
        #endif
        if (pkt->p.status == USB_RET_ASYNC) {
            goto end;
        }
        timer_mod_ns(s->timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL)
                               + PACKET_DELAY);
        if (pkt->p.status == USB_RET_NAK) {
            pkt->nakcnt++;
            goto end;
        }
        s->pkt = get_next_packet(s, s->pkt);
        if (s->pkt == NULL) {
            usb_fuzz_packet_complete(s, &pkt->p);
        }
        usb_packet_cleanup(&pkt->p);
        g_free(pkt->buffer);
        g_free(pkt);
    }

end:
    if (ended) {
        puts("usb_fuzz_bh: ====== ended =======");
        if (s->fd != -1 && s->input_file) {
            close(s->fd);
        }
        s->fd = -1;
        timer_mod_ns(s->timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL)
                               + END_DELAY);
    }
}

static void usb_fuzz_host_timer_expire(void *opaque)
{
    usb_fuzz_bh(opaque);
}

static void usb_fuzz_host_attach(USBPort *uport)
{
    USBFuzzHostState *s = USB_FUZZ_HOST(uport->opaque);

    if (uport->index > 0) {
        error_report("%s: attached to unused port\n", __func__);
        return;
    }

    if (!uport->dev || !uport->dev->attached) {
        return;
    }
    s->state = STATE_NONE;
    if (getenv(SHM_ENV_VAR)) {
        migrate_add_blocker(s->migration_blocker, NULL);
        timer_mod_ns(s->timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL)
                               + PACKET_DELAY);
    } else {
        vm_stop(RUN_STATE_DEBUG);
    }
}

static void usb_fuzz_host_detach(USBPort *uport)
{
    USBFuzzHostState *s = USB_FUZZ_HOST(uport->opaque);
    migrate_del_blocker(s->migration_blocker);
    s->fd = -1;
}

static void usb_fuzz_host_async_packet_complete(USBPort *port, USBPacket *p)
{
    USBFuzzHostState *s = USB_FUZZ_HOST(port->opaque);
    struct fuzz_packet *pkt = container_of(p, struct fuzz_packet, p);
    #ifdef DEBUG_PRINT
    fprintf(stderr, "%s: p->status: %d\n", __func__, pkt->p.status);
    #endif
    usb_fuzz_packet_complete(s, p);
    s->pkt = NULL;
    usb_packet_cleanup(p);
    g_free(pkt->buffer);
    g_free(pkt);
    timer_mod_ns(s->timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL)
                           + PACKET_DELAY);
}

static USBBusOps usb_fuzz_bus_ops = { };

static USBPortOps usb_fuzz_host_port_ops = {
        .attach = usb_fuzz_host_attach,
        .detach = usb_fuzz_host_detach,
        .child_detach = NULL,
        .wakeup = NULL,
        .complete = usb_fuzz_host_async_packet_complete,
};

static void usb_fuzz_host_reset(DeviceState *dev)
{
    USBFuzzHostState *s = USB_FUZZ_HOST(dev);

    if (s->pkt) {
        usb_packet_cleanup(&s->pkt->p);
        g_free(s->pkt->buffer);
        g_free(s->pkt);
        s->pkt = NULL;
    }
    s->state = STATE_NONE;
    s->fd = 9;
    afl_filter_tid(0);

    if (s->input_file) {
        s->fd = open(s->input_file, O_RDONLY);
        assert(s->fd >= 0);
    }
    s->tx_seq = 0;
    s->tx_ack = 0;
}

static void usb_fuzz_host_realize(DeviceState *dev, Error **errp)
{
    USBFuzzHostState *s = USB_FUZZ_HOST(dev);

    usb_bus_new(&s->bus, sizeof(s->bus), &usb_fuzz_bus_ops, dev);
    usb_register_port(&s->bus, &s->uport, s, 0, &usb_fuzz_host_port_ops,
                      USB_SPEED_MASK_LOW | USB_SPEED_MASK_FULL |
                      USB_SPEED_MASK_HIGH);

    /* Unused port to avoid hub creation */
    usb_register_port(&s->bus, &s->uport2, s, 1, &usb_fuzz_host_port_ops,
                      USB_SPEED_MASK_LOW | USB_SPEED_MASK_FULL |
                      USB_SPEED_MASK_HIGH);
}

static void usb_fuzz_host_unrealize(DeviceState *dev)
{
}

static void usb_fuzz_host_init(Object *obj)
{
    USBFuzzHostState *s = USB_FUZZ_HOST(obj);
    error_setg(&s->migration_blocker, "%s does not support migration "
                                      "now", TYPE_USB_FUZZ_HOST);
    s->bh = qemu_bh_new(usb_fuzz_bh, s);
    s->timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, usb_fuzz_host_timer_expire, s);
    s->fd = -1;
    s->pkt = NULL;
    s->host_mac[0] = 0xca;
    s->host_mac[1] = 0xfe;
    s->host_mac[2] = 0xba;
    s->host_mac[3] = 0xbe;
    s->host_mac[4] = 0x11;
    s->host_mac[5] = 0x22;

    s->tx_win = 131072;
    s->sport = 49152;
    s->dport = 62078;
    s->max_payload = (3 * 16384) - sizeof(struct mux_header)
                                 - sizeof(struct tcphdr);
}

static int usb_fuzz_host_post_load(void *opaque, int version_id)
{
    USBFuzzHostState *s = USB_FUZZ_HOST(opaque);
    /* TODO: start timer? */
    timer_mod_ns(s->timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL)
                           + PACKET_DELAY);
    return 0;
}

static Property usb_fuzz_host_properties[] = {
    DEFINE_PROP_STRING("usbfuzz-input", USBFuzzHostState, input_file),
    DEFINE_PROP_END_OF_LIST(),
};

static const VMStateDescription vmstate_usb_fuzz = {
    .name = "usb_fuzz_hcd",
    .version_id = 1,
    .minimum_version_id = 1,
    .post_load = usb_fuzz_host_post_load,
    .fields = (VMStateField[]) {
        VMSTATE_END_OF_LIST()
    }
};

static void usb_fuzz_host_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->realize = usb_fuzz_host_realize;
    dc->unrealize = usb_fuzz_host_unrealize;
    dc->reset = usb_fuzz_host_reset;
    dc->desc = "QEMU USB Fuzz Host Controller";
    dc->vmsd = &vmstate_usb_fuzz;
    device_class_set_props(dc, usb_fuzz_host_properties);
    set_bit(DEVICE_CATEGORY_USB, dc->categories);
}

static const TypeInfo usb_fuzz_host_type_info = {
    .name = TYPE_USB_FUZZ_HOST,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(USBFuzzHostState),
    .class_init = usb_fuzz_host_class_init,
    .instance_init = usb_fuzz_host_init,
};

static void usb_fuzz_host_register_types(void)
{
    type_register_static(&usb_fuzz_host_type_info);
}

type_init(usb_fuzz_host_register_types)
