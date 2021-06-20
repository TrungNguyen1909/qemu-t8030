#include "qemu/osdep.h"
#include "qom/object.h"
#include "qemu/lockable.h"
#include "hw/usb.h"
#include "tcp-usb.h"
#include "hw/usb/hcd-tcp.h"
#include "qemu-common.h"
#include "hw/qdev-properties.h"

static void usb_tcp_host_closed(USBTCPHostState *s)
{
    fprintf(stderr, "%s\n", __func__);
    s->socket = -1;
    s->closed = true;
    qemu_cond_broadcast(&s->cond);
}

static int usb_tcp_host_read(USBTCPHostState *s, void *buffer, unsigned int length)
{
    int amount_done = 0;
    int n = 0;

    while ((n = read(s->socket, (char *)buffer + amount_done, length - amount_done)) > 0) {
        amount_done += n;
    }

    return amount_done;
}

static int usb_tcp_host_write(USBTCPHostState *s, void *buffer, unsigned int length)
{
    int amount_done = 0;
    int n = 0;

    while ((n = write(s->socket, (char *)buffer + amount_done, length - amount_done)) > 0) {
        amount_done += n;
    }

    return amount_done;
}

static void usb_tcp_host_respond_packet(USBTCPHostState *s, USBPacket *p)
{
    tcp_usb_header_t hdr = { 0 };
    tcp_usb_response_header resp = { 0 };
    g_autofree void *buffer = NULL;

    if (!s->closed) {
        hdr.type = TCP_USB_RESPONSE;
        resp.addr = s->uport.dev->addr;
        resp.pid = p->pid;
        resp.ep = p->ep->nr;
        resp.id = p->id;
        resp.status = p->status;
        resp.length = p->iov.size;

        if (resp.length > p->actual_length) {
            resp.length = p->actual_length;
        }

        if (p->pid == USB_TOKEN_IN) {
            buffer = g_malloc(resp.length);
            iov_to_buf(p->iov.iov, p->iov.niov, 0, buffer, resp.length);
        }

        WITH_QEMU_LOCK_GUARD(&s->write_mutex) {
            if (usb_tcp_host_write(s, &hdr, sizeof(hdr)) < sizeof(hdr)) {
                usb_tcp_host_closed(s);
                return;
            }

            if (usb_tcp_host_write(s, &resp, sizeof(resp)) < sizeof(resp)) {
                usb_tcp_host_closed(s);
                return;
            }

            if (buffer) {
                if (usb_tcp_host_write(s, buffer, resp.length) < resp.length) {
                    usb_tcp_host_closed(s);
                    return;
                }
            }
        }
    }

    if (!usb_packet_is_inflight(p)) {
        if (container_of(p, USBTCPPacket, p)->buffer) {
            g_free(container_of(p, USBTCPPacket, p)->buffer);
        }
        usb_packet_cleanup(p);
    }
}

static void *usb_tcp_host_read_thread(void *opaque)
{
    USBTCPHostState *s = USB_TCP_HOST(opaque);

    while (!s->stopped) {
        while (!s->closed) {
            tcp_usb_header_t hdr = { 0 };

            if (usb_tcp_host_read(s, &hdr, sizeof(hdr)) < sizeof(hdr)) {
                usb_tcp_host_closed(s);
                break;
            }

            switch (hdr.type) {
                case TCP_USB_REQUEST: {
                    /* fprintf(stderr, "%s: TCP_USB_REQUEST\n", __func__); */
                    tcp_usb_request_header pkt_hdr = {0};
                    g_autofree void *buffer = NULL;
                    g_autofree USBTCPPacket *pkt = (USBTCPPacket *) g_malloc0(sizeof(USBTCPPacket));
                    USBEndpoint *ep = NULL;

                    if (usb_tcp_host_read(s, &pkt_hdr, sizeof(pkt_hdr)) < sizeof(pkt_hdr)) {
                        usb_tcp_host_closed(s);
                        break;
                    }

                    /* fprintf(stderr, "%s: TCP_USB_REQUEST pid: 0x%x ep: %d\n", __func__, pkt_hdr.pid, pkt_hdr.ep); */
                    ep = usb_ep_get(s->uport.dev, pkt_hdr.pid, pkt_hdr.ep);
                    if (ep == NULL) {
                        fprintf(stderr, "%s: TCP_USB_REQUEST unknown EP\n", __func__);
                        usb_tcp_host_closed(s);
                        break;
                    }

                    usb_packet_init(&pkt->p);
                    usb_packet_setup(&pkt->p, pkt_hdr.pid, ep, pkt_hdr.stream, pkt_hdr.id, pkt_hdr.short_not_ok, pkt_hdr.int_req);

                    if (pkt_hdr.length > 0) {
                        buffer = g_malloc0(pkt_hdr.length);

                        if (pkt_hdr.pid != USB_TOKEN_IN) {
                            if (usb_tcp_host_read(s, buffer, pkt_hdr.length) < pkt_hdr.length) {
                                usb_tcp_host_closed(s);
                                usb_packet_cleanup(&pkt->p);
                                break;
                            }
                            /* qemu_hexdump(stderr, __func__, buffer, pkt_hdr.length); */
                        }

                        usb_packet_addbuf(&pkt->p, buffer, pkt_hdr.length);
                        pkt->buffer = buffer;
                        g_steal_pointer(&buffer);
                    }

                    if (pkt_hdr.addr != s->uport.dev->addr) {
                        fprintf(stderr,
                                "%s: USB_RET_NODEV: pkt_hdr.addr != s->uport.dev->addr: %d != %d\n",
                                __func__, pkt_hdr.addr, s->uport.dev->addr);
                        /* Can't enforce this check because dwc2 address transition time is slow */
                    }

                    usb_handle_packet(ep->dev, &pkt->p);
                    usb_tcp_host_respond_packet(s, &pkt->p);

                    if (usb_packet_is_inflight(&pkt->p)) {
                        g_steal_pointer(&pkt);
                    }

                    break;
                }
                case TCP_USB_RESPONSE:
                    fprintf(stderr, "%s: unexpected TCP_USB_RESPONSE\n", __func__);
                    usb_tcp_host_closed(s);
                    break;
                case TCP_USB_RESET:
                    /* fprintf(stderr, "%s: TCP_USB_RESET\n", __func__); */
                    usb_device_reset(s->uport.dev);
                    break;
            }
        }

        while (s->closed) {
            qemu_cond_wait(&s->cond, &s->mutex);
        }

        qemu_mutex_unlock(&s->mutex);
    }

    return NULL;
}

static void usb_tcp_host_attach(USBPort *uport)
{
    struct hostent *hostname;
    struct sockaddr_in server_addr;
    USBTCPHostState *s = USB_TCP_HOST(uport->opaque);
    int ret;

    if (uport->index > 0) {
        fprintf(stderr, "%s: attached to unused port\n", __func__);
        return;
    }

    if (!uport->dev || !uport->dev->attached) {
        return;
    }

    s->socket = socket(AF_INET, SOCK_STREAM, 0);
    if (s->host == NULL) {
        s->host = g_strdup("127.0.0.1");
    }

    hostname = gethostbyname(s->host);

    memset(&server_addr, 0, sizeof(server_addr));

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(s->port);
    memcpy(&server_addr.sin_addr.s_addr,
           hostname->h_addr, hostname->h_length);

    ret = connect(s->socket, (const struct sockaddr *) &server_addr, sizeof(server_addr));
    if (ret < 0) {
        fprintf(stderr, "%s: failed to connect to server: %d\n", __func__, ret);
        close(s->socket);
        return;
    }

    s->closed = 0;
    qemu_cond_broadcast(&s->cond);
}

static void usb_tcp_host_detach(USBPort *uport)
{
    USBTCPHostState *s = USB_TCP_HOST(uport->opaque);

    close(s->socket);
    s->closed = 1;
    s->socket = -1;
    qemu_cond_broadcast(&s->cond);
}

static void usb_tcp_host_async_packet_complete(USBPort *port, USBPacket *p)
{
    USBTCPHostState *s = USB_TCP_HOST(port->opaque);
    usb_tcp_host_respond_packet(s, p);
}

static USBBusOps usb_tcp_bus_ops = { };

static USBPortOps usb_tcp_host_port_ops = {
        .attach = usb_tcp_host_attach,
        .detach = usb_tcp_host_detach,
        .child_detach = NULL,
        .wakeup = NULL,
        .complete = usb_tcp_host_async_packet_complete,
};

static void usb_tcp_host_realize(DeviceState *dev, Error **errp)
{
    USBTCPHostState *s = USB_TCP_HOST(dev);

    usb_bus_new(&s->bus, sizeof(s->bus), &usb_tcp_bus_ops, dev);
    usb_register_port(&s->bus, &s->uport, s, 0, &usb_tcp_host_port_ops,
            USB_SPEED_MASK_LOW | USB_SPEED_MASK_FULL |
                      USB_SPEED_MASK_HIGH);

    // Unused port to avoid hub creation
    usb_register_port(&s->bus, &s->uport2, s, 1, &usb_tcp_host_port_ops,
            USB_SPEED_MASK_LOW | USB_SPEED_MASK_FULL |
                      USB_SPEED_MASK_HIGH);

    s->socket = -1;
    s->closed = 1;
}

static void usb_tcp_host_unrealize(DeviceState *dev)
{
    USBTCPHostState *s = USB_TCP_HOST(dev);

    if (s->socket >= 0) {
        close(s->socket);
    }

    s->closed = 1;
    s->stopped = 1;
    qemu_cond_broadcast(&s->cond);
}

static void usb_tcp_host_init(Object *obj)
{
    USBTCPHostState *s = USB_TCP_HOST(obj);

    s->socket = -1;
    qemu_mutex_init(&s->mutex);
    qemu_mutex_init(&s->write_mutex);
    qemu_cond_init(&s->cond);
    qemu_thread_create(&s->read_thread, TYPE_USB_TCP_HOST ".read", &usb_tcp_host_read_thread, s, QEMU_THREAD_JOINABLE);
}


static Property usb_tcp_host_properties[] = {
    DEFINE_PROP_STRING("host", USBTCPHostState, host),
    DEFINE_PROP_UINT32("port", USBTCPHostState, port, 7632),
    DEFINE_PROP_END_OF_LIST(),
};

static void usb_tcp_host_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->realize = usb_tcp_host_realize;
    dc->unrealize = usb_tcp_host_unrealize;
    dc->desc = "QEMU USB Passthrough Host Controller";
    device_class_set_props(dc, usb_tcp_host_properties);
    set_bit(DEVICE_CATEGORY_USB, dc->categories);
}

static const TypeInfo usb_tcp_host_type_info = {
    .name = TYPE_USB_TCP_HOST,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(USBTCPHostState),
    .class_init = usb_tcp_host_class_init,
    .instance_init = usb_tcp_host_init,
};

static void usb_tcp_host_register_types(void)
{
    type_register_static(&usb_tcp_host_type_info);
}

type_init(usb_tcp_host_register_types)
