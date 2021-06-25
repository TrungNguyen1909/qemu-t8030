#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/cutils.h"
#include "qemu/error-report.h"
#include "qemu/module.h"
#include "qemu/main-loop.h"
#include "hw/qdev-properties.h"
#include "hw/qdev-properties-system.h"
#include "hw/usb.h"
#include "migration/vmstate.h"
#include "desc.h"
#include "qom/object.h"
#include "trace.h"
#include "dev-tcp-remote.h"
#include "tcp-usb.h"
#include "qemu-common.h"

static USBTCPInflightPacket *usb_tcp_remote_find_inflight_packet(USBTCPRemoteState *s, int pid, uint8_t ep, uint64_t id)
{
    USBTCPInflightPacket *p;

    WITH_QEMU_LOCK_GUARD(&s->queue_mutex) {
        QTAILQ_FOREACH(p, &s->queue, queue) {
            if (p->p->pid == pid && p->p->ep->nr == ep && p->p->id == id) {
                return p;
            }
        }
    }

    return NULL;
}

static void usb_tcp_remote_clean_inflight_queue(USBTCPRemoteState *s)
{
    USBTCPInflightPacket *p;

    WITH_QEMU_LOCK_GUARD(&s->queue_mutex) {
        QTAILQ_FOREACH(p, &s->queue, queue) {
            p->p->status = USB_RET_STALL;
            p->handled = 1;
            qemu_cond_signal(&p->c);
        }
    }
}

static void usb_tcp_remote_closed(USBTCPRemoteState *s)
{
    /* fprintf(stderr, "%s\n", __func__); */
    close(s->fd);

    s->fd = -1;
    s->closed = true;
    s->addr = 0;

    usb_tcp_remote_clean_inflight_queue(s);

    if (USB_DEVICE(s)->attached) {
        usb_device_detach(USB_DEVICE(s));
    }

    qemu_cond_broadcast(&s->cond);
}

static int usb_tcp_remote_read(USBTCPRemoteState *s, void *buffer, unsigned int length)
{
    int ret = 0;
    int n = 0;

    while (n < length) {
        ret = read(s->fd, (char *)buffer + n, length - n);
        if (ret <= 0) {
            usb_tcp_remote_closed(s);
            return -errno;
        }

        n += ret;
    }

    return n;
}

static int usb_tcp_remote_write(USBTCPRemoteState *s, void *buffer, unsigned int length)
{
    int ret = 0;
    int n = 0;

    while (n < length) {
        ret = write(s->fd, (char *)buffer + n, length - n);
        if (ret <= 0) {
            usb_tcp_remote_closed(s);
            return -errno;
        }

        n += ret;
    }

    return n;
}

static void *usb_tcp_remote_read_thread(void *opaque)
{
    USBTCPRemoteState *s = USB_TCP_REMOTE(opaque);

    while (!s->closed) {
        tcp_usb_header_t hdr = { 0 };

        if (usb_tcp_remote_read(s, &hdr, sizeof(hdr)) < sizeof(hdr)) {
            break;
        }

        switch (hdr.type) {
        case TCP_USB_RESPONSE: {
            tcp_usb_response_header rhdr = { 0 };
            USBPacket *p = NULL;
            USBTCPInflightPacket *pkt = NULL;

            if (usb_tcp_remote_read(s, &rhdr, sizeof(rhdr)) < sizeof(rhdr)) {
                break;
            }

            p = usb_ep_find_packet_by_id(USB_DEVICE(s), rhdr.pid, rhdr.ep, rhdr.id);

            if (p == NULL) {
                pkt = usb_tcp_remote_find_inflight_packet(s, rhdr.pid, rhdr.ep, rhdr.id);
            }

            if (pkt) {
                p = pkt->p;
            } else {
                fprintf(stderr,
                        "%s: TCP_USB_RESPONSE "
                        "Invalid packet pid: 0x%x ep: 0x%x id: 0x%" PRIx64 "\n",
                        __func__, rhdr.pid, rhdr.ep, rhdr.id);
                usb_tcp_remote_closed(s);
                break;
            }

            if (rhdr.length > 0) {
                g_autofree void *buffer = g_malloc(rhdr.length);
                if (p->pid == USB_TOKEN_IN) {
                    if (usb_tcp_remote_read(s, buffer, rhdr.length) < rhdr.length) {
                        break;
                    }
                    usb_packet_copy(p, buffer, rhdr.length);
                } else {
                    p->actual_length += rhdr.length;
                }
            }

            p->status = rhdr.status;
            if (p->state == USB_PACKET_ASYNC) {
                if (p->status != USB_RET_SUCCESS
                    && p->status != USB_RET_ASYNC
                    && p->status != USB_RET_NAK
                    && p->ep->nr == 0) {
                    s->addr = USB_DEVICE(s)->addr;
                }
                usb_packet_complete(USB_DEVICE(s), p);
            } else {
                WITH_QEMU_LOCK_GUARD(&pkt->m) {
                    pkt->addr = rhdr.addr;
                    pkt->handled = 1;
                    qemu_cond_signal(&pkt->c);
                }
            }
            break;
        }

        case TCP_USB_REQUEST:
        case TCP_USB_RESET:
        default:
            fprintf(stderr, "%s: Invalid header type: 0x%x\n", __func__, hdr.type);
            usb_tcp_remote_closed(s);
            break;
        }
    }

    return NULL;
}

static void *usb_tcp_remote_thread(void *arg)
{
    USBTCPRemoteState *s = USB_TCP_REMOTE(arg);

    while (!s->stopped) {
        if (s->closed) {
            struct sockaddr_in addr = { 0 };
            unsigned int addr_sz = sizeof(addr);

            fprintf(stderr, "%s: waiting on accept...\n", __func__);

            s->fd = accept(s->socket, (struct sockaddr *) &addr, &addr_sz);
            if (s->fd < 0) {
                fprintf(stderr, "%s: accept error %d.\n", __func__, errno);
                continue;
            }

            s->closed = 0;

            qemu_cond_broadcast(&s->cond);

            fprintf(stderr, "%s: USB device accepted!\n", __func__);

            usb_device_attach(USB_DEVICE(s), &error_abort);
            qemu_thread_create(&s->read_thread, TYPE_USB_TCP_REMOTE ".read", usb_tcp_remote_read_thread, s, QEMU_THREAD_JOINABLE);
        }

        while (!s->closed) {
            qemu_cond_wait(&s->cond, &s->mutex);
        }

        qemu_mutex_unlock(&s->mutex);
    }

    return NULL;
}

static void usb_tcp_remote_realize(USBDevice *dev, Error **errp)
{
    struct linger linger;
    int enable = 1;
    struct sockaddr_in ai;
    USBTCPRemoteState *s = USB_TCP_REMOTE(dev);

    dev->speed = USB_SPEED_FULL;
    dev->speedmask = USB_SPEED_MASK_FULL;
    dev->auto_attach = 0;

    qemu_cond_init(&s->cond);
    qemu_mutex_init(&s->mutex);
    qemu_mutex_init(&s->request_mutex);

    qemu_mutex_init(&s->queue_mutex);
    QTAILQ_INIT(&s->queue);

    s->socket = -1;
    s->fd = -1;
    s->closed = true;

    s->socket = socket(AF_INET, SOCK_STREAM, 0);
    if (s->socket < 0) {
        error_setg(errp, "Cannot open socket: %d", s->socket);
        return;
    }

    linger.l_onoff = 0;
    linger.l_linger = 0;
    setsockopt(s->socket, SOL_SOCKET, SO_LINGER, &linger, sizeof(linger));

    setsockopt(s->socket, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));

    ai.sin_family = AF_INET;
    ai.sin_port = htons(s->lport);
    ai.sin_addr.s_addr = INADDR_ANY;

    if (bind(s->socket, (struct sockaddr *)&ai, sizeof(ai)) < 0) {
        error_setg(errp, "Cannot bind socket");
        return;
    }

    if (listen(s->socket, 5) < 0) {
        error_setg(errp, "Cannot listen on socket");
        return;
    }

    qemu_thread_create(&s->thread, TYPE_USB_TCP_REMOTE ".thread",
                       &usb_tcp_remote_thread, s, QEMU_THREAD_JOINABLE);
}

static void usb_tcp_remote_unrealize(USBDevice *dev)
{
    USBTCPRemoteState *s = USB_TCP_REMOTE(dev);

    if (s->socket >= 0) {
        close(s->socket);
        s->socket = -1;
    }

    if (s->fd >= 0) {
        close(s->fd);
        s->fd = -1;
    }

    s->closed = true;

    qemu_cond_broadcast(&s->cond);

    s->stopped = true;
    usb_tcp_remote_clean_inflight_queue(s);
}

static void usb_tcp_remote_handle_reset(USBDevice *dev)
{
    tcp_usb_header_t hdr = { 0 };
    USBTCPRemoteState *s = USB_TCP_REMOTE(dev);

    if (s->closed) {
        return;
    }

    /* fprintf(stderr, "%s\n", __func__); */
    usb_tcp_remote_clean_inflight_queue(s);
    s->addr = 0;
    hdr.type = TCP_USB_RESET;

    WITH_QEMU_LOCK_GUARD(&s->request_mutex) {
        usb_tcp_remote_write(s, &hdr, sizeof(hdr));
    }
}

static void usb_tcp_remote_handle_packet(USBDevice *dev, USBPacket *p)
{
    USBTCPRemoteState *s = USB_TCP_REMOTE(dev);
    tcp_usb_header_t hdr = { 0 };
    tcp_usb_request_header pkt = { 0 };
    USBTCPInflightPacket inflightPacket = { 0 };
    g_autofree void *buffer = NULL;

    if (s->closed) {
        p->status = USB_RET_STALL;
        return;
    }

    hdr.type = TCP_USB_REQUEST;
    pkt.addr = s->addr;
    pkt.pid = p->pid;
    pkt.ep = p->ep->nr;
    pkt.stream = p->stream;
    pkt.id = p->id;
    pkt.short_not_ok = p->short_not_ok;
    pkt.int_req = p->int_req;
    pkt.length = p->iov.size - p->actual_length;

    /* fprintf(stderr, "%s: pid: 0x%x ep 0x%x id 0x%llx\n", __func__, pkt.pid, pkt.ep, pkt.id); */

    if (p->pid != USB_TOKEN_IN) {
        buffer = g_malloc0(pkt.length);
        usb_packet_copy(p, buffer, pkt.length);
        /* qemu_hexdump(stderr, __func__, buffer, pkt.length); */
        if (p->pid == USB_TOKEN_SETUP && p->ep->nr == 0) {
            struct usb_control_packet *setup = (struct usb_control_packet *)buffer;

            if (setup->bRequest == USB_REQ_SET_ADDRESS) {
                s->addr = setup->wValue;
            }
        }
    }

    inflightPacket.p = p;
    inflightPacket.handled = 0;
    inflightPacket.addr = dev->addr;
    qemu_mutex_init(&inflightPacket.m);
    qemu_cond_init(&inflightPacket.c);

    WITH_QEMU_LOCK_GUARD(&s->queue_mutex) {
        QTAILQ_INSERT_TAIL(&s->queue, &inflightPacket, queue);
    }

   WITH_QEMU_LOCK_GUARD(&s->request_mutex) {
       if (usb_tcp_remote_write(s, &hdr, sizeof(hdr)) < sizeof(hdr)) {
           p->status = USB_RET_STALL;
           goto out;
       }

       if (usb_tcp_remote_write(s, &pkt, sizeof(pkt)) < sizeof(pkt)) {
           p->status = USB_RET_STALL;
           goto out;
       }

       if (buffer) {
           if (usb_tcp_remote_write(s, buffer, pkt.length) < pkt.length) {
               p->status = USB_RET_STALL;
               goto out;
           }
       }
   }

   /* TODO: This should be async instead of sync (USB_RET_ASYNC here instead of wait);
    * however, QEMU USB stack does not allow NAK-ing an async packet.
    */
   WITH_QEMU_LOCK_GUARD(&inflightPacket.m) {
       while ((qatomic_read(&inflightPacket.handled) & 1) == 0) {
           qemu_cond_wait(&inflightPacket.c, &inflightPacket.m);
       }
   }

out:
    if (p->status != USB_RET_SUCCESS && p->status != USB_RET_ASYNC && p->status != USB_RET_NAK) {
        s->addr = dev->addr;
    }

    if (s->addr != dev->addr && p->ep->nr == 0 && p->pid == USB_TOKEN_IN && p->status == USB_RET_SUCCESS) {
        dev->addr = s->addr;
        trace_usb_set_addr(dev->addr);
    }

    WITH_QEMU_LOCK_GUARD(&s->queue_mutex) {
        QTAILQ_REMOVE(&s->queue, &inflightPacket, queue);
    }

    qemu_cond_destroy(&inflightPacket.c);
    qemu_mutex_destroy(&inflightPacket.m);
}

static Property usb_tcp_remote_properties[] = {
        DEFINE_PROP_UINT32("lport", USBTCPRemoteState, lport, 7632),
        DEFINE_PROP_END_OF_LIST(),
};

static void usb_tcp_remote_dev_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    USBDeviceClass *uc = USB_DEVICE_CLASS(klass);

    uc->realize        = usb_tcp_remote_realize;
    uc->unrealize      = usb_tcp_remote_unrealize;
    uc->handle_attach  = NULL;
    uc->handle_detach  = NULL;
    uc->cancel_packet  = NULL;
    uc->handle_reset   = usb_tcp_remote_handle_reset;
    uc->handle_control = NULL;
    uc->handle_data    = NULL;
    uc->handle_packet  = usb_tcp_remote_handle_packet;
    uc->product_desc   = "QEMU USB Passthrough Device";

    dc->desc = "QEMU USB Passthrough Device";

    device_class_set_props(dc, usb_tcp_remote_properties);

    set_bit(DEVICE_CATEGORY_USB, dc->categories);
}

static const TypeInfo usb_tcp_remote_dev_type_info = {
    .name = TYPE_USB_TCP_REMOTE,
    .parent = TYPE_USB_DEVICE,
    .instance_size = sizeof(USBTCPRemoteState),
    .class_init = usb_tcp_remote_dev_class_init,
};

static void usb_tcp_register_types(void)
{
    type_register_static(&usb_tcp_remote_dev_type_info);
}

type_init(usb_tcp_register_types)
