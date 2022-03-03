#include "qemu/osdep.h"
#include "qapi/error.h"
#include "hw/arm/apple_sep.h"
#include "hw/misc/apple_mbox.h"
#include "hw/irq.h"
#include "migration/vmstate.h"
#include "qemu/bitops.h"
#include "qemu/lockable.h"
#include "qemu/log.h"
#include "qemu/module.h"
#include "qemu/queue.h"
#include "qemu/timer.h"
#include "sysemu/runstate.h"
#include "hw/arm/xnu.h"
#include "hw/arm/xnu_dtb.h"
#include "hw/arm/apple_sep_protocol.h"
#include "crypto/random.h"
#include "crypto/cipher.h"

#define TYPE_APPLE_SEP "apple.sep"
OBJECT_DECLARE_SIMPLE_TYPE(AppleSEPState, APPLE_SEP)

#define SEP_LOG_MSG(ep, msg) \
do { qemu_log_mask(LOG_GUEST_ERROR, "SEP: message:" \
                   " ep=%u msg=0x" TARGET_FMT_plx "\n", \
                   ep, msg); } while (0)

enum {
    kStatusSEPROM = 1,
    kStatusTz0Booted = 2,
};

typedef void AppleSEPEPHandler (AppleSEPState *s, struct sep_message *msg);

typedef struct sep_endpoint {
    uint8_t id;
    uint32_t name;
    QTAILQ_ENTRY(sep_endpoint) entry;
    AppleSEPEPHandler *handler;
} sep_endpoint;


struct AppleSEPState {
    SysBusDevice parent_obj;
    AppleMboxState *mbox;
    QTAILQ_HEAD(, sep_endpoint) endpoints;
    uint32_t boot_status;
};

static void apple_sep_control_endpoint(AppleSEPState *s,
                                       struct sep_message *msg)
{
    struct sep_message reply = { 0 };

    reply.endpoint = kEndpoint_CONTROL; //msg->endpoint;
    reply.tag = msg->tag;
    switch (msg->opcode) {
    case kOpCode_Sleep:
        reply.param = 0;
        apple_mbox_send_control_message(s->mbox, 0, reply.raw);
        break;
    case kOpCode_SECMODE_REQUEST:
        reply.param = 0;
        apple_mbox_send_control_message(s->mbox, 0, reply.raw);
        break;
    case kOpCode_SET_OOL_IN_ADDR:
        reply.param = 0;
        apple_mbox_send_control_message(s->mbox, 0, reply.raw);
        break;
    case kOpCode_SET_OOL_IN_SIZE:
        reply.param = 0;
        apple_mbox_send_control_message(s->mbox, 0, reply.raw);
        break;
    case kOpCode_SET_OOL_OUT_ADDR:
        reply.param = 0;
        apple_mbox_send_control_message(s->mbox, 0, reply.raw);
        break;
    case kOpCode_SET_OOL_OUT_SIZE:
        reply.param = 0;
        apple_mbox_send_control_message(s->mbox, 0, reply.raw);
        break;
    default:
        reply.param = 0;
        apple_mbox_send_control_message(s->mbox, 0, reply.raw);
        break;
    }
}

static void apple_sep_ep_discover(AppleSEPState *s)
{
    sep_endpoint *ep = NULL;
    QTAILQ_FOREACH(ep, &s->endpoints, entry) {
        struct sep_message msg = { 0 };
        msg.endpoint = kEndpoint_DISCOVERY;
        msg.tag = 0;
        msg.opcode = kOpCode_Advertise;
        msg.ep_advertise_data.id = ep->id;
        msg.ep_advertise_data.name = ep->name;
        apple_mbox_send_control_message(s->mbox, 0, msg.raw);
    }

    QTAILQ_FOREACH(ep, &s->endpoints, entry) {
        struct sep_message msg = { 0 };
        msg.endpoint = kEndpoint_DISCOVERY;
        msg.tag = 0;
        msg.opcode = kOpCode_Expose;
        msg.ep_expose_data.id = ep->id;
        msg.ep_expose_data.ool_in_min_pages = 1;
        msg.ep_expose_data.ool_in_max_pages = 5;
        msg.ep_expose_data.ool_out_min_pages = 1;
        msg.ep_expose_data.ool_out_max_pages = 5;
        apple_mbox_send_control_message(s->mbox, 0, msg.raw);
    }
}

static void apple_seprom_endpoint(AppleSEPState *s, struct sep_message *msg)
{
    struct sep_message reply = { 0 };
    reply.endpoint = kEndpoint_SEPROM; //msg->endpoint;
    reply.tag = msg->tag;
    switch (msg->opcode) {
    case kOpCode_Ping:
        reply.opcode = kOpCode_Ack;
        reply.data = 0;
        apple_mbox_send_control_message(s->mbox, 0, reply.raw);
        break;
    case kOpCode_GenerateNonce:
        reply.opcode = kOpCode_ReportGeneratedNonce;
        reply.data = 20 * 8;
        apple_mbox_send_control_message(s->mbox, 0, reply.raw);
        break;
    case kOpCode_GetNonceWord:
        reply.opcode = kOpCode_ReportNonceWord;
        reply.data = 0xdeadbeef;
        apple_mbox_send_control_message(s->mbox, 0, reply.raw);
        break;
    case kOpCode_GetStatus:
        reply.opcode = kOpCode_AckStatus;
        reply.data = s->boot_status;
        apple_mbox_send_control_message(s->mbox, 0, reply.raw);
        break;
    case kOpCode_BootTz0:
        s->boot_status = kStatusTz0Booted;
        reply.opcode = kOpCode_AcceptTz0;
        apple_mbox_send_control_message(s->mbox, 0, reply.raw);
        break;
    case kOpCode_Start:
        reply.opcode = kOpCode_Ack;
        apple_mbox_send_control_message(s->mbox, 0, reply.raw);
        apple_sep_ep_discover(s);
        break;
    default:
        break;
    }
}

static sep_endpoint *apple_sep_get_endpoint(AppleSEPState *s, uint8_t id)
{
    sep_endpoint *d;
    QTAILQ_FOREACH(d, &s->endpoints, entry) {
        if (d->id == id) {
            return d;
        }
    }
    return NULL;
}

static void apple_sep_register_endpoint(AppleSEPState *s, uint8_t id,
                                        uint32_t name,
                                        AppleSEPEPHandler *handler)
{
    sep_endpoint *ep = g_new0(sep_endpoint, 1);
    ep->name = name;
    ep->id = id;
    ep->handler = handler;
    QTAILQ_INSERT_TAIL(&s->endpoints, ep, entry);
}

static void apple_sep_endpoint_handler(void *opaque, uint32_t ep,
                                                     uint64_t msg)
{
    AppleSEPState *s = APPLE_SEP(opaque);
    struct sep_message *m = (struct sep_message *)&msg;
    SEP_LOG_MSG(ep, msg);
    switch (m->endpoint) {
    case kEndpoint_SEPROM:
        apple_seprom_endpoint(s, m);
        break;
    default: {
        sep_endpoint *ep = apple_sep_get_endpoint(s, m->endpoint);
        if (ep) {
            ep->handler(s, m);
        } else {
            g_assert_not_reached();
        }
        break;
    }
    }
}

static const struct AppleMboxOps sep_mailbox_ops = {
};

SysBusDevice *apple_sep_create(DTBNode *node, uint32_t build_version)
{
    DeviceState  *dev;
    AppleSEPState *s;
    SysBusDevice *sbd;
    DTBNode *child;
    DTBProp *prop;
    uint64_t *reg;
    uint32_t protocol_version = 0;
    int i;
    uint32_t data;

    dev = qdev_new(TYPE_APPLE_SEP);
    s = APPLE_SEP(dev);
    sbd = SYS_BUS_DEVICE(dev);

    switch (BUILD_VERSION_MAJOR(build_version)) {
        case 14:
            protocol_version = 11;
            break;
        case 15:
            protocol_version = 12;
            break;
        default:
            break;
    }

    prop = find_dtb_prop(node, "reg");
    assert(prop);

    reg = (uint64_t *)prop->value;

    /*
     * 0: AppleA7IOP akfRegMap
     * 1: AppleASCWrapV2 coreRegisterMap
     */
    s->mbox = apple_mbox_create("SEP", s, reg[1], protocol_version,
                                       &sep_mailbox_ops);
    object_property_add_child(OBJECT(s), "mbox", OBJECT(s->mbox));
    apple_mbox_register_control_endpoint(s->mbox, 0,
                                         &apple_sep_endpoint_handler);

    sysbus_init_mmio(sbd, sysbus_mmio_get_region(SYS_BUS_DEVICE(s->mbox), 0));
    sysbus_init_mmio(sbd, sysbus_mmio_get_region(SYS_BUS_DEVICE(s->mbox), 2));

    sysbus_pass_irq(sbd, SYS_BUS_DEVICE(s->mbox));

    child = find_dtb_node(node, "iop-sep-nub");
    assert(child);

    /* TODO: we don't load sepfw during restore */
    data = 1;
    set_dtb_prop(child, "sepfw-loaded", 4, (uint8_t *)&data);

    s->boot_status = kStatusSEPROM;

    QTAILQ_INIT(&s->endpoints);

    apple_sep_register_endpoint(s, kEndpoint_CONTROL, 'cntl',
                                           apple_sep_control_endpoint);
    return sbd;
}

static void apple_sep_reset(DeviceState *dev)
{
}

static void apple_sep_realize(DeviceState *dev, Error **errp)
{
    AppleSEPState *s = APPLE_SEP(dev);
    sysbus_realize(SYS_BUS_DEVICE(s->mbox), errp);
}

static void apple_sep_unrealize(DeviceState *dev)
{
    AppleSEPState *s = APPLE_SEP(dev);

    qdev_unrealize(DEVICE(s->mbox));
}

static void apple_sep_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->realize = apple_sep_realize;
    dc->unrealize = apple_sep_unrealize;
    dc->reset = apple_sep_reset;
    dc->desc = "Apple SEP";
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
}

static const TypeInfo apple_sep_info = {
    .name = TYPE_APPLE_SEP,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(AppleSEPState),
    .class_init = apple_sep_class_init,
};

static void apple_sep_register_types(void)
{
    type_register_static(&apple_sep_info);
}

type_init(apple_sep_register_types);
