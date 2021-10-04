#include "qemu/osdep.h"
#include "qemu/main-loop.h"
#include "qemu/log.h"
#include "qemu/lockable.h"
#include "qemu/main-loop.h"
#include "hw/irq.h"
#include "hw/misc/apple_mbox.h"
#include "migration/vmstate.h"
#include "trace.h"

#define IOP_LOG_MSG(s, msg) \
do { qemu_log_mask(LOG_GUEST_ERROR, "%s: message:" \
                   " type=0x%x ep=%u QWORD0=0x" TARGET_FMT_plx \
                   " QWORD1=0x" TARGET_FMT_plx " ep0_state=0x%x\n", \
                   s->role, msg->type, msg->endpoint, \
                   msg->data[0], msg->data[1], \
                   s->ep0_status); } while (0)

#define REG_A7V4_CPU_CTRL                   0x0044
#define     REG_A7V4_CPU_CTRL_RUN           0x10
#define REG_A7V4_NMI0                       0xc04
#define REG_A7V4_NMI1                       0xc14
#define REG_AKF_CONFIG                  0x2043
#define REG_A7V4_INBOX_CTRL                 0x8108
#define     REG_A7V4_INBOX_CTRL_ENABLE      (1 << 0)
#define     REG_A7V4_INBOX_CTRL_FULL        (1 << 16)
#define     REG_A7V4_INBOX_CTRL_EMPTY       (1 << 17)
#define REG_A7V4_OUTBOX_CTRL                0x810C
#define     REG_A7V4_OUTBOX_CTRL_ENABLE     (1 << 0)
#define     REG_A7V4_OUTBOX_CTRL_FULL       (1 << 16)
#define     REG_A7V4_OUTBOX_CTRL_EMPTY      (1 << 17)
#define     REG_A7V4_OUTBOX_CTRL_HAS_MSG    (1 << 21)
#define REG_A7V4_A2I_MSG0                   0x8800
#define REG_A7V4_A2I_MSG1                   0x8808
#define REG_A7V4_I2A_MSG0                   0x8830
#define REG_A7V4_I2A_MSG1                   0x8838

#define A7V4_MSG_FLAG_LAST                  (1 << 20)
#define A7V4_MSG_FLAG_NOTLAST               REG_A7V4_OUTBOX_CTRL_HAS_MSG
#define IOP_INBOX_SIZE                      16

#define MSG_SEND_HELLO                      1
#define MSG_RECV_HELLO                      2
#define MSG_TYPE_PING                       3
#define MSG_PING_ACK                        4
#define MSG_TYPE_EPSTART                    5
#define MSG_TYPE_WAKE                       6
#define MSG_TYPE_POWER                      7
#define MSG_TYPE_ROLLCALL                   8
#define MSG_TYPE_POWERACK                   11

/*
 * AP -> IOP: A2I; IOP -> AP: I2A
 * Inbox: A2I
 * Outbox: I2A
 */
enum apple_mbox_ep0_state {
    EP0_IDLE,
    EP0_WAIT_HELLO,
    EP0_WAIT_ROLLCALL,
    EP0_DONE,
};

struct apple_mbox_msg {
    union QEMU_PACKED {
        uint64_t data[2];
        struct QEMU_PACKED {
            union {
                uint64_t msg;
                struct QEMU_PACKED {
                    union {
                        struct QEMU_PACKED {
                            uint16_t major;
                            uint16_t minor;
                        } hello;
                        struct QEMU_PACKED {
                            uint32_t seg;
                            uint16_t timestamp;
                        } ping;
                        struct QEMU_PACKED {
                            uint32_t state;
                            uint32_t ep;
                        } epstart;
                        struct QEMU_PACKED {
                            uint32_t state;
                        } power;
                        struct QEMU_PACKED {
                            uint32_t epMask;
                            /* bit x -> endpoint ((epBlock * 32) + x) */
                            uint8_t epBlock:6;
                            uint16_t unk38:13;
                            uint8_t epEnded:1;
                        } rollcall;
                    };
                };
                struct QEMU_PACKED {
                    uint32_t field_0;
                    uint16_t field_32;
                    uint8_t field_48:4;
                    uint8_t type:4;
                };
            };
            uint32_t endpoint;
            uint32_t flags;
        };
    };
    QTAILQ_ENTRY(apple_mbox_msg) entry;
};

typedef struct apple_mbox_msg *apple_mbox_msg_t;

struct AppleMboxState {
    SysBusDevice parent_obj;

    MemoryRegion mmio;
    QemuMutex mutex;
    void *opaque;
    const struct AppleMboxOps *ops;
    char *role;
    uint32_t ep0_status;
    uint32_t protocol_version;
    uint32_t config;
    uint32_t cpu_ctrl;
    qemu_irq irqs[3];
    uint64_t inboxBuffer[2];
    QTAILQ_HEAD(, apple_mbox_msg) inbox;

    bool outboxEnable;
    QTAILQ_HEAD(, apple_mbox_msg) outbox;

    GTree *endpoints;
    QEMUBH *bh;
};

struct iop_rollcall_data {
    AppleMboxState *s;
    uint32_t mask;
    uint32_t last_block;
};

static gint g_uint_cmp(gconstpointer a, gconstpointer b)
{
    return a - b;
}

static bool apple_mbox_outbox_empty(AppleMboxState *s)
{
    return QTAILQ_EMPTY(&s->outbox);
}

static bool apple_mbox_empty(AppleMboxState *s)
{
    return QTAILQ_EMPTY(&s->inbox);
}

static inline uint32_t iop_outbox_flags(AppleMboxState *s)
{
    uint32_t flags = 0;

    if (apple_mbox_outbox_empty(s)) {
        flags = A7V4_MSG_FLAG_LAST;
    } else {
        flags = A7V4_MSG_FLAG_NOTLAST;
    }

    return flags;
}

/*
 * Push a message from AP to IOP,
 * take ownership of msg
 */
static void apple_mbox_inbox_push(AppleMboxState *s,
                                  apple_mbox_msg_t msg)
{
    QTAILQ_INSERT_TAIL(&s->inbox, msg, entry);
    qemu_irq_lower(s->irqs[APPLE_MBOX_IRQ_INBOX]);
    qemu_bh_schedule(s->bh);
}

static apple_mbox_msg_t apple_mbox_pop(AppleMboxState *s)
{
    apple_mbox_msg_t msg = QTAILQ_FIRST(&s->inbox);
    QTAILQ_REMOVE(&s->inbox, msg, entry);
    return msg;
}

/*
 * Push a message from IOP to AP,
 * take ownership of msg
 */
static void apple_mbox_push(AppleMboxState *s,
                            apple_mbox_msg_t msg)
{
    if (!s->outboxEnable) {
        return;
    }
    QTAILQ_INSERT_TAIL(&s->outbox, msg, entry);
    qemu_irq_raise(s->irqs[APPLE_MBOX_IRQ_OUTBOX]);
}

void apple_mbox_send_message(AppleMboxState *s, uint32_t ep, uint64_t msg)
{
    apple_mbox_msg_t m = g_new(struct apple_mbox_msg, 1);
    m->msg = msg;
    m->endpoint = ep + 31;
    apple_mbox_push(s, m);
}

static gboolean iop_rollcall(gpointer key, gpointer value, gpointer data)
{
    struct iop_rollcall_data *d = (struct iop_rollcall_data *)data;
    AppleMboxState *s = d->s;
    uint32_t ep = (uint64_t)key;

    if ((ep - 1) / 32 != d->last_block) {
        apple_mbox_msg_t m = g_new0(struct apple_mbox_msg, 1);
        m->type = MSG_TYPE_ROLLCALL;
        m->rollcall.epMask = d->mask;
        m->rollcall.epBlock = (d->last_block + 1);
        m->rollcall.epEnded = false;
        apple_mbox_push(s, m);
        d->mask = 0;
    }
    d->last_block = (ep - 1) / 32;
    d->mask |= (1 << ((ep - 1) & 31));
    return false;
}

static void iop_start(AppleMboxState *s)
{
    if (s->ops->start) {
        s->ops->start(s->opaque);
    }
}

static void iop_wakeup(AppleMboxState *s)
{
    if (s->ops->wakeup) {
        s->ops->wakeup(s->opaque);
    }
}

static void iop_handle_management_msg(AppleMboxState *s,
                                      apple_mbox_msg_t msg)
{
    if (msg->type == MSG_TYPE_PING) {
        apple_mbox_msg_t m;
        m = g_new0(struct apple_mbox_msg, 1);
        m->type = MSG_PING_ACK;
        m->ping.seg = msg->ping.seg;
        m->ping.timestamp = msg->ping.timestamp;
        apple_mbox_push(s, m);
        goto end;
    }
    switch (s->ep0_status) {
        case EP0_IDLE:
            switch (msg->type) {
            case MSG_TYPE_WAKE: {
                apple_mbox_msg_t m = g_new0(struct apple_mbox_msg, 1);

                iop_wakeup(s);
                m->type = MSG_SEND_HELLO;
                m->hello.major = s->protocol_version;
                m->hello.minor = s->protocol_version;
                m->endpoint = 0;
                s->ep0_status = EP0_WAIT_HELLO;
                apple_mbox_push(s, m);
                break;
            }
            case MSG_TYPE_EPSTART:
                break;
            case MSG_TYPE_POWERACK: {
                apple_mbox_msg_t m = g_new0(struct apple_mbox_msg, 1);

                m->type = MSG_TYPE_POWERACK;
                m->power.state = msg->power.state;
                apple_mbox_push(s, m);
                break;
            }
            default:
                IOP_LOG_MSG(s, msg);
                break;
            }
            break;
        case EP0_WAIT_HELLO:
            if (msg->type == MSG_RECV_HELLO) {
                apple_mbox_msg_t m = g_new0(struct apple_mbox_msg, 1);
                struct iop_rollcall_data d = { 0 };
                d.s = s;
                g_tree_foreach(s->endpoints, iop_rollcall, &d);
                m->type = MSG_TYPE_ROLLCALL;
                m->rollcall.epMask = d.mask;
                m->rollcall.epBlock = (d.last_block + 1);
                m->rollcall.epEnded = true;
                s->ep0_status = EP0_WAIT_ROLLCALL;
                apple_mbox_push(s, m);
            } else {
                IOP_LOG_MSG(s, msg);
            }
            break;
        case EP0_WAIT_ROLLCALL:
            if (msg->type == MSG_TYPE_ROLLCALL) {
                if (msg->rollcall.epEnded) {
                    apple_mbox_msg_t m = g_new0(struct apple_mbox_msg, 1);
                    m->type = MSG_TYPE_POWER;
                    m->power.state = 32;
                    s->ep0_status = EP0_IDLE;
                    apple_mbox_push(s, m);
                }
            } else {
                IOP_LOG_MSG(s, msg);
            }
            break;
        default:
            IOP_LOG_MSG(s, msg);
            break;
    }
    end:
    g_free(msg);
}

static void apple_mbox_bh(void *opaque)
{
    AppleMboxState *s = APPLE_MBOX(opaque);

    WITH_QEMU_LOCK_GUARD(&s->mutex) {
        while (!apple_mbox_empty(s)) {
            apple_mbox_msg_t msg = apple_mbox_pop(s);
            switch (msg->endpoint) {
                case 0:
                    iop_handle_management_msg(s, msg);
                    break;
                default: {
                    AppleMboxEPHandler *handler = NULL;
                    if (msg->endpoint > 31) {
                        handler = g_tree_lookup(s->endpoints, GUINT_TO_POINTER(msg->endpoint - 31));
                    }
                    if (handler) {
                        handler(s->opaque, msg->endpoint - 31, msg->msg);
                    } else {
                        qemu_log_mask(LOG_GUEST_ERROR,
                                      "%s: Unexpected message to endpoint %u\n", s->role, msg->endpoint);
                        IOP_LOG_MSG(s, msg);
                        g_free(msg);
                    }
                    break;
                }
            }
        }
    }
}

static void apple_mbox_reg_write(void *opaque, hwaddr addr,
                                 uint64_t data, unsigned size)
{
    AppleMboxState *s = APPLE_MBOX(opaque);
    WITH_QEMU_LOCK_GUARD(&s->mutex) {
        switch (addr) {
            case REG_AKF_CONFIG:
                s->config = data;
                return;

            case REG_A7V4_CPU_CTRL:
                if (data & REG_A7V4_CPU_CTRL_RUN) {
                    apple_mbox_msg_t msg;

                    s->cpu_ctrl = data;

                    iop_start(s);

                    msg = g_new0(struct apple_mbox_msg, 1);
                    msg->type = MSG_SEND_HELLO;
                    msg->hello.major = s->protocol_version;
                    msg->hello.minor = s->protocol_version;
                    msg->endpoint = 0;
                    s->ep0_status = EP0_WAIT_HELLO;

                    apple_mbox_push(s, msg);
                }
                return;

            case REG_A7V4_A2I_MSG0:
                s->inboxBuffer[0] = data;
                return;

            case REG_A7V4_A2I_MSG1:
            {
                apple_mbox_msg_t msg;

                s->inboxBuffer[1] = data;
                msg = g_new0(struct apple_mbox_msg, 1);
                memcpy(msg->data, s->inboxBuffer, sizeof(s->inboxBuffer));
                apple_mbox_inbox_push(s, msg);
                return;
            }

            case REG_A7V4_OUTBOX_CTRL:
                if (data & REG_A7V4_OUTBOX_CTRL_ENABLE) {
                    s->outboxEnable = true;
                } else {
                    s->outboxEnable = false;
                }
                return;

            default:
                break;
        }

        qemu_log_mask(LOG_GUEST_ERROR,
                      "%s: AppleA7IOP AKF unknown reg WRITE @ 0x"
                      TARGET_FMT_plx " value: 0x" TARGET_FMT_plx "\n",
                      s->role, addr, data);
    }
}

static uint64_t apple_mbox_reg_read(void *opaque, hwaddr addr,
                                    unsigned size)
{
    AppleMboxState *s = APPLE_MBOX(opaque);
    WITH_QEMU_LOCK_GUARD(&s->mutex) {
        apple_mbox_msg_t m;
        uint64_t ret = 0;

        switch (addr) {
        case REG_AKF_CONFIG:
            return s->config;

        case REG_A7V4_CPU_CTRL:
            return s->cpu_ctrl;

        case REG_A7V4_I2A_MSG0:
            m = QTAILQ_FIRST(&s->outbox);
            assert(m);
            return m->data[0];

        case REG_A7V4_I2A_MSG1:
            m = QTAILQ_FIRST(&s->outbox);
            assert(m);

            QTAILQ_REMOVE(&s->outbox, m, entry);
            m->flags = iop_outbox_flags(s);
            ret = m->data[1];

            if (apple_mbox_outbox_empty(s)) {
                qemu_irq_lower(s->irqs[APPLE_MBOX_IRQ_OUTBOX]);
            }

            g_free(m);
            return ret;

        case REG_A7V4_INBOX_CTRL:
            if (apple_mbox_empty(s)) {
                ret |= REG_A7V4_INBOX_CTRL_EMPTY;
            }
            return ret;

        case REG_A7V4_OUTBOX_CTRL:
            if (apple_mbox_outbox_empty(s)) {
                ret |= REG_A7V4_OUTBOX_CTRL_EMPTY;
            } else {
                ret |= REG_A7V4_OUTBOX_CTRL_HAS_MSG;
            }

            if (s->outboxEnable) {
                ret |= REG_A7V4_OUTBOX_CTRL_ENABLE;
            }
            return ret;

        default:
            break;
        }

        qemu_log_mask(LOG_UNIMP, "%s: AppleA7IOP AKF unknown reg READ @ 0x"
                                 TARGET_FMT_plx "\n", s->role, addr);
    }

    return 0;
}

static const MemoryRegionOps apple_mbox_reg_ops = {
        .write = apple_mbox_reg_write,
        .read = apple_mbox_reg_read,
        .endianness = DEVICE_NATIVE_ENDIAN,
        .valid.min_access_size = 4,
        .valid.max_access_size = 8,
        .impl.min_access_size = 4,
        .impl.max_access_size = 8,
        .valid.unaligned = false,
};

void apple_mbox_register_endpoint(AppleMboxState *s, uint32_t ep,
                                  AppleMboxEPHandler handler)
{
    assert(ep > 0);
    g_tree_insert(s->endpoints, GUINT_TO_POINTER(ep), handler);
}

void apple_mbox_unregister_endpoint(AppleMboxState *s, uint32_t ep)
{
    assert(ep > 0);
    g_tree_remove(s->endpoints, GUINT_TO_POINTER(ep));
}

AppleMboxState *apple_mbox_create(const char *role,
                                  void *opaque,
                                  uint64_t mmio_size,
                                  uint32_t protocol_version,
                                  const struct AppleMboxOps *ops)
{
    DeviceState  *dev;
    SysBusDevice *sbd;
    AppleMboxState *s;
    int i;
    char name[32];

    dev = qdev_new(TYPE_APPLE_MBOX);
    sbd = SYS_BUS_DEVICE(dev);
    s = APPLE_MBOX(dev);

    qemu_mutex_init(&s->mutex);

    s->endpoints = g_tree_new(g_uint_cmp);

    s->opaque = opaque;
    s->protocol_version = protocol_version;
    s->role = g_strdup(role);
    s->ops = ops;

    snprintf(name, sizeof(name), TYPE_APPLE_MBOX ".%s.akf-reg", s->role);
    /*
     * 0: AppleA7IOP akfRegMap
     */
    memory_region_init_io(&s->mmio, OBJECT(dev), &apple_mbox_reg_ops, s,
                          name, mmio_size);
    sysbus_init_mmio(sbd, &s->mmio);

    for (i = 0; i < 3; i++) {
        sysbus_init_irq(sbd, &s->irqs[i]);
    }

    QTAILQ_INIT(&s->inbox);
    QTAILQ_INIT(&s->outbox);

    return s;
}

static void apple_mbox_realize(DeviceState *dev, Error **errp)
{
    AppleMboxState *s = APPLE_MBOX(dev);
    if (apple_mbox_empty(s)) {
        qemu_irq_raise(s->irqs[APPLE_MBOX_IRQ_INBOX]);
    }

    s->bh = qemu_bh_new(apple_mbox_bh, s);
}

static void apple_mbox_unrealize(DeviceState *dev)
{
}

static void apple_mbox_reset(DeviceState *dev)
{
    AppleMboxState *s = APPLE_MBOX(dev);

    s->ep0_status = EP0_IDLE;

    WITH_QEMU_LOCK_GUARD(&s->mutex) {
        while (!QTAILQ_EMPTY(&s->inbox)) {
            apple_mbox_msg_t m = QTAILQ_FIRST(&s->inbox);
            QTAILQ_REMOVE(&s->inbox, m, entry);
            g_free(m);
        }

        while (!QTAILQ_EMPTY(&s->outbox)) {
            apple_mbox_msg_t m = QTAILQ_FIRST(&s->outbox);
            QTAILQ_REMOVE(&s->outbox, m, entry);
            g_free(m);
        }
    }
    s->cpu_ctrl = 0;
    s->outboxEnable = 0;
    qemu_irq_raise(s->irqs[APPLE_MBOX_IRQ_INBOX]);
}

static int apple_mbox_post_load(void *opaque, int version_id)
{
    AppleMboxState *s = APPLE_MBOX(opaque);

    WITH_QEMU_LOCK_GUARD(&s->mutex) {
        if (!apple_mbox_empty(s)) {
            qemu_bh_schedule(s->bh);
        }
    }
    return 0;
}

static const VMStateDescription vmstate_apple_mbox_msg = {
    .name = "apple_mbox_msg",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (VMStateField[]) {
        VMSTATE_UINT64_ARRAY(data, struct apple_mbox_msg, 2),
        VMSTATE_END_OF_LIST()
    }
};

static const VMStateDescription vmstate_apple_mbox = {
    .name = "apple_mbox",
    .version_id = 1,
    .minimum_version_id = 1,
    .post_load = apple_mbox_post_load,
    .fields = (VMStateField[]) {
        VMSTATE_UINT32(ep0_status, AppleMboxState),
        VMSTATE_UINT32(protocol_version, AppleMboxState),
        VMSTATE_UINT32(config, AppleMboxState),
        VMSTATE_UINT32(cpu_ctrl, AppleMboxState),
        VMSTATE_UINT64_ARRAY(inboxBuffer, AppleMboxState, 2),
        VMSTATE_QTAILQ_V(inbox, AppleMboxState, 1, vmstate_apple_mbox_msg,
                        struct apple_mbox_msg, entry),
        VMSTATE_BOOL(outboxEnable, AppleMboxState),
        VMSTATE_QTAILQ_V(outbox, AppleMboxState, 1, vmstate_apple_mbox_msg,
                        struct apple_mbox_msg, entry),

        VMSTATE_END_OF_LIST()
    }
};

static void apple_mbox_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->realize = apple_mbox_realize;
    dc->unrealize = apple_mbox_unrealize;
    dc->reset = apple_mbox_reset;
    dc->desc = "Apple IOP Mailbox";
    dc->vmsd = &vmstate_apple_mbox;
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
}

static const TypeInfo apple_mbox_info = {
        .name = TYPE_APPLE_MBOX,
        .parent = TYPE_SYS_BUS_DEVICE,
        .instance_size = sizeof(AppleMboxState),
        .class_init = apple_mbox_class_init,
};

static void apple_mbox_register_types(void)
{
    type_register_static(&apple_mbox_info);
}

type_init(apple_mbox_register_types);
