#include "qemu/osdep.h"
#include "qemu/main-loop.h"
#include "qemu/log.h"
#include "hw/iop/mailbox.h"

#define IOP_LOG_MSG(s, msg) \
do { qemu_log_mask(LOG_GUEST_ERROR, "%s: message:" \
                   " type=0x%x ep=%u QWORD0=0x" TARGET_FMT_plx \
                   " QWORD1=0x" TARGET_FMT_plx " ep0_state=0x%x\n", \
                   s->role, msg->type, msg->endpoint, \
                   msg->data[0], msg->data[1], \
                   s->ep0_status); } while (0)

/*
 * Push a message from AP to IOP,
 * called with iothread locked,
 * take ownership of msg
 */
void iop_inbox_push(struct AppleIOPMailboxState *s, iop_message_t msg)
{
    QTAILQ_INSERT_TAIL(&s->inbox, msg, entry);
    qemu_irq_lower(s->irqs[IRQ_IOP_INBOX]);
    qemu_cond_broadcast(&s->iop_halt);
}

iop_message_t iop_inbox_get(struct AppleIOPMailboxState *s)
{
    iop_message_t msg = QTAILQ_FIRST(&s->inbox);
    QTAILQ_REMOVE(&s->inbox, msg, entry);
    return msg;
}

bool iop_inbox_empty(struct AppleIOPMailboxState *s)
{
    return QTAILQ_EMPTY(&s->inbox);
}

/*
 * Push a message from IOP to AP,
 * called with iothread locked,
 * take ownership of msg
 */
void iop_outbox_push_nolock(struct AppleIOPMailboxState *s, iop_message_t msg)
{
    if (!s->outboxEnable) {
        return;
    }
    QTAILQ_INSERT_TAIL(&s->outbox, msg, entry);
    qemu_irq_raise(s->irqs[IRQ_IOP_OUTBOX]);
}

/*
 * Push a message from IOP to AP,
 * called with iothread unlocked,
 * take ownership of msg
 */
void iop_outbox_push(struct AppleIOPMailboxState *s, iop_message_t msg)
{
    qemu_mutex_unlock(&s->mutex);
    qemu_mutex_lock_iothread();
    iop_outbox_push_nolock(s, msg);
    qemu_mutex_unlock_iothread();
    qemu_mutex_lock(&s->mutex);
}

bool iop_outbox_empty(struct AppleIOPMailboxState *s)
{
    return QTAILQ_EMPTY(&s->outbox);
}

static inline uint32_t iop_outbox_flags(struct AppleIOPMailboxState *s)
{
    uint32_t flags = 0;

    if (iop_outbox_empty(s)) {
        flags = A7V4_MSG_FLAG_LAST;
    } else {
        flags = A7V4_MSG_FLAG_NOTLAST;
    }

    return flags;
}

static void iop_start(struct AppleIOPMailboxState *s)
{
    if (s->ops->start) {
        s->ops->start(s->opaque);
    }
}

static void iop_wakeup(struct AppleIOPMailboxState *s)
{
    if (s->ops->wakeup) {
        s->ops->wakeup(s->opaque);
    }
}

static void iop_handle_management_msg(struct AppleIOPMailboxState *s, iop_message_t msg)
{
    if (msg->type == MSG_TYPE_PING) {
        iop_message_t m;
        m = g_new0(struct iop_message, 1);
        m->type = MSG_PING_ACK;
        m->ping.seg = msg->ping.seg;
        m->ping.timestamp = msg->ping.timestamp;
        iop_outbox_push(s, m);
        goto end;
    }
    switch (s->ep0_status) {
        case EP0_IDLE:
            if (msg->type == MSG_TYPE_WAKE) {
                iop_wakeup(s);
                iop_message_t m;
                m = g_new0(struct iop_message, 1);
                m->type = MSG_SEND_HELLO;
                m->hello.major = s->protocol_version;
                m->hello.minor = s->protocol_version;
                m->endpoint = 0;
                s->ep0_status = EP0_WAIT_HELLO;

                iop_outbox_push(s, m);
            } else {
                IOP_LOG_MSG(s, msg);
            }
            break;

        case EP0_WAIT_HELLO:
            if (msg->type == MSG_RECV_HELLO) {
                iop_message_t m = g_new0(struct iop_message, 1);
                m->type = MSG_TYPE_ROLLCALL;
                m->rollcall.epMask = (1 << 0); /* Register SMCEndpoint1 */
                m->rollcall.epBlock = 1;
                m->rollcall.epEnded = true;
                iop_outbox_push(s, m);
                s->ep0_status = EP0_WAIT_ROLLCALL;
            } else
                IOP_LOG_MSG(s, msg);
            break;

        case EP0_WAIT_ROLLCALL:
            if (msg->type == MSG_TYPE_ROLLCALL) {
                iop_message_t m = g_new0(struct iop_message, 1);
                m->type = MSG_TYPE_POWER;
                m->power.state = 32;
                s->ep0_status = EP0_WAIT_POWERACK;
                iop_outbox_push(s, m);
            } else {
                IOP_LOG_MSG(s, msg);
            }
            break;

        case EP0_WAIT_POWERACK:
            if (msg->type == MSG_TYPE_POWERACK) {
                iop_message_t m = g_new0(struct iop_message, 1);
                m->type = MSG_TYPE_POWERACK;
                m->power.state = msg->power.state;
                s->ep0_status = EP0_DONE;
                iop_outbox_push(s, m);
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

static void *iop_thread_fn(void *opaque)
{
    AppleIOPMailboxState *s = APPLE_IOP_MAILBOX(opaque);

    while (!s->stopping) {
        bool has_work;

        WITH_QEMU_LOCK_GUARD(&s->mutex) {
            has_work = !iop_inbox_empty(s);

            if (has_work) {
                iop_message_t msg = iop_inbox_get(s);
                switch (msg->endpoint) {
                    case 0:
                        iop_handle_management_msg(s, msg);
                        break;
                    default:
                        if (s->ops->message) {
                            s->ops->message(s->opaque, msg);
                        } else {
                            qemu_log_mask(LOG_GUEST_ERROR,
                                          "%s: Unexpected message to endpoint %u\n", s->role, msg->endpoint);
                            IOP_LOG_MSG(s, msg);
                            g_free(msg);
                        }
                        break;
                }

                if (iop_inbox_empty(s)) {
                    qemu_mutex_unlock(&s->mutex);
                    qemu_mutex_lock_iothread();
                    qemu_irq_raise(s->irqs[IRQ_IOP_INBOX]);
                    qemu_mutex_unlock_iothread();
                    qemu_mutex_lock(&s->mutex);
                }
            } else {
                qemu_cond_wait(&s->iop_halt, &s->mutex);
            }
        }
    }

    return NULL;
}

static void iop_akf_reg_write(void *opaque, hwaddr addr,
                              uint64_t data, unsigned size)
{
    AppleIOPMailboxState *s = APPLE_IOP_MAILBOX(opaque);

    WITH_QEMU_LOCK_GUARD(&s->mutex) {
        switch (addr) {
            case REG_AKF_CONFIG:
                s->config = data;
                return;

            case REG_A7V4_CPU_CTRL:
                if (data & REG_A7V4_CPU_CTRL_RUN) {
                    iop_message_t msg;

                    s->cpu_ctrl = data;

                    iop_start(s);

                    msg = g_new0(struct iop_message, 1);
                    msg->type = MSG_SEND_HELLO;
                    msg->hello.major = s->protocol_version;
                    msg->hello.minor = s->protocol_version;
                    msg->endpoint = 0;
                    s->ep0_status = EP0_WAIT_HELLO;

                    iop_outbox_push_nolock(s, msg);
                }
                return;

            case REG_A7V4_A2I_MSG0:
                s->inboxBuffer[0] = data;
                return;

            case REG_A7V4_A2I_MSG1:
            {
                iop_message_t msg;

                s->inboxBuffer[1] = data;
                msg = g_new0(struct iop_message, 1);
                memcpy(msg->data, s->inboxBuffer, sizeof(s->inboxBuffer));
                iop_inbox_push(s, msg);
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

static uint64_t iop_akf_reg_read(void *opaque, hwaddr addr, unsigned size)
{
    AppleIOPMailboxState *s = APPLE_IOP_MAILBOX(opaque);
    WITH_QEMU_LOCK_GUARD(&s->mutex) {
        iop_message_t m;
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

                if (iop_outbox_empty(s)) {
                    qemu_irq_lower(s->irqs[IRQ_IOP_OUTBOX]);
                }

                g_free(m);
                return ret;

            case REG_A7V4_INBOX_CTRL:
                if (iop_inbox_empty(s)) {
                    ret |= REG_A7V4_INBOX_CTRL_EMPTY;
                }
                return ret;

            case REG_A7V4_OUTBOX_CTRL:
                if (iop_outbox_empty(s)) {
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

static const MemoryRegionOps iop_akf_reg_ops = {
        .write = iop_akf_reg_write,
        .read = iop_akf_reg_read,
        .endianness = DEVICE_NATIVE_ENDIAN,
        .valid.min_access_size = 4,
        .valid.max_access_size = 8,
        .impl.min_access_size = 4,
        .impl.max_access_size = 8,
        .valid.unaligned = false,
};

AppleIOPMailboxState *apple_iop_mailbox_create(const char *role,
                                               void *opaque,
                                               uint64_t mmio_size,
                                               uint32_t protocol_version,
                                               const struct AppleIOPMailboxOps *ops)
{
    DeviceState  *dev;
    SysBusDevice *sbd;
    AppleIOPMailboxState *s;
    int i;
    char name[32];

    dev = qdev_new(TYPE_APPLE_IOP_MAILBOX);
    sbd = SYS_BUS_DEVICE(dev);
    s = APPLE_IOP_MAILBOX(dev);

    qemu_mutex_init(&s->mutex);

    s->opaque = opaque;
    s->protocol_version = protocol_version;
    s->role = g_strdup(role);
    s->ops = ops;

    snprintf(name, sizeof(name), TYPE_APPLE_IOP_MAILBOX ".%s.akf-reg", s->role);
    /*
     * 0: AppleA7IOP akfRegMap
     */
    memory_region_init_io(&s->mmio, OBJECT(dev), &iop_akf_reg_ops, s,
                          name, mmio_size);
    sysbus_init_mmio(sbd, &s->mmio);

    for (i = 0; i < 3; i++) {
        sysbus_init_irq(sbd, &s->irqs[i]);
    }

    QTAILQ_INIT(&s->inbox);
    QTAILQ_INIT(&s->outbox);
    qemu_cond_init(&s->iop_halt);

    return s;
}

static void apple_iop_mailbox_realize(DeviceState *dev, Error **errp)
{
    AppleIOPMailboxState *s = APPLE_IOP_MAILBOX(dev);
    char name[32];
    if (iop_inbox_empty(s)) {
        qemu_irq_raise(s->irqs[IRQ_IOP_INBOX]);
    }

    snprintf(name, sizeof(name), TYPE_APPLE_IOP_MAILBOX ".%s.thread", s->role);

    qemu_thread_create(&s->iop_thread, name, iop_thread_fn,
                       (void *)s, QEMU_THREAD_JOINABLE);
}

static void apple_iop_mailbox_unrealize(DeviceState *dev)
{
    AppleIOPMailboxState *s = APPLE_IOP_MAILBOX(dev);

    WITH_QEMU_LOCK_GUARD(&s->mutex) {
        s->stopping = true;
    }
    qemu_cond_broadcast(&s->iop_halt);
}

static void apple_iop_mailbox_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->realize = apple_iop_mailbox_realize;
    dc->unrealize = apple_iop_mailbox_unrealize;
    /* dc->reset = apple_iop_mailbox_reset; */
    dc->desc = "Apple IOP Mailbox";
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
}

static const TypeInfo apple_iop_mailbox_info = {
        .name = TYPE_APPLE_IOP_MAILBOX,
        .parent = TYPE_SYS_BUS_DEVICE,
        .instance_size = sizeof(AppleIOPMailboxState),
        .class_init = apple_iop_mailbox_class_init,
};

static void apple_iop_mailbox_register_types(void)
{
    type_register_static(&apple_iop_mailbox_info);
}

type_init(apple_iop_mailbox_register_types);