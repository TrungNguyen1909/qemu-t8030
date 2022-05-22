#include "qemu/osdep.h"
#include "qemu/main-loop.h"
#include "qemu/log.h"
#include "qemu/lockable.h"
#include "qemu/main-loop.h"
#include "hw/irq.h"
#include "hw/misc/apple_mbox.h"
#include "migration/vmstate.h"
#include "trace.h"
#include "hw/qdev-properties.h"

#define IOP_LOG_MSG(s, msg) \
do { qemu_log_mask(LOG_GUEST_ERROR, "%s: message:" \
                   " type=0x%x ep=%u QWORD0=0x" TARGET_FMT_plx \
                   " QWORD1=0x" TARGET_FMT_plx " ep0_state=0x%x\n", \
                   s->role, msg->mgmt_msg.type, msg->endpoint, \
                   msg->data[0], msg->data[1], \
                   s->ep0_status); } while (0)

#define IOP_LOG_MGMT_MSG(s, msg) \
do { qemu_log_mask(LOG_GUEST_ERROR, "%s: message:" \
                   " ep=0 QWORD0=0x" TARGET_FMT_plx \
                   " ep0_state=0x%x\n", \
                   s->role, \
                   msg->raw, \
                   s->ep0_status); } while (0)

/*
 * AP -> IOP: A2I; IOP -> AP: I2A
 * Inbox: A2I
 * Outbox: I2A
 */

#define REG_A7V4_CPU_CTRL                   0x0044
#define     REG_A7V4_CPU_CTRL_RUN           0x10
#define REG_A7V4_CPU_STATUS                 0x0048
#define     REG_A7V4_CPU_STATUS_IDLE        0x1
#define REG_A7V4_NMI0                       0xc04
#define REG_A7V4_NMI1                       0xc14
#define REG_AKF_CONFIG                      0x2043
#define REG_A7V4_INT_MASK_SET               0x8100
#define REG_A7V4_INT_MASK_CLR               0x8104
#define REG_A7V4_A2I_CTRL                   0x8108
#define REG_A7V4_I2A_CTRL                   0x810C
#define     REG_A7V4_CTRL_ENABLE            (1 << 0)
#define     REG_A7V4_CTRL_FULL              (1 << 16)
#define     REG_A7V4_CTRL_EMPTY             (1 << 17)
#define     REG_A7V4_CTRL_COUNT_SHIFT       (20)
#define     REG_A7V4_CTRL_COUNT_MASK        (0xF << 20)
#define REG_A7V4_A2I_SEND0                  0x8800
#define REG_A7V4_A2I_SEND1                  0x8808
#define REG_A7V4_A2I_RECV0                  0x8810
#define REG_A7V4_A2I_RECV1                  0x8818
#define REG_A7V4_I2A_SEND0                  0x8820
#define REG_A7V4_I2A_SEND1                  0x8828
#define REG_A7V4_I2A_RECV0                  0x8830
#define REG_A7V4_I2A_RECV1                  0x8838

#define REG_A7V2_INT_MASK_SET               0x4000
#define REG_A7V2_INT_MASK_CLR               0x4004
#define REG_A7V2_I2A_NON_EMPTY                  (1 << 12)
#define REG_A7V2_I2A_EMPTY                      (1 << 8)
#define REG_A7V2_A2I_NON_EMPTY                  (1 << 4)
#define REG_A7V2_A2I_EMPTY                      (1 << 0)

#define REG_A7V2_A2I_CTRL                   0x4008
#define REG_A7V2_I2A_CTRL                   0x4020
#define     REG_A7V2_CTRL_ENABLE            (1 << 0)
#define     REG_A7V2_CTRL_FULL              (1 << 16)
#define     REG_A7V2_CTRL_EMPTY             (1 << 17)
#define REG_A7V2_A2I_SEND0                  0x4010
#define REG_A7V2_A2I_SEND1                  0x4014

#define REG_A7V2_A2I_RECV0                  0x4018
#define REG_A7V2_A2I_RECV1                  0x401c

#define REG_A7V2_I2A_SEND0                  0x4030
#define REG_A7V2_I2A_SEND1                  0x4034

#define REG_A7V2_I2A_RECV0                  0x4038
#define REG_A7V2_I2A_RECV1                  0x403c

#define REG_IOP_INT_MASK_SET                (0x100)
#define REG_IOP_INT_MASK_CLR                (0x104)
#define REG_IOP_I2A_CTRL                    (0x10C)
#define     REG_IOP_I2A_CTRL_ENABLE             (1 << 0)
#define     REG_IOP_I2A_CTRL_FULL               (1 << 16)
#define     REG_IOP_I2A_CTRL_EMPTY              (1 << 17)
#define     REG_IOP_I2A_CTRL_OVFL               (1 << 18)
#define     REG_IOP_I2A_CTRL_UDFL               (1 << 19)

#define REG_IOP_I2A_CTRL                    (0x10C)
#define REG_IOP_I2A_SEND0                   (0x820)
#define REG_IOP_I2A_SEND1                   (0x824)
#define REG_IOP_I2A_SEND2                   (0x828)
#define REG_IOP_I2A_SEND3                   (0x82C)

#define REG_IOP_A2I_CTRL                    (0x108)
#define REG_IOP_A2I_RECV0                   (0x810)
#define REG_IOP_A2I_RECV1                   (0x814)
#define REG_IOP_A2I_RECV2                   (0x818)
#define REG_IOP_A2I_RECV3                   (0x81C)

#define REG_SIZE                        (0x10000)

#define IOP_INBOX_SIZE                      16

#define MSG_SEND_HELLO                      1
#define MSG_RECV_HELLO                      2
#define MSG_TYPE_PING                       3
#define MSG_PING_ACK                        4
#define MSG_TYPE_EPSTART                    5
#define MSG_TYPE_REQUEST_PSTATE             6
#define MSG_GET_PSTATE(_x)                  ((_x) & 0xfff)
#define  PSTATE_WAIT_VR             0x201
#define  PSTATE_ON                  0x220
#define  PSTATE_PWRGATE             0x202
#define  PSTATE_SLPNOMEM            0x0
#define MSG_TYPE_POWER                      7
#define MSG_TYPE_ROLLCALL                   8
#define MSG_TYPE_POWERACK                   11

enum apple_mbox_ep0_state {
    EP0_IDLE,
    EP0_WAIT_HELLO,
    EP0_WAIT_ROLLCALL,
    EP0_DONE,
};

typedef struct QEMU_PACKED apple_mbox_mgmt_msg {
    union {
        uint64_t raw;
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
} *apple_mbox_mgmt_msg_t;

struct apple_mbox_msg {
    union QEMU_PACKED {
        uint64_t data[2];
        struct QEMU_PACKED {
            union QEMU_PACKED {
                uint64_t msg;
                struct apple_mbox_mgmt_msg mgmt_msg;
            };
            uint32_t endpoint;
            uint32_t flags;
        };
    };
    QTAILQ_ENTRY(apple_mbox_msg) entry;
};

typedef struct apple_mbox_msg *apple_mbox_msg_t;

typedef struct apple_mbox_ep_handler_data {
    AppleMboxEPHandler *handler;
    void *opaque;
} apple_mbox_ep_handler_data;

struct AppleMboxState {
    SysBusDevice parent_obj;

    MemoryRegion mmio;
    MemoryRegion mmio_v2;
    MemoryRegion iop_mmio;
    QemuMutex mutex;
    void *opaque;
    const struct AppleMboxOps *ops;
    char *role;
    uint32_t ep0_status;
    uint32_t protocol_version;
    qemu_irq irqs[4];
    qemu_irq iop_irq;
    QTAILQ_HEAD(, apple_mbox_msg) inbox;
    QTAILQ_HEAD(, apple_mbox_msg) outbox;
    uint32_t inboxCount;
    uint32_t outboxCount;

    GTree *endpoints;
    QEMUBH *bh;
    uint8_t regs[REG_SIZE];
    uint8_t iop_regs[REG_SIZE];
    uint32_t int_mask;
    uint32_t iop_int_mask;
    bool real;
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

    flags = ((s->outboxCount + 1) << REG_A7V4_CTRL_COUNT_SHIFT)
           & REG_A7V4_CTRL_COUNT_MASK;

    return flags;
}

static void iop_update_irq(AppleMboxState *s)
{
    if (s->real) {
        if (!apple_mbox_empty(s) && ((s->iop_int_mask & 0x10) == 0)) {
            qemu_irq_raise(s->iop_irq);
        } else {
            qemu_irq_lower(s->iop_irq);
        }
    }
}

static void ap_update_irq(AppleMboxState *s)
{
    if (apple_mbox_outbox_empty(s)) {
        if ((s->int_mask & REG_A7V2_I2A_EMPTY) == 0) {
            qemu_irq_raise(s->irqs[APPLE_MBOX_IRQ_OUTBOX_EMPTY]);
        } else {
            qemu_irq_lower(s->irqs[APPLE_MBOX_IRQ_OUTBOX_EMPTY]);
        }
        qemu_irq_lower(s->irqs[APPLE_MBOX_IRQ_OUTBOX_NON_EMPTY]);
    } else {
        qemu_irq_lower(s->irqs[APPLE_MBOX_IRQ_OUTBOX_EMPTY]);
        if ((s->int_mask & REG_A7V2_I2A_NON_EMPTY) == 0) {
            qemu_irq_raise(s->irqs[APPLE_MBOX_IRQ_OUTBOX_NON_EMPTY]);
        } else {
            qemu_irq_lower(s->irqs[APPLE_MBOX_IRQ_OUTBOX_NON_EMPTY]);
        }
    }

    if (apple_mbox_empty(s)) {
        if ((s->int_mask & REG_A7V2_A2I_EMPTY) == 0) {
            qemu_irq_raise(s->irqs[APPLE_MBOX_IRQ_INBOX_EMPTY]);
        } else {
            qemu_irq_lower(s->irqs[APPLE_MBOX_IRQ_INBOX_EMPTY]);
        }
        qemu_irq_lower(s->irqs[APPLE_MBOX_IRQ_INBOX_NON_EMPTY]);
    } else {
        qemu_irq_lower(s->irqs[APPLE_MBOX_IRQ_INBOX_EMPTY]);
        if ((s->int_mask & REG_A7V2_A2I_NON_EMPTY) == 0) {
            qemu_irq_raise(s->irqs[APPLE_MBOX_IRQ_INBOX_NON_EMPTY]);
        } else {
            qemu_irq_lower(s->irqs[APPLE_MBOX_IRQ_INBOX_NON_EMPTY]);
        }
    }
}

/*
 * Push a message from AP to IOP,
 * take ownership of msg
 */
static void apple_mbox_inbox_push(AppleMboxState *s,
                                  apple_mbox_msg_t msg)
{
    QTAILQ_INSERT_TAIL(&s->inbox, msg, entry);
    s->inboxCount++;
    ap_update_irq(s);
    qemu_bh_schedule(s->bh);
}

static apple_mbox_msg_t apple_mbox_pop(AppleMboxState *s)
{
    apple_mbox_msg_t msg = QTAILQ_FIRST(&s->inbox);
    if (msg) {
        QTAILQ_REMOVE(&s->inbox, msg, entry);
        s->inboxCount--;
    }
    ap_update_irq(s);
    return msg;
}

/*
 * Push a message from IOP to AP,
 * take ownership of msg
 */
static void apple_mbox_push(AppleMboxState *s,
                            apple_mbox_msg_t msg)
{
    QTAILQ_INSERT_TAIL(&s->outbox, msg, entry);
    s->outboxCount++;
    ap_update_irq(s);
}

static apple_mbox_msg_t apple_mbox_outbox_pop(AppleMboxState *s)
{
    apple_mbox_msg_t msg = QTAILQ_FIRST(&s->outbox);
    if (msg) {
        QTAILQ_REMOVE(&s->outbox, msg, entry);
        s->outboxCount--;
    }
    ap_update_irq(s);
    return msg;
}

void apple_mbox_send_control_message(AppleMboxState *s, uint32_t ep,
                                                        uint64_t msg)
{
    apple_mbox_msg_t m = g_new(struct apple_mbox_msg, 1);
    m->msg = msg;
    m->endpoint = ep;
    apple_mbox_push(s, m);
}

void apple_mbox_send_message(AppleMboxState *s, uint32_t ep, uint64_t msg)
{
    apple_mbox_send_control_message(s, ep + 31, msg);
}

static gboolean iop_rollcall(gpointer key, gpointer value, gpointer data)
{
    struct iop_rollcall_data *d = (struct iop_rollcall_data *)data;
    AppleMboxState *s = d->s;
    uint32_t ep = (uint64_t)key - 31;
    if ((uint64_t)key < 31) {
        return false;
    }

    if ((ep - 1) / 32 != d->last_block) {
        apple_mbox_mgmt_msg_t m = g_new0(struct apple_mbox_mgmt_msg, 1);
        m->type = MSG_TYPE_ROLLCALL;
        m->rollcall.epMask = d->mask;
        m->rollcall.epBlock = (d->last_block + 1);
        m->rollcall.epEnded = false;
        apple_mbox_send_control_message(s, 0, m->raw);
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

static void iop_handle_management_msg(void *opaque, uint32_t ep,
                                                    uint64_t message)
{
    AppleMboxState *s = APPLE_MBOX(opaque);
    apple_mbox_mgmt_msg_t msg = (apple_mbox_mgmt_msg_t)&message;
    if (msg->type == MSG_TYPE_PING) {
        apple_mbox_mgmt_msg_t m = g_new0(struct apple_mbox_mgmt_msg, 1);
        m->type = MSG_PING_ACK;
        m->ping.seg = msg->ping.seg;
        m->ping.timestamp = msg->ping.timestamp;
        apple_mbox_send_control_message(s, 0, m->raw);
        goto end;
    }
    switch (s->ep0_status) {
        case EP0_IDLE:
            switch (msg->type) {
            case MSG_TYPE_REQUEST_PSTATE: {
                apple_mbox_mgmt_msg_t m = g_new0(struct apple_mbox_mgmt_msg, 1);

                switch (MSG_GET_PSTATE(msg->raw)) {
                case PSTATE_WAIT_VR:
                case PSTATE_ON:
                    iop_wakeup(s);
                    m->type = MSG_SEND_HELLO;
                    m->hello.major = s->protocol_version;
                    m->hello.minor = s->protocol_version;
                    s->ep0_status = EP0_WAIT_HELLO;
                    apple_mbox_send_control_message(s, 0, m->raw);
                    break;
                case PSTATE_SLPNOMEM:
                    m->type = MSG_TYPE_POWER;
                    m->power.state = 0;
                    s->regs[REG_A7V4_CPU_STATUS] = REG_A7V4_CPU_STATUS_IDLE;
                    smp_wmb();
                    apple_mbox_send_control_message(s, 0, m->raw);
                    break;
                default:
                    break;
                }
                break;
            }
            case MSG_TYPE_EPSTART:
                break;
            case MSG_TYPE_POWERACK: {
                apple_mbox_mgmt_msg_t m = g_new0(struct apple_mbox_mgmt_msg, 1);

                m->type = MSG_TYPE_POWERACK;
                m->power.state = msg->power.state;
                apple_mbox_send_control_message(s, 0, m->raw);
                break;
            }
            default:
                IOP_LOG_MGMT_MSG(s, msg);
                break;
            }
            break;
        case EP0_WAIT_HELLO:
            if (msg->type == MSG_RECV_HELLO) {
                apple_mbox_mgmt_msg_t m = g_new0(struct apple_mbox_mgmt_msg, 1);
                struct iop_rollcall_data d = { 0 };
                d.s = s;
                g_tree_foreach(s->endpoints, iop_rollcall, &d);
                m->type = MSG_TYPE_ROLLCALL;
                m->rollcall.epMask = d.mask;
                m->rollcall.epBlock = (d.last_block + 1);
                m->rollcall.epEnded = true;
                s->ep0_status = EP0_WAIT_ROLLCALL;
                apple_mbox_send_control_message(s, 0, m->raw);
            } else {
                IOP_LOG_MGMT_MSG(s, msg);
            }
            break;
        case EP0_WAIT_ROLLCALL:
            if (msg->type == MSG_TYPE_ROLLCALL) {
                if (msg->rollcall.epEnded) {
                    apple_mbox_mgmt_msg_t m = g_new0(struct apple_mbox_mgmt_msg, 1);
                    m->type = MSG_TYPE_POWER;
                    m->power.state = 32;
                    s->ep0_status = EP0_IDLE;
                    apple_mbox_send_control_message(s, 0, m->raw);
                }
            } else {
                IOP_LOG_MGMT_MSG(s, msg);
            }
            break;
        default:
            IOP_LOG_MGMT_MSG(s, msg);
            break;
    }
end:
    return;
}

static void apple_mbox_bh(void *opaque)
{
    AppleMboxState *s = APPLE_MBOX(opaque);

    if (s->real) {
        return;
    }
    WITH_QEMU_LOCK_GUARD(&s->mutex) {
        while (!apple_mbox_empty(s)) {
            apple_mbox_msg_t msg = apple_mbox_pop(s);
            apple_mbox_ep_handler_data *hd = NULL;
            hd = g_tree_lookup(s->endpoints, GUINT_TO_POINTER(msg->endpoint));
            if (hd && hd->handler) {
                /* TODO: Better API */
                hd->handler(hd->opaque,
                            msg->endpoint >= 31 ? msg->endpoint - 31
                                                : msg->endpoint, msg->msg);
            } else {
                qemu_log_mask(LOG_GUEST_ERROR,
                              "%s: Unexpected message to endpoint %u\n", s->role, msg->endpoint);
                IOP_LOG_MSG(s, msg);
            }
            g_free(msg);
            break;
        }
    }
}

static void apple_mbox_reg_write(void *opaque, hwaddr addr,
                                 uint64_t data, unsigned size)
{
    AppleMboxState *s = APPLE_MBOX(opaque);
    bool doorbell = false;
    bool iflg = false;

    s->int_mask = 0;
    WITH_QEMU_LOCK_GUARD(&s->mutex) {
        switch (addr) {
            case REG_A7V4_CPU_CTRL:
                if (data & REG_A7V4_CPU_CTRL_RUN) {
                    apple_mbox_mgmt_msg_t msg;
                    iop_start(s);

                    msg = g_new0(struct apple_mbox_mgmt_msg, 1);
                    msg->type = MSG_SEND_HELLO;
                    msg->hello.major = s->protocol_version;
                    msg->hello.minor = s->protocol_version;
                    s->ep0_status = EP0_WAIT_HELLO;

                    apple_mbox_send_control_message(s, 0, msg->raw);
                }
                break;

            case REG_A7V4_A2I_SEND0:
            case REG_A7V4_A2I_SEND1:
            {
                if (addr + size == REG_A7V4_A2I_SEND0 + 16) {
                    doorbell = true;
                }
                break;
            }
            case REG_A7V4_A2I_CTRL:
            case REG_A7V4_I2A_CTRL:
                data &= REG_A7V4_CTRL_ENABLE;
                break;
            case REG_A7V4_INT_MASK_SET:
                s->int_mask |= data;
                iflg = true;
                break;
            case REG_A7V4_INT_MASK_CLR:
                s->int_mask &= ~data;
                iflg = true;
                break;
            default:
                qemu_log_mask(LOG_GUEST_ERROR,
                              "%s: AppleA7IOP AKF unknown reg WRITE @ 0x"
                              TARGET_FMT_plx " value: 0x" TARGET_FMT_plx "\n",
                              s->role, addr, data);
                break;
        }

        memcpy(&s->regs[addr], &data, size);
        if (doorbell) {
            apple_mbox_msg_t msg;

            msg = g_new0(struct apple_mbox_msg, 1);
            memcpy(msg->data, &s->regs[REG_A7V4_A2I_SEND0], 16);
            apple_mbox_inbox_push(s, msg);
            iop_update_irq(s);
        }
        if (iflg) {
            ap_update_irq(s);
        }
    }
}

static uint64_t apple_mbox_reg_read(void *opaque, hwaddr addr,
                                    unsigned size)
{
    AppleMboxState *s = APPLE_MBOX(opaque);
    uint64_t ret = 0;
    WITH_QEMU_LOCK_GUARD(&s->mutex) {
        apple_mbox_msg_t m;
        memcpy(&ret, &s->regs[addr], size);

        switch (addr) {

        case REG_A7V4_I2A_RECV0:
            m = apple_mbox_outbox_pop(s);
            if (!m) {
                break;
            }
            m->flags = iop_outbox_flags(s);

            memcpy(&s->regs[REG_A7V4_I2A_RECV0], m->data, 16);
            memcpy(&ret, &s->regs[addr], size);

            g_free(m);
            break;
        case REG_A7V4_I2A_RECV1:
            break;
        case REG_A7V4_A2I_CTRL:
            if (apple_mbox_empty(s)) {
                ret |= REG_A7V4_CTRL_EMPTY;
            } else {
                ret |= (s->inboxCount << REG_A7V4_CTRL_COUNT_SHIFT)
                       & REG_A7V4_CTRL_COUNT_MASK;
            }
            break;
        case REG_A7V4_I2A_CTRL:
            if (apple_mbox_outbox_empty(s)) {
                ret |= REG_A7V4_CTRL_EMPTY;
            } else {
                ret |= (s->outboxCount << REG_A7V4_CTRL_COUNT_SHIFT)
                       & REG_A7V4_CTRL_COUNT_MASK;
            }
            break;
        default:
            qemu_log_mask(LOG_UNIMP, "%s: AppleA7IOP AKF unknown reg READ @ 0x"
                                     TARGET_FMT_plx "\n", s->role, addr);
            break;
        }
    }

    return ret;
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

static void apple_mbox_v2_reg_write(void *opaque, hwaddr addr,
                                    uint64_t data, unsigned size)
{
    AppleMboxState *s = APPLE_MBOX(opaque);
    bool doorbell = false;
    bool iflg = false;

    WITH_QEMU_LOCK_GUARD(&s->mutex) {
        switch (addr) {
            case REG_A7V4_CPU_CTRL:
                if (data & REG_A7V4_CPU_CTRL_RUN) {
                    apple_mbox_mgmt_msg_t msg;
                    iop_start(s);

                    msg = g_new0(struct apple_mbox_mgmt_msg, 1);
                    msg->type = MSG_SEND_HELLO;
                    msg->hello.major = s->protocol_version;
                    msg->hello.minor = s->protocol_version;
                    s->ep0_status = EP0_WAIT_HELLO;

                    apple_mbox_send_control_message(s, 0, msg->raw);
                }
                break;

            case REG_A7V2_A2I_SEND0:
            case REG_A7V2_A2I_SEND1:
            {
                if (addr + size == REG_A7V2_A2I_SEND0 + 8) {
                    doorbell = true;
                }
                break;
            }
            case REG_A7V2_A2I_CTRL:
            case REG_A7V2_I2A_CTRL:
                data &= REG_A7V2_CTRL_ENABLE;
                break;
            case REG_A7V2_INT_MASK_SET:
                s->int_mask |= (uint32_t)data;
                iflg = true;
                break;
            case REG_A7V2_INT_MASK_CLR:
                s->int_mask &= ~(uint32_t)data;
                iflg = true;
                break;
            default:
                qemu_log_mask(LOG_GUEST_ERROR,
                              "%s: AppleA7IOP AKF unknown reg WRITE @ 0x"
                              TARGET_FMT_plx " value: 0x" TARGET_FMT_plx "\n",
                              s->role, addr, data);
                break;
        }

        memcpy(&s->regs[addr], &data, size);
        if (doorbell) {
            apple_mbox_msg_t msg;

            msg = g_new0(struct apple_mbox_msg, 1);
            memcpy(msg->data, &s->regs[REG_A7V2_A2I_SEND0], 8);
            apple_mbox_inbox_push(s, msg);
            iop_update_irq(s);
        }
        if (iflg) {
            ap_update_irq(s);
        }
    }
}

static uint64_t apple_mbox_v2_reg_read(void *opaque, hwaddr addr,
                                       unsigned size)
{
    AppleMboxState *s = APPLE_MBOX(opaque);
    uint64_t ret = 0;

    WITH_QEMU_LOCK_GUARD(&s->mutex) {
        apple_mbox_msg_t m;
        memcpy(&ret, &s->regs[addr], size);

        switch (addr) {

        case REG_A7V2_I2A_RECV0:
            m = apple_mbox_outbox_pop(s);
            if (!m) {
                break;
            }
            m->flags = iop_outbox_flags(s);

            memcpy(&s->regs[REG_A7V2_I2A_RECV0], m->data, 8);
            memcpy(&ret, &s->regs[addr], size);

            g_free(m);
            break;
        case REG_A7V2_I2A_RECV1:
            break;
        case REG_A7V2_A2I_CTRL:
            if (apple_mbox_empty(s)) {
                ret |= REG_A7V2_CTRL_EMPTY;
            }
            break;
        case REG_A7V2_I2A_CTRL:
            if (apple_mbox_outbox_empty(s)) {
                ret |= REG_A7V2_CTRL_EMPTY;
            }
            break;
        default:
            qemu_log_mask(LOG_UNIMP, "%s: AppleA7IOP AKF unknown reg READ @ 0x"
                                     TARGET_FMT_plx "\n", s->role, addr);
            break;
        }
    }

    return ret;
}

static const MemoryRegionOps apple_mbox_v2_reg_ops = {
        .write = apple_mbox_v2_reg_write,
        .read = apple_mbox_v2_reg_read,
        .endianness = DEVICE_NATIVE_ENDIAN,
        .valid.min_access_size = 4,
        .valid.max_access_size = 8,
        .impl.min_access_size = 4,
        .impl.max_access_size = 8,
        .valid.unaligned = false,
};

static void apple_mbox_iop_reg_write(void *opaque, hwaddr addr,
                                     uint64_t data, unsigned size)
{
    AppleMboxState *s = APPLE_MBOX(opaque);
    bool doorbell = false;
    bool iflg = false;
    uint32_t value = data;

    WITH_QEMU_LOCK_GUARD(&s->mutex) {
        switch (addr) {
            case REG_IOP_I2A_SEND0:
            case REG_IOP_I2A_SEND1:
            case REG_IOP_I2A_SEND2:
            case REG_IOP_I2A_SEND3:
            {
                if (addr + size == REG_IOP_I2A_SEND0 + 16) {
                    doorbell = true;
                }
                break;
            }
            case REG_IOP_INT_MASK_SET:
                s->iop_int_mask |= value;
                iflg = true;
                break;
            case REG_IOP_INT_MASK_CLR:
                s->iop_int_mask &= ~value;
                iflg = true;
                break;
            default:
                qemu_log_mask(LOG_GUEST_ERROR,
                              "%s: AppleA7IOP AKF unknown IOP reg WRITE @ 0x"
                              TARGET_FMT_plx " value: 0x" TARGET_FMT_plx "\n",
                              s->role, addr, data);
                break;
        }
        memcpy(&s->iop_regs[addr], &data, size);

        if (doorbell) {
            apple_mbox_msg_t msg;

            msg = g_new0(struct apple_mbox_msg, 1);
            memcpy(msg->data, &s->iop_regs[REG_IOP_I2A_SEND0], 16);
            apple_mbox_push(s, msg);
        }

        if (iflg) {
            iop_update_irq(s);
        }

    }
}

static uint64_t apple_mbox_iop_reg_read(void *opaque, hwaddr addr,
                                        unsigned size)
{
    AppleMboxState *s = APPLE_MBOX(opaque);

    WITH_QEMU_LOCK_GUARD(&s->mutex) {
        apple_mbox_msg_t m;
        uint32_t ret = 0;
        memcpy(&ret, &s->iop_regs[addr], sizeof(ret));

        switch (addr) {
        case REG_IOP_I2A_CTRL:
            if (apple_mbox_outbox_empty(s)) {
                ret |= REG_IOP_I2A_CTRL_EMPTY;
            }
            break;
        case REG_IOP_A2I_CTRL:
            ret &= ~(REG_IOP_I2A_CTRL_EMPTY);
            if (apple_mbox_empty(s)) {
                ret |= REG_IOP_I2A_CTRL_EMPTY;
            }
            break;
        case REG_IOP_A2I_RECV0:
            m = apple_mbox_pop(s);
            if (!m) {
                break;
            }
            m->flags = iop_outbox_flags(s);
            memcpy(&s->iop_regs[REG_IOP_A2I_RECV0], m->data, 16);
            memcpy(&ret, &s->iop_regs[addr], size);
            g_free(m);
            iop_update_irq(s);
        case REG_IOP_A2I_RECV1:
        case REG_IOP_A2I_RECV2:
        case REG_IOP_A2I_RECV3:
            break;
        default:
            qemu_log_mask(LOG_UNIMP, "%s: AppleA7IOP AKF unknown IOP reg READ @ 0x"
                                     TARGET_FMT_plx " ret: 0x%08x\n",
                                     s->role, addr, ret);
            break;
        }

        return ret;
    }

    return 0;
}

static const MemoryRegionOps apple_mbox_iop_reg_ops = {
        .write = apple_mbox_iop_reg_write,
        .read = apple_mbox_iop_reg_read,
        .endianness = DEVICE_NATIVE_ENDIAN,
        .valid.min_access_size = 4,
        .valid.max_access_size = 4,
        .impl.min_access_size = 4,
        .impl.max_access_size = 4,
        .valid.unaligned = false,
};

void apple_mbox_set_real(AppleMboxState *s, bool real)
{
    s->real = real;
    qemu_log_mask(LOG_UNIMP, "AppleA7IOP set real: %s\n",
                                             real ? "true" : "false");
    smp_wmb();
}

void apple_mbox_register_endpoint(AppleMboxState *s, uint32_t ep,
                                  AppleMboxEPHandler *handler)
{
    assert(ep > 0);
    apple_mbox_ep_handler_data *hd = g_new0(apple_mbox_ep_handler_data, 1);
    ep += 31;
    hd->handler = handler;
    hd->opaque = s->opaque;
    g_tree_insert(s->endpoints, GUINT_TO_POINTER(ep), hd);
}

void apple_mbox_unregister_endpoint(AppleMboxState *s, uint32_t ep)
{
    assert(ep > 0);
    ep += 31;
    void *hd = g_tree_lookup(s->endpoints, GUINT_TO_POINTER(ep));
    if (hd) {
        g_tree_remove(s->endpoints, GUINT_TO_POINTER(ep));
        g_free(hd);
    }
}

void apple_mbox_register_control_endpoint(AppleMboxState *s, uint32_t ep,
                                          AppleMboxEPHandler *handler)
{
    assert(ep < 31);
    apple_mbox_ep_handler_data *hd = g_new0(apple_mbox_ep_handler_data, 1);
    hd->handler = handler;
    hd->opaque = s->opaque;
    g_tree_insert(s->endpoints, GUINT_TO_POINTER(ep), hd);
}

static void
    apple_mbox_register_control_endpoint_internal(AppleMboxState *s,
                                                  uint32_t ep,
                                                  AppleMboxEPHandler *handler)
{
    assert(ep < 31);
    apple_mbox_ep_handler_data *hd = g_new0(apple_mbox_ep_handler_data, 1);
    hd->handler = handler;
    hd->opaque = s;
    g_tree_insert(s->endpoints, GUINT_TO_POINTER(ep), hd);
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

    memory_region_init_io(&s->iop_mmio, OBJECT(dev), &apple_mbox_iop_reg_ops,
                          s, name, REG_SIZE);
    sysbus_init_mmio(sbd, &s->iop_mmio);

    memory_region_init_io(&s->mmio_v2, OBJECT(dev), &apple_mbox_v2_reg_ops, s,
                          name, mmio_size);
    sysbus_init_mmio(sbd, &s->mmio_v2);

    for (i = 0; i < 4; i++) {
        sysbus_init_irq(sbd, &s->irqs[i]);
    }

    qdev_init_gpio_out_named(DEVICE(dev), &s->iop_irq, APPLE_MBOX_IOP_IRQ, 1);
    QTAILQ_INIT(&s->inbox);
    QTAILQ_INIT(&s->outbox);
    apple_mbox_register_control_endpoint_internal(s, 0,
                                                   &iop_handle_management_msg);

    return s;
}

static void apple_mbox_realize(DeviceState *dev, Error **errp)
{
    AppleMboxState *s = APPLE_MBOX(dev);
    ap_update_irq(s);

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
        s->inboxCount = 0;
        s->outboxCount = 0;
    }
    s->iop_int_mask = 0xffffffff;
    s->int_mask = 0xffffffff;
    ap_update_irq(s);
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

static Property apple_mbox_properties[] = {
    DEFINE_PROP_BOOL("real", AppleMboxState, real, false),
    DEFINE_PROP_END_OF_LIST(),
};

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
        VMSTATE_BOOL(real, AppleMboxState),
        VMSTATE_UINT32(int_mask, AppleMboxState),
        VMSTATE_UINT32(iop_int_mask, AppleMboxState),
        VMSTATE_UINT32(ep0_status, AppleMboxState),
        VMSTATE_UINT32(protocol_version, AppleMboxState),
        VMSTATE_UINT8_ARRAY(regs, AppleMboxState, REG_SIZE),
        VMSTATE_UINT8_ARRAY(iop_regs, AppleMboxState, REG_SIZE),
        VMSTATE_QTAILQ_V(inbox, AppleMboxState, 1, vmstate_apple_mbox_msg,
                        struct apple_mbox_msg, entry),
        VMSTATE_QTAILQ_V(outbox, AppleMboxState, 1, vmstate_apple_mbox_msg,
                        struct apple_mbox_msg, entry),
        VMSTATE_UINT32(inboxCount, AppleMboxState),
        VMSTATE_UINT32(outboxCount, AppleMboxState),

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
    device_class_set_props(dc, apple_mbox_properties);
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
