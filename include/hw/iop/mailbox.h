#ifndef HW_IOP_MAILBOX_H
#define HW_IOP_MAILBOX_H

#include "qemu/osdep.h"
#include "qemu/lockable.h"
#include "exec/memory.h"
#include "hw/irq.h"
#include "hw/sysbus.h"

#define IRQ_IOP_RESERVED    0
#define IRQ_IOP_INBOX       1
#define IRQ_IOP_OUTBOX      2

#define REG_AKF_CONFIG                  0x2043

/*
 * AP -> IOP: A2I; IOP -> AP: I2A
 * Inbox: A2I
 * Outbox: I2A
 */
#define REG_A7V4_CPU_CTRL                   0x0044
#define     REG_A7V4_CPU_CTRL_RUN           0x10
#define REG_A7V4_NMI0                       0xc04
#define REG_A7V4_NMI1                       0xc14
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

enum apple_iop_mailbox_ep0_state {
    EP0_IDLE,
    EP0_WAIT_HELLO,
    EP0_WAIT_ROLLCALL,
    EP0_WAIT_EPSTART,
    EP0_WAIT_POWERACK,
    EP0_DONE,
};

struct iop_message {
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
    QTAILQ_ENTRY(iop_message) entry;
};

typedef struct iop_message *iop_message_t;

#define TYPE_APPLE_IOP_MAILBOX "apple.iop.mailbox"
OBJECT_DECLARE_SIMPLE_TYPE(AppleIOPMailboxState, APPLE_IOP_MAILBOX)

typedef struct AppleIOPMailboxState {
    SysBusDevice parent_obj;

    MemoryRegion mmio;
    QemuMutex mutex;
    QemuThread iop_thread;
    QemuCond iop_halt;
    void *opaque;
    const struct AppleIOPMailboxOps *ops;
    char *role;
    uint32_t ep0_status;
    uint32_t protocol_version;
    bool stopping;
    uint32_t config;
    uint32_t cpu_ctrl;
    qemu_irq irqs[3];
    uint64_t inboxBuffer[2];
    QTAILQ_HEAD(, iop_message) inbox;
    uint64_t inboxSize;
    QemuMutex *inboxLock;

    bool outboxEnable;
    QTAILQ_HEAD(, iop_message) outbox;
    QemuMutex *outboxLock;
    uint64_t outboxSize;
} AppleIOPMailboxState;

struct AppleIOPMailboxOps {
    void (*start)(void *opaque);
    void (*wakeup)(void *opaque);
    void (*message)(void *opaque, iop_message_t m);
};

void iop_inbox_push(struct AppleIOPMailboxState *s, iop_message_t msg);

iop_message_t iop_inbox_get(struct AppleIOPMailboxState *s);

bool iop_inbox_empty(struct AppleIOPMailboxState *s);

void iop_outbox_push_nolock(struct AppleIOPMailboxState *s, iop_message_t msg);

void iop_outbox_push(struct AppleIOPMailboxState *s, iop_message_t msg);

bool iop_outbox_empty(struct AppleIOPMailboxState *s);

AppleIOPMailboxState *apple_iop_mailbox_create(const char *role,
                                               void *opaque,
                                               uint64_t mmio_size,
                                               uint32_t protocol_version,
                                               const struct AppleIOPMailboxOps *ops);

#endif //HW_IOP_MAILBOX_H
