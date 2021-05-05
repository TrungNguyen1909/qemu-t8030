#ifndef APPLE_ANS_H
#define APPLE_ANS_H

#include "qemu/queue.h"
#include "hw/sysbus.h"
#include "qom/object.h"
#include "hw/arm/xnu_dtb.h"
#include "hw/block/block.h"
#include "hw/pci/pci.h"
#include "hw/pci/pcie_host.h"
#include "hw/pci/msi.h"
#include "hw/pci/msix.h"
#include "sysemu/dma.h"
#include "hw/block/nvme.h"

#define TYPE_APPLE_ANS "apple.ans"
OBJECT_DECLARE_SIMPLE_TYPE(AppleANSState, APPLE_ANS)

#define IRQ_IOP_INBOX 1
#define IRQ_IOP_OUTBOX 2

#define REG_AKF_CONFIG                  0x2043

/* 
AP -> IOP: A2I; IOP -> AP: I2A
Inbox: A2I
Outbox: I2A
*/
#define REG_A7V4_CPU_CTRL		            0x0044
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
#define REG_A7V4_A2I_MSG1		            0x8808
#define REG_A7V4_I2A_MSG0		            0x8830
#define REG_A7V4_I2A_MSG1		            0x8838

#define A7V4_MSG_FLAG_LAST                  (1 << 20)
#define A7V4_MSG_FLAG_NOTLAST               REG_A7V4_OUTBOX_CTRL_HAS_MSG
#define IOP_INBOX_SIZE                      16

#define MSG_SEND_HELLO                      1
#define MSG_RECV_HELLO                      2
#define MSG_TYPE_PING                       4
#define MSG_TYPE_EPSTART                    5
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
                            //bit x set -> create endpoint ((epBlock * 32) + x)
                            uint8_t epBlock : 6; 
                            uint16_t unk38 : 13;
                            uint8_t epEnded : 1;
                        } rollcall;
                    };
                };
                struct QEMU_PACKED {
                    uint32_t field_0;
                    uint16_t field_32;
                    uint8_t field_48 : 4;
                    uint8_t type : 4;
                };
            };
            uint32_t endpoint;
            uint32_t flags;
        };
    };
    QTAILQ_ENTRY(iop_message) entry;
};

typedef struct iop_message* iop_message_t;

#define APPLE_BOOT_STATUS		0x1300
#define   APPLE_BOOT_STATUS_OK		0xde71ce55

typedef struct QEMU_PACKED {
    uint32_t unk0;
    uint32_t unk4;
    uint32_t numBlocks;
} NVMeCreateNamespacesEntryStruct;
struct AppleANSState {
    PCIExpressHost parent_obj;
    MemoryRegion* iomems[4];
    MemoryRegion io_mmio;
    MemoryRegion io_ioport;
    MemoryRegion msix;
    QemuMutex mutex;
    QemuThread iop_thread;
    QemuCond iop_halt;
    uint32_t ep0_status;
    bool stopping;
    //bit 0: outbox enable?
    uint32_t config;
    uint32_t cpu_ctrl;
    qemu_irq irqs[5];

    uint64_t inboxBuffer[2];
    QTAILQ_HEAD(, iop_message) inbox;
    uint64_t inboxSize;
    QemuMutex* inboxLock;

    bool outboxEnable;
    QTAILQ_HEAD(, iop_message) outbox;
    QemuMutex* outboxLock;
    uint64_t outboxSize;
    NvmeCtrl nvme;
    uint32_t nvme_interrupt_idx;
};
SysBusDevice* apple_ans_create(DTBNode* node);
#endif /* APPLE_ANS_H */