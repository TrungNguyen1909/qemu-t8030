#ifndef HW_MISC_APPLE_MBOX_H
#define HW_MISC_APPLE_MBOX_H

#include "qemu/osdep.h"
#include "exec/memory.h"
#include "hw/sysbus.h"

#define APPLE_MBOX_IRQ_RESERVED    0
#define APPLE_MBOX_IRQ_INBOX       1
#define APPLE_MBOX_IRQ_OUTBOX      2

typedef struct AppleMboxState AppleMboxState;

#define TYPE_APPLE_MBOX "apple.mbox"
OBJECT_DECLARE_SIMPLE_TYPE(AppleMboxState, APPLE_MBOX)

typedef void AppleMboxEPHandler(void *opaque, uint32_t ep, uint64_t msg);

struct AppleMboxOps {
    void (*start)(void *opaque);
    void (*wakeup)(void *opaque);
};

/*
 * Send an message to an endpoint
 */
void apple_mbox_send_message(AppleMboxState *s, uint32_t ep, uint64_t msg);

/*
 * Register an inbox endpoint listener.
 */
void apple_mbox_register_endpoint(AppleMboxState *s, uint32_t ep,
                                  AppleMboxEPHandler handler);

AppleMboxState *apple_mbox_create(const char *role,
                                               void *opaque,
                                               uint64_t mmio_size,
                                               uint32_t protocol_version,
                                               const struct AppleMboxOps *ops);

#endif /* HW_MISC_APPLE_MBOX_H */
