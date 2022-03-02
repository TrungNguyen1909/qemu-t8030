#ifndef HW_MISC_APPLE_MBOX_H
#define HW_MISC_APPLE_MBOX_H

#include "qemu/osdep.h"
#include "exec/memory.h"
#include "hw/sysbus.h"

#define APPLE_MBOX_IRQ_INBOX_EMPTY          1
#define APPLE_MBOX_IRQ_INBOX_NON_EMPTY      0
#define APPLE_MBOX_IRQ_OUTBOX_EMPTY         3
#define APPLE_MBOX_IRQ_OUTBOX_NON_EMPTY     2
#define APPLE_MBOX_IOP_IRQ         "apple-mbox-iop-irq"

/* sysbus mmio order */
#define APPLE_MBOX_AP_MMIO         0
#define APPLE_MBOX_IOP_MMIO        1 
#define APPLE_MBOX_AP_v2_MMIO      2 


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
 * Send an message to a control endpoint
 */
void apple_mbox_send_control_message(AppleMboxState *s, uint32_t ep,
                                                        uint64_t msg);

/*
 * Register an inbox endpoint listener.
 */
void apple_mbox_register_endpoint(AppleMboxState *s, uint32_t ep,
                                  AppleMboxEPHandler *handler);

/*
 * Unregister an inbox endpoint listener.
 */
void apple_mbox_unregister_endpoint(AppleMboxState *s, uint32_t ep);

/*
 * Register an control inbox endpoint listener.
 */
void apple_mbox_register_control_endpoint(AppleMboxState *s, uint32_t ep,
                                          AppleMboxEPHandler *handler);

void apple_mbox_set_real(AppleMboxState *s, bool real);

AppleMboxState *apple_mbox_create(const char *role,
                                  void *opaque,
                                  uint64_t mmio_size,
                                  uint32_t protocol_version,
                                  const struct AppleMboxOps *ops);

#endif /* HW_MISC_APPLE_MBOX_H */
