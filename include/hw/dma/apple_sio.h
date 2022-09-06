#ifndef APPLE_SIO_H
#define APPLE_SIO_H

#include "qemu/osdep.h"
#include "hw/sysbus.h"
#include "qom/object.h"
#include "qemu/iov.h"
#include "sysemu/dma.h"
#include "hw/misc/apple_mbox.h"
#include "hw/arm/xnu_dtb.h"

#define TYPE_APPLE_SIO "apple.sio"
OBJECT_DECLARE_SIMPLE_TYPE(AppleSIOState, APPLE_SIO)

#define SIO_NUM_EPS         (0xdb)

typedef struct QEMU_PACKED sio_dma_config {
    uint32_t xfer;
    uint32_t timeout;
    uint32_t fifo;
    uint32_t trigger;
    uint32_t depth;
    uint64_t unk18;
} sio_dma_config;

typedef struct QEMU_PACKED sio_dma_segment {
    uint64_t addr;
    uint32_t len;
} sio_dma_segment;

typedef void AppleSIODMAHandler(void *opaque, uint32_t ep, uint32_t length);

typedef struct AppleSIODMAEndpoint {
    struct sio_dma_config config;
    struct sio_dma_segment *segments;
    QEMUSGList sgl;
    QEMUIOVector iov;
    uint32_t count;
    uint32_t actual_length;
    AppleSIODMAHandler *handler;
    uint32_t id;
    uint32_t tag;
    bool mapped;
    DMADirection dir;
} AppleSIODMAEndpoint;

typedef struct AppleSIOState {
    SysBusDevice parent_obj;
    MemoryRegion ascv2_iomem;
    AppleMboxState *mbox;
    MemoryRegion *dma_mr;
    AddressSpace dma_as;

    AppleSIODMAEndpoint eps[SIO_NUM_EPS];
    uint32_t params[0x100];
} AppleSIOState;

int apple_sio_dma_read(AppleSIODMAEndpoint *ep, void *buffer, size_t len);
int apple_sio_dma_write(AppleSIODMAEndpoint *ep, void *buffer, size_t len);
int apple_sio_dma_remaining(AppleSIODMAEndpoint *ep);
AppleSIODMAEndpoint *apple_sio_get_endpoint(AppleSIOState *s, int ep);
AppleSIODMAEndpoint *apple_sio_get_endpoint_from_node(AppleSIOState *s,
                                                      DTBNode *node, int idx);
SysBusDevice *apple_sio_create(DTBNode *node, uint32_t protocol_version);

#endif /* APPLE_SIO_H */
