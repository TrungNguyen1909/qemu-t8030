#include "qemu/osdep.h"
#include "qapi/error.h"
#include "hw/dma/apple_sio.h"
#include "hw/misc/apple_mbox.h"
#include "hw/irq.h"
#include "migration/vmstate.h"
#include "qemu/bitops.h"
#include "qemu/iov.h"
#include "qemu/log.h"
#include "qemu/module.h"
#include "qemu/queue.h"
#include "sysemu/dma.h"
#include "sysemu/runstate.h"
#include "hw/arm/xnu.h"
#include "hw/arm/xnu_dtb.h"

//#define DEBUG_SIO

#ifdef DEBUG_SIO
#define SIO_LOG_MSG(ep, msg) \
do { qemu_log_mask(LOG_GUEST_ERROR, "SIO: message:" \
                   " ep=%u msg=0x" TARGET_FMT_plx "\n", \
                   ep, msg); } while (0)
#else
#define SIO_LOG_MSG(ep, msg) do {} while (0)
#endif

typedef enum sio_op {
    GET_PARAM = 2,
    GET_PARAM_RETURN = 103,
    CONFIG_SHIM = 5,
    SET_PARAM = 3,
    ERROR = 2,
    SET_PARAM_ERROR = 3,
    START_DMA = 6,
    QUERY_DMA = 7,
    STOP_DMA = 8,
    ACK = 101,
    ASYNC_ERROR = 102,
    DMA_COMPLETE = 104,
    QUERY_DMA_OK = 105,
} sio_op;

typedef enum sio_endpoint {
    CONTROL = 0,
    PERF = 3,
} sio_endpoint;

typedef enum sio_param_id {
    PROTOCOL    = 0, /* Should be 9 for 14.0b5 */
    DMA_SEGMENT_BASE  = 1,
    DMA_SEGMENT_SIZE  = 2,
    DMA_RESPONSE_BASE  = 11,
    DMA_RESPONSE_SIZE  = 12,
    PERF_BASE  = 13,
    PERF_SIZE  = 14,
    PANIC_BASE  = 15,
    PANIC_SIZE  = 16,
    PIO_BASE  = 26,
    PIO_SIZE  = 27,
    DEVICES_BASE  = 28,
    DEVICES_SIZE  = 29,
    TUNABLE_0_BASE  = 30,
    TUNABLE_0_SIZE  = 31,
    TUNABLE_1_BASE  = 32,
    TUNABLE_1_SIZE  = 33,
    PS_REGS_BASE  = 36,
    PS_REGS_SIZE  = 37,
    FORWARD_IRQS_BASE  = 38,
    FORWARD_IRQS_SIZE  = 39,
} sio_param_id;

typedef struct QEMU_PACKED sio_msg {
    union {
        uint64_t raw;
        struct QEMU_PACKED {
            uint8_t ep;
            uint8_t tag;
            uint8_t op;
            uint8_t param;
            uint32_t data;
        };
    };
} sio_msg;

static void apple_sio_map_dma(AppleSIOState *s, AppleSIODMAEndpoint *ep)
{
    if (ep->mapped) {
        return;
    }
    qemu_iovec_init(&ep->iov, ep->count);
    for (int i = 0; i < ep->count; i++) {
        dma_addr_t base = ep->sgl.sg[i].base;
        dma_addr_t len = ep->sgl.sg[i].len;

        while (len) {
            dma_addr_t xlen = len;
            void *mem = dma_memory_map(&s->dma_as, base,
                                       &xlen, ep->dir,
                                       MEMTXATTRS_UNSPECIFIED);
            if (!mem) {
                qemu_log_mask(LOG_GUEST_ERROR, "%s: unable to map memory\n",
                              __func__);
                continue;
            }
            if (xlen > len) {
                xlen = len;
            }
            qemu_iovec_add(&ep->iov, mem, xlen);
            len -= xlen;
            base += xlen;
        }
    }

    ep->mapped = true;
    ep->actual_length = 0;
    /* TODO: call handler? */
}

static void apple_sio_unmap_dma(AppleSIOState *s, AppleSIODMAEndpoint *ep)
{
    ep->mapped = false;
    int unmap_length = ep->actual_length;
    for (int i = 0; i < ep->iov.niov; i++) {
        int access_len = ep->iov.iov[i].iov_len;
        if (access_len > unmap_length) {
            access_len = unmap_length;
        }

        dma_memory_unmap(&s->dma_as, ep->iov.iov[i].iov_base,
                         ep->iov.iov[i].iov_len, ep->dir,
                         access_len);
        unmap_length -= access_len;
    }
    qemu_iovec_destroy(&ep->iov);
    ep->count = 0;
    ep->actual_length = 0;
    ep->tag = 0;
    g_free(ep->segments);
    ep->segments = NULL;
    qemu_sglist_destroy(&ep->sgl);
}

static void apple_sio_dma_writeback(AppleSIOState *s, AppleSIODMAEndpoint *ep)
{
    sio_msg m = { 0 };
    m.op = DMA_COMPLETE;
    m.ep = ep->id;
    m.param = (1 << 7);
    m.tag = ep->tag;
    m.data = ep->actual_length;
    apple_sio_unmap_dma(s, ep);
    apple_mbox_send_message(s->mbox, 1, m.raw);
}

int apple_sio_dma_read(AppleSIODMAEndpoint *ep, void *buffer, size_t len)
{
    AppleSIOState *s = container_of(ep, AppleSIOState, eps[ep->id]);
    int xlen = 0;
    if (!ep->mapped) {
        return 0;
    }
    assert(ep->dir == DMA_DIRECTION_TO_DEVICE);
    xlen = qemu_iovec_to_buf(&ep->iov, ep->actual_length, buffer, len);
    ep->actual_length += xlen;
    if (ep->actual_length >= ep->iov.size) {
        apple_sio_dma_writeback(s, ep);
    }
    return xlen;
}

int apple_sio_dma_write(AppleSIODMAEndpoint *ep, void *buffer, size_t len)
{
    AppleSIOState *s = container_of(ep, AppleSIOState, eps[ep->id]);
    int xlen = 0;
    if (!ep->mapped) {
        return 0;
    }
    assert(ep->dir == DMA_DIRECTION_FROM_DEVICE);
    xlen = qemu_iovec_from_buf(&ep->iov, ep->actual_length, buffer, len);
    ep->actual_length += xlen;
    if (ep->actual_length >= ep->iov.size) {
        apple_sio_dma_writeback(s, ep);
    }
    return xlen;
}

int apple_sio_dma_remaining(AppleSIODMAEndpoint *ep) {
    return ep->iov.size - ep->actual_length;
}

static void apple_sio_control(AppleSIOState *s, AppleSIODMAEndpoint *ep, sio_msg m)
{
    sio_msg reply = { 0 };
    reply.ep = m.ep;
    reply.tag = m.tag;
    switch (m.op) {
    case GET_PARAM: {
        reply.data = s->params[m.param];
        reply.op = GET_PARAM_RETURN;
        break;
    }
    case SET_PARAM: {
        s->params[m.param] = m.data;
        reply.op = ACK;
        break;
    }
    default:
        break;
    }
    apple_mbox_send_message(s->mbox, 1, reply.raw);
};

static void apple_sio_dma(AppleSIOState *s, AppleSIODMAEndpoint *ep, sio_msg m)
{
    sio_msg reply = { 0 };
    reply.ep = m.ep;
    reply.tag = m.tag;
    switch (m.op) {
    case CONFIG_SHIM: {
        dma_addr_t config_addr = (s->params[DMA_SEGMENT_BASE] << 12) + m.data * 12;
        if (dma_memory_read(&s->dma_as, config_addr, &ep->config,
                            sizeof(ep->config),
                            MEMTXATTRS_UNSPECIFIED) != MEMTX_OK) {
            return;
        };
        reply.op = ACK;
        break;
    }
    case START_DMA: {
        dma_addr_t handle_addr = (s->params[DMA_SEGMENT_BASE] << 12) + m.data * 12;
        dma_addr_t seg_addr = handle_addr + 0x48;
        uint32_t segment_count = 0;
        if (ep->mapped) {
            qemu_log_mask(LOG_GUEST_ERROR, "SIO: Another DMA is running\n");
            reply.op = ERROR;
            break;
        }
        if (dma_memory_read(&s->dma_as, handle_addr + 0x3C, &segment_count,
                            sizeof(segment_count),
                            MEMTXATTRS_UNSPECIFIED) != MEMTX_OK) {
            return;
        }

        qemu_sglist_init(&ep->sgl, DEVICE(s), segment_count, &s->dma_as);
        ep->tag = m.tag;
        ep->count = segment_count;
        ep->segments = g_new0(sio_dma_segment, segment_count);
        dma_memory_read(&s->dma_as, seg_addr, ep->segments,
                        segment_count * sizeof(sio_dma_segment),
                        MEMTXATTRS_UNSPECIFIED);
        for (int i = 0; i < segment_count; i++) {
            qemu_sglist_add(&ep->sgl, ep->segments[i].addr, ep->segments[i].len);
        }
        apple_sio_map_dma(s, ep);
        reply.op = ACK;
        break;
    }
    case QUERY_DMA:
        if (!ep->mapped) {
            reply.op = ERROR;
            break;
        }
        reply.op = QUERY_DMA_OK;
        reply.data = ep->actual_length;
        break;
    case STOP_DMA:
        if (!ep->mapped) {
            reply.op = ERROR;
            break;
        }
        reply.op = ACK;
        apple_sio_unmap_dma(s, ep);
        break;
    default:
        qemu_log_mask(LOG_UNIMP, "%s: Unknown SIO op: %d\n", __func__, m.op);
        reply.op = ERROR;
        break;
    }
    apple_mbox_send_message(s->mbox, 1, reply.raw);
};

static void apple_sio_handle_endpoint(void *opaque,
                                      uint32_t ep,
                                      uint64_t msg)
{
    AppleSIOState *s = APPLE_SIO(opaque);
    sio_msg m = { 0 };
    m.raw = msg;

    switch (m.ep) {
    case CONTROL:
    case PERF:
        apple_sio_control(s, &s->eps[CONTROL], m);
        break;
    default:
        if (m.ep >= SIO_NUM_EPS) {
            qemu_log_mask(LOG_UNIMP, "%s: Unknown SIO ep: %d\n", __func__, m.ep);
            SIO_LOG_MSG(ep, msg);
        } else {
            apple_sio_dma(s, &s->eps[m.ep], m);
        }
        break;
    }
}

AppleSIODMAEndpoint *apple_sio_get_endpoint(AppleSIOState *s, int ep)
{
    if (ep <= PERF || ep >= SIO_NUM_EPS) {
        return NULL;
    }
    return &s->eps[ep];
}

AppleSIODMAEndpoint *apple_sio_get_endpoint_from_node(AppleSIOState *s,
                                                      DTBNode *node, int idx)
{
    DTBProp *prop = find_dtb_prop(node, "dma-channels");
    uint32_t *data;
    int count;
    if (!prop) {
        return NULL;
    }
    count = prop->length / 32;
    if (idx >= count) {
        return NULL;
    }
    data = (uint32_t *)prop->value;
    return apple_sio_get_endpoint(s, data[8 * idx]);
}

static void ascv2_core_reg_write(void *opaque, hwaddr addr,
                  uint64_t data,
                  unsigned size)
{
#ifdef DEBUG_SIO
    qemu_log_mask(LOG_UNIMP, "SIO: AppleASCWrapV2 core reg WRITE @ 0x"
                  TARGET_FMT_plx " value: 0x" TARGET_FMT_plx "\n", addr, data);
#endif
}

static uint64_t ascv2_core_reg_read(void *opaque,
                     hwaddr addr,
                     unsigned size)
{
#ifdef DEBUG_SIO
    qemu_log_mask(LOG_UNIMP, "SIO: AppleASCWrapV2 core reg READ @ 0x"
                  TARGET_FMT_plx "\n", addr);
#endif
    return 0;
}

static const MemoryRegionOps ascv2_core_reg_ops = {
    .write = ascv2_core_reg_write,
    .read = ascv2_core_reg_read,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .impl.min_access_size = 8,
    .impl.max_access_size = 8,
    .valid.min_access_size = 8,
    .valid.max_access_size = 8,
    .valid.unaligned = false,
};

static const struct AppleMboxOps sio_mailbox_ops = {
};

SysBusDevice *apple_sio_create(DTBNode *node, uint32_t protocol_version)
{
    DeviceState  *dev;
    AppleSIOState *s;
    SysBusDevice *sbd;
    DTBNode *child;
    DTBProp *prop;
    uint64_t *reg;
    uint32_t data;

    dev = qdev_new(TYPE_APPLE_SIO);
    s = APPLE_SIO(dev);
    sbd = SYS_BUS_DEVICE(dev);

    dev->id = g_strdup("sio");

    child = find_dtb_node(node, "iop-sio-nub");
    assert(child);

    prop = find_dtb_prop(node, "reg");
    assert(prop);

    reg = (uint64_t *)prop->value;

    /*
     * 0: AppleA7IOP akfRegMap
     * 1: AppleASCWrapV2 coreRegisterMap
     */
    s->mbox = apple_mbox_create("SIO", s, reg[1], protocol_version,
                                       &sio_mailbox_ops);
    object_property_add_child(OBJECT(s), "mbox", OBJECT(s->mbox));
    apple_mbox_register_endpoint(s->mbox, 1,
                                 &apple_sio_handle_endpoint);

    sysbus_init_mmio(sbd, sysbus_mmio_get_region(SYS_BUS_DEVICE(s->mbox), 0));

    memory_region_init_io(&s->ascv2_iomem, OBJECT(dev), &ascv2_core_reg_ops, s,
                          TYPE_APPLE_SIO ".ascv2-core-reg", reg[3]);
    sysbus_init_mmio(sbd, &s->ascv2_iomem);

    sysbus_pass_irq(sbd, SYS_BUS_DEVICE(s->mbox));

    data = 1;
    set_dtb_prop(child, "pre-loaded", 4, (uint8_t *)&data);
    #if 0
    set_dtb_prop(child, "running", 4, (uint8_t *)&data);
    #endif

    return sbd;
}

static void apple_sio_realize(DeviceState *dev, Error **errp)
{
    AppleSIOState *s = APPLE_SIO(dev);
    Object *obj;

    obj = object_property_get_link(OBJECT(dev), "dma-mr", &error_abort);

    s->dma_mr = MEMORY_REGION(obj);
    assert(s->dma_mr);
    address_space_init(&s->dma_as, s->dma_mr, "sio.dma-as");

    sysbus_realize(SYS_BUS_DEVICE(s->mbox), errp);

    for (int i = 0; i < SIO_NUM_EPS; i++) {
        s->eps[i].id = i;
        s->eps[i].dir = i & 1 ? DMA_DIRECTION_FROM_DEVICE :
                                DMA_DIRECTION_TO_DEVICE;
    }
}

static void apple_sio_unrealize(DeviceState *dev)
{
    AppleSIOState *s = APPLE_SIO(dev);

    qdev_unrealize(DEVICE(s->mbox));
}

static void apple_sio_reset(DeviceState *dev)
{
    AppleSIOState *s = APPLE_SIO(dev);

    s->params[PROTOCOL] = 9;
    for (int i = 0; i < SIO_NUM_EPS; i++) {
        if (s->eps[i].mapped) {
            apple_sio_unmap_dma(s, &s->eps[i]);
        }
        memset(&s->eps[i].config, 0, sizeof(s->eps[i].config));
    }
    device_cold_reset(DEVICE(s->mbox));
}

static void apple_sio_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->realize = apple_sio_realize;
    dc->unrealize = apple_sio_unrealize;
    dc->reset = apple_sio_reset;
    dc->desc = "Apple Smart IO DMA Controller";
}

static const TypeInfo apple_sio_info = {
    .name = TYPE_APPLE_SIO,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(AppleSIOState),
    .class_init = apple_sio_class_init,
};

static void apple_sio_register_types(void)
{
    type_register_static(&apple_sio_info);
}

type_init(apple_sio_register_types);
