#include "qemu/osdep.h"
#include "qapi/error.h"
#include "hw/misc/apple_smc.h"
#include "hw/misc/apple_mbox.h"
#include "hw/irq.h"
#include "migration/vmstate.h"
#include "qemu/bitops.h"
#include "qemu/log.h"
#include "qemu/module.h"
#include "qemu/queue.h"
#include "sysemu/runstate.h"
#include "hw/arm/xnu.h"
#include "hw/arm/xnu_dtb.h"

#define TYPE_APPLE_SMC_IOP "apple.smc"
OBJECT_DECLARE_SIMPLE_TYPE(AppleSMCState, APPLE_SMC_IOP)

//#define DEBUG_SMC

#ifdef DEBUG_SMC
#define SMC_LOG_MSG(ep, msg) \
do { qemu_log_mask(LOG_GUEST_ERROR, "SMC: message:" \
                   " ep=%u msg=0x" TARGET_FMT_plx "\n", \
                   ep, msg); } while (0)
#else
#define SMC_LOG_MSG(ep, msg) do {} while (0)
#endif

enum smc_command {
    SMC_READ_KEY = 0x10,
    SMC_WRITE_KEY = 0x11,
    SMC_GET_KEY_BY_INDEX = 0x12,
    SMC_GET_KEY_INFO = 0x13,
    SMC_GET_SRAM_ADDR = 0x17,
    SMC_NOTIFICATION = 0x18,
    SMC_READ_KEY_PAYLOAD = 0x20
};

enum smc_result {
    kSMCBadFuncParameter = 0xc0,
    kSMCEventBuffWrongOrder = 0xc4,
    kSMCEventBuffReadError = 0xc5,
    kSMCDeviceAccessError = 0xc7,
    kSMCUnsupportedFeature = 0xcb,
    kSMCSMBAccessError = 0xcc,
    kSMCTimeoutError = 0xb7,
    kSMCKeyIndexRangeError = 0xb8,
    kSMCCommCollision = 0x80,
    kSMCSpuriousData = 0x81,
    kSMCBadCommand = 0x82,
    kSMCBadParameter = 0x83,
    kSMCKeyNotFound = 0x84,
    kSMCKeyNotReadable = 0x85,
    kSMCKeyNotWritable = 0x86,
    kSMCKeySizeMismatch = 0x87,
    kSMCFramingError = 0x88,
    kSMCBadArgumentError = 0x89,
    kSMCError = 1,
    kSMCSuccess = 0,
};

enum smc_notify_type {
    kSMCSystemStateNotify = 'p',
    kSMCPowerStateNotify = 'q',
    kSMCHIDEventNotify = 'r',
    kSMCBatteryAuthNotify = 's',
    kSMCGGFwUpdateNotify = 't',
};

#define kSMCKeyEndpoint     1

struct QEMU_PACKED key_message {
    uint8_t cmd;
    uint8_t ui8TagAndId;
    uint8_t length;
    uint8_t payload_length;
    uint32_t key;
};

typedef struct QEMU_PACKED key_response {
    union {
        struct {
            uint8_t status;
            uint8_t ui8TagAndId;
            uint8_t length;
            uint8_t unk3;
            uint8_t response[4];
        };
        uint64_t raw;
    };
} key_response;

typedef struct QEMU_PACKED smc_key_info {
    uint8_t size;
    uint32_t type;
    uint8_t attr;
} smc_key_info;

enum smc_attr {
    SMC_ATTR_LITTLE_ENDIAN = (1 << 2),
};

typedef struct smc_key smc_key;

typedef uint8_t (*KeyReader)(AppleSMCState *s, smc_key *k,
                             void *payload, uint8_t length);
typedef uint8_t (*KeyWriter)(AppleSMCState *s, smc_key *k,
                             void *payload, uint8_t length);

struct smc_key {
    uint32_t key;
    smc_key_info info;
    void *data;

    QTAILQ_ENTRY(smc_key) entry;
    KeyReader read;
    KeyWriter write;
};

struct AppleSMCState {
    SysBusDevice parent_obj;
    MemoryRegion *iomems[3];
    AppleMboxState *mbox;
    QTAILQ_HEAD(, smc_key) keys;
    uint32_t key_count;
    uint64_t sram_addr;
    uint8_t sram[0x4000];
};

static smc_key *smc_get_key(AppleSMCState *s, uint32_t key)
{
    smc_key *d;
    QTAILQ_FOREACH(d, &s->keys, entry) {
        if (d->key == key) {
            return d;
        }
    }
    return NULL;
}

static smc_key *smc_create_key(AppleSMCState *s, uint32_t key, uint32_t size,
                               uint32_t type, uint32_t attr, void *data)
{
    smc_key *k = smc_get_key(s, key);
    if (!k) {
        k = g_new0(smc_key, 1);
        QTAILQ_INSERT_TAIL(&s->keys, k, entry);
        s->key_count++;
    }
    k->key = key;
    k->info.size = size;
    k->info.type = type;
    k->info.attr = attr;
    k->data = g_realloc(k->data, size);
    memcpy(k->data, data, size);
    return k;
}

static smc_key *smc_create_key_func(AppleSMCState *s, uint32_t key,
                                    uint32_t size, uint32_t type, uint32_t attr,
                                    KeyReader reader, KeyWriter writer)
{
    smc_key *k = smc_get_key(s, key);
    if (!k) {
        k = g_new0(smc_key, 1);
        QTAILQ_INSERT_TAIL(&s->keys, k, entry);
        s->key_count++;
    }
    k->key = key;
    k->info.size = size;
    k->info.type = type;
    k->info.attr = attr;
    k->data = g_realloc(k->data, size);
    k->read = reader;
    k->write = writer;
    return k;
}

static smc_key *smc_set_key(AppleSMCState *s, uint32_t key, uint32_t size,
                            void *data)
{
    smc_key *k = smc_get_key(s, key);
    if (!k) {
        k = g_new0(smc_key, 1);
        QTAILQ_INSERT_TAIL(&s->keys, k, entry);
        s->key_count++;
    }
    k->key = key;
    k->info.size = size;
    k->data = g_realloc(k->data, size);
    memcpy(k->data, data, size);
    return k;
}

static uint8_t smc_key_reject_read(AppleSMCState *s, smc_key *k,
                                   void *payload, uint8_t length)
{
    return kSMCKeyNotReadable;
}

static uint8_t smc_key_reject_write(AppleSMCState *s, smc_key *k,
                                    void *payload, uint8_t length)
{
    return kSMCKeyNotWritable;
}

static uint8_t smc_key_noop_read(AppleSMCState *s, smc_key *k,
                                 void *payload, uint8_t length)
{
    return kSMCSuccess;
}

static uint8_t smc_key_copy_write(AppleSMCState *s, smc_key *k,
                                  void *payload, uint8_t length)
{
    smc_set_key(s, k->key, length, payload);
    return kSMCSuccess;
}

static uint8_t smc_key_count_read(AppleSMCState *s, smc_key *k,
                                  void *payload, uint8_t length)
{
    k->info.size = 4;
    k->data = g_realloc(k->data, 4);
    *(uint32_t *)k->data = s->key_count;
    return kSMCSuccess;
}

static uint8_t smc_key_mbse_write(AppleSMCState *s, smc_key *k,
                                  void *payload, uint8_t length)
{
    uint32_t value;
    if (!payload || length != k->info.size) {
        return kSMCBadArgumentError;
    }
    value = *(uint32_t *)payload;
    switch (value) {
    case 'off1':
        qemu_system_shutdown_request(SHUTDOWN_CAUSE_GUEST_SHUTDOWN);
        return kSMCSuccess;
    case 'susp':
        /*
         * XXX: iOS actually suspends/deep sleeps when "turn off",
         * It sets a RTC wake alarm before suspending
         * However, we are not interested in emulating deep sleep,
         * so I put a shutdown request here instead of a suspend.
         */
        /* qemu_system_suspend_request(); */
        qemu_system_shutdown_request(SHUTDOWN_CAUSE_GUEST_SHUTDOWN);
        return kSMCSuccess;
    case 'rest':
        /* Reboot is handled by wdt */
        return kSMCSuccess;
    case 'slpw':
        return kSMCSuccess;
    default:
        return kSMCBadFuncParameter;
    }
}

static uint8_t smc_key_lgpb_write(AppleSMCState *s, smc_key *k,
                                  void *payload, uint8_t length)
{
    /* fprintf(stderr, "LGPB: payload: 0x%x\n", *(uint8_t *)payload); */
    smc_set_key(s, k->key, length, payload);
    return kSMCSuccess;
}

static uint8_t smc_key_lgpe_write(AppleSMCState *s, smc_key *k,
                                  void *payload, uint8_t length)
{
    /* fprintf(stderr, "LGPE: payload: 0x%x\n", *(uint8_t *)payload); */
    smc_set_key(s, k->key, length, payload);
    return kSMCSuccess;
}

static uint8_t smc_key_nesn_write(AppleSMCState *s, smc_key *k,
                                  void *payload, uint8_t length)
{
    key_response r = { 0 };
    uint8_t *p = (uint8_t *)payload;
    /* fprintf(stderr, "NESN: payload: 0x%x\n", *(uint32_t *)payload); */
    smc_set_key(s, k->key, length, payload);
    r.status = SMC_NOTIFICATION;
    r.response[2] = 0xA; /* kSMCNotifySMCPanicDone */
    r.response[3] = kSMCSystemStateNotify;
    apple_mbox_send_message(s->mbox, kSMCKeyEndpoint, r.raw);
    return kSMCSuccess;
}

static void apple_smc_handle_key_endpoint(void *opaque,
                                          uint32_t ep,
                                          uint64_t msg)
{
    AppleSMCState *s = APPLE_SMC_IOP(opaque);
    struct key_message *kmsg = (struct key_message *)&msg;
    SMC_LOG_MSG(ep, msg);
    switch (kmsg->cmd) {
    case SMC_GET_SRAM_ADDR: {
        apple_mbox_send_message(s->mbox, ep, s->sram_addr);
        break;
    }
    case SMC_READ_KEY:
    case SMC_READ_KEY_PAYLOAD: {
        key_response r = { 0 };
        smc_key *k = smc_get_key(s, kmsg->key);
        if (!k) {
            r.status = kSMCKeyNotFound;
        } else {
            if (k->read) {
                r.status = k->read(s, k, s->sram, kmsg->payload_length);
            }
            if (r.status == kSMCSuccess) {
                r.length = k->info.size;
                if (k->info.size <= 4) {
                    memcpy(r.response, k->data, k->info.size);
                } else {
                    memcpy(s->sram, k->data, k->info.size);
                }
                r.status = kSMCSuccess;
            }
        }
        r.ui8TagAndId = kmsg->ui8TagAndId;
        apple_mbox_send_message(s->mbox, ep, r.raw);
        break;
    }
    case SMC_WRITE_KEY: {
        smc_key *k = smc_get_key(s, kmsg->key);
        key_response r = { 0 };
        if (k && k->write) {
            r.status = k->write(s, k, s->sram, kmsg->length);
        } else {
            smc_set_key(s, kmsg->key, kmsg->length, s->sram);
            r.status = kSMCSuccess;
        }
        r.ui8TagAndId = kmsg->ui8TagAndId;
        apple_mbox_send_message(s->mbox, ep, r.raw);
        break;
    }
    case SMC_GET_KEY_BY_INDEX: {
        key_response r = { 0 };
        uint32_t idx = kmsg->key;
        smc_key *k = QTAILQ_FIRST(&s->keys);

        for (int i = 0; i < idx && k; i++) {
            k = QTAILQ_NEXT(k, entry);
        }

        if (!k) {
            r.status = kSMCKeyIndexRangeError;
        } else {
            r.status = kSMCSuccess;
            memcpy(r.response, &k->key, 4);
            bswap32s((uint32_t *)r.response);
        }
        r.ui8TagAndId = kmsg->ui8TagAndId;
        apple_mbox_send_message(s->mbox, ep, r.raw);
        break;
    }
    case SMC_GET_KEY_INFO: {
        smc_key *k = smc_get_key(s, kmsg->key);
        key_response r = { 0 };
        if (!k) {
            r.status = kSMCKeyNotFound;
        } else {
            memcpy(s->sram, &k->info, sizeof(k->info));
            r.status = kSMCSuccess;
        }
        r.ui8TagAndId = kmsg->ui8TagAndId;
        apple_mbox_send_message(s->mbox, ep, r.raw);
        break;
    }
    default: {
        key_response r = { 0 };
        r.status = kSMCBadCommand;
        r.ui8TagAndId = kmsg->ui8TagAndId;
        apple_mbox_send_message(s->mbox, ep, r.raw);
        fprintf(stderr, "SMC: Unknown SMC Command: 0x%02x\n", kmsg->cmd);
        break;
    }
    }
}

static void ascv2_core_reg_write(void *opaque, hwaddr addr,
                  uint64_t data,
                  unsigned size)
{
    qemu_log_mask(LOG_UNIMP, "SMC: AppleASCWrapV2 core reg WRITE @ 0x"
                  TARGET_FMT_plx " value: 0x" TARGET_FMT_plx "\n", addr, data);
}

static uint64_t ascv2_core_reg_read(void *opaque,
                     hwaddr addr,
                     unsigned size)
{
    qemu_log_mask(LOG_UNIMP, "SMC: AppleASCWrapV2 core reg READ @ 0x"
                  TARGET_FMT_plx "\n", addr);
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

static const struct AppleMboxOps smc_mailbox_ops = {
};

static void apple_smc_set_irq(void *opaque, int irq_num, int level)
{
}

SysBusDevice *apple_smc_create(DTBNode *node, uint32_t build_version)
{
    DeviceState  *dev;
    AppleSMCState *s;
    SysBusDevice *sbd;
    DTBNode *child;
    DTBProp *prop;
    uint64_t *reg;
    uint32_t protocol_version = 0;
    int i;
    uint32_t data;
    struct segment_range {
        uint64_t phys;
        uint64_t virt;
        uint64_t remap;
        uint32_t size;
        uint32_t flag;
    };
    struct segment_range segrange[2] = { 0 };

    dev = qdev_new(TYPE_APPLE_SMC_IOP);
    s = APPLE_SMC_IOP(dev);
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
    s->mbox = apple_mbox_create("SMC", s, reg[1], protocol_version,
                                       &smc_mailbox_ops);
    object_property_add_child(OBJECT(s), "mbox", OBJECT(s->mbox));
    apple_mbox_register_endpoint(s->mbox, kSMCKeyEndpoint,
                                 &apple_smc_handle_key_endpoint);

    sysbus_init_mmio(sbd, sysbus_mmio_get_region(SYS_BUS_DEVICE(s->mbox), 0));

    s->iomems[1] = g_new(MemoryRegion, 1);
    memory_region_init_io(s->iomems[1], OBJECT(dev), &ascv2_core_reg_ops, s,
                          TYPE_APPLE_SMC_IOP ".ascv2-core-reg", reg[3]);
    sysbus_init_mmio(sbd, s->iomems[1]);

    prop->value = g_realloc(prop->value, prop->length + 16);
    prop->length += 16;
    reg = (uint64_t *)prop->value;
    s->sram_addr = 0x23fe60000; /* size: 0x4000 */
    reg[4] = 0x3fe60000;
    reg[5] = 0x4000;
    s->iomems[2] = g_new(MemoryRegion, 1);
    memory_region_init_ram_device_ptr(s->iomems[2], OBJECT(dev),
                                      TYPE_APPLE_SMC_IOP ".sram",
                                      sizeof(s->sram), s->sram);
    sysbus_init_mmio(sbd, s->iomems[2]);

    sysbus_pass_irq(sbd, SYS_BUS_DEVICE(s->mbox));

    child = find_dtb_node(node, "iop-smc-nub");
    assert(child);

    data = 1;
    set_dtb_prop(child, "pre-loaded", 4, (uint8_t *)&data);
    set_dtb_prop(child, "running", 4, (uint8_t *)&data);

    prop = find_dtb_prop(child, "region-base");
    *(uint64_t *)prop->value = 0x23fe00000;

    prop = find_dtb_prop(child, "region-size");
    *(uint64_t *)prop->value = 0x80000;

    set_dtb_prop(child, "segment-names", 14, (uint8_t *)"__TEXT;__DATA");

    segrange[0].phys = 0x23fe00000;
    segrange[0].virt = 0x0;
    segrange[0].remap = 0x23fe00000;
    segrange[0].size = 0x30000;
    segrange[0].flag = 0x1;

    segrange[1].phys = 0x23fe30000;
    segrange[1].virt = 0x30000;
    segrange[1].remap = 0x23fe30000;
    segrange[1].size = 0x30000;
    segrange[1].flag = 0x0;

    set_dtb_prop(child, "segment-ranges", 64, (uint8_t *)segrange);
    QTAILQ_INIT(&s->keys);

    return sbd;
}

static void apple_smc_realize(DeviceState *dev, Error **errp)
{
    AppleSMCState *s = APPLE_SMC_IOP(dev);
    uint8_t data[8] = {0x00, 0x00, 0x70, 0x80, 0x00, 0x01, 0x19, 0x40};
    uint64_t value;

    smc_create_key_func(s, '#KEY', 4, bswap32('ui32'), SMC_ATTR_LITTLE_ENDIAN,
                        &smc_key_count_read, &smc_key_reject_write);

    smc_create_key(s, 'CLKH', 8, 0x7b636c68, SMC_ATTR_LITTLE_ENDIAN, data);

    data[0] = 3;
    smc_create_key(s, 'RGEN', 1, bswap32('ui8 '), SMC_ATTR_LITTLE_ENDIAN, data);

    value = 0;
    smc_create_key(s, 'aDC#', 4, bswap32('ui32'), SMC_ATTR_LITTLE_ENDIAN, &value);

    smc_create_key_func(s, 'MBSE', 4, bswap32('hex_'), SMC_ATTR_LITTLE_ENDIAN,
                        &smc_key_reject_read, &smc_key_mbse_write);

    smc_create_key_func(s, 'LGPB', 1, bswap32('flag'), SMC_ATTR_LITTLE_ENDIAN,
                        &smc_key_reject_read, &smc_key_lgpb_write);
    smc_create_key_func(s, 'LGPE', 1, bswap32('flag'), SMC_ATTR_LITTLE_ENDIAN,
                        &smc_key_noop_read, &smc_key_lgpe_write);
    smc_create_key_func(s, 'NESN', 4, bswap32('hex_'), SMC_ATTR_LITTLE_ENDIAN,
                        &smc_key_reject_read, &smc_key_nesn_write);

    sysbus_realize(SYS_BUS_DEVICE(s->mbox), errp);
}

static void apple_smc_unrealize(DeviceState *dev)
{
    AppleSMCState *s = APPLE_SMC_IOP(dev);

    qdev_unrealize(DEVICE(s->mbox));
}

static void apple_smc_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->realize = apple_smc_realize;
    dc->unrealize = apple_smc_unrealize;
    /* dc->reset = apple_smc_reset; */
    dc->desc = "Apple SMC IOP";
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
}

static const TypeInfo apple_smc_info = {
    .name = TYPE_APPLE_SMC_IOP,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(AppleSMCState),
    .class_init = apple_smc_class_init,
};

static void apple_smc_register_types(void)
{
    type_register_static(&apple_smc_info);
}

type_init(apple_smc_register_types);
