/*
 *
 * Copyright (c) 2019 Jonathan Afek <jonyafek@me.com>
 * Copyright (c) 2021 Nguyen Hoang Trung (TrungNguyen1909)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu-common.h"
#include "hw/arm/boot.h"
#include "sysemu/sysemu.h"
#include "qemu/error-report.h"
#include "crypto/hash.h"
#include "hw/arm/xnu.h"
#include "hw/loader.h"
#include "img4.h"
#include "lzfse.h"

struct mach_header_64 *xnu_header;

static const char *KEEP_COMP[] = {
    "uart-1,samsung\0$",
    "N104AP\0iPhone12,1\0AppleARM\0$", "arm-io,t8030\0$",
    "N104DEV\0iPhone12,1\0AppleARM\0$",
    "apple,thunder\0ARM,v8\0$", "apple,lightning\0ARMv8\0$",
    "aic,1\0$", "pmgr1,t8030\0$",
    "sart,t8030\0$", "sart,coastguard\0$",
    "iop,ascwrap-v2\0$", "iop-nub,rtbuddy-v2\0$",
    "aes,s8000\0$",
    "gpio,t8030\0gpio,s5l8960x\0$",
    "gpio,t8015\0gpio,s5l8960x\0$",
    "iic,soft\0$",
    "dock,9pin\0$",
    "accbuck,fan53740\0$",
    "otgphyctrl,s8000\0otgphyctrl,s5l8960x\0$",
    "usb-complex,s8000\0usb-complex,s5l8960x\0$",
    "usb-device,s5l8900x\0$",
    "wdt,t8030\0wdt,s5l8960x\0$",
};

static const char *REM_NAMES[] = {
    "backlight\0$",
    "dockchannel-uart\0$",
    "sep\0$", "pmp\0$",
    "aop-gpio\0$",
    "atc-phy\0$", "usb-drd\0$"
};

static const char *REM_DEV_TYPES[] = { "backlight\0$", "pmp\0$" };

static const char *REM_PROPS[] = {
    "function-error_handler", "nvme-coastguard", "nand-debug",
    "function-spi0_sclk_config", "function-spi0_mosi_config",
    "function-pmp_control", "function-mcc_ctrl", "pmp",
    "function-vbus_voltage",
    "function-brick_id_voltage", "function-ldcm_bypass_en",
    "content-protect", /* We don't want encrypted data volume */
};

static void allocate_and_copy(MemoryRegion *mem, AddressSpace *as,
                              const char *name, hwaddr pa, hwaddr size,
                              void *buf)
{
    address_space_rw(as, pa, MEMTXATTRS_UNSPECIFIED, (uint8_t *)buf, size, 1);
}

static void *srawmemchr(void *str, int chr)
{
    uint8_t *ptr = (uint8_t *)str;

    while (*ptr != chr) {
        ptr++;
    }

    return ptr;
}

static uint64_t sstrlen(const char *str)
{
    const int chr = *(uint8_t *)"$";
    char *end = srawmemchr((void *)str, chr);

    return end - str;
}

static void macho_dtb_node_process(DTBNode *node, DTBNode *parent)
{
    GList *iter = NULL;
    DTBNode *child = NULL;
    DTBProp *prop = NULL;
    uint64_t i = 0;
    int cnt;

    //remove by compatible property
    prop = find_dtb_prop(node, "compatible");

    if (prop) {
        uint64_t count = sizeof(KEEP_COMP) / sizeof(KEEP_COMP[0]);
        bool found = false;

        for (i = 0; i < count; i++) {
            uint64_t size = MIN(prop->length, sstrlen(KEEP_COMP[i]));
            if (0 == memcmp(prop->value, KEEP_COMP[i], size)) {
                found = true;
                break;
            }
        }

        if (!found) {
            if (parent) {
                remove_dtb_node(parent, node);
                return;
            }
        }
    }

    /* remove by name property */
    prop = find_dtb_prop(node, "name");
    if (prop) {
        uint64_t count = sizeof(REM_NAMES) / sizeof(REM_NAMES[0]);

        for (i = 0; i < count; i++) {
            uint64_t size = MIN(prop->length, sstrlen(REM_NAMES[i]));
            if (!memcmp(prop->value, REM_NAMES[i], size)) {
                if (parent) {
                    remove_dtb_node(parent, node);
                    return;
                }
                break;
            }
        }
    }

    /* remove dev type properties */
    prop = find_dtb_prop(node, "device_type");
    if (prop) {
        uint64_t count = sizeof(REM_DEV_TYPES) / sizeof(REM_DEV_TYPES[0]);
        for (i = 0; i < count; i++) {
            uint64_t size = MIN(prop->length, sstrlen(REM_DEV_TYPES[i]));
            if (!memcmp(prop->value, REM_DEV_TYPES[i], size)) {
                //TODO: maybe remove the whole node and sub nodes?
                overwrite_dtb_prop_val(prop, *(uint8_t *)"~");
                break;
            }
        }
    }

    {
        uint64_t count = sizeof(REM_PROPS) / sizeof(REM_PROPS[0]);

        for (i = 0; i < count; i++) {
            prop = find_dtb_prop(node, REM_PROPS[i]);
            if (prop) {
                remove_dtb_prop(node, prop);
            }
        }
    }

    cnt = node->child_node_count;
    for (iter = node->child_nodes; iter != NULL;) {
        child = (DTBNode *)iter->data;

        /* iter might be invalidated by macho_dtb_node_process */
        iter = iter->next;
        macho_dtb_node_process(child, node);
        cnt--;
    }

    assert(cnt == 0);
}

/*
 Extracts the payload from an im4p file. If the file is not an im4p file,
 the raw file contents are returned. Exits if an error occurs.
 See https://www.theiphonewiki.com/wiki/IMG4_File_Format for an overview
 of the file format.
*/
static void extract_im4p_payload(const char *filename,
        char *payload_type /* must be at least 4 bytes long */,
        uint8_t **data, uint32_t* length)
{
    uint8_t *file_data = NULL;
    unsigned long fsize;

    char errorDescription[ASN1_MAX_ERROR_DESCRIPTION_SIZE];
    asn1_node img4_definitions = NULL;
    asn1_node img4;
    int ret;

    if (!g_file_get_contents(filename, (char **)&file_data, &fsize, NULL)) {
        error_report("Could not load data from file '%s'", filename);
        exit(EXIT_FAILURE);
    }

    if (asn1_array2tree(img4_definitions_array, &img4_definitions, errorDescription)) {
        error_report("Could not initialize the ASN.1 parser: %s.", errorDescription);
        exit(EXIT_FAILURE);
    }

    if ((ret = asn1_create_element(img4_definitions, "Img4.Img4Payload", &img4) != ASN1_SUCCESS)) {
        error_report("Could not create an Img4Payload element: %d", ret);
        exit(EXIT_FAILURE);
    }

    if ((ret = asn1_der_decoding(&img4, (const uint8_t*)file_data, (uint32_t)fsize, errorDescription)) == ASN1_SUCCESS) {
        char magic[4];
        char description[128];
        int len;
        uint8_t *payload_data;

        len = 4;
        if ((ret = asn1_read_value(img4, "magic", magic, &len)) != ASN1_SUCCESS) {
            error_report("Failed to read the im4p magic in file '%s': %d.", filename, ret);
            exit(EXIT_FAILURE);
        }

        if (strncmp(magic, "IM4P", 4) != 0) {
            error_report("Couldn't parse ASN.1 data in file '%s' because it does not start with the IM4P header.", filename);
            exit(EXIT_FAILURE);
        }

        len = 4;
        if ((ret = asn1_read_value(img4, "type", payload_type, &len)) != ASN1_SUCCESS) {
            error_report("Failed to read the im4p type in file '%s': %d.", filename, ret);
            exit(EXIT_FAILURE);
        }

        len = 128;
        if ((ret = asn1_read_value(img4, "description", description, &len)) != ASN1_SUCCESS) {
            error_report("Failed to read the im4p description in file '%s': %d.", filename, ret);
            exit(EXIT_FAILURE);
        }

        payload_data = NULL;
        len = 0;

        if ((ret = asn1_read_value(img4, "data", payload_data, &len) != ASN1_MEM_ERROR)) {
            error_report("Failed to read the im4p payload in file '%s': %d.", filename, ret);
            exit(EXIT_FAILURE);
        }

        payload_data = g_malloc0(len);

        if ((ret = asn1_read_value(img4, "data", payload_data, &len) != ASN1_SUCCESS)) {
            error_report("Failed to read the im4p payload in file '%s': %d.", filename, ret);
            exit(EXIT_FAILURE);
        }

        // Determine whether the payload is LZFSE-compressed: LZFSE-compressed files contains various buffer blocks,
        // and each buffer block starts with bvx? magic, where ? is -, 1, 2 or n.
        // See https://github.com/lzfse/lzfse/blob/e634ca58b4821d9f3d560cdc6df5dec02ffc93fd/src/lzfse_internal.h
        // for the details
        if (payload_data[0] == (uint8_t)'b' && payload_data[1] == (uint8_t)'v' && payload_data[2] == (uint8_t)'x') {
            size_t decode_buffer_size = len * 8;
            uint8_t *decode_buffer = g_malloc0(decode_buffer_size);
            int decoded_length = lzfse_decode_buffer(decode_buffer, decode_buffer_size, payload_data, len, NULL /* scratch_buffer */);

            if (decoded_length == 0 || decoded_length == decode_buffer_size) {
                error_report("Could not decompress LZFSE-compressed data in file '%s' because the decode buffer was too small.", filename);
                exit(EXIT_FAILURE);
            }

            *data = decode_buffer;
            *length = decoded_length;

            g_free(payload_data);
            g_free(file_data);
        } else {
            *data = payload_data;
            *length = len;

            g_free(file_data);
        }
    } else {
        *data = file_data;
        *length = (uint32_t)fsize;
        strncpy(payload_type, "raw", 4);
    }
}

DTBNode *load_dtb_from_file(char *filename)
{
    DTBNode *root = NULL;
    uint8_t *file_data = NULL;
    uint32_t fsize;
    char payload_type[4];

    extract_im4p_payload(filename, payload_type, &file_data, &fsize);

    if (strncmp(payload_type, "dtre", 4) != 0
        && strncmp(payload_type, "raw", 4) != 0) {
        error_report("Couldn't parse ASN.1 data in file '%s' because it is not a 'dtre' object, found '%.4s' object.", filename, payload_type);
        exit(EXIT_FAILURE);
    }

    root = load_dtb(file_data);
    g_free(file_data);

    return root;
}

void macho_load_dtb(DTBNode *root, AddressSpace *as, MemoryRegion *mem,
                    const char *name, macho_boot_info_t info)
{
    DTBNode *child = NULL;
    DTBProp *prop = NULL;
    uint32_t data;
    uint32_t display_rotation = 0;
    uint32_t display_scale = 1;
    uint64_t memmap[2] = {0};
    g_autofree uint8_t *buf = NULL;
    // need to set the random seed insread of iboot
    uint64_t seed[8] = {0xdead000d, 0xdead000d, 0xdead000d, 0xdead000d,
                        0xdead000d, 0xdead000d, 0xdead000d, 0xdead000d};

    // remove this prop as it is responsible for the waited for event
    // in PE that never happens
    prop = find_dtb_prop(root, "secure-root-prefix");
    if (prop) {
        remove_dtb_prop(root, prop);
    }

    child = get_dtb_node(root, "arm-io");
    prop = find_dtb_prop(child, "chip-revision");
    assert(prop);
    *(uint32_t *)prop->value = 0x10;

    child = get_dtb_node(root, "chosen");
    assert(child != NULL);
    prop = find_dtb_prop(child, "random-seed");
    assert(prop != NULL);
    remove_dtb_prop(child, prop);
    set_dtb_prop(child, "random-seed", sizeof(seed), (uint8_t *)&seed[0]);

    set_dtb_prop(child, "dram-base", 8, (uint8_t *)&info->dram_base);
    set_dtb_prop(child, "dram-size", 8, (uint8_t *)&info->dram_size);
    prop = find_dtb_prop(child, "firmware-version");
    remove_dtb_prop(child, prop);
    set_dtb_prop(child, "firmware-version", 11, (uint8_t *)"qemu-t8030");

    if (info->nvram_size > XNU_MAX_NVRAM_SIZE) {
        info->nvram_size = XNU_MAX_NVRAM_SIZE;
    }
    set_dtb_prop(child, "nvram-total-size", 4, (uint8_t *)&info->nvram_size);
    set_dtb_prop(child, "nvram-proxy-data", info->nvram_size, info->nvram_data);

    data = 1;
    set_dtb_prop(child, "research-enabled", sizeof(data), (uint8_t *)&data);
    prop = set_dtb_prop(child, "effective-production-status-ap", sizeof(data), (uint8_t *)&data);

    //update the display parameters
    set_dtb_prop(child, "display-rotation", sizeof(display_rotation),
                    (uint8_t *)&display_rotation);

    set_dtb_prop(child, "display-scale", sizeof(display_scale),
                    (uint8_t *)&display_scale);

    //these are needed by the image4 parser module$
    set_dtb_prop(child, "security-domain", sizeof(data), (uint8_t *)&data);
    set_dtb_prop(child, "chip-epoch", sizeof(data), (uint8_t *)&data);
    set_dtb_prop(child, "amfi-allows-trust-cache-load", sizeof(data), (uint8_t *)&data);
    data = 0xffffffff;
    set_dtb_prop(child, "debug-enabled", sizeof(data), (uint8_t *)&data);

    child = get_dtb_node(root, "chosen");
    assert(child);
    child = get_dtb_node(child, "lock-regs");
    if (!child) {
        child = get_dtb_node(root, "chosen");
        child = get_dtb_node(child, "lock-regs");
        get_dtb_node(child, "amcc");
    }
    child = get_dtb_node(child, "amcc");
    assert(child);
    data = 0;
    set_dtb_prop(child, "aperture-count", 4, (uint8_t *)&data);
    set_dtb_prop(child, "aperture-size", 4, (uint8_t *)&data);
    set_dtb_prop(child, "plane-count", 4, (uint8_t *)&data);
    set_dtb_prop(child, "aperture-phys-addr", 0, (uint8_t *)&data);
    set_dtb_prop(child, "cache-status-reg-offset", 4, (uint8_t *)&data);
    set_dtb_prop(child, "cache-status-reg-mask", 4, (uint8_t *)&data);
    set_dtb_prop(child, "cache-status-reg-value", 4, (uint8_t *)&data);
    child = get_dtb_node(child, "amcc-ctrr-a");
    if (!child) {
        child = get_dtb_node(child, "amcc-ctrr-a");
    }

    data = 14;
    set_dtb_prop(child, "page-size-shift", 4, (uint8_t *)&data);

    data = 0;
    set_dtb_prop(child, "lower-limit-reg-offset", 4, (uint8_t *)&data);
    set_dtb_prop(child, "lower-limit-reg-mask", 4, (uint8_t *)&data);
    set_dtb_prop(child, "upper-limit-reg-offset", 4, (uint8_t *)&data);
    set_dtb_prop(child, "upper-limit-reg-mask", 4, (uint8_t *)&data);
    set_dtb_prop(child, "lock-reg-offset", 4, (uint8_t *)&data);
    set_dtb_prop(child, "lock-reg-mask", 4, (uint8_t *)&data);
    set_dtb_prop(child, "lock-reg-value", 4, (uint8_t *)&data);

    child = get_dtb_node(root, "filesystems");
    child = get_dtb_node(child, "fstab");

    /* TODO: SEP xART */
    remove_dtb_node_by_name(child, "xart-vol");

    remove_dtb_node_by_name(child, "baseband-vol");

    child = get_dtb_node(root, "defaults");
    assert(child);
    data = 1;
    // TODO: Workaround: AppleKeyStore SEP(?)
    set_dtb_prop(child, "no-effaceable-storage", sizeof(data), (uint8_t *)&data);

    child = get_dtb_node(root, "product");
    assert(child);
    data = 1;
    // TODO: Workaround: AppleKeyStore SEP(?)
    set_dtb_prop(child, "boot-ios-diagnostics", sizeof(data), (uint8_t *)&data);

    uint8_t buffer[0x40] = { 0 };

    memset(buffer, 0, sizeof(buffer));
    memcpy(buffer, "MWCH2", 5);
    set_dtb_prop(root, "model-number", 32, buffer);
    memset(buffer, 0, sizeof(buffer));
    memcpy(buffer, "LL/A", 4);
    set_dtb_prop(root, "region-info", 32, buffer);
    memset(buffer, 0, sizeof(buffer));
    set_dtb_prop(root, "config-number", 0x40, buffer);
    memset(buffer, 0, sizeof(buffer));
    memcpy(buffer, "C39ZRMDEN72J", 12);
    set_dtb_prop(root, "serial-number", 32, buffer);
    memset(buffer, 0, sizeof(buffer));
    memcpy(buffer, "C39948108J9N72J1F", 17);
    set_dtb_prop(root, "mlb-serial-number", 32, buffer);
    memset(buffer, 0, sizeof(buffer));
    memcpy(buffer, "A2160", 5);
    set_dtb_prop(root, "regulatory-model-number", 32, buffer);

    child = get_dtb_node(root, "chosen");
    data = 0x8030;
    set_dtb_prop(child, "chip-id", 4, (uint8_t *)&data);
    data = 0x4;
    set_dtb_prop(child, "board-id", 4, (uint8_t *)&data);

    uint64_t ecid = 0x1122334455667788;
    set_dtb_prop(child, "unique-chip-id", 8, (uint8_t *)&ecid);

    if (info->ticket_data && info->ticket_length) {
        QCryptoHashAlgorithm alg = QCRYPTO_HASH_ALG_SHA1;
        g_autofree uint8_t *hash = NULL;
        size_t hash_len = 0;
        g_autofree Error *err = NULL;
        prop = find_dtb_prop(child, "crypto-hash-method");

        if (prop) {
            if (strcmp((char *)prop->value, "sha2-384") == 0) {
                alg = QCRYPTO_HASH_ALG_SHA384;
            }
        }

        if (qcrypto_hash_bytes(alg, info->ticket_data, info->ticket_length, &hash, &hash_len, &err) >= 0) {
            set_dtb_prop(child, "boot-manifest-hash", hash_len, hash);
        } else {
            error_report_err(err);
        }
    }

    macho_dtb_node_process(root, NULL);

    child = get_dtb_node(root, "chosen");
    assert(child != NULL);
    child = get_dtb_node(child, "memory-map");
    assert(child != NULL);

    if ((info->ramdisk_pa) && (info->ramdisk_size)) {
        memmap[0] = info->ramdisk_pa;
        memmap[1] = info->ramdisk_size;
        set_dtb_prop(child, "RAMDisk", sizeof(memmap),
                           (uint8_t *)&memmap[0]);
    }

    if ((info->trustcache_pa) && (info->trustcache_size)) {
        memmap[0] = info->trustcache_pa;
        memmap[1] = info->trustcache_size;
        set_dtb_prop(child, "TrustCache", sizeof(memmap),
                           (uint8_t *)&memmap[0]);
    }

    memmap[0] = info->bootargs_pa;
    memmap[1] = sizeof(struct xnu_arm64_boot_args);
    set_dtb_prop(child, "BootArgs", sizeof(memmap), (uint8_t *)&memmap[0]);
    set_dtb_prop(child, "DeviceTree", sizeof(memmap), (uint8_t *)&memmap[0]);

    info->dtb_size = get_dtb_node_buffer_size(root);
    child = get_dtb_node(root, "chosen");
    child = get_dtb_node(child, "memory-map");
    prop = find_dtb_prop(child, "DeviceTree");
    ((uint64_t *)prop->value)[0] = info->dtb_pa;
    ((uint64_t *)prop->value)[1] = info->dtb_size;

    buf = g_malloc0(info->dtb_size);
    save_dtb(buf, root);
    allocate_and_copy(mem, as, name, info->dtb_pa, info->dtb_size, buf);
}

void macho_load_trustcache(const char *filename, AddressSpace *as, MemoryRegion *mem,
                            hwaddr pa, uint64_t *size)
{
    uint32_t *trustcache_data = NULL;
    uint64_t trustcache_size = 0;
    uint8_t *file_data = NULL;
    unsigned long file_size = 0;
    uint32_t length = 0;
    char payload_type[4];
    uint32_t trustcache_version, trustcache_entry_count, expected_file_size;

    extract_im4p_payload(filename, payload_type, &file_data, &length);

    if (strncmp(payload_type, "trst", 4) != 0
        && strncmp(payload_type, "rtsc", 4) != 0
        && strncmp(payload_type, "raw", 4) != 0) {
        error_report("Couldn't parse ASN.1 data in file '%s' because it is not a 'trst' or 'rtsc' object, found '%.4s' object.", filename, payload_type);
        exit(EXIT_FAILURE);
    }

    file_size = (unsigned long)length;

    trustcache_size = file_size + 8;
    trustcache_data = (uint32_t *)g_malloc(trustcache_size);
    trustcache_data[0] = 1; //#trustcaches
    trustcache_data[1] = 8; //offset
    memcpy(&trustcache_data[2], file_data, file_size);

    // Validate the trustcache v1 header. The layout is:
    // uint32_t version
    // uuid (16 bytes)
    // uint32_t entry_count
    //
    // The cache is then followed by entry_count entries, each of which
    // contains a 20 byte hash and 2 additional bytes (hence is 22 bytes long)
    trustcache_version = trustcache_data[2];
    trustcache_entry_count = trustcache_data[7];
    expected_file_size = 24 /* header size */ + trustcache_entry_count * 22 /* entry size */;

    if (trustcache_version != 1) {
        error_report("The trust cache '%s' does not have a v1 header", filename);
        exit(EXIT_FAILURE);
    }

    if (file_size != expected_file_size) {
        error_report("The expected size %d of trust cache '%s' does not match the actual size %ld", expected_file_size, filename, file_size);
        exit(EXIT_FAILURE);
    }

    allocate_and_copy(mem, as, "TrustCache", pa, trustcache_size, trustcache_data);
    *size = trustcache_size;
    g_free(file_data);
    g_free(trustcache_data);
}

void macho_load_ramdisk(const char *filename, AddressSpace *as, MemoryRegion *mem,
                            hwaddr pa, uint64_t *size)
{
    uint8_t *file_data = NULL;
    unsigned long file_size = 0;
    uint32_t length = 0;
    char payload_type[4];

    extract_im4p_payload(filename, payload_type, &file_data, &length);
    if (strncmp(payload_type, "rdsk", 4) != 0
        && strncmp(payload_type, "raw", 4) != 0) {
        error_report("Couldn't parse ASN.1 data in file '%s' because it is not a 'rdsk' object, found '%.4s' object.", filename, payload_type);
        exit(EXIT_FAILURE);
    }

    file_size = length;
    file_data = g_realloc(file_data, file_size);

    allocate_and_copy(mem, as, "RamDisk", pa, file_size, file_data);
    *size = file_size;
    g_free(file_data);
}

void macho_map_raw_file(const char *filename, AddressSpace *as, MemoryRegion *mem,
                        const char *name, hwaddr file_pa, uint64_t *size)
{
    Error *err = NULL;
    MemoryRegion *mr = NULL;
    struct stat file_info;

    if (stat(filename, &file_info)) {
        fprintf(stderr, "Couldn't get file size for mmapping. Loading into RAM.\n");
        goto load_fallback;
    }

    mr = g_new(MemoryRegion, 1);
    *size = file_info.st_size;

    memory_region_init_ram_from_file(mr, NULL, name, *size & (~0xffffUL), 0, 0, filename, false, &err);
    if (err) {
        error_report_err(err);
        fprintf(stderr, "Couldn't mmap file. Loading into RAM.\n");
        goto load_fallback;
    }
    memory_region_add_subregion(mem, file_pa, mr);
    return;

load_fallback:
    g_free(mr);
    macho_load_raw_file(filename, as, mem, name, file_pa, size);
}

void macho_load_raw_file(const char *filename, AddressSpace *as, MemoryRegion *mem,
                         const char *name, hwaddr file_pa, uint64_t *size)
{
    uint8_t *file_data = NULL;
    unsigned long sizef;

    if (g_file_get_contents(filename, (char **)&file_data, &sizef, NULL)) {
        *size = sizef;
        allocate_and_copy(mem, as, name, file_pa, *size, file_data);
        g_free(file_data);
    } else {
        abort();
    }
}

bool xnu_contains_boot_arg(const char *bootArgs, const char *arg, bool prefixmatch)
{
    g_autofree char *args = g_strdup(bootArgs);
    char *pos = args;
    char *token;
    size_t arglen = strlen(arg);

    if (args == NULL) {
    	return false;
    }

    while ((token = strsep(&pos, " ")) != NULL) {
    	if (prefixmatch && strncmp(token, arg, arglen) == 0) {
    		return true;
    	} else if (strcmp(token, arg) == 0) {
    		return true;
    	}
    }

    return false;
}

void macho_setup_bootargs(const char *name, AddressSpace *as,
                          MemoryRegion *mem, hwaddr bootargs_pa,
                          hwaddr virt_base, hwaddr phys_base, hwaddr mem_size,
                          hwaddr top_of_kernel_data_pa, hwaddr dtb_va,
                          hwaddr dtb_size, video_boot_args v_bootargs,
                          char *kern_args)
{
    struct xnu_arm64_boot_args boot_args;

    memset(&boot_args, 0, sizeof(boot_args));
    boot_args.Revision = xnu_arm64_kBootArgsRevision2;
    boot_args.Version = xnu_arm64_kBootArgsVersion2;
    boot_args.virtBase = virt_base;
    boot_args.physBase = phys_base;
    boot_args.memSize = mem_size;

    boot_args.Video.v_baseAddr = v_bootargs.v_baseAddr;
    boot_args.Video.v_depth = v_bootargs.v_depth;
    boot_args.Video.v_display = v_bootargs.v_display;
    boot_args.Video.v_height = v_bootargs.v_height;
    boot_args.Video.v_rowBytes = v_bootargs.v_rowBytes;
    boot_args.Video.v_width = v_bootargs.v_width;

    boot_args.topOfKernelData = top_of_kernel_data_pa;
    boot_args.deviceTreeP = dtb_va;
    boot_args.deviceTreeLength = dtb_size;
    boot_args.memSizeActual = 0;
    boot_args.bootFlags = 1;
    if (kern_args) {
        g_strlcpy(boot_args.CommandLine, kern_args,
                  sizeof(boot_args.CommandLine));
    }

    allocate_and_copy(mem, as, name, bootargs_pa, sizeof(boot_args),
                      &boot_args);
}

void macho_highest_lowest(struct mach_header_64 *mh, uint64_t *lowaddr,
                          uint64_t *highaddr)
{
    struct load_command *cmd = (struct load_command*)((uint8_t *)mh +
            sizeof(struct mach_header_64));
    // iterate all the segments once to find highest and lowest addresses
    uint64_t low_addr_temp = ~0;
    uint64_t high_addr_temp = 0;
    unsigned int index;

    for (index = 0; index < mh->ncmds; index++) {
        switch (cmd->cmd) {
        case LC_SEGMENT_64: {
            struct segment_command_64 *segCmd =
                (struct segment_command_64 *)cmd;

            if (segCmd->vmaddr < low_addr_temp) {
                low_addr_temp = segCmd->vmaddr;
            }
            if (segCmd->vmaddr + segCmd->vmsize > high_addr_temp) {
                high_addr_temp = segCmd->vmaddr + segCmd->vmsize;
            }
            break;
        }

        default:
            break;
        }
        cmd = (struct load_command *)((char *)cmd + cmd->cmdsize);
    }
    if (lowaddr) {
        *lowaddr = (low_addr_temp) & 0xfffffffffff00000ULL;
    }
    if (highaddr) {
        *highaddr = high_addr_temp;
    }
}

void macho_text_base(struct mach_header_64 *mh, uint64_t *base)
{
    struct load_command *cmd = (struct load_command*)((uint8_t *)mh +
            sizeof(struct mach_header_64));
    unsigned int index;
    *base = 0;
    for (index = 0; index < mh->ncmds; index++) {
        switch (cmd->cmd) {
        case LC_SEGMENT_64: {
            struct segment_command_64 *segCmd =
                (struct segment_command_64 *)cmd;

            if (segCmd->vmaddr && segCmd->fileoff == 0) {
                *base = segCmd->vmaddr;
            }
            break;
        }

        default:
            break;
        }
        cmd = (struct load_command *)((char *)cmd + cmd->cmdsize);
    }
}

struct mach_header_64 *macho_load_file(const char *filename)
{
    uint32_t len;
    uint8_t *data = NULL;
    char payload_type[4];
    struct mach_header_64 *mh = NULL;

    extract_im4p_payload(filename, payload_type, &data, &len);

    if (strncmp(payload_type, "krnl", 4) != 0
        && strncmp(payload_type, "raw", 4) != 0) {
        error_report("Couldn't parse ASN.1 data in file '%s' because it is not a 'krnl' object, found '%.4s' object.", filename, payload_type);
        exit(EXIT_FAILURE);
    }

    mh = macho_parse(data, len);
    g_free(data);
    return mh;
}

struct mach_header_64 *macho_parse(uint8_t *data, uint32_t len)
{
    uint8_t *phys_base = NULL;
    struct mach_header_64 *mh;
    struct load_command *cmd;
    uint64_t lowaddr = 0, highaddr = 0;
    uint64_t virt_base = 0;
    uint64_t text_base = 0;
    int index;

    mh = (struct mach_header_64 *)data;
    if (mh->magic != MACH_MAGIC_64) {
        error_report("%s: Invalid Mach-O object: mh->magic != MACH_MAGIC_64", __func__);
        exit(EXIT_FAILURE);
    }

    macho_highest_lowest(mh, &lowaddr, &highaddr);
    assert(lowaddr < highaddr);

    phys_base = g_malloc0(highaddr - lowaddr);
    virt_base = lowaddr;
    cmd = (struct load_command *)(data + sizeof(struct mach_header_64));

    for (index = 0; index < mh->ncmds; index++) {
        switch (cmd->cmd) {
        case LC_SEGMENT_64: {
            struct segment_command_64 *segCmd =
                (struct segment_command_64 *)cmd;
            if (segCmd->vmsize == 0) {
                break;
            }
            if (segCmd->fileoff >= len) {
                error_report("%s: Invalid Mach-O: segCmd->fileoff >= len", __func__);
                exit(EXIT_FAILURE);
            }
            if (segCmd->fileoff == 0) {
                text_base = segCmd->vmaddr;
            }
            memcpy(phys_base + segCmd->vmaddr - virt_base, data + segCmd->fileoff, segCmd->filesize);
            break;
        }

        default:
            break;
        }

        cmd = (struct load_command *)((char *)cmd + cmd->cmdsize);
    }

    return (struct mach_header_64 *)(phys_base + text_base - virt_base);
}

uint32_t macho_build_version(struct mach_header_64 *mh)
{
    struct load_command *cmd;
    int index;

    cmd = (struct load_command *)((char *)mh + sizeof(struct mach_header_64));

    for (index = 0; index < mh->ncmds; index++) {
        switch (cmd->cmd) {
        case LC_BUILD_VERSION: {
            struct build_version_command *buildVerCmd = (struct build_version_command *)cmd;
            return buildVerCmd->sdk;
            break;
        }

        default:
            break;
        }

        cmd = (struct load_command *)((char *)cmd + cmd->cmdsize);
    }
    return 0;
}

uint32_t macho_platform(struct mach_header_64 *mh)
{
    struct load_command *cmd;
    int index;

    cmd = (struct load_command *)((char *)mh + sizeof(struct mach_header_64));

    for (index = 0; index < mh->ncmds; index++) {
        switch (cmd->cmd) {
        case LC_BUILD_VERSION: {
            struct build_version_command *buildVerCmd = (struct build_version_command *)cmd;
            return buildVerCmd->platform;
            break;
        }

        default:
            break;
        }

        cmd = (struct load_command *)((char *)cmd + cmd->cmdsize);
    }
    return 0;
}

char *macho_platform_string(struct mach_header_64 *mh)
{
    uint32_t platform = macho_platform(mh);
    switch (platform) {
        case PLATFORM_MACOS:
            return (char *)("macOS");
        case PLATFORM_IOS:
            return (char *)("iOS");
        case PLATFORM_TVOS:
            return (char *)("tvOS");
        case PLATFORM_WATCHOS:
            return (char *)("watchOS");
        case PLATFORM_BRIDGEOS:
            return (char *)("bridgeOS");
        default:
            return (char *)("Unknown");
    }
}

hwaddr arm_load_macho(struct mach_header_64 *mh, AddressSpace *as, MemoryRegion *mem,
                    const char *name, hwaddr phys_base, hwaddr virt_base)
{
    uint8_t *data = NULL;
    unsigned int index;
    struct load_command *cmd;
    hwaddr pc = 0;
    data = macho_get_buffer(mh);

    cmd = (struct load_command *)((char *)mh + sizeof(struct mach_header_64));
    for (index = 0; index < mh->ncmds; index++) {
        switch (cmd->cmd) {
        case LC_SEGMENT_64: {
            struct segment_command_64 *segCmd =
                (struct segment_command_64 *)cmd;
            char region_name[32] = {0};

            snprintf(region_name, sizeof(region_name), "%s-%s", name, segCmd->segname);
            if (segCmd->vmsize == 0) {
                break;
            }
            allocate_and_copy(mem, as, region_name,
                              phys_base + segCmd->vmaddr - virt_base, segCmd->vmsize,
                              data + segCmd->vmaddr - virt_base);

            break;
        }

        case LC_UNIXTHREAD: {
            // grab just the entry point PC
            uint64_t *ptrPc = (uint64_t *)((char *)cmd + 0x110);

            // 0x110 for arm64 only.
            pc = vtop_bases(*ptrPc, phys_base, virt_base);

            break;
        }

        default:
            break;
        }

        cmd = (struct load_command *)((char *)cmd + cmd->cmdsize);
    }

    return pc;
}

uint8_t *macho_get_buffer(struct mach_header_64 *hdr)
{
    uint64_t lowaddr = 0, highaddr = 0, text_base = 0;

    macho_highest_lowest(hdr, &lowaddr, &highaddr);
    macho_text_base(hdr, &text_base);

    return (uint8_t *)((uint8_t *)hdr - text_base + lowaddr);
}

void macho_free(struct mach_header_64 *hdr)
{
    g_free(macho_get_buffer(hdr));
}

struct segment_command_64 *macho_get_segment(struct mach_header_64 *header, const char *segname)
{
    struct segment_command_64 *sgp;
    uint32_t i;

    sgp = (struct segment_command_64 *)
        ((char *)header + sizeof(struct mach_header_64));

    for(i = 0; i < header->ncmds; i++) {
        if (sgp->cmd == LC_SEGMENT_64) {
            if (strncmp(sgp->segname, segname, sizeof(sgp->segname)) == 0)
                return sgp;
        }

        sgp = (struct segment_command_64 *)((char *)sgp + sgp->cmdsize);
    }

    // not found
    return NULL;
}

struct section_64 *macho_get_section(struct segment_command_64 *seg, const char *sectname)
{
    struct section_64 *sp;
    uint32_t i;

    sp = (struct section_64 *)((char *)seg + sizeof(struct segment_command_64));

    for(i = 0; i < seg->nsects; i++) {
        if (strncmp(sp->sectname, sectname, sizeof(sp->sectname)) == 0) {
            return sp;
        }

        sp = (struct section_64 *)((char *)sp + sizeof(struct section_64));
    }

    // not found
    return NULL;
}

static bool xnu_is_slid(struct mach_header_64 *header)
{
    struct segment_command_64 *seg = macho_get_segment(header, "__TEXT");
    if (seg && seg->vmaddr == 0xFFFFFFF007004000ULL) {
        return false;
    }

    return true;
}

uint64_t xnu_slide_hdr_va(struct mach_header_64 *header, uint64_t hdr_va)
{
    uint64_t text_va_base, slide;

    if (xnu_is_slid(header)) {
        return hdr_va;
    }

    text_va_base = ((uint64_t)header) - kCacheableView - g_phys_slide + g_virt_base;
    slide = text_va_base - 0xFFFFFFF007004000ULL;
    return hdr_va + slide;
}

uint64_t xnu_slide_value(struct mach_header_64 *header)
{
    uint64_t text_va_base = ((uint64_t) header) - kCacheableView - g_phys_slide + g_virt_base;
    uint64_t slide = text_va_base - 0xFFFFFFF007004000ULL;
    return slide;
}

void *xnu_va_to_ptr(uint64_t va)
{
    return (void*)(va - g_virt_base + g_phys_slide + kCacheableView);
}

uint64_t xnu_ptr_to_va(void *ptr)
{
    return ((uint64_t)ptr) - kCacheableView + g_phys_slide + g_virt_base;
}

// NOTE: iBoot-based rebase only applies to main XNU.
//       Kexts will never ever have been rebased when Pongo runs.
static bool has_been_rebased(void)
{
    static int8_t rebase_status = -1;
    // First, determine whether we've been rebased. his feels really hacky, but it correctly covers all cases:
    //
    // 1. New-style kernels rebase themselves, so this is always false.
    // 2. Old-style kernels on a live device will always have been rebased.
    // 3. Old-style kernels on kpf-test will not have been rebase, but we use a slide of 0x0 there
    //    and the pointers are valid by themselves, so they can be treated as correctly rebased.
    //
    if (rebase_status == -1) {
        struct segment_command_64 *seg = macho_get_segment(xnu_header, "__TEXT");
        struct section_64 *sec = seg ? macho_get_section(seg, "__thread_starts") : NULL;
        rebase_status = sec->size == 0 ? 1 : 0;
    }

    return rebase_status == 1;
}

uint64_t xnu_rebase_va(uint64_t va)
{
    if (!has_been_rebased()) {
        va = (uint64_t)(((int64_t)va << 13) >> 13) + xnu_slide_value(xnu_header);
    }

    return va;
}

uint64_t kext_rebase_va(uint64_t va)
{
    if (!has_been_rebased()) {
        va = (uint64_t)(((int64_t)va << 13) >> 13);
    }

    return va + xnu_slide_value(xnu_header);
}
