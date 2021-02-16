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
#include "hw/arm/xnu.h"
#include "hw/loader.h"

const char *KEEP_COMP[] = {"uart-1,samsung\0$",
                           "N104AP\0iPhone12,1\0AppleARM\0$", "arm-io,t8030\0$", "apple,thunder\0ARM,v8\0$", "aic,1\0$", "pmgr1,t8030\0$"};

const char *REM_NAMES[] = {"backlight\0$", "dockchannel-uart\0$"};

const char *REM_DEV_TYPES[] = {"backlight\0$"};

const char *REM_PROPS[] = {"function-error_handler"};
//TODO: error_handler probably needs arm-io to initialize properly

static void allocate_and_copy(MemoryRegion *mem, AddressSpace *as,
                              const char *name, hwaddr pa, hwaddr size,
                              void *buf)
{
    if (mem) {
        allocate_ram(mem, name, pa, align_64k_high(size));
    }
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
    return (end - str);
}

static void macho_dtb_node_process(DTBNode *node)
{
    GList *iter = NULL;
    DTBNode *child = NULL;
    DTBProp *prop = NULL;
    uint64_t i = 0;

    //remove compatible properties
    prop = get_dtb_prop(node, "compatible");
    if (NULL != prop) {
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
            //TODO: maybe remove the whole node and sub nodes?
            overwrite_dtb_prop_val(prop, *(uint8_t *)"~");
        }
    }

    //remove name properties
    prop = get_dtb_prop(node, "name");
    if (NULL != prop) {
        uint64_t count = sizeof(REM_NAMES) / sizeof(REM_NAMES[0]);
        for (i = 0; i < count; i++) {
            uint64_t size = MIN(prop->length, sstrlen(REM_NAMES[i]));
            if (0 == memcmp(prop->value, REM_NAMES[i], size)) {
                //TODO: maybe remove the whole node and sub nodes?
                overwrite_dtb_prop_val(prop, *(uint8_t *)"~");
                break;
            }
        }
    }

    //remove dev type properties
    prop = get_dtb_prop(node, "device_type");
    if (NULL != prop) {
        uint64_t count = sizeof(REM_DEV_TYPES) / sizeof(REM_DEV_TYPES[0]);
        for (i = 0; i < count; i++) {
            uint64_t size = MIN(prop->length, sstrlen(REM_DEV_TYPES[i]));
            if (0 == memcmp(prop->value, REM_DEV_TYPES[i], size)) {
                //TODO: maybe remove the whole node and sub nodes?
                overwrite_dtb_prop_val(prop, *(uint8_t *)"~");
                break;
            }
        }
    }
    {
        uint64_t count = sizeof(REM_PROPS) / sizeof(REM_PROPS[0]);
        for (i = 0; i < count; i++) {
            prop = get_dtb_prop(node, REM_PROPS[i]);
            if(prop!=NULL){
                remove_dtb_prop(node, prop);
            }
        }
    }
    for (iter = node->child_nodes; iter != NULL; iter = iter->next) {
        child = (DTBNode *)iter->data;
        macho_dtb_node_process(child);
    }

}

DTBNode* load_dtb_from_file(char *filename){
    uint8_t *file_data = NULL;
    unsigned long fsize;

    if (g_file_get_contents(filename, (char **)&file_data, &fsize, NULL)) {
        DTBNode *root = load_dtb(file_data);
        return root;
    } else {
        abort();
    }
    g_free(file_data);
}

void macho_load_dtb(DTBNode* root, AddressSpace *as, MemoryRegion *mem,
                    const char *name, hwaddr dtb_pa, uint64_t *size,
                    hwaddr ramdisk_addr, hwaddr ramdisk_size,
                    hwaddr trustcache_addr, hwaddr trustcache_size,
                    hwaddr dram_base, unsigned long dram_size)
{
    DTBNode* child = NULL;
    DTBProp* prop = NULL;

    //remove this prop as it is responsible for the waited for event
    //in PE that never happens
    prop = get_dtb_prop(root, "secure-root-prefix");
    if (NULL == prop) {
        abort();
    }
    remove_dtb_prop(root, prop);

    //need to set the random seed insread of iboot
    uint64_t seed[8] = {0xdead000d, 0xdead000d, 0xdead000d, 0xdead000d,
                        0xdead000d, 0xdead000d, 0xdead000d, 0xdead000d};
    child = get_dtb_child_node_by_name(root, "chosen");
    assert(child != NULL);
    prop = get_dtb_prop(child, "random-seed");
    assert(prop != NULL);
    remove_dtb_prop(child, prop);
    add_dtb_prop(child, "random-seed", sizeof(seed), (uint8_t *)&seed[0]);

    add_dtb_prop(child, "dram-base", sizeof(dram_base), &dram_base);
    add_dtb_prop(child, "dram-size", sizeof(dram_base), &dram_size);
    prop = get_dtb_prop(child, "debug-enabled");
    *(uint32_t*)prop->value = 1;
    prop = get_dtb_prop(child, "firmware-version");
    remove_dtb_prop(child, prop);
    add_dtb_prop(child, "firmware-version", 15, "qemu-t8030");
    prop = get_dtb_prop(child, "nvram-total-size");
    remove_dtb_prop(child, prop);
    uint32_t nvram_total_size = 0xFFFF * 0x10;
    add_dtb_prop(child, "nvram-total-size", 4, &nvram_total_size);

    uint8_t *nvram_file_data = NULL;
    unsigned long nvram_fsize;
    
    char nvram_proxy_data[] = "0000common\0     nonce-seeds=aaaabbbbccccddddaaaabbbbccccdddd\0\0\0";
    prop = get_dtb_prop(child, "nvram-proxy-data");
    remove_dtb_prop(child, prop);
    add_dtb_prop(child, "nvram-proxy-data", sizeof(nvram_proxy_data), nvram_proxy_data);
    g_free(nvram_file_data);

    uint64_t data64;
    uint32_t data = 1;
    add_dtb_prop(child, "research-enabled", sizeof(data), (uint8_t *)&data);
    prop = get_dtb_prop(child, "effective-production-status-ap");
    if(prop != NULL){
        //disable coresight
        *(uint32_t*)prop->value = 1;
    }
    //update the display parameters
    uint32_t display_rotation = 0;
    prop = get_dtb_prop(child, "display-rotation");
    assert(prop != NULL);
    remove_dtb_prop(child, prop);
    add_dtb_prop(child, "display-rotation", sizeof(display_rotation),
                    (uint8_t *)&display_rotation);
    uint32_t display_scale = 1;
    prop = get_dtb_prop(child, "display-scale");
    assert(prop != NULL);
    remove_dtb_prop(child, prop);
    add_dtb_prop(child, "display-scale", sizeof(display_scale),
                    (uint8_t *)&display_scale);

    //these are needed by the image4 parser module$
    add_dtb_prop(child, "security-domain", sizeof(data), (uint8_t *)&data);
    add_dtb_prop(child, "chip-epoch", sizeof(data), (uint8_t *)&data);
    data = 0xffffffff;
    add_dtb_prop(child, "debug-enabled", sizeof(data), (uint8_t *)&data);

    child = get_dtb_child_node_by_name(child, "memory-map");
    assert(child != NULL);

    uint64_t memmap[2] = {0};

    if ((0 != ramdisk_addr) && (0 != ramdisk_size)) {
        memmap[0] = ramdisk_addr;
        memmap[1] = ramdisk_size;
        add_dtb_prop(child, "RAMDisk", sizeof(memmap),
                        (uint8_t *)&memmap[0]);
    }
    if ((0 != trustcache_addr) && (0 != trustcache_size)) {
        memmap[0] = trustcache_addr;
        memmap[1] = trustcache_size;
        add_dtb_prop(child, "TrustCache", sizeof(memmap),
                        (uint8_t *)&memmap[0]);
    }

    macho_dtb_node_process(root);

    uint64_t size_n = get_dtb_node_buffer_size(root);

    uint8_t *buf = g_malloc0(size_n);
    save_dtb(buf, root);
    allocate_and_copy(mem, as, name, dtb_pa, size_n, buf);
    // delete_dtb_node(root);
    g_free(buf);
    *size = size_n;
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

    memory_region_init_ram_from_file(mr, NULL, name, *size & (~0xffffUL), 0, 0, filename, &err);
    if (err) {
        error_report_err(err);
        fprintf(stderr, "Couldn't mmap file. Loading into RAM.\n");
        goto load_fallback;
    }
    memory_region_add_subregion(mem, file_pa, mr);
    return;

load_fallback:
    if (mr) {
        g_free(mr);
    }
    macho_load_raw_file(filename, as, mem, name, file_pa, size);
}

void macho_load_raw_file(const char *filename, AddressSpace *as, MemoryRegion *mem,
                         const char *name, hwaddr file_pa, uint64_t *size)
{
    uint8_t* file_data = NULL;
    unsigned long sizef;
    if (g_file_get_contents(filename, (char **)&file_data, &sizef, NULL)) {
        *size = sizef;
        allocate_and_copy(mem, as, name, file_pa, *size, file_data);
        g_free(file_data);
    } else {
        abort();
    }
}

void macho_tz_setup_bootargs(const char *name, AddressSpace *as,
                             MemoryRegion *mem, hwaddr bootargs_addr,
                             hwaddr virt_base, hwaddr phys_base,
                             hwaddr mem_size, hwaddr kern_args,
                             hwaddr kern_entry, hwaddr kern_phys_base)
{
    struct xnu_arm64_monitor_boot_args boot_args;
    memset(&boot_args, 0, sizeof(boot_args));
    boot_args.version = xnu_arm64_kBootArgsVersion2;
    boot_args.virtBase = virt_base;
    boot_args.physBase = phys_base;
    boot_args.memSize = mem_size;
    boot_args.kernArgs = kern_args;
    boot_args.kernEntry = kern_entry;
    boot_args.kernPhysBase = kern_phys_base;

    boot_args.kernPhysSlide = 0;
    boot_args.kernVirtSlide = 0;

    allocate_and_copy(mem, as, name, bootargs_addr, sizeof(boot_args),
                      &boot_args);
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

static void macho_highest_lowest(struct mach_header_64* mh, uint64_t *lowaddr,
                                 uint64_t *highaddr)
{
    struct load_command* cmd = (struct load_command*)((uint8_t*)mh +
                                                sizeof(struct mach_header_64));
    // iterate all the segments once to find highest and lowest addresses
    uint64_t low_addr_temp = ~0;
    uint64_t high_addr_temp = 0;
    for (unsigned int index = 0; index < mh->ncmds; index++) {
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
        }
        cmd = (struct load_command*)((char*)cmd + cmd->cmdsize);
    }
    *lowaddr = low_addr_temp;
    *highaddr = high_addr_temp;
}

static void macho_file_highest_lowest(const char *filename, hwaddr *lowest,
                                      hwaddr *highest)
{
    gsize len;
    uint8_t *data = NULL;
    if (!g_file_get_contents(filename, (char **)&data, &len, NULL)) {
        abort();
    }
    struct mach_header_64* mh = (struct mach_header_64*)data;
    macho_highest_lowest(mh, lowest, highest);
    g_free(data);
}

void macho_file_highest_lowest_base(const char *filename, hwaddr phys_base,
                                    hwaddr *virt_base, hwaddr *lowest,
                                    hwaddr *highest)
{
    uint8_t high_Low_dif_bit_index;
    uint8_t phys_base_non_zero_bit_index;
    hwaddr bit_mask_for_index;

    macho_file_highest_lowest(filename, lowest, highest);
    high_Low_dif_bit_index =
        get_highest_different_bit_index(align_64k_high(*highest),
                                        align_64k_low(*lowest));
    if (phys_base) {
        phys_base_non_zero_bit_index =
            get_lowest_non_zero_bit_index(phys_base);

        //make sure we have enough zero bits to have all the diffrent kernel
        //image addresses have the same non static bits in physical and in
        //virtual memory.
        if (high_Low_dif_bit_index > phys_base_non_zero_bit_index) {
            abort();
        }
        bit_mask_for_index =
            get_low_bits_mask_for_bit_index(phys_base_non_zero_bit_index);

        *virt_base = align_64k_low(*lowest) & (~bit_mask_for_index);
    }

}

void arm_load_macho(char *filename, AddressSpace *as, MemoryRegion *mem,
                    const char *name, hwaddr phys_base, hwaddr virt_base,
                    hwaddr low_virt_addr, hwaddr high_virt_addr, hwaddr *pc)
{
    uint8_t *data = NULL;
    gsize len;
    uint8_t* rom_buf = NULL;

    if (!g_file_get_contents(filename, (char **)&data, &len, NULL)) {
        abort();
    }
    struct mach_header_64* mh = (struct mach_header_64*)data;
    struct load_command* cmd = (struct load_command*)(data +
                                                sizeof(struct mach_header_64));

    uint64_t rom_buf_size = align_64k_high(high_virt_addr) - low_virt_addr;
    rom_buf = g_malloc0(rom_buf_size);
    for (unsigned int index = 0; index < mh->ncmds; index++) {
        switch (cmd->cmd) {
            case LC_SEGMENT_64: {
                struct segment_command_64 *segCmd =
                                            (struct segment_command_64 *)cmd;
                memcpy(rom_buf + (segCmd->vmaddr - low_virt_addr),
                       data + segCmd->fileoff, segCmd->filesize);
                break;
            }
            case LC_UNIXTHREAD: {
                // grab just the entry point PC
                uint64_t* ptrPc = (uint64_t*)((char*)cmd + 0x110);
                // 0x110 for arm64 only.
                *pc = vtop_bases(*ptrPc, phys_base, virt_base);
                break;
            }
        }
        cmd = (struct load_command*)((char*)cmd + cmd->cmdsize);
    }
    hwaddr low_phys_addr = vtop_bases(low_virt_addr, phys_base, virt_base);
    allocate_and_copy(mem, as, name, low_phys_addr, rom_buf_size, rom_buf);

    if (data) {
        g_free(data);
    }
    if (rom_buf) {
        g_free(rom_buf);
    }
}
