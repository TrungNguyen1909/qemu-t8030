/*
 * iPhone 11 - T8030
 *
 * Copyright (c) 2019 Johnathan Afek <jonyafek@me.com>
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
#include "qemu/log.h"
#include "qemu/units.h"
#include "qemu/guest-random.h"
#include "qapi/error.h"
#include "qapi/visitor.h"
#include "qemu/cutils.h"
#include "hw/arm/boot.h"
#include "exec/address-spaces.h"
#include "hw/misc/unimp.h"
#include "sysemu/block-backend.h"
#include "sysemu/sysemu.h"
#include "sysemu/reset.h"
#include "sysemu/runstate.h"
#include "qemu/error-report.h"
#include "hw/platform-bus.h"
#include "arm-powerctl.h"

#include "hw/arm/t8030.h"
#include "hw/arm/t8030-config.c.inc"
#include "hw/arm/apple_a13.h"

#include "hw/irq.h"
#include "hw/or-irq.h"
#include "hw/intc/apple_aic.h"
#include "hw/block/apple_ans.h"
#include "hw/arm/apple_sart.h"
#include "hw/gpio/apple_gpio.h"
#include "hw/i2c/apple_i2c.h"
#include "hw/usb/apple_otg.h"
#include "hw/usb/apple_typec.h"
#include "hw/watchdog/apple_wdt.h"
#include "hw/misc/apple_aes.h"
#include "hw/nvram/apple_nvram.h"
#include "hw/spmi/apple_spmi.h"
#include "hw/spmi/apple_spmi_pmu.h"
#include "hw/misc/apple_smc.h"
#include "hw/arm/apple_dart.h"
#include "hw/dma/apple_sio.h"
#include "hw/ssi/ssi.h"
#include "hw/ssi/apple_spi.h"
#include "hw/char/apple_uart.h"

#include "hw/arm/xnu_pf.h"
#include "hw/display/m1_fb.h"

#define T8030_DRAM_BASE         (0x800000000)
#define T8030_DRAM_SIZE         (4 * GiB)

/*
 * This is from /chosen/carveout-memory-map/region-id-24
 */
#define T8030_KERNEL_REGION_BASE (0x801964000)
#define T8030_KERNEL_REGION_SIZE (0xf09cc000)

#define T8030_SPI_BASE(_x)      (0x35100000 + (_x) * APPLE_SPI_MMIO_SIZE)

#define T8030_DWC2_IRQ          (495)

#define T8030_NUM_UARTS         (9)
#define T8030_NUM_SPIS          (4)

#define T8030_ANS_TEXT_BASE     (0x800024000)
#define T8030_ANS_TEXT_SIZE     (0x124000)
#define T8030_ANS_DATA_BASE     (0x8fc400000)
#define T8030_ANS_DATA_SIZE     (0x3c00000)
#define T8030_SMC_REGION_SIZE   (0x80000)
#define T8030_SMC_TEXT_BASE     (0x23fe00000)
#define T8030_SMC_TEXT_SIZE     (0x30000)
#define T8030_SMC_DATA_BASE     (0x23fe30000)
#define T8030_SMC_DATA_SIZE     (0x30000)
#define T8030_SMC_SRAM_BASE     (0x23fe60000)
#define T8030_SMC_SRAM_SIZE     (0x4000)

#define T8030_SIO_TEXT_BASE     (0x8010a8000)
#define T8030_SIO_TEXT_SIZE     (0x1c000)
#define T8030_SIO_TEXT_REMAP    (0x200000)
#define T8030_SIO_DATA_BASE     (0x80186c000)
#define T8030_SIO_DATA_SIZE     (0xf8000)
#define T8030_SIO_DATA_REMAP    (0x220000)

#define T8030_DISPLAY_BASE      (0x8f7fb4000)
#define T8030_DISPLAY_SIZE      (35 * 1024 * 1024)

#define T8030_PANIC_BASE        (0x8ffeb0000)
#define T8030_PANIC_SIZE        (0x100000)

#define NOP_INST 0xd503201f
#define MOV_W0_01_INST 0x52800020
#define MOV_X13_0_INST 0xd280000d
#define RET_INST 0xd65f03c0
#define RETAB_INST 0xd65f0fff

#define T8030_AMCC_BASE         (0x200000000)
#define T8030_AMCC_SIZE         (0x100000)
#define AMCC_PLANE_COUNT        (4)
#define AMCC_PLANE_STRIDE       (0x40000)
#define AMCC_LOWER(_p)          (0x680 + (_p) * AMCC_PLANE_STRIDE)
#define AMCC_UPPER(_p)          (0x684 + (_p) * AMCC_PLANE_STRIDE)
#define AMCC_REG(_tms, _x)      *(uint32_t *)(&_tms->amcc_reg[_x])

static void t8030_start_cpus(MachineState* machine, uint64_t cpu_mask)
{
    T8030MachineState* tms = T8030_MACHINE(machine);
    int i;

    for(i = 0; i < machine->smp.cpus; i++) {
        if (test_bit(i, (unsigned long*)&cpu_mask)
            && apple_a13_cpu_is_powered_off(tms->cpus[i])) {
            apple_a13_cpu_start(tms->cpus[i]);
        }
    }
}

static void t8030_create_s3c_uart(const T8030MachineState *tms, uint32_t port,
                                  Chardev *chr)
{
    DeviceState *dev;
    hwaddr base;
    //first fetch the uart mmio address
    int vector;
    DTBProp *prop;
    hwaddr *uart_offset;
    DTBNode *child = find_dtb_node(tms->device_tree, "arm-io/uart0");
    char name[32] = { 0 };

    assert(port < T8030_NUM_UARTS);

    assert(child != NULL);
    snprintf(name, sizeof(name), "uart%d", port);

    prop = find_dtb_prop(child, "reg");
    assert(prop != NULL);

    uart_offset = (hwaddr *)prop->value;
    base = tms->soc_base_pa + uart_offset[0] + uart_offset[1] * port;

    prop = find_dtb_prop(child, "interrupts");
    assert(prop);

    vector = *(uint32_t*)prop->value + port;
    dev = apple_uart_create(base, 15, 0, chr,
                            qdev_get_gpio_in(DEVICE(tms->aic), vector));
    assert(dev);
    dev->id = g_strdup(name);
}

static void t8030_patch_kernel(struct mach_header_64 *hdr)
{
    //disable_kprintf_output = 0
    // *(uint32_t *)vtop_static(0xFFFFFFF0077142C8) = 0;
    kpf();
}

static bool t8030_check_panic(MachineState *machine)
{
    T8030MachineState *tms = T8030_MACHINE(machine);
    if (!tms->panic_size) {
        return false;
    }
    g_autofree struct xnu_embedded_panic_header *panic_info =
                                                   g_malloc0(tms->panic_size);
    g_autofree void *buffer = g_malloc0(tms->panic_size);

    address_space_rw(&address_space_memory, tms->panic_base,
                     MEMTXATTRS_UNSPECIFIED, panic_info,
                     tms->panic_size, 0);
    address_space_rw(&address_space_memory, tms->panic_base,
                     MEMTXATTRS_UNSPECIFIED, buffer,
                     tms->panic_size, 1);

    return panic_info->eph_magic == EMBEDDED_PANIC_MAGIC;
}

static size_t get_kaslr_random()
{
    size_t value = 0;
    qemu_guest_getrandom(&value, sizeof(value), NULL);
    return value;
}

#define L2_GRANULE          ((16384) * (16384 / 8))
#define L2_GRANULE_MASK     (L2_GRANULE - 1)

static void get_kaslr_slides(T8030MachineState *tms,
                             hwaddr *phys_slide_out, hwaddr *virt_slide_out)
{
    hwaddr slide_phys = 0, slide_virt = 0;
    const size_t slide_granular = (1 << 14);
    const size_t slide_granular_mask = slide_granular - 1;
    const size_t slide_virt_max = 0x100 * (2 * 1024 * 1024);
    size_t random_value = get_kaslr_random();

    if (tms->kaslr_off) {
        *phys_slide_out = 0;
        *virt_slide_out = 0;
        return;
    }

    slide_virt = (random_value & ~slide_granular_mask) % slide_virt_max;
    if (slide_virt == 0) {
        slide_virt = slide_virt_max;
    }
    slide_phys = slide_virt & L2_GRANULE_MASK;

    *phys_slide_out = slide_phys;
    *virt_slide_out = slide_virt;
}

static void t8030_load_classic_kc(T8030MachineState *tms, const char *cmdline)
{
    MachineState *machine = MACHINE(tms);
    struct mach_header_64 *hdr = tms->kernel;
    MemoryRegion *sysmem = tms->sysmem;
    AddressSpace *nsas = &address_space_memory;
    hwaddr virt_low;
    hwaddr virt_end;
    hwaddr dtb_va;
    hwaddr top_of_kernel_data_pa;
    hwaddr mem_size;
    hwaddr phys_ptr;
    hwaddr amcc_lower;
    hwaddr amcc_upper;
    hwaddr slide_phys = 0;
    hwaddr slide_virt = 0;
    macho_boot_info_t info = &tms->bootinfo;
    g_autofree xnu_pf_range_t *last_range = NULL;
    g_autofree xnu_pf_range_t *text_range = NULL;
    DTBNode *memory_map = get_dtb_node(tms->device_tree, "/chosen/memory-map");

    /*
     * Setup the memory layout:
     * The trustcache is right in front of the __TEXT section, aligned to 16k
     * Then we have all the kernel sections.
     * After that we have ramdisk
     * After that we have the kernel boot args
     * After that we have the device tree
     * After that we have the rest of the RAM
     */

    g_phys_base = (hwaddr)macho_get_buffer(hdr);
    macho_highest_lowest(hdr, &virt_low, &virt_end);
    last_range = xnu_pf_segment(hdr, "__LAST");
    text_range = xnu_pf_segment(hdr, "__TEXT");

    get_kaslr_slides(tms, &slide_phys, &slide_virt);

    g_phys_base = phys_ptr = align_up(T8030_KERNEL_REGION_BASE, 16 * MiB);
    phys_ptr += slide_phys;
    g_virt_base += slide_virt - slide_phys;

    /* TrustCache */
    info->trustcache_pa = vtop_static(text_range->va + slide_virt) - 
                          info->trustcache_size;

    macho_load_trustcache(tms->trustcache, info->trustcache_size,
                          nsas, sysmem, info->trustcache_pa);
    phys_ptr += align_16k_high(info->trustcache_size);

    info->entry = arm_load_macho(hdr, nsas, sysmem, memory_map,
                                 g_phys_base + slide_phys, slide_virt);
    fprintf(stderr, "g_virt_base: 0x" TARGET_FMT_lx "\n"
                    "g_phys_base: 0x" TARGET_FMT_lx "\n",
                    g_virt_base, g_phys_base);
    fprintf(stderr, "slide_virt: 0x" TARGET_FMT_lx "\n"
                    "slide_phys: 0x" TARGET_FMT_lx "\n",
                    slide_virt, slide_phys);
    fprintf(stderr, "entry: 0x" TARGET_FMT_lx "\n", info->entry);

    virt_end += slide_virt;
    phys_ptr = vtop_static(align_16k_high(virt_end));

    amcc_lower = info->trustcache_pa;
    amcc_upper = vtop_static(last_range->va + slide_virt) + last_range->size - 1;
    for (int i = 0; i < 4; i++) {
        AMCC_REG(tms, AMCC_LOWER(i)) = (amcc_lower - T8030_DRAM_BASE) >> 14;
        AMCC_REG(tms, AMCC_UPPER(i)) = (amcc_upper - T8030_DRAM_BASE) >> 14;
    }

    /* ramdisk */
    if (machine->initrd_filename) {
        info->ramdisk_pa = phys_ptr;
        macho_load_ramdisk(machine->initrd_filename, nsas, sysmem, info->ramdisk_pa, &info->ramdisk_size);
        info->ramdisk_size = align_16k_high(info->ramdisk_size);
        phys_ptr += info->ramdisk_size;
    }

    /* Kernel boot args */
    info->bootargs_pa = phys_ptr;
    phys_ptr += align_16k_high(0x4000);

    /* device tree */
    info->dtb_pa = phys_ptr;
    dtb_va = ptov_static(info->dtb_pa);
    phys_ptr += align_16k_high(info->dtb_size);

    mem_size = T8030_KERNEL_REGION_SIZE -
               (g_phys_base - T8030_KERNEL_REGION_BASE);

    macho_load_dtb(tms->device_tree, nsas, sysmem, "DeviceTree", info);

    top_of_kernel_data_pa = (align_16k_high(phys_ptr) + 0x3000ull) & ~0x3fffull;

    fprintf(stderr, "cmdline: [%s]\n", cmdline);
    macho_setup_bootargs("BootArgs", nsas, sysmem, info->bootargs_pa,
                         g_virt_base, g_phys_base, mem_size,
                         top_of_kernel_data_pa, dtb_va, info->dtb_size,
                         tms->video, cmdline);
    g_virt_base = virt_low;
}

static void t8030_load_fileset_kc(T8030MachineState *tms, const char *cmdline)
{
    MachineState *machine = MACHINE(tms);
    struct mach_header_64 *hdr = tms->kernel;
    MemoryRegion *sysmem = tms->sysmem;
    AddressSpace *nsas = &address_space_memory;
    hwaddr virt_low;
    hwaddr virt_end;
    hwaddr dtb_va;
    hwaddr top_of_kernel_data_pa;
    hwaddr mem_size;
    hwaddr phys_ptr;
    hwaddr amcc_lower;
    hwaddr amcc_upper;
    hwaddr slide_phys = 0;
    hwaddr slide_virt = 0;
    uint64_t l2_remaining = 0;
    uint64_t extradata_size = 0;
    macho_boot_info_t info = &tms->bootinfo;
    g_autofree xnu_pf_range_t *last_range = NULL;
    DTBNode *memory_map = get_dtb_node(tms->device_tree, "/chosen/memory-map");

    /*
     * Setup the memory layout:
     * First we have the device tree
     * The trustcache is right after the device tree
     * Then we have all the kernel sections.
     * After that we have ramdisk
     * After that we have the kernel boot args
     * After that we have the rest of the RAM
     */

    g_phys_base = (hwaddr)macho_get_buffer(hdr);
    macho_highest_lowest(hdr, &virt_low, &virt_end);
    g_virt_base = virt_low;
    last_range = xnu_pf_segment(hdr, "__PRELINK_INFO");

    extradata_size = align_16k_high(info->dtb_size + info->trustcache_size);
    assert(extradata_size < L2_GRANULE);

    get_kaslr_slides(tms, &slide_phys, &slide_virt);

    l2_remaining = (virt_low + slide_virt) & L2_GRANULE_MASK;

    if (extradata_size >= l2_remaining) {
        uint64_t grown_slide = align_16k_high(extradata_size - l2_remaining);
        slide_phys += grown_slide;
        slide_virt += grown_slide;
    }

    phys_ptr = align_up(T8030_KERNEL_REGION_BASE, 32 * MiB) | (virt_low & L2_GRANULE_MASK);
    g_phys_base = phys_ptr & ~L2_GRANULE_MASK;
    phys_ptr += slide_phys;
    phys_ptr -= extradata_size;

    /* device tree */
    info->dtb_pa = phys_ptr;
    phys_ptr += info->dtb_size;

    /* TrustCache */
    info->trustcache_pa = phys_ptr;
    macho_load_trustcache(tms->trustcache, info->trustcache_size,
                          nsas, sysmem, info->trustcache_pa);
    phys_ptr += align_16k_high(info->trustcache_size);

    g_virt_base += slide_virt;
    g_virt_base -= phys_ptr - g_phys_base;
    info->entry = arm_load_macho(hdr, nsas, sysmem, memory_map,
                                 phys_ptr, slide_virt);
    fprintf(stderr, "g_virt_base: 0x" TARGET_FMT_lx "\n"
                    "g_phys_base: 0x" TARGET_FMT_lx "\n",
                    g_virt_base, g_phys_base);
    fprintf(stderr, "slide_virt: 0x" TARGET_FMT_lx "\n"
                    "slide_phys: 0x" TARGET_FMT_lx "\n",
                    slide_virt, slide_phys);
    fprintf(stderr, "entry: 0x" TARGET_FMT_lx "\n", info->entry);

    virt_end += slide_virt;
    phys_ptr = vtop_static(align_16k_high(virt_end));

    amcc_lower = info->dtb_pa;
    amcc_upper = vtop_static(last_range->va + slide_virt) + last_range->size - 1;
    for (int i = 0; i < 4; i++) {
        AMCC_REG(tms, AMCC_LOWER(i)) = (amcc_lower - T8030_DRAM_BASE) >> 14;
        AMCC_REG(tms, AMCC_UPPER(i)) = (amcc_upper - T8030_DRAM_BASE) >> 14;
    }

    dtb_va = ptov_static(info->dtb_pa);

    /* ramdisk */
    if (machine->initrd_filename) {
        info->ramdisk_pa = phys_ptr;
        macho_load_ramdisk(machine->initrd_filename, nsas, sysmem,
                           info->ramdisk_pa, &info->ramdisk_size);
        info->ramdisk_size = align_16k_high(info->ramdisk_size);
        phys_ptr += info->ramdisk_size;
    }

    /* Kernel boot args */
    info->bootargs_pa = phys_ptr;
    phys_ptr += align_16k_high(0x4000);

    mem_size = T8030_KERNEL_REGION_SIZE -
               (g_phys_base - T8030_KERNEL_REGION_BASE);

    macho_load_dtb(tms->device_tree, nsas, sysmem, "DeviceTree", info);

    top_of_kernel_data_pa = (align_16k_high(phys_ptr) + 0x3000ull) & ~0x3fffull;

    fprintf(stderr, "cmdline: [%s]\n", cmdline);
    macho_setup_bootargs("BootArgs", nsas, sysmem, info->bootargs_pa,
                         g_virt_base, g_phys_base, mem_size,
                         top_of_kernel_data_pa, dtb_va, info->dtb_size,
                         tms->video, cmdline);
    g_virt_base = virt_low;
}

static void t8030_memory_setup(MachineState *machine)
{
    struct mach_header_64 *hdr;
    T8030MachineState *tms = T8030_MACHINE(machine);
    AppleNvramState *nvram = NULL;
    macho_boot_info_t info = &tms->bootinfo;
    DTBNode *memory_map = get_dtb_node(tms->device_tree, "/chosen/memory-map");
    g_autofree char *cmdline = NULL;


    #if 0
    The end of DRAM:
    0x8fa298000, 0x2300000: VRAM
    0x8fc598000, 0x3900000: ANS
    0x8ffeb0000, 0x100000: PRAM
    0x8fffb4000, 0x4000: GFX handoff
    0x8fffb8000, 0x40000: GFX shared region
    0x8ffff8000, 0x4000: GPU region
    #endif

    if (t8030_check_panic(machine)) {
        qemu_system_guest_panicked(NULL);
        return;
    }
    info->dram_base = T8030_DRAM_BASE;
    info->dram_size = T8030_DRAM_SIZE;

    nvram = APPLE_NVRAM(qdev_find_recursive(sysbus_get_default(), "nvram"));
    if (!nvram) {
        error_setg(&error_abort, "%s: Failed to find nvram device", __func__);
        return;
    };
    apple_nvram_load(nvram);

    fprintf(stderr, "boot_mode: %u\n", tms->boot_mode);
    switch (tms->boot_mode) {
    case kBootModeEnterRecovery:
        env_set(nvram, "auto-boot", "false", 0);
        tms->boot_mode = kBootModeAuto;
        break;
    case kBootModeExitRecovery:
        env_set(nvram, "auto-boot", "true", 0);
        tms->boot_mode = kBootModeAuto;
        break;
    default:
        break;
    }

    fprintf(stderr, "auto-boot=%s\n", env_get_bool(nvram, "auto-boot", false) ? "true" : "false");
    switch (tms->boot_mode) {
    case kBootModeAuto:
        if (!env_get_bool(nvram, "auto-boot", false)) {
            asprintf(&cmdline, "-restore rd=md0 nand-enable-reformat=1 -progress %s", machine->kernel_cmdline);
            break;
        }
        QEMU_FALLTHROUGH;
    default:
        asprintf(&cmdline, "%s", machine->kernel_cmdline);
    }

    apple_nvram_save(nvram);

    info->nvram_size = nvram->len;

    if (info->nvram_size > XNU_MAX_NVRAM_SIZE) {
        info->nvram_size = XNU_MAX_NVRAM_SIZE;
    }
    if (apple_nvram_serialize(nvram, info->nvram_data, sizeof(info->nvram_data)) < 0) {
        error_report("%s: Failed to read NVRAM", __func__);
    }

    if (tms->ticket_filename) {
        if (!g_file_get_contents(tms->ticket_filename, &info->ticket_data, (gsize *)&info->ticket_length, NULL)) {
            error_report("%s: Failed to read ticket from file %s", __func__, tms->ticket_filename);
        }
    }

    if (xnu_contains_boot_arg(cmdline, "-restore", false)) {
        /* HACK: Use DEV Hardware model to restore without FDR errors */
        set_dtb_prop(tms->device_tree, "compatible", 28, "N104DEV\0iPhone12,1\0AppleARM\0$");
    } else {
        set_dtb_prop(tms->device_tree, "compatible", 27, "N104AP\0iPhone12,1\0AppleARM\0$");
    }

    if (!xnu_contains_boot_arg(cmdline, "rd=", true)) {
        DTBNode *chosen = find_dtb_node(tms->device_tree, "chosen");
        DTBProp *prop = find_dtb_prop(chosen, "root-matching");

        if (prop) {
            snprintf((char *)prop->value, prop->length, "<dict><key>IOProviderClass</key><string>IOMedia</string><key>IOPropertyMatch</key><dict><key>Partition ID</key><integer>1</integer></dict></dict>");
        }
    }

    DTBNode *pram = find_dtb_node(tms->device_tree, "pram");
    if (pram) {
        uint64_t panic_reg[2] = { 0 };
        uint64_t panic_base = T8030_PANIC_BASE;
        uint64_t panic_size = T8030_PANIC_SIZE;

        panic_reg[0] = panic_base;
        panic_reg[1] = panic_size;

        set_dtb_prop(pram, "reg", 16, &panic_reg);
        DTBNode *chosen = find_dtb_node(tms->device_tree, "chosen");
        set_dtb_prop(chosen, "embedded-panic-log-size", 8,
                     &panic_size);
        tms->panic_base = panic_base;
        tms->panic_size = panic_size;
    }

    DTBNode *vram = find_dtb_node(tms->device_tree, "vram");
    if (vram) {
        uint64_t vram_reg[2] = { 0 };
        uint64_t vram_base = T8030_DISPLAY_BASE;
        uint64_t vram_size = T8030_DISPLAY_SIZE;
        vram_reg[0] = vram_base;
        vram_reg[1] = vram_size;
        set_dtb_prop(vram, "reg", 16, &vram_reg);
    }

    hdr = tms->kernel;
    assert(hdr);

    macho_allocate_segment_records(memory_map, hdr);

    macho_populate_dtb(tms->device_tree, info);

    switch (hdr->filetype) {
    case MH_EXECUTE:
        t8030_load_classic_kc(tms, cmdline);
        break;
    case MH_FILESET:
        t8030_load_fileset_kc(tms, cmdline);
        break;
    default:
        error_setg(&error_abort, "%s: Unsupported kernelcache type: 0x%x\n",
                   __func__, hdr->filetype);                
        break;
    }
}

static void pmgr_unk_reg_write(void *opaque, hwaddr addr, uint64_t data, unsigned size)
{
    // hwaddr base = (hwaddr) opaque;
    // fprintf(stderr, "PMGR reg WRITE unk @ 0x" TARGET_FMT_lx " base: 0x" TARGET_FMT_lx " value: 0x" TARGET_FMT_lx "\n", base + addr, base, data);
}

static uint64_t pmgr_unk_reg_read(void *opaque, hwaddr addr, unsigned size)
{
    hwaddr base = (hwaddr) opaque;

    // fprintf(stderr, "PMGR reg READ unk @ 0x" TARGET_FMT_lx " base: 0x" TARGET_FMT_lx "\n", base + addr, base);
    if (((uint64_t)(base + addr) & 0x10e70000) == 0x10e70000) {
        return (108<<4) | 0x200000;
    }

    return 0;
}

static const MemoryRegionOps pmgr_unk_reg_ops = {
    .write = pmgr_unk_reg_write,
    .read = pmgr_unk_reg_read,
};

static void pmgr_reg_write(void *opaque, hwaddr addr, uint64_t data, unsigned size)
{
    MachineState *machine = MACHINE(opaque);
    T8030MachineState *tms = T8030_MACHINE(opaque);
    uint32_t value = data;

    if (addr >= 0x80000 && addr <= 0x8c000) {
        value = (value & 0xf) << 4 | (value & 0xf);
    }
    // fprintf(stderr, "PMGR reg WRITE @ 0x" TARGET_FMT_lx " value: 0x" TARGET_FMT_lx "\n", addr, data);
    switch (addr) {
    case 0xd4004:
        t8030_start_cpus(machine, data);
        return;
    }
    memcpy(tms->pmgr_reg + addr, &value, size);
}

static uint64_t pmgr_reg_read(void *opaque, hwaddr addr, unsigned size)
{
    T8030MachineState *tms = T8030_MACHINE(opaque);
    // fprintf(stderr, "PMGR reg READ @ 0x" TARGET_FMT_lx "\n", addr);
    uint64_t result = 0;
    switch(addr) {
    case 0xf0010: /* AppleT8030PMGR::commonSramCheck */
        return 0x5000;
    default:
        break;
    }
    memcpy(&result, tms->pmgr_reg + addr, size);
    return result;
}

static const MemoryRegionOps pmgr_reg_ops = {
    .write = pmgr_reg_write,
    .read = pmgr_reg_read,
};

static void amcc_reg_write(void *opaque, hwaddr addr,
                           uint64_t data, unsigned size)
{
    T8030MachineState *tms = T8030_MACHINE(opaque);
    uint32_t value = data;

    memcpy(tms->amcc_reg + addr, &value, size);
}

static uint64_t amcc_reg_read(void *opaque, hwaddr addr, unsigned size)
{
    T8030MachineState *tms = T8030_MACHINE(opaque);
    uint64_t result = 0;
    memcpy(&result, tms->amcc_reg + addr, size);
    return result;
}

static const MemoryRegionOps amcc_reg_ops = {
    .write = amcc_reg_write,
    .read = amcc_reg_read,
};

static void t8030_cluster_setup(MachineState *machine)
{
    T8030MachineState *tms = T8030_MACHINE(machine);

    for (int i = 0; i < A13_MAX_CLUSTER; i++) {
        g_autofree char *name = NULL;

        name = g_strdup_printf("cluster%d", i);
        object_initialize_child(OBJECT(machine), name, &tms->clusters[i],
                                TYPE_APPLE_A13_CLUSTER);
        qdev_prop_set_uint32(DEVICE(&tms->clusters[i]), "cluster-id", i);
    }
}

static void t8030_cluster_realize(MachineState *machine)
{
    T8030MachineState *tms = T8030_MACHINE(machine);
    for (int i = 0; i < A13_MAX_CLUSTER; i++) {
        qdev_realize(DEVICE(&tms->clusters[i]), NULL, &error_fatal);
        if (tms->clusters[i].base) {
            memory_region_add_subregion(tms->sysmem, tms->clusters[i].base,
                                        &tms->clusters[i].mr);
        }
    }
}

static void t8030_cpu_setup(MachineState *machine)
{
    unsigned int i;
    DTBNode *root;
    T8030MachineState *tms = T8030_MACHINE(machine);
    GList *iter;
    GList *next = NULL;

    t8030_cluster_setup(machine);

    root = find_dtb_node(tms->device_tree, "cpus");
    assert(root);

    for (iter = root->child_nodes, i = 0; iter != NULL; iter = next,i++) {
        uint32_t cluster_id;
        DTBNode *node;

        next = iter->next;
        node = (DTBNode *)iter->data;
        if (i >= machine->smp.cpus) {
            remove_dtb_node(root, node);
            continue;
        }

        tms->cpus[i] = apple_a13_cpu_create(node);
        cluster_id = tms->cpus[i]->cluster_id;

        object_property_add_child(OBJECT(&tms->clusters[cluster_id]),
                                  DEVICE(tms->cpus[i])->id,
                                  OBJECT(tms->cpus[i]));
        qdev_realize(DEVICE(tms->cpus[i]), NULL, &error_fatal);
    }
    t8030_cluster_realize(machine);
}

static void t8030_create_aic(MachineState *machine)
{
    unsigned int i;
    hwaddr *reg;
    DTBProp *prop;
    T8030MachineState *tms = T8030_MACHINE(machine);
    DTBNode *soc = find_dtb_node(tms->device_tree, "arm-io");
    DTBNode *child;
    DTBNode *timebase;

    assert(soc != NULL);
    child = find_dtb_node(soc, "aic");
    assert(child != NULL);
    timebase = find_dtb_node(soc, "aic-timebase");
    assert(timebase);

    tms->aic = apple_aic_create(machine->smp.cpus, child, timebase);
    object_property_add_child(OBJECT(machine), "aic", OBJECT(tms->aic));
    assert(tms->aic);
    sysbus_realize(tms->aic, &error_fatal);

    prop = find_dtb_prop(child, "reg");
    assert(prop != NULL);

    reg = (hwaddr*)prop->value;

    for(i = 0; i < machine->smp.cpus; i++) {
        memory_region_add_subregion_overlap(&tms->cpus[i]->memory,
                                            tms->soc_base_pa + reg[0],
                                            sysbus_mmio_get_region(tms->aic, i),
                                                                   0);
        sysbus_connect_irq(tms->aic, i,
                           qdev_get_gpio_in(DEVICE(tms->cpus[i]),
                                            ARM_CPU_IRQ));
    }

}

static void t8030_pmgr_setup(MachineState* machine)
{
    uint64_t *reg;
    int i;
    char name[32];
    DTBProp *prop;
    T8030MachineState *tms = T8030_MACHINE(machine);
    DTBNode *child = find_dtb_node(tms->device_tree, "arm-io");

    assert(child != NULL);
    child = find_dtb_node(child, "pmgr");
    assert(child != NULL);

    prop = find_dtb_prop(child, "reg");
    assert(prop);

    reg = (uint64_t*)prop->value;

    for(i = 0; i < prop->length / 8; i+=2) {
        MemoryRegion* mem = g_new(MemoryRegion, 1);
        if (i > 0) {
            snprintf(name, 32, "pmgr-unk-reg-%d", i);
            memory_region_init_io(mem, OBJECT(machine), &pmgr_unk_reg_ops, (void*)reg[i], name, reg[i+1]);
        } else {
            memory_region_init_io(mem, OBJECT(machine), &pmgr_reg_ops, tms, "pmgr-reg", reg[i+1]);
        }
        memory_region_add_subregion(tms->sysmem, reg[i] + reg[i+1] < tms->soc_size ? tms->soc_base_pa + reg[i] : reg[i], mem);
    }

    {
        MemoryRegion *mem = g_new(MemoryRegion, 1);

        snprintf(name, 32, "pmp-reg");
        memory_region_init_io(mem, OBJECT(machine), &pmgr_unk_reg_ops, (void*)0x3BC00000, name, 0x60000);
        memory_region_add_subregion(tms->sysmem, tms->soc_base_pa + 0x3BC00000, mem);
    }
    set_dtb_prop(child, "voltage-states5", sizeof(voltage_states5), voltage_states5);
    set_dtb_prop(child, "voltage-states9-sram", sizeof(voltage_states9_sram), voltage_states9_sram);
    set_dtb_prop(child, "voltage-states0", sizeof(voltage_states0), voltage_states0);
    set_dtb_prop(child, "voltage-states9", sizeof(voltage_states9), voltage_states9);
    set_dtb_prop(child, "voltage-states2", sizeof(voltage_states2), voltage_states2);
    set_dtb_prop(child, "voltage-states1-sram", sizeof(voltage_states1_sram), voltage_states1_sram);
    set_dtb_prop(child, "voltage-states10", sizeof(voltage_states10), voltage_states10);
    set_dtb_prop(child, "voltage-states11", sizeof(voltage_states11), voltage_states11);
    set_dtb_prop(child, "voltage-states8", sizeof(voltage_states8), voltage_states8);
    set_dtb_prop(child, "voltage-states5-sram", sizeof(voltage_states5_sram), voltage_states5_sram);
    set_dtb_prop(child, "voltage-states1", sizeof(voltage_states1), voltage_states1);
    set_dtb_prop(child, "bridge-settings-17", sizeof(bridge_settings17), bridge_settings17);
    set_dtb_prop(child, "bridge-settings-15", sizeof(bridge_settings15), bridge_settings15);
    set_dtb_prop(child, "bridge-settings-13", sizeof(bridge_settings13), bridge_settings13);
    set_dtb_prop(child, "bridge-settings-1", sizeof(bridge_settings1), bridge_settings1);
    set_dtb_prop(child, "bridge-settings-5", sizeof(bridge_settings5), bridge_settings5);
    set_dtb_prop(child, "bridge-settings-6", sizeof(bridge_settings6), bridge_settings6);
    set_dtb_prop(child, "bridge-settings-2", sizeof(bridge_settings2), bridge_settings2);
    set_dtb_prop(child, "bridge-settings-16", sizeof(bridge_settings16), bridge_settings16);
    set_dtb_prop(child, "bridge-settings-14", sizeof(bridge_settings14), bridge_settings14);
    set_dtb_prop(child, "bridge-settings-7", sizeof(bridge_settings7), bridge_settings7);
    set_dtb_prop(child, "bridge-settings-12", sizeof(bridge_settings12), bridge_settings12);
    set_dtb_prop(child, "bridge-settings-3", sizeof(bridge_settings3), bridge_settings3);
    set_dtb_prop(child, "bridge-settings-8", sizeof(bridge_settings8), bridge_settings8);
    set_dtb_prop(child, "bridge-settings-4", sizeof(bridge_settings4), bridge_settings4);
    set_dtb_prop(child, "bridge-settings-0", sizeof(bridge_settings0), bridge_settings0);
}

static void t8030_amcc_setup(MachineState *machine)
{
    T8030MachineState *tms = T8030_MACHINE(machine);
    DTBNode *child;
    uint32_t data;
    uint64_t data64;

    child = get_dtb_node(tms->device_tree, "chosen");
    assert(child);
    child = get_dtb_node(child, "lock-regs");
    assert(child);
    child = get_dtb_node(child, "amcc");
    assert(child);
    data = 1;
    set_dtb_prop(child, "aperture-count", 4, &data);
    data = 0x100000;
    set_dtb_prop(child, "aperture-size", 4, &data);
    data = AMCC_PLANE_COUNT;
    set_dtb_prop(child, "plane-count", 4, &data);
    data = AMCC_PLANE_STRIDE;
    set_dtb_prop(child, "plane-stride", 4, &data);
    data64 = T8030_AMCC_BASE;
    set_dtb_prop(child, "aperture-phys-addr", 8, &data64);
    data = 0x1c00;
    set_dtb_prop(child, "cache-status-reg-offset", 4, &data);
    data = 0x1f;
    set_dtb_prop(child, "cache-status-reg-mask", 4, &data);
    data = 0;
    set_dtb_prop(child, "cache-status-reg-value", 4, &data);
    child = get_dtb_node(child, "amcc-ctrr-a");

    data = 14;
    set_dtb_prop(child, "page-size-shift", 4, &data);

    data = AMCC_LOWER(0);
    set_dtb_prop(child, "lower-limit-reg-offset", 4, &data);
    data = 0xffffffff;
    set_dtb_prop(child, "lower-limit-reg-mask", 4, &data);
    data = AMCC_UPPER(0);
    set_dtb_prop(child, "upper-limit-reg-offset", 4, &data);
    data = 0xffffffff;
    set_dtb_prop(child, "upper-limit-reg-mask", 4, &data);
    data = 0x68c;
    set_dtb_prop(child, "lock-reg-offset", 4, &data);
    data = 1;
    set_dtb_prop(child, "lock-reg-mask", 4, &data);
    data = 1;
    set_dtb_prop(child, "lock-reg-value", 4, &data);

    memory_region_init_io(&tms->amcc, OBJECT(machine),
                          &amcc_reg_ops, tms, "amcc", T8030_AMCC_SIZE);
    memory_region_add_subregion(tms->sysmem, T8030_AMCC_BASE, &tms->amcc);
}

static void t8030_create_dart(MachineState *machine, const char *name)
{
    AppleDARTState *dart = NULL;
    DTBProp *prop;
    uint64_t *reg;
    uint32_t* ints;
    int i;
    T8030MachineState *tms = T8030_MACHINE(machine);
    DTBNode *child = find_dtb_node(tms->device_tree, "arm-io");

    assert(child);
    child = find_dtb_node(child, name);
    if (!child) return;

    dart = apple_dart_create(child);
    assert(dart);
    object_property_add_child(OBJECT(machine), name, OBJECT(dart));

    prop = find_dtb_prop(child, "reg");
    assert(prop);

    reg = (uint64_t *)prop->value;

    for (int i = 0; i < prop->length / 16; i++) {
        sysbus_mmio_map(SYS_BUS_DEVICE(dart), i, tms->soc_base_pa + reg[i*2]);
    }

    prop = find_dtb_prop(child, "interrupts");
    assert(prop);
    ints = (uint32_t*)prop->value;

    for(i = 0; i < prop->length / sizeof(uint32_t); i++) {
        sysbus_connect_irq(SYS_BUS_DEVICE(dart), i,
                           qdev_get_gpio_in(DEVICE(tms->aic), ints[i]));
    }

    sysbus_realize_and_unref(SYS_BUS_DEVICE(dart), &error_fatal);
}

static void t8030_create_sart(MachineState* machine)
{
    uint64_t *reg;
    T8030MachineState *tms = T8030_MACHINE(machine);
    DTBNode *child = find_dtb_node(tms->device_tree, "arm-io");
    DTBProp *prop;
    SysBusDevice *sart;

    assert(child != NULL);
    child = find_dtb_node(child, "sart-ans");
    assert(child != NULL);

    sart = apple_sart_create(child);
    assert(sart);
    object_property_add_child(OBJECT(machine), "sart-ans", OBJECT(sart));

    prop = find_dtb_prop(child, "reg");
    assert(prop);
    reg = (uint64_t*)prop->value;

    sysbus_mmio_map(sart, 0, tms->soc_base_pa + reg[0]);
    sysbus_realize_and_unref(sart, &error_fatal);
}

static void t8030_create_ans(MachineState* machine)
{
    int i;
    uint32_t *ints;
    DTBProp *prop;
    uint64_t *reg;
    T8030MachineState *tms = T8030_MACHINE(machine);
    SysBusDevice *sart;
    SysBusDevice *ans;
    DTBNode *child = find_dtb_node(tms->device_tree, "arm-io");
    DTBNode *iop_nub;
    struct xnu_iop_segment_range segranges[2] = { 0 };

    assert(child != NULL);
    child = find_dtb_node(child, "ans");
    assert(child != NULL);
    iop_nub = find_dtb_node(child, "iop-ans-nub");
    assert(iop_nub != NULL);

    prop = find_dtb_prop(iop_nub, "region-base");
    *(uint64_t *)prop->value = T8030_ANS_DATA_BASE;

    prop = find_dtb_prop(iop_nub, "region-size");
    *(uint64_t *)prop->value = T8030_ANS_DATA_SIZE;

    set_dtb_prop(iop_nub, "segment-names", 14, "__TEXT;__DATA");

    segranges[0].phys = T8030_ANS_TEXT_BASE;
    segranges[0].virt = 0x0;
    segranges[0].remap = T8030_ANS_TEXT_BASE;
    segranges[0].size = T8030_ANS_TEXT_SIZE;
    segranges[0].flag = 0x1;

    segranges[1].phys = T8030_ANS_DATA_BASE;
    segranges[1].virt = T8030_ANS_TEXT_SIZE;
    segranges[1].remap = T8030_ANS_DATA_BASE;
    segranges[1].size = T8030_ANS_DATA_SIZE;
    segranges[1].flag = 0x0;

    set_dtb_prop(iop_nub, "segment-ranges", 64, segranges);

    t8030_create_sart(machine);
    sart = SYS_BUS_DEVICE(object_property_get_link(OBJECT(machine),
                          "sart-ans", &error_fatal));

    ans = apple_ans_create(child, tms->rtbuddyv2_protocol_version);
    assert(ans);
    assert(object_property_add_const_link(OBJECT(ans),
          "dma-mr", OBJECT(sysbus_mmio_get_region(sart, 1))));

    object_property_add_child(OBJECT(machine), "ans", OBJECT(ans));
    prop = find_dtb_prop(child, "reg");
    assert(prop);
    reg = (uint64_t*)prop->value;

    /*
    0: AppleA7IOP akfRegMap
    1: AppleASCWrapV2 coreRegisterMap
    2: AppleA7IOP autoBootRegMap
    3: NVMe BAR
    */

    for (i = 0; i < 4; i++) {
        sysbus_mmio_map(ans, i, tms->soc_base_pa + reg[i << 1]);
    }

    prop = find_dtb_prop(child, "interrupts");
    assert(prop);
    assert(prop->length == 20);
    ints = (uint32_t*)prop->value;

    for(i = 0; i < prop->length / sizeof(uint32_t); i++) {
        sysbus_connect_irq(ans, i, qdev_get_gpio_in(DEVICE(tms->aic), ints[i]));
    }

    sysbus_realize_and_unref(ans, &error_fatal);
}

static void t8030_create_gpio(MachineState *machine, const char *name)
{
    DeviceState *gpio = NULL;
    DTBProp *prop;
    uint64_t *reg;
    uint32_t *ints;
    int i;
    T8030MachineState *tms = T8030_MACHINE(machine);
    DTBNode *child = find_dtb_node(tms->device_tree, "arm-io");

    child = find_dtb_node(child, name);
    assert(child);
    gpio = apple_gpio_create(child);
    assert(gpio);
    object_property_add_child(OBJECT(machine), name, OBJECT(gpio));

    prop = find_dtb_prop(child, "reg");
    assert(prop);
    reg = (uint64_t*)prop->value;
    sysbus_mmio_map(SYS_BUS_DEVICE(gpio), 0, tms->soc_base_pa + reg[0]);
    prop = find_dtb_prop(child, "interrupts");
    assert(prop);

    ints = (uint32_t*)prop->value;

    for(i = 0; i < prop->length / sizeof(uint32_t); i++) {
        sysbus_connect_irq(SYS_BUS_DEVICE(gpio), i, qdev_get_gpio_in(DEVICE(tms->aic), ints[i]));
    }

    sysbus_realize_and_unref(SYS_BUS_DEVICE(gpio), &error_fatal);
}

static void t8030_create_i2c(MachineState *machine, const char *name)
{
    SysBusDevice *i2c = NULL;
    DTBProp *prop;
    uint64_t *reg;
    uint32_t *ints;
    int i;
    T8030MachineState *tms = T8030_MACHINE(machine);
    DTBNode *child = find_dtb_node(tms->device_tree, "arm-io");

    child = find_dtb_node(child, name);
    if (!child) return;
    i2c = apple_i2c_create(name);
    assert(i2c);
    object_property_add_child(OBJECT(machine), name, OBJECT(i2c));

    prop = find_dtb_prop(child, "reg");
    assert(prop);
    reg = (uint64_t *)prop->value;
    sysbus_mmio_map(i2c, 0, tms->soc_base_pa + reg[0]);
    prop = find_dtb_prop(child, "interrupts");
    assert(prop);

    ints = (uint32_t*)prop->value;

    for(i = 0; i < prop->length / sizeof(uint32_t); i++) {
        sysbus_connect_irq(i2c, i, qdev_get_gpio_in(DEVICE(tms->aic), ints[i]));
    }

    sysbus_realize_and_unref(i2c, &error_fatal);
}

static void t8030_create_spi(MachineState *machine, uint32_t port)
{
    SysBusDevice *spi = NULL;
    DeviceState *gpio = NULL;
    DTBProp *prop;
    uint64_t *reg;
    uint32_t *ints;
    T8030MachineState *tms = T8030_MACHINE(machine);
    DTBNode *child = find_dtb_node(tms->device_tree, "arm-io");
    Object *sio;
    char name[32] = { 0 };
    hwaddr base = tms->soc_base_pa + T8030_SPI_BASE(port);
    uint32_t irq = spi_irqs[port];
    uint32_t cs_pin = spi_cs_pins[port];

    assert(port < T8030_NUM_SPIS);
    snprintf(name, sizeof(name), "spi%d", port);
    child = find_dtb_node(child, name);

    if (child) {
        spi = apple_spi_create(child);
    } else {
        spi = SYS_BUS_DEVICE(qdev_new(TYPE_APPLE_SPI));
        DEVICE(spi)->id = g_strdup(name);
    }
    assert(spi);
    object_property_add_child(OBJECT(machine), name, OBJECT(spi));

    sio = object_property_get_link(OBJECT(machine), "sio", &error_fatal);
    assert(object_property_add_const_link(OBJECT(spi), "sio", sio));
    sysbus_realize_and_unref(SYS_BUS_DEVICE(spi), &error_fatal);

    if (child) {
        prop = find_dtb_prop(child, "reg");
        assert(prop);
        reg = (uint64_t*)prop->value;
        base = tms->soc_base_pa + reg[0];

        prop = find_dtb_prop(child, "interrupts");
        assert(prop);
        ints = (uint32_t *)prop->value;
        irq = ints[0];
    }
    sysbus_mmio_map(spi, 0, base);

    /* The second sysbus IRQ is the cs line */
    sysbus_connect_irq(SYS_BUS_DEVICE(spi), 0,
                       qdev_get_gpio_in(DEVICE(tms->aic), irq));

    if (child) {
        prop = find_dtb_prop(child, "function-spi_cs0");
        if (prop) {
            ints = (uint32_t *)prop->value;
            cs_pin = ints[2];
        }
    }
    if (cs_pin != -1) {
        gpio = DEVICE(object_property_get_link(OBJECT(machine), "gpio", &error_fatal));
        assert(gpio);
        qdev_connect_gpio_out(gpio, cs_pin,
                              qdev_get_gpio_in_named(DEVICE(spi),
                                                     SSI_GPIO_CS, 0));
    }
}

static void t8030_create_usb(MachineState *machine)
{
    T8030MachineState *tms = T8030_MACHINE(machine);
    DTBNode *child = find_dtb_node(tms->device_tree, "arm-io");
    DTBNode *drd = find_dtb_node(child, "usb-drd");
    DTBNode *dart_usb = find_dtb_node(child, "dart-usb");
    DTBNode *dart_mapper = find_dtb_node(dart_usb, "mapper-usb-drd");
    DTBNode *dart_dwc2_mapper = find_dtb_node(dart_usb, "mapper-usb-device");
    DTBNode *phy = find_dtb_node(child, "atc-phy");
    DTBProp *prop;
    DeviceState *atc;
    AppleDARTState *dart;
    IOMMUMemoryRegion *iommu = NULL;
    uint32_t *ints;
    uint32_t value;

    set_dtb_prop(drd, "device-mac-address", 6, "\xbc\xde\x48\x33\x44\x55");
    set_dtb_prop(drd, "host-mac-address", 6, "\xbc\xde\x48\x00\x11\x22");

    dart = APPLE_DART(object_property_get_link(OBJECT(machine),
                      "dart-usb", &error_fatal));

    atc = qdev_new(TYPE_APPLE_TYPEC);
    object_property_add_child(OBJECT(machine), "atc", OBJECT(atc));

    prop = find_dtb_prop(dart_mapper, "reg");
    assert(prop);
    assert(prop->length == 4);
    iommu = apple_dart_instance_iommu_mr(dart, 1, *(uint32_t *)prop->value);
    assert(iommu);

    assert(object_property_add_const_link(OBJECT(atc), "dma-xhci",
                                          OBJECT(iommu)));
    assert(object_property_add_const_link(OBJECT(atc), "dma-drd",
                                          OBJECT(iommu)));

    prop = find_dtb_prop(dart_dwc2_mapper, "reg");
    assert(prop);
    assert(prop->length == 4);
    iommu = apple_dart_instance_iommu_mr(dart, 1, *(uint32_t *)prop->value);
    assert(iommu);

    assert(object_property_add_const_link(OBJECT(atc), "dma-otg",
                                          OBJECT(iommu)));

    prop = find_dtb_prop(phy, "reg");
    assert(prop);
    sysbus_mmio_map(SYS_BUS_DEVICE(atc), 0,
                    tms->soc_base_pa + ((uint64_t*)prop->value)[0]);

    sysbus_realize_and_unref(SYS_BUS_DEVICE(atc), &error_fatal);

    prop = find_dtb_prop(drd, "interrupts");
    assert(prop);
    ints = (uint32_t *)prop->value;
    for(int i = 0; i < 4; i++) {
        sysbus_connect_irq(SYS_BUS_DEVICE(atc), i,
                           qdev_get_gpio_in(DEVICE(tms->aic), ints[i]));
    }
    sysbus_connect_irq(SYS_BUS_DEVICE(atc), 4,
                       qdev_get_gpio_in(DEVICE(tms->aic), T8030_DWC2_IRQ));
}

static void t8030_create_wdt(MachineState *machine)
{
    int i;
    uint32_t *ints;
    DTBProp *prop;
    uint64_t *reg;
    uint32_t value;
    T8030MachineState *tms = T8030_MACHINE(machine);
    SysBusDevice *wdt;
    DTBNode *child = find_dtb_node(tms->device_tree, "arm-io");

    assert(child != NULL);
    child = find_dtb_node(child, "wdt");
    assert(child != NULL);

    wdt = apple_wdt_create(child);
    assert(wdt);

    object_property_add_child(OBJECT(machine), "wdt", OBJECT(wdt));
    prop = find_dtb_prop(child, "reg");
    assert(prop);
    reg = (uint64_t*)prop->value;

    /*
    0: reg
    1: scratch reg
    */
    sysbus_mmio_map(wdt, 0, tms->soc_base_pa + reg[0]);
    sysbus_mmio_map(wdt, 1, tms->soc_base_pa + reg[2]);

    prop = find_dtb_prop(child, "interrupts");
    assert(prop);
    ints = (uint32_t*)prop->value;

    for(i = 0; i < prop->length / sizeof(uint32_t); i++) {
        sysbus_connect_irq(wdt, i, qdev_get_gpio_in(DEVICE(tms->aic), ints[i]));
    }

    /* TODO: MCC */
    prop = find_dtb_prop(child, "function-panic_flush_helper");
    if (prop) {
        remove_dtb_prop(child, prop);
    }

    prop = find_dtb_prop(child, "function-panic_halt_helper");
    if (prop) {
        remove_dtb_prop(child, prop);
    }

    value = 1;
    set_dtb_prop(child, "no-pmu", 4, (uint8_t*)&value);

    sysbus_realize_and_unref(wdt, &error_fatal);
}

static void t8030_create_aes(MachineState* machine)
{
    uint32_t *ints;
    DTBProp *prop;
    uint64_t *reg;
    T8030MachineState *tms = T8030_MACHINE(machine);
    SysBusDevice *aes;
    AppleDARTState *dart;
    DTBNode *child = find_dtb_node(tms->device_tree, "arm-io");
    IOMMUMemoryRegion *dma_mr = NULL;
    DTBNode *dart_sio = find_dtb_node(child, "dart-sio");
    DTBNode *dart_aes_mapper = find_dtb_node(dart_sio, "mapper-aes");

    assert(child != NULL);
    child = find_dtb_node(child, "aes");
    assert(child != NULL);
    assert(dart_sio);
    assert(dart_aes_mapper);

    aes = apple_aes_create(child);
    assert(aes);

    object_property_add_child(OBJECT(machine), "aes", OBJECT(aes));
    prop = find_dtb_prop(child, "reg");
    assert(prop);
    reg = (uint64_t*)prop->value;

    /*
    0: aesMemoryMap
    1: aesDisableKeyMap
    */
    sysbus_mmio_map(aes, 0, tms->soc_base_pa + reg[0]);
    sysbus_mmio_map(aes, 1, tms->soc_base_pa + reg[2]);

    prop = find_dtb_prop(child, "interrupts");
    assert(prop);
    assert(prop->length == 4);
    ints = (uint32_t*)prop->value;

    sysbus_connect_irq(aes, 0, qdev_get_gpio_in(DEVICE(tms->aic), *ints));

    dart = APPLE_DART(object_property_get_link(OBJECT(machine),
                      "dart-sio", &error_fatal));
    assert(dart);

    prop = find_dtb_prop(dart_aes_mapper, "reg");

    dma_mr = apple_dart_iommu_mr(dart, *(uint32_t *)prop->value);
    assert(dma_mr);
    assert(object_property_add_const_link(OBJECT(aes), "dma-mr", OBJECT(dma_mr)));

    sysbus_realize_and_unref(aes, &error_fatal);
}

static void t8030_create_spmi(MachineState *machine, const char *name)
{
    SysBusDevice *spmi = NULL;
    DTBProp *prop;
    uint64_t *reg;
    uint32_t* ints;
    T8030MachineState *tms = T8030_MACHINE(machine);
    DTBNode *child = find_dtb_node(tms->device_tree, "arm-io");

    assert(child);
    child = find_dtb_node(child, name);
    if (!child) return;

    spmi = apple_spmi_create(child);
    assert(spmi);
    object_property_add_child(OBJECT(machine), name, OBJECT(spmi));

    prop = find_dtb_prop(child, "reg");
    assert(prop);

    reg = (uint64_t*)prop->value;

    sysbus_mmio_map(SYS_BUS_DEVICE(spmi), 0,
                    (tms->soc_base_pa + reg[2]) & ~(APPLE_SPMI_MMIO_SIZE - 1));

    prop = find_dtb_prop(child, "interrupts");
    assert(prop);
    ints = (uint32_t*)prop->value;
    /* XXX: Only the second interrupt's parent is AIC */
    sysbus_connect_irq(SYS_BUS_DEVICE(spmi), 0,
                       qdev_get_gpio_in(DEVICE(tms->aic), ints[1]));

    sysbus_realize_and_unref(SYS_BUS_DEVICE(spmi), &error_fatal);
}

static void t8030_create_pmu(MachineState *machine, const char *parent,
                             const char *name)
{
    DeviceState *pmu = NULL;
    AppleSPMIState *spmi = NULL;
    DTBProp *prop;
    T8030MachineState *tms = T8030_MACHINE(machine);
    DTBNode *child = find_dtb_node(tms->device_tree, "arm-io");
    uint32_t *ints;

    assert(child);
    child = find_dtb_node(child, parent);
    if (!child) return;

    spmi = APPLE_SPMI(object_property_get_link(OBJECT(machine), parent,
                      &error_fatal));
    assert(spmi);

    child = find_dtb_node(child, name);
    if (!child) return;

    pmu = apple_spmi_pmu_create(child);
    assert(pmu);
    object_property_add_child(OBJECT(machine), name, OBJECT(pmu));

    prop = find_dtb_prop(child, "interrupts");
    assert(prop);
    ints = (uint32_t *)prop->value;

    qdev_connect_gpio_out(pmu, 0, qdev_get_gpio_in(DEVICE(spmi), ints[0]));
    spmi_slave_realize_and_unref(SPMI_SLAVE(pmu), spmi->bus, &error_fatal);
}

static void t8030_create_smc(MachineState* machine)
{
    int i;
    uint32_t *ints;
    DTBProp *prop;
    uint64_t *reg;
    uint64_t data;
    T8030MachineState *tms = T8030_MACHINE(machine);
    SysBusDevice *smc;
    DTBNode *child = find_dtb_node(tms->device_tree, "arm-io");
    DTBNode *iop_nub;
    struct xnu_iop_segment_range segranges[2] = { 0 };

    assert(child != NULL);
    child = find_dtb_node(child, "smc");
    assert(child != NULL);
    iop_nub = find_dtb_node(child, "iop-smc-nub");
    assert(iop_nub != NULL);

    set_dtb_prop(iop_nub, "segment-names", 14, "__TEXT;__DATA");

    segranges[0].phys = T8030_SMC_TEXT_BASE;
    segranges[0].virt = 0x0;
    segranges[0].remap = T8030_SMC_TEXT_BASE;
    segranges[0].size = T8030_SMC_TEXT_SIZE;
    segranges[0].flag = 0x1;

    segranges[1].phys = T8030_SMC_DATA_BASE;
    segranges[1].virt = T8030_SMC_TEXT_SIZE;
    segranges[1].remap = T8030_SMC_DATA_BASE;
    segranges[1].size = T8030_SMC_DATA_SIZE;
    segranges[1].flag = 0x0;

    set_dtb_prop(iop_nub, "segment-ranges", 64, segranges);

    data = T8030_SMC_REGION_SIZE;
    set_dtb_prop(iop_nub, "region-size", 8, &data);
    data = T8030_SMC_SRAM_BASE;
    set_dtb_prop(iop_nub, "sram-addr", 8, &data);

    smc = apple_smc_create(child, tms->rtbuddyv2_protocol_version);
    assert(smc);

    object_property_add_child(OBJECT(machine), "smc", OBJECT(smc));
    prop = find_dtb_prop(child, "reg");
    assert(prop);
    reg = (uint64_t*)prop->value;

    /*
    0: AppleA7IOP akfRegMap
    1: AppleASCWrapV2 coreRegisterMap
    */
    for (int i = 0; i < prop->length / 16; i++) {
        sysbus_mmio_map(smc, i, tms->soc_base_pa + reg[i * 2]);
    }
    /* 2: SRAM */
    sysbus_mmio_map(smc, 2, T8030_SMC_SRAM_BASE);

    prop = find_dtb_prop(child, "interrupts");
    assert(prop);
    ints = (uint32_t*)prop->value;

    for(i = 0; i < prop->length / sizeof(uint32_t); i++) {
        sysbus_connect_irq(smc, i, qdev_get_gpio_in(DEVICE(tms->aic), ints[i]));
    }

    sysbus_realize_and_unref(smc, &error_fatal);
}

static void t8030_create_sio(MachineState* machine)
{
    int i;
    uint32_t *ints;
    DTBProp *prop;
    uint64_t *reg;
    uint64_t data;
    T8030MachineState *tms = T8030_MACHINE(machine);
    SysBusDevice *sio;
    AppleDARTState *dart;
    DTBNode *child = find_dtb_node(tms->device_tree, "arm-io");
    DTBNode *iop_nub;
    struct xnu_iop_segment_range segranges[2] = { 0 };
    IOMMUMemoryRegion *dma_mr = NULL;
    DTBNode *dart_sio = find_dtb_node(child, "dart-sio");
    DTBNode *dart_sio_mapper = find_dtb_node(dart_sio, "mapper-sio");
    Object *obj;

    assert(child != NULL);
    child = find_dtb_node(child, "sio");
    assert(child != NULL);
    iop_nub = find_dtb_node(child, "iop-sio-nub");
    assert(iop_nub != NULL);

    set_dtb_prop(child, "segment-names", 14, "__TEXT;__DATA");
    set_dtb_prop(iop_nub, "segment-names", 14, "__TEXT;__DATA");

    segranges[0].phys = T8030_SIO_TEXT_BASE;
    segranges[0].virt = 0x0;
    segranges[0].remap = T8030_SIO_TEXT_REMAP;
    segranges[0].size = T8030_SIO_TEXT_SIZE;
    segranges[0].flag = 0x1;

    segranges[1].phys = T8030_SIO_DATA_BASE;
    segranges[1].virt = T8030_SIO_TEXT_SIZE;
    segranges[1].remap = T8030_SIO_DATA_REMAP;
    segranges[1].size = T8030_SIO_DATA_SIZE;
    segranges[1].flag = 0x0;

    set_dtb_prop(child, "segment-ranges", sizeof(segranges), segranges);
    set_dtb_prop(iop_nub, "segment-ranges", sizeof(segranges), segranges);

    sio = apple_sio_create(child, tms->rtbuddyv2_protocol_version);
    assert(sio);

    object_property_add_child(OBJECT(machine), "sio", OBJECT(sio));
    prop = find_dtb_prop(child, "reg");
    assert(prop);
    reg = (uint64_t*)prop->value;

    /*
    0: AppleA7IOP akfRegMap
    1: AppleASCWrapV2 coreRegisterMap
    */
    for (int i = 0; i < 2; i++) {
        sysbus_mmio_map(sio, i, tms->soc_base_pa + reg[i * 2]);
    }

    prop = find_dtb_prop(child, "interrupts");
    assert(prop);
    ints = (uint32_t*)prop->value;

    for(i = 0; i < prop->length / sizeof(uint32_t); i++) {
        sysbus_connect_irq(sio, i, qdev_get_gpio_in(DEVICE(tms->aic), ints[i]));
    }

    dart = APPLE_DART(object_property_get_link(OBJECT(machine),
                      "dart-sio", &error_fatal));
    assert(dart);

    prop = find_dtb_prop(dart_sio_mapper, "reg");

    dma_mr = apple_dart_iommu_mr(dart, *(uint32_t *)prop->value);
    assert(dma_mr);
    assert(object_property_add_const_link(OBJECT(sio), "dma-mr", OBJECT(dma_mr)));

    sysbus_realize_and_unref(sio, &error_fatal);
}

static void t8030_create_boot_display(MachineState *machine)
{
    T8030MachineState *tms = T8030_MACHINE(machine);
    SysBusDevice *fb = NULL;
    MemoryRegion *vram = NULL;
    tms->video.v_baseAddr = T8030_DISPLAY_BASE;
    tms->video.v_rowBytes = 480 * 4;
    tms->video.v_width = 480;
    tms->video.v_height = 640;
    tms->video.v_depth = 32 | ((2 - 1) << 16);
    tms->video.v_display = 1;

    if (xnu_contains_boot_arg(machine->kernel_cmdline, "-s", false)
        || xnu_contains_boot_arg(machine->kernel_cmdline, "-v", false)) {
        tms->video.v_display = 0;
    }

    fb = SYS_BUS_DEVICE(qdev_new(TYPE_M1_FB));
    object_property_set_uint(OBJECT(fb), "width", 480, &error_fatal);
    object_property_set_uint(OBJECT(fb), "height", 640, &error_fatal);

    vram = g_new(MemoryRegion, 1);
    memory_region_init_ram(vram, OBJECT(fb), "vram", T8030_DISPLAY_SIZE, &error_fatal);
    memory_region_add_subregion_overlap(tms->sysmem, tms->video.v_baseAddr, vram, 1);

    object_property_add_const_link(OBJECT(fb), "vram", OBJECT(vram));
    object_property_add_child(OBJECT(machine), "fb", OBJECT(fb));

    sysbus_realize_and_unref(fb, &error_fatal);
}

static void t8030_cpu_reset_work(CPUState *cpu, run_on_cpu_data data)
{
    T8030MachineState *tms = data.host_ptr;
    CPUARMState *env;
    AppleA13State *tcpu = (AppleA13State *)object_dynamic_cast(OBJECT(cpu),
                                                           TYPE_APPLE_A13);
    if (!tcpu) {
        return;
    }
    cpu_reset(cpu);
    env = &ARM_CPU(cpu)->env;
    env->xregs[0] = tms->bootinfo.bootargs_pa;
    cpu_set_pc(cpu, tms->bootinfo.entry);
}

static void t8030_cpu_reset(void *opaque)
{
    MachineState *machine = MACHINE(opaque);
    T8030MachineState *tms = T8030_MACHINE(machine);
    CPUState *cpu;
    uint64_t m_lo = 0;
    uint64_t m_hi = 0;
    qemu_guest_getrandom(&m_lo, sizeof(m_lo), NULL);
    qemu_guest_getrandom(&m_hi, sizeof(m_hi), NULL);


    CPU_FOREACH(cpu) {
        AppleA13State *tcpu = (AppleA13State *)object_dynamic_cast(OBJECT(cpu),
                                                               TYPE_APPLE_A13);
        if (tcpu) {
            object_property_set_uint(OBJECT(cpu), "rvbar",
                                    tms->bootinfo.entry & ~0xfff,
                                    &error_abort);
            object_property_set_uint(OBJECT(cpu), "pauth-mlo",
                                    m_lo,
                                    &error_abort);
            object_property_set_uint(OBJECT(cpu), "pauth-mhi",
                                    m_hi,
                                    &error_abort);
            if (tcpu->cpu_id == 0) {
                run_on_cpu(cpu, t8030_cpu_reset_work, RUN_ON_CPU_HOST_PTR(tms));
            } else {
                run_on_cpu(cpu, (run_on_cpu_func)cpu_reset, RUN_ON_CPU_NULL);
            }
        }
    }
}

static void t8030_machine_reset(MachineState* machine)
{
    T8030MachineState *tms = T8030_MACHINE(machine);

    qemu_devices_reset();
    memset(&tms->pmgr_reg, 0, sizeof(tms->pmgr_reg));
    if (!runstate_check(RUN_STATE_RESTORE_VM)
        && !runstate_check(RUN_STATE_PRELAUNCH)) {
        if (!runstate_check(RUN_STATE_PAUSED)
            || qemu_reset_requested_get() != SHUTDOWN_CAUSE_NONE) {
            t8030_memory_setup(MACHINE(tms));
        }
    }
    t8030_cpu_reset(tms);
}

static void t8030_machine_init_done(Notifier *notifier, void *data)
{
    T8030MachineState *tms = container_of(notifier, T8030MachineState,
                                          init_done_notifier);
    t8030_memory_setup(MACHINE(tms));
    t8030_cpu_reset(tms);
}

static void t8030_machine_init(MachineState *machine)
{
    T8030MachineState *tms = T8030_MACHINE(machine);
    struct mach_header_64 *hdr;
    uint64_t kernel_low = 0, kernel_high = 0;
    uint32_t build_version;
    uint32_t data;
    uint8_t buffer[0x40] = { 0 };
    uint32_t display_rotation = 0;
    uint32_t display_scale = 2;
    DTBNode *child;
    DTBProp *prop;
    hwaddr *ranges;

    tms->sysmem = get_system_memory();
    allocate_ram(tms->sysmem, "DRAM", T8030_DRAM_BASE, T8030_DRAM_SIZE, 0);

    hdr = macho_load_file(machine->kernel_filename);
    assert(hdr);
    tms->kernel = hdr;
    xnu_header = hdr;
    build_version = macho_build_version(hdr);
    fprintf(stderr, "Loading %s %u.%u...\n", macho_platform_string(hdr),
                                             BUILD_VERSION_MAJOR(build_version),
                                             BUILD_VERSION_MINOR(build_version));
    tms->build_version = build_version;

    if (tms->rtbuddyv2_protocol_version == 0) {
        switch (BUILD_VERSION_MAJOR(build_version)) {
            case 13:
                tms->rtbuddyv2_protocol_version = 10;
                break;
            case 14:
                tms->rtbuddyv2_protocol_version = 11;
                break;
            case 15:
            case 16:
                tms->rtbuddyv2_protocol_version = 12;
                break;
            default:
                break;
        }
    }

    macho_highest_lowest(hdr, &kernel_low, &kernel_high);
    fprintf(stderr, "kernel_low: 0x" TARGET_FMT_lx "\n"
                    "kernel_high: 0x" TARGET_FMT_lx "\n",
                    kernel_low, kernel_high);

    g_virt_base = kernel_low;
    g_phys_base = (hwaddr)macho_get_buffer(hdr);

    t8030_patch_kernel(hdr);

    tms->device_tree = load_dtb_from_file(machine->dtb);
    tms->trustcache = load_trustcache_from_file(tms->trustcache_filename,
                                                &tms->bootinfo.trustcache_size);
    data = 24000000;
    set_dtb_prop(tms->device_tree, "clock-frequency", 4, &data);
    child = find_dtb_node(tms->device_tree, "arm-io");
    assert(child != NULL);

    data = 0x11; /* B1 */
    set_dtb_prop(child, "chip-revision", 4, &data);

    set_dtb_prop(child, "clock-frequencies", sizeof(clock_freq), clock_freq);
    set_dtb_prop(child, "clock-frequencies-nclk", sizeof(clock_freq_nclk),
                 clock_freq_nclk);

    prop = find_dtb_prop(child, "ranges");
    assert(prop != NULL);

    ranges = (hwaddr *)prop->value;
    tms->soc_base_pa = ranges[1];
    tms->soc_size = ranges[2];

    memset(buffer, 0, sizeof(buffer));
    memcpy(buffer, "MWL72", 5);
    set_dtb_prop(tms->device_tree, "model-number", 32, buffer);
    memset(buffer, 0, sizeof(buffer));
    memcpy(buffer, "LL/A", 4);
    set_dtb_prop(tms->device_tree, "region-info", 32, buffer);
    memset(buffer, 0, sizeof(buffer));
    set_dtb_prop(tms->device_tree, "config-number", 0x40, buffer);
    memset(buffer, 0, sizeof(buffer));
    memcpy(buffer, "C39ZRMDEN72J", 12);
    set_dtb_prop(tms->device_tree, "serial-number", 32, buffer);
    memset(buffer, 0, sizeof(buffer));
    memcpy(buffer, "C39948108J9N72J1F", 17);
    set_dtb_prop(tms->device_tree, "mlb-serial-number", 32, buffer);
    memset(buffer, 0, sizeof(buffer));
    memcpy(buffer, "A2111", 5);
    set_dtb_prop(tms->device_tree, "regulatory-model-number", 32, buffer);

    child = get_dtb_node(tms->device_tree, "chosen");
    data = 0x8030;
    set_dtb_prop(child, "chip-id", 4, &data);
    data = 0x4;
    set_dtb_prop(child, "board-id", 4, &data);

    if (tms->ecid == 0) {
        tms->ecid = 0x1122334455667788;
    }
    set_dtb_prop(child, "unique-chip-id", 8, &tms->ecid);

    /* update the display parameters */
    set_dtb_prop(child, "display-rotation", sizeof(display_rotation),
                    &display_rotation);

    set_dtb_prop(child, "display-scale", sizeof(display_scale),
                    &display_scale);

    child = get_dtb_node(tms->device_tree, "product");
    /* TODO: SEP, iOS 15 data encryption */
    set_dtb_prop(child, "product-name", 8, "FastSim");

    t8030_cpu_setup(machine);

    t8030_create_aic(machine);

    for (int i = 0; i < T8030_NUM_UARTS; i++) {
        t8030_create_s3c_uart(tms, i, serial_hd(i));
    }

    t8030_pmgr_setup(machine);
    t8030_amcc_setup(machine);

    t8030_create_ans(machine);

    t8030_create_gpio(machine, "gpio");
    t8030_create_gpio(machine, "smc-gpio");
    t8030_create_gpio(machine, "nub-gpio");

    t8030_create_i2c(machine, "i2c0");
    t8030_create_i2c(machine, "i2c1");
    t8030_create_i2c(machine, "i2c2");
    t8030_create_i2c(machine, "i2c3");
    t8030_create_i2c(machine, "smc-i2c0");
    t8030_create_i2c(machine, "smc-i2c1");

    t8030_create_dart(machine, "dart-usb");
    t8030_create_dart(machine, "dart-sio");
    t8030_create_dart(machine, "dart-disp0");
    t8030_create_usb(machine);

    t8030_create_wdt(machine);

    t8030_create_aes(machine);

    t8030_create_spmi(machine, "spmi0");
    t8030_create_spmi(machine, "spmi1");
    t8030_create_spmi(machine, "spmi2");

    t8030_create_pmu(machine, "spmi0", "spmi-pmu");

    t8030_create_smc(machine);
    t8030_create_sio(machine);

    for (int i = 0; i < T8030_NUM_SPIS; i++) {
        t8030_create_spi(machine, i);
    }

    t8030_create_boot_display(machine);

    tms->init_done_notifier.notify = t8030_machine_init_done;
    qemu_add_machine_init_done_notifier(&tms->init_done_notifier);
}

static void t8030_set_trustcache_filename(Object *obj, const char *value, Error **errp)
{
    T8030MachineState *tms = T8030_MACHINE(obj);

    g_free(tms->trustcache_filename);
    tms->trustcache_filename = g_strdup(value);
}

static char *t8030_get_trustcache_filename(Object *obj, Error **errp)
{
    T8030MachineState *tms = T8030_MACHINE(obj);

    return g_strdup(tms->trustcache_filename);
}

static void t8030_set_ticket_filename(Object *obj, const char *value, Error **errp)
{
    T8030MachineState *tms = T8030_MACHINE(obj);

    g_free(tms->ticket_filename);
    tms->ticket_filename = g_strdup(value);
}

static char *t8030_get_ticket_filename(Object *obj, Error **errp)
{
    T8030MachineState *tms = T8030_MACHINE(obj);

    return g_strdup(tms->ticket_filename);
}

static void t8030_set_boot_mode(Object *obj, const char *value, Error **errp)
{
    T8030MachineState *tms = T8030_MACHINE(obj);

    if (g_str_equal(value, "auto")) {
        tms->boot_mode = kBootModeAuto;
    } else if (g_str_equal(value, "manual")) {
        tms->boot_mode = kBootModeManual;
    } else if (g_str_equal(value, "enter_recovery")) {
        tms->boot_mode = kBootModeEnterRecovery;
    } else if (g_str_equal(value, "exit_recovery")) {
        tms->boot_mode = kBootModeExitRecovery;
    } else {
        tms->boot_mode = kBootModeAuto;
        error_setg(errp, "Invalid boot mode: %s", value);
    }
}

static char *t8030_get_boot_mode(Object *obj, Error **errp)
{
    T8030MachineState *tms = T8030_MACHINE(obj);

    switch (tms->boot_mode) {
    case kBootModeManual:
        return g_strdup("manual");
    case kBootModeEnterRecovery:
        return g_strdup("enter_recovery");
    case kBootModeExitRecovery:
        return g_strdup("exit_recovery");
    default:
    case kBootModeAuto:
        return g_strdup("auto");
    }
}

static void t8030_get_rtbuddyv2_protocol_version(Object *obj, Visitor *v,
                                                 const char *name, void *opaque,
                                                 Error **errp)
{
    T8030MachineState *tms = T8030_MACHINE(obj);
    int64_t value = tms->rtbuddyv2_protocol_version;

    visit_type_int(v, name, &value, errp);
}

static void t8030_set_rtbuddyv2_protocol_version(Object *obj, Visitor *v,
                                                 const char *name, void *opaque,
                                                 Error **errp)
{
    T8030MachineState *tms = T8030_MACHINE(obj);
    int64_t value;

    if (!visit_type_int(v, name, &value, errp)) {
        return;
    }

    tms->rtbuddyv2_protocol_version = value;
}

static void t8030_get_ecid(Object *obj, Visitor *v,
                           const char *name, void *opaque,
                           Error **errp)
{
    T8030MachineState *tms = T8030_MACHINE(obj);
    int64_t value = tms->ecid;

    visit_type_int(v, name, &value, errp);
}

static void t8030_set_ecid(Object *obj, Visitor *v,
                           const char *name, void *opaque,
                           Error **errp)
{
    T8030MachineState *tms = T8030_MACHINE(obj);
    int64_t value;

    if (!visit_type_int(v, name, &value, errp)) {
        return;
    }

    tms->ecid = value;
}

static void t8030_set_kaslr_off(Object *obj, bool value, Error **errp)
{
    T8030MachineState *tms = T8030_MACHINE(obj);

    tms->kaslr_off = value;
}

static bool t8030_get_kaslr_off(Object *obj, Error **errp)
{
    T8030MachineState *tms = T8030_MACHINE(obj);

    return tms->kaslr_off;
}

static ram_addr_t t8030_machine_fixup_ram_size(ram_addr_t size)
{
    if (size != T8030_DRAM_SIZE) {
        warn_report("The T8030 machine only supports 4 GiB RAM. Overriding");
    }
    return T8030_DRAM_SIZE;
}

static void t8030_machine_class_init(ObjectClass *oc, void *data)
{
    MachineClass *mc = MACHINE_CLASS(oc);

    mc->desc = "T8030";
    mc->init = t8030_machine_init;
    mc->reset = t8030_machine_reset;
    mc->max_cpus = A13_MAX_CPU;
    // this disables the error message "Failed to query for block devices!"
    // when starting qemu - must keep at least one device
    mc->no_sdcard = 1;
    mc->no_floppy = 1;
    mc->no_cdrom = 1;
    mc->no_parallel = 1;
    mc->default_cpu_type = TYPE_APPLE_A13;
    mc->minimum_page_bits = 14;
    mc->default_ram_size = T8030_DRAM_SIZE;
    mc->fixup_ram_size = t8030_machine_fixup_ram_size;

    object_class_property_add_str(oc, "trustcache-filename",
                                  t8030_get_trustcache_filename,
                                  t8030_set_trustcache_filename);
    object_class_property_set_description(oc, "trustcache-filename",
                                   "Set the trustcache filename to be loaded");
    object_class_property_add_str(oc, "ticket-filename",
                                  t8030_get_ticket_filename,
                                  t8030_set_ticket_filename);
    object_class_property_set_description(oc, "ticket-filename",
                                    "Set the APTicket filename to be loaded");
    object_class_property_add_str(oc, "boot-mode",
                                  t8030_get_boot_mode,
                                  t8030_set_boot_mode);
    object_class_property_set_description(oc, "boot-mode",
                                    "Set boot mode of the machine");
    object_class_property_add(oc, "rtbuddyv2-protocol-version", "int",
        t8030_get_rtbuddyv2_protocol_version,
        t8030_set_rtbuddyv2_protocol_version,
        NULL, NULL);
    object_class_property_set_description(oc, "rtbuddyv2-protocol-version",
        "Override RTBuddyV2 protocol version");
    object_class_property_add(oc, "ecid", "uint64",
        t8030_get_ecid,
        t8030_set_ecid,
        NULL, NULL);
    object_class_property_set_description(oc, "ecid",
        "Set device's ECID");
    object_class_property_add_bool(oc, "kaslr-off",
                                  t8030_get_kaslr_off,
                                  t8030_set_kaslr_off);
    object_class_property_set_description(oc, "kaslr-off",
                                          "Disable KASLR");
}

static const TypeInfo t8030_machine_info = {
    .name = TYPE_T8030_MACHINE,
    .parent = TYPE_MACHINE,
    .instance_size = sizeof(T8030MachineState),
    .class_size = sizeof(T8030MachineClass),
    .class_init = t8030_machine_class_init,
};

static void t8030_machine_types(void)
{
    type_register_static(&t8030_machine_info);
}

type_init(t8030_machine_types)
