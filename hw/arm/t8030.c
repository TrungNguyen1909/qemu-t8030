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
#include "qapi/error.h"
#include "qemu-common.h"
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
#include "hw/arm/t8030_cpu.h"

#include "hw/irq.h"
#include "hw/or-irq.h"
#include "hw/intc/apple_aic.h"
#include "hw/block/apple_ans.h"
#include "hw/arm/apple_sart.h"
#include "hw/gpio/apple_gpio.h"
#include "hw/i2c/apple_i2c.h"
#include "hw/usb/apple_otg.h"
#include "hw/watchdog/apple_wdt.h"
#include "hw/misc/apple_aes.h"
#include "hw/nvram/apple_nvram.h"
#include "hw/spmi/apple_spmi.h"
#include "hw/spmi/apple_spmi_pmu.h"
#include "hw/misc/apple_smc.h"
#include "hw/arm/apple_dart.h"

#include "hw/arm/exynos4210.h"
#include "hw/arm/xnu_pf.h"

#define T8030_DRAM_BASE 0x800000000
#define T8030_PANIC_LOG_SIZE (0x100000)
#define T8030_USB_OTG_BASE 0x39000000
#define NOP_INST 0xd503201f
#define MOV_W0_01_INST 0x52800020
#define MOV_X13_0_INST 0xd280000d
#define RET_INST 0xd65f03c0
#define RETAB_INST 0xd65f0fff

static void t8030_wake_up_cpus(MachineState* machine, uint64_t cpu_mask)
{
    T8030MachineState* tms = T8030_MACHINE(machine);
    int i;

    for(i = 0; i < machine->smp.cpus; i++) {
        if (test_bit(i, (unsigned long*)&cpu_mask)
            && t8030_cpu_is_sleep(tms->cpus[i])) {
            t8030_cpu_wakeup(tms->cpus[i]);
        }
    }
}

static void t8030_create_s3c_uart(const T8030MachineState *tms, Chardev *chr)
{
    DeviceState *dev;
    hwaddr base;
    //first fetch the uart mmio address
    int vector;
    DTBProp *prop;
    hwaddr *uart_offset;
    DTBNode *child = find_dtb_node(tms->device_tree, "arm-io");

    assert(child != NULL);

    child = find_dtb_node(child, "uart0");
    assert(child != NULL);

    //make sure this node has the boot-console prop
    prop = find_dtb_prop(child, "boot-console");
    assert(prop != NULL);

    prop = find_dtb_prop(child, "reg");
    assert(prop != NULL);

    uart_offset = (hwaddr *)prop->value;
    base = tms->soc_base_pa + uart_offset[0];

    prop = find_dtb_prop(child, "interrupts");
    assert(prop);

    vector = *(uint32_t*)prop->value;
    dev = exynos4210_uart_create(base, 256, 0, chr, qdev_get_gpio_in(DEVICE(tms->aic), vector));
    assert(dev);
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
                     MEMTXATTRS_UNSPECIFIED, (uint8_t *)panic_info,
                     tms->panic_size, 0);
    address_space_rw(&address_space_memory, tms->panic_base,
                     MEMTXATTRS_UNSPECIFIED, (uint8_t *)buffer,
                     tms->panic_size, 1);

    return panic_info->eph_magic == EMBEDDED_PANIC_MAGIC;
}

static void t8030_memory_setup(MachineState *machine)
{
    struct mach_header_64 *hdr;
    hwaddr virt_end;
    hwaddr dtb_va;
    hwaddr top_of_kernel_data_pa;
    hwaddr mem_size;
    hwaddr phys_ptr;
    T8030MachineState *tms = T8030_MACHINE(machine);
    MemoryRegion *sysmem = tms->sysmem;
    AddressSpace *nsas = &address_space_memory;
    AppleNvramState *nvram = NULL;
    macho_boot_info_t info = &tms->bootinfo;
    g_autofree char *cmdline = NULL;

    //setup the memory layout:

    //At the beginning of the non-secure ram we have the raw kernel file.
    //After that we have the static trust cache.
    //After that we have all the kernel sections.
    //After that we have ramdisk
    //After that we have the kernel boot args
    //After that we have the device tree
    //After that we have the rest of the RAM

    if (t8030_check_panic(machine)) {
        qemu_system_guest_panicked(NULL);
        return;
    }
    hdr = tms->kernel;
    assert(hdr);
    macho_highest_lowest(hdr, NULL, &virt_end);
    g_phys_base = phys_ptr = T8030_DRAM_BASE;

    // //now account for the trustcache
    phys_ptr += align_16k_high(0x2000000);
    info->trustcache_pa = phys_ptr;
    macho_load_trustcache(tms->trustcache_filename, nsas, sysmem, info->trustcache_pa, &info->trustcache_size);
    phys_ptr += align_16k_high(info->trustcache_size);

    //now account for the loaded kernel
    info->entry = arm_load_macho(hdr, nsas, sysmem, "Kernel", g_phys_base, g_virt_base);
    fprintf(stderr, "g_virt_base: 0x" TARGET_FMT_lx "\n"
                    "g_phys_base: 0x" TARGET_FMT_lx "\n",
                    g_virt_base, g_phys_base);
    fprintf(stderr, "entry: 0x" TARGET_FMT_lx "\n", info->entry);

    phys_ptr = vtop_static(align_16k_high(virt_end));

    //now account for the ramdisk

    if (machine->initrd_filename) {
        info->ramdisk_pa = phys_ptr;
        macho_load_ramdisk(machine->initrd_filename, nsas, sysmem, info->ramdisk_pa, &info->ramdisk_size);
        info->ramdisk_size = align_16k_high(info->ramdisk_size);
        phys_ptr += info->ramdisk_size;
    }

    //now account for kernel boot args
    info->bootargs_pa = phys_ptr;
    phys_ptr += align_16k_high(0x4000);

    //now account for device tree
    info->dram_base = T8030_DRAM_BASE;
    info->dram_size = machine->ram_size;
    info->dtb_pa = phys_ptr;

    dtb_va = ptov_static(info->dtb_pa);

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
        set_dtb_prop(tms->device_tree, "compatible", 28, (uint8_t *)"N104DEV\0iPhone12,1\0AppleARM\0$");
    } else {
        set_dtb_prop(tms->device_tree, "compatible", 27, (uint8_t *)"N104AP\0iPhone12,1\0AppleARM\0$");
    }

    if (!xnu_contains_boot_arg(cmdline, "rd=", true)) {
        DTBNode *chosen = find_dtb_node(tms->device_tree, "chosen");
        DTBProp *prop = find_dtb_prop(chosen, "root-matching");

        if (prop) {
            snprintf((char *)prop->value, prop->length, "<dict><key>IOProviderClass</key><string>IOMedia</string><key>IOPropertyMatch</key><dict><key>Partition ID</key><integer>1</integer></dict></dict>");
        }
    }

    mem_size = machine->ram_size - T8030_PANIC_LOG_SIZE;

    DTBNode *pram = find_dtb_node(tms->device_tree, "pram");
    if (pram) {
        uint64_t panic_base = T8030_DRAM_BASE + mem_size;
        uint64_t panic_size = T8030_PANIC_LOG_SIZE;
        set_dtb_prop(pram, "reg", 8, (uint8_t *)&panic_base);
        DTBNode *chosen = find_dtb_node(tms->device_tree, "chosen");
        set_dtb_prop(chosen, "embedded-panic-log-size", 8,
                     (uint8_t *)&panic_size);
        tms->panic_base = panic_base;
        tms->panic_size = panic_size;
    }

    macho_load_dtb(tms->device_tree, nsas, sysmem, "DeviceTree", info);

    phys_ptr += align_16k_high(info->dtb_size);

    top_of_kernel_data_pa = (align_16k_high(phys_ptr) + 0x3000ull) & ~0x3fffull;

    fprintf(stderr, "cmdline: [%s]\n", cmdline);
    macho_setup_bootargs("BootArgs", nsas, sysmem, info->bootargs_pa,
                         g_virt_base, g_phys_base, mem_size,
                         top_of_kernel_data_pa, dtb_va, info->dtb_size,
                         tms->video, cmdline);
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

    // fprintf(stderr, "PMGR reg WRITE @ 0x" TARGET_FMT_lx " value: 0x" TARGET_FMT_lx "\n", addr, data);
    switch (addr) {
    case 0xd4004:
        t8030_wake_up_cpus(machine, data);
        return;
    }
}

static uint64_t pmgr_reg_read(void *opaque, hwaddr addr, unsigned size)
{
    // fprintf(stderr, "PMGR reg READ @ 0x" TARGET_FMT_lx "\n", addr);
    switch(addr) {
    case 0xf0010: /* AppleT8030PMGR::commonSramCheck */
        return 0x5000;
    case 0x80100 ... 0x803b8:
        return 0xf0;
    default:
        break;
    }
    return 0;
}

static const MemoryRegionOps pmgr_reg_ops = {
    .write = pmgr_reg_write,
    .read = pmgr_reg_read,
};

static void t8030_cluster_setup(MachineState *machine)
{
    T8030MachineState *tms = T8030_MACHINE(machine);

    for (int i = 0; i < T8030_MAX_CLUSTER; i++) {
        g_autofree char *name = NULL;

        name = g_strdup_printf("cluster%d", i);
        object_initialize_child(OBJECT(machine), name, &tms->clusters[i],
                                TYPE_T8030_CPU_CLUSTER);
        qdev_prop_set_uint32(DEVICE(&tms->clusters[i]), "cluster-id", i);
    }
}

static void t8030_cluster_realize(MachineState *machine)
{
    T8030MachineState *tms = T8030_MACHINE(machine);
    for (int i = 0; i < T8030_MAX_CLUSTER; i++) {
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

        tms->cpus[i] = t8030_cpu_create(node);
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

    set_dtb_prop(child, "voltage-states0", 24, (uint8_t*)"\x01\x00\x00\x00\x71\x02\x00\x00\x01\x00\x00\x00\xa9\x02\x00\x00\x01\x00\x00\x00\xe4\x02\x00\x00");
    set_dtb_prop(child, "voltage-states1", 40, (uint8_t*)"\x71\xbc\x01\x00\x38\x02\x00\x00\x4b\x28\x01\x00\x83\x02\x00\x00\x38\xde\x00\x00\xde\x02\x00\x00\xc7\xb1\x00\x00\x42\x03\x00\x00\x25\x94\x00\x00\xaf\x03\x00\x00");
    set_dtb_prop(child, "voltage-states2", 24, (uint8_t*)"\x01\x00\x00\x00\x74\x02\x00\x00\x01\x00\x00\x00\xb8\x02\x00\x00\x01\x00\x00\x00\x42\x03\x00\x00");
    set_dtb_prop(child, "voltage-states5", 64, (uint8_t*)"\x12\xda\x01\x00\x38\x02\x00\x00\xb3\x18\x01\x00\x71\x02\x00\x00\x87\xc5\x00\x00\xb8\x02\x00\x00\xa2\x89\x00\x00\x20\x03\x00\x00\x37\x75\x00\x00\x87\x03\x00\x00\xaa\x6a\x00\x00\xe8\x03\x00\x00\xc3\x62\x00\x00\x48\x04\x00\x00\x18\x60\x00\x00\x65\x04\x00\x00");
    set_dtb_prop(child, "voltage-states8", 96, (uint8_t*)"\x00\xf4\x06\x14\xff\xff\xff\xff\x00\x2a\x75\x15\xff\xff\xff\xff\x00\x6e\x0a\x1e\xff\xff\xff\xff\x00\xbf\x2f\x20\xff\xff\xff\xff\x00\x1e\x7c\x29\xff\xff\xff\xff\x00\xa5\x0f\x2d\xff\xff\xff\xff\x00\x55\x81\x38\xff\xff\xff\xff\x00\x7e\x5f\x40\xff\xff\xff\xff\x00\xb4\xcd\x41\xff\xff\xff\xff\x00\x8c\x86\x47\xff\xff\xff\xff\x00\x64\x3f\x4d\xff\xff\xff\xff\x80\xc9\x53\x53\xff\xff\xff\xff");
    set_dtb_prop(child, "voltage-states9", 56, (uint8_t*)"\x00\x00\x00\x00\x90\x01\x00\x00\x00\x2a\x75\x15\x3f\x02\x00\x00\xc0\x4f\xef\x1e\x7a\x02\x00\x00\x00\xcd\x56\x27\x90\x02\x00\x00\x00\x11\xec\x2f\xc8\x02\x00\x00\x00\x55\x81\x38\x16\x03\x00\x00\x80\xfe\x2a\x47\x96\x03\x00\x00");
    set_dtb_prop(child, "voltage-states10", 24, (uint8_t*)"\x01\x00\x00\x00\x67\x02\x00\x00\x01\x00\x00\x00\x90\x02\x00\x00\x01\x00\x00\x00\xc2\x02\x00\x00");
    set_dtb_prop(child, "voltage-states11", 24, (uint8_t*)"\x01\x00\x00\x00\x29\x02\x00\x00\x01\x00\x00\x00\x71\x02\x00\x00\x01\x00\x00\x00\xf4\x02\x00\x00");
    set_dtb_prop(child, "bridge-settings-12", 192, (uint8_t*)"\x00\x00\x00\x00\x11\x00\x00\x00\x0c\x00\x00\x00\xe8\x7c\x18\x03\x54\x00\x00\x00\x12\x00\x00\x00\x00\x09\x00\x00\x01\x00\x01\x40\x24\x09\x00\x00\x18\x08\x08\x00\x28\x09\x00\x00\x01\x00\x00\x00\x48\x09\x00\x00\x01\x00\x00\x00\x64\x09\x00\x00\x18\x08\x08\x00\x88\x09\x00\x00\x01\x00\x00\x00\x00\x0a\x00\x00\x7f\x00\x00\x00\x00\x10\x00\x00\x01\x01\x00\x00\x00\x40\x00\x00\x03\x00\x00\x00\x04\x40\x00\x00\x03\x00\x00\x00\x08\x40\x00\x00\x03\x00\x00\x00\x0c\x40\x00\x00\x03\x00\x00\x00\x04\x41\x00\x00\x01\x00\x00\x00\x00\x43\x00\x00\x01\x00\x01\xc0\x38\x43\x00\x00\x01\x00\x00\x00\x48\x43\x00\x00\x01\x00\x00\x00\x00\x80\x00\x00\x0f\x00\x00\x00\x00\x82\x00\x00\x01\x00\x01\xc0\x28\x82\x00\x00\x01\x00\x00\x00\x38\x82\x00\x00\x01\x00\x00\x00\x48\x82\x00\x00\x01\x00\x00\x00");
    set_dtb_prop(child, "bridge-settings-13", 64, (uint8_t*)"\x00\x00\x00\x00\x03\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x08\x00\x00\x00\x03\x00\x00\x00\x0c\x00\x00\x00\x03\x00\x00\x00\x04\x01\x00\x00\x01\x00\x00\x00\x00\x03\x00\x00\x01\x00\x01\xc0\x38\x03\x00\x00\x01\x00\x00\x00\x48\x03\x00\x00\x01\x00\x00\x00");
    set_dtb_prop(child, "bridge-settings-14", 40, (uint8_t*)"\x00\x00\x00\x00\x0f\x00\x00\x00\x00\x02\x00\x00\x01\x00\x01\xc0\x28\x02\x00\x00\x01\x00\x00\x00\x38\x02\x00\x00\x01\x00\x00\x00\x48\x02\x00\x00\x01\x00\x00\x00");
    set_dtb_prop(child, "bridge-settings-15", 144, (uint8_t*)"\x00\x00\x00\x00\x01\x00\x00\x00\x0c\x00\x00\x00\x98\x7e\x68\x01\x00\x0a\x00\x00\x01\x00\x01\x40\x24\x0a\x00\x00\x18\x08\x08\x00\x44\x0a\x00\x00\x18\x08\x08\x00\x64\x0a\x00\x00\x18\x08\x08\x00\x84\x0a\x00\x00\x18\x08\x08\x00\x00\x0b\x00\x00\x7f\x00\x00\x00\x00\x11\x00\x00\x01\x01\x00\x00\x00\x40\x00\x00\x03\x00\x00\x00\x04\x40\x00\x00\x03\x00\x00\x00\x08\x40\x00\x00\x03\x00\x00\x00\x0c\x40\x00\x00\x03\x00\x00\x00\x10\x40\x00\x00\x03\x00\x00\x00\x04\x41\x00\x00\x01\x00\x00\x00\x00\x43\x00\x00\x01\x00\x01\xc0\x00\x80\x00\x00\x0f\x00\x00\x00\x00\x82\x00\x00\x01\x00\x01\xc0");
    set_dtb_prop(child, "bridge-settings-16", 56, (uint8_t*)"\x00\x00\x00\x00\x03\x00\x00\x00\x04\x00\x00\x00\x03\x00\x00\x00\x08\x00\x00\x00\x03\x00\x00\x00\x0c\x00\x00\x00\x03\x00\x00\x00\x10\x00\x00\x00\x03\x00\x00\x00\x04\x01\x00\x00\x01\x00\x00\x00\x00\x03\x00\x00\x01\x00\x01\xc0");
    set_dtb_prop(child, "bridge-settings-17", 16, (uint8_t*)"\x00\x00\x00\x00\x0f\x00\x00\x00\x00\x02\x00\x00\x01\x00\x01\xc0");
    set_dtb_prop(child, "bridge-settings-6", 128, (uint8_t*)"\x00\x00\x00\x00\x10\x04\x00\x00\x00\x04\x00\x00\x01\x00\x01\x40\x00\x06\x00\x00\xff\xff\xff\x01\x08\x07\x00\x00\x00\x00\x00\x02\x0c\x07\x00\x00\x80\x00\x40\x00\x10\x07\x00\x00\x80\x00\x40\x00\x14\x07\x00\x00\x80\x00\x40\x00\x18\x07\x00\x00\x80\x00\x40\x00\x1c\x07\x00\x00\x10\x00\x10\x00\x44\x07\x00\x00\x12\x00\x29\x00\x48\x07\x00\x00\x0a\x00\x40\x00\x4c\x07\x00\x00\x0a\x00\x40\x00\x50\x07\x00\x00\x0a\x00\x40\x00\x54\x07\x00\x00\x0a\x00\x40\x00\x58\x07\x00\x00\x10\x00\x40\x00\x00\x08\x00\x00\x01\x01\x00\x00");
    set_dtb_prop(child, "bridge-settings-1", 128, (uint8_t*)"\x00\x00\x00\x00\x10\x04\x00\x00\x00\x04\x00\x00\x01\x00\x01\x40\x00\x06\x00\x00\xff\xff\xff\x01\x08\x07\x00\x00\x00\x00\x00\x02\x0c\x07\x00\x00\x80\x00\x40\x00\x10\x07\x00\x00\x80\x00\x40\x00\x14\x07\x00\x00\x80\x00\x40\x00\x18\x07\x00\x00\x80\x00\x40\x00\x1c\x07\x00\x00\x10\x00\x40\x00\x44\x07\x00\x00\x00\x00\x00\x02\x48\x07\x00\x00\x80\x00\x40\x00\x4c\x07\x00\x00\x80\x00\x40\x00\x50\x07\x00\x00\x80\x00\x40\x00\x54\x07\x00\x00\x80\x00\x40\x00\x58\x07\x00\x00\x10\x00\x40\x00\x00\x08\x00\x00\x01\x01\x00\x00");
    set_dtb_prop(child, "bridge-settings-0", 128, (uint8_t*)"\x00\x00\x00\x00\x10\x04\x00\x00\x00\x04\x00\x00\x01\x00\x01\x40\x00\x06\x00\x00\xff\xff\xff\x01\x08\x07\x00\x00\x00\x00\x00\x02\x0c\x07\x00\x00\x80\x00\x40\x00\x10\x07\x00\x00\x80\x00\x40\x00\x14\x07\x00\x00\x80\x00\x40\x00\x18\x07\x00\x00\x80\x00\x40\x00\x1c\x07\x00\x00\x10\x00\x20\x00\x44\x07\x00\x00\x00\x00\x00\x02\x48\x07\x00\x00\x80\x00\x40\x00\x4c\x07\x00\x00\x80\x00\x40\x00\x50\x07\x00\x00\x80\x00\x40\x00\x54\x07\x00\x00\x80\x00\x40\x00\x58\x07\x00\x00\x10\x00\x40\x00\x00\x08\x00\x00\x01\x01\x00\x00");
    set_dtb_prop(child, "bridge-settings-8", 128, (uint8_t*)"\x00\x00\x00\x00\x10\x04\x00\x00\x00\x04\x00\x00\x01\x00\x01\x40\x00\x06\x00\x00\xff\xff\xff\x01\x08\x07\x00\x00\x00\x00\x00\x02\x0c\x07\x00\x00\x80\x00\x40\x00\x10\x07\x00\x00\x80\x00\x40\x00\x14\x07\x00\x00\x80\x00\x40\x00\x18\x07\x00\x00\x80\x00\x40\x00\x1c\x07\x00\x00\x20\x00\x20\x00\x44\x07\x00\x00\x00\x00\x00\x02\x48\x07\x00\x00\x80\x00\x40\x00\x4c\x07\x00\x00\x80\x00\x40\x00\x50\x07\x00\x00\x80\x00\x40\x00\x54\x07\x00\x00\x80\x00\x40\x00\x58\x07\x00\x00\x10\x00\x80\x00\x00\x08\x00\x00\x01\x01\x00\x00");
    set_dtb_prop(child, "bridge-settings-7", 80, (uint8_t*)"\x00\x00\x00\x00\x10\x04\x00\x00\x00\x04\x00\x00\x01\x00\x01\x40\x00\x06\x00\x00\xff\xff\xff\x01\x08\x07\x00\x00\x00\x00\x00\x02\x0c\x07\x00\x00\x80\x00\x40\x00\x10\x07\x00\x00\x80\x00\x40\x00\x14\x07\x00\x00\x80\x00\x40\x00\x18\x07\x00\x00\x80\x00\x40\x00\x1c\x07\x00\x00\x10\x00\x10\x00\x00\x08\x00\x00\x01\x01\x00\x00");
    set_dtb_prop(child, "bridge-settings-5", 176, (uint8_t*)"\x00\x00\x00\x00\x10\x04\x00\x00\x00\x04\x00\x00\x01\x00\x00\x40\x00\x06\x00\x00\xff\xff\xff\x01\x08\x07\x00\x00\x00\x00\x00\x02\x0c\x07\x00\x00\x13\x00\xc7\x00\x10\x07\x00\x00\x13\x00\xc7\x00\x14\x07\x00\x00\x13\x00\xc7\x00\x18\x07\x00\x00\x13\x00\xc7\x00\x1c\x07\x00\x00\x10\x00\x20\x00\x44\x07\x00\x00\x00\x00\x00\x02\x48\x07\x00\x00\x80\x00\x40\x00\x4c\x07\x00\x00\x80\x00\x40\x00\x50\x07\x00\x00\x80\x00\x40\x00\x54\x07\x00\x00\x80\x00\x40\x00\x58\x07\x00\x00\x10\x00\x40\x00\x80\x07\x00\x00\x12\x00\x29\x00\x84\x07\x00\x00\x0a\x00\x40\x00\x88\x07\x00\x00\x0a\x00\x40\x00\x8c\x07\x00\x00\x0a\x00\x40\x00\x90\x07\x00\x00\x0a\x00\x40\x00\x94\x07\x00\x00\x10\x00\x30\x00\x00\x08\x00\x00\x01\x01\x00\x00");
    set_dtb_prop(child, "bridge-settings-2", 128, (uint8_t*)"\x00\x00\x00\x00\x10\x04\x00\x00\x00\x04\x00\x00\x01\x00\x01\x40\x00\x06\x00\x00\xff\xff\xff\x01\x08\x07\x00\x00\x00\x00\x00\x02\x0c\x07\x00\x00\x80\x00\x40\x00\x10\x07\x00\x00\x80\x00\x40\x00\x14\x07\x00\x00\x80\x00\x40\x00\x18\x07\x00\x00\x80\x00\x40\x00\x1c\x07\x00\x00\x10\x00\x10\x00\x44\x07\x00\x00\x00\x00\x00\x02\x48\x07\x00\x00\x80\x00\x40\x00\x4c\x07\x00\x00\x80\x00\x40\x00\x50\x07\x00\x00\x80\x00\x40\x00\x54\x07\x00\x00\x80\x00\x40\x00\x58\x07\x00\x00\x10\x00\x39\x00\x00\x08\x00\x00\x01\x01\x00\x00");
    set_dtb_prop(child, "bridge-settings-3", 128, (uint8_t*)"\x00\x00\x00\x00\x10\x04\x00\x00\x00\x04\x00\x00\x01\x00\x01\x40\x00\x06\x00\x00\xff\xff\xff\x01\x08\x07\x00\x00\x00\x00\x00\x02\x0c\x07\x00\x00\x80\x00\x40\x00\x10\x07\x00\x00\x80\x00\x40\x00\x14\x07\x00\x00\x80\x00\x40\x00\x18\x07\x00\x00\x80\x00\x40\x00\x1c\x07\x00\x00\x10\x00\x30\x00\x44\x07\x00\x00\x00\x00\x00\x02\x48\x07\x00\x00\x80\x00\x40\x00\x4c\x07\x00\x00\x80\x00\x40\x00\x50\x07\x00\x00\x80\x00\x40\x00\x54\x07\x00\x00\x80\x00\x40\x00\x58\x07\x00\x00\x10\x00\x37\x00\x00\x08\x00\x00\x01\x01\x00\x00");
    set_dtb_prop(child, "bridge-settings-4", 128, (uint8_t*)"\x00\x00\x00\x00\x10\x04\x00\x00\x00\x04\x00\x00\x01\x00\x00\x40\x00\x06\x00\x00\xff\xff\xff\x01\x08\x07\x00\x00\x00\x00\x00\x02\x0c\x07\x00\x00\x10\x00\xa6\x00\x10\x07\x00\x00\x10\x00\xa6\x00\x14\x07\x00\x00\x10\x00\xa6\x00\x18\x07\x00\x00\x10\x00\xa6\x00\x1c\x07\x00\x00\x10\x00\x10\x00\x44\x07\x00\x00\x00\x00\x00\x02\x48\x07\x00\x00\x80\x00\x40\x00\x4c\x07\x00\x00\x80\x00\x40\x00\x50\x07\x00\x00\x80\x00\x40\x00\x54\x07\x00\x00\x80\x00\x40\x00\x58\x07\x00\x00\x10\x00\x80\x00\x00\x08\x00\x00\x01\x01\x00\x00");
    set_dtb_prop(child, "voltage-states5-sram", 64, (uint8_t*)"\x00\xbf\x2f\x20\xf1\x02\x00\x00\x00\x04\x5c\x36\xf1\x02\x00\x00\x00\x64\x3f\x4d\xf1\x02\x00\x00\x00\x59\xdd\x6e\x20\x03\x00\x00\x00\x32\x2d\x82\x87\x03\x00\x00\x00\x18\x0d\x8f\xe8\x03\x00\x00\x00\xc8\x7e\x9a\x48\x04\x00\x00\x00\x6a\xc9\x9e\x65\x04\x00\x00");
    set_dtb_prop(child, "voltage-states1-sram", 40, (uint8_t*)"\x00\x10\x55\x22\xf1\x02\x00\x00\x00\x98\x7f\x33\xf1\x02\x00\x00\x00\x20\xaa\x44\xf1\x02\x00\x00\x00\xa8\xd4\x55\x42\x03\x00\x00\x00\x30\xff\x66\xaf\x03\x00\x00");
    set_dtb_prop(child, "voltage-states9-sram", 56, (uint8_t*)"\x00\x00\x00\x00\xf1\x02\x00\x00\x00\x2a\x75\x15\xf1\x02\x00\x00\xc0\x4f\xef\x1e\xf1\x02\x00\x00\x00\xcd\x56\x27\xf1\x02\x00\x00\x00\x11\xec\x2f\xf1\x02\x00\x00\x00\x55\x81\x38\x16\x03\x00\x00\x80\xfe\x2a\x47\x96\x03\x00\x00");
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

    assert(child != NULL);
    child = find_dtb_node(child, "ans");
    assert(child != NULL);

    t8030_create_sart(machine);
    sart = SYS_BUS_DEVICE(object_property_get_link(OBJECT(machine),
                          "sart-ans", &error_fatal));

    ans = apple_ans_create(child, tms->build_version);
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

static DeviceState *t8030_get_gpio_with_role(MachineState *machine, uint32_t role)
{
    switch (role) {
        case 0x00005041: /* AP */
            return DEVICE(object_property_get_link(OBJECT(machine), "gpio", &error_fatal));
            break;
        case 0x00434d53: /* SMC */
            return DEVICE(object_property_get_link(OBJECT(machine), "smc-gpio", &error_fatal));
            break;
        case 0x0042554e: /* NUB */
            return DEVICE(object_property_get_link(OBJECT(machine), "nub-gpio", &error_fatal));
            break;
        default:
            qemu_log_mask(LOG_GUEST_ERROR, "%s: invalid gpio role %s\n", __func__, (const char*)&role);
    }
    return NULL;
}

static void t8030_create_i2c(MachineState *machine, const char *name)
{
    uint32_t line = 0;
    uint32_t opts = 0;
    uint32_t role = 0;
    DeviceState *gpio;
    DeviceState *i2c = NULL;
    DTBProp *prop;
    uint64_t *reg;
    uint32_t* ints;
    int i;
    T8030MachineState *tms = T8030_MACHINE(machine);
    DTBNode *child = find_dtb_node(tms->device_tree, "arm-io");

    assert(child);
    child = find_dtb_node(child, name);
    if (!child) return;

    i2c = apple_i2c_create(child);
    assert(i2c);
    object_property_add_child(OBJECT(machine), name, OBJECT(i2c));

    prop = find_dtb_prop(child, "reg");
    assert(prop);

    reg = (uint64_t*)prop->value;
    sysbus_mmio_map(SYS_BUS_DEVICE(i2c), 0, tms->soc_base_pa + reg[0]);

    prop = find_dtb_prop(child, "interrupts");
    assert(prop);
    ints = (uint32_t*)prop->value;
    for(i = 0; i < prop->length / sizeof(uint32_t); i++) {
        sysbus_connect_irq(SYS_BUS_DEVICE(i2c), i, qdev_get_gpio_in(DEVICE(tms->aic), ints[i]));
    }

    prop = find_dtb_prop(child, "gpio-iic_scl");
    assert(prop);
    line = ((uint32_t*)prop->value)[0];
    opts = ((uint32_t*)prop->value)[1];
    role = ((uint32_t*)prop->value)[2];

    gpio = t8030_get_gpio_with_role(machine, role);
    if (gpio) {
        if (!find_dtb_prop(child, "function-iic_scl")) {
            uint32_t func[] = {
                APPLE_GPIO(gpio)->phandle,
                0x4750494F, /* GPIO */
                line,
                opts
            };
            prop = set_dtb_prop(child, "function-iic_scl", sizeof(func), (uint8_t*)func);
        }
        qdev_connect_gpio_out(gpio, line, qdev_get_gpio_in(i2c, BITBANG_I2C_SCL));
    }

    prop = find_dtb_prop(child, "gpio-iic_sda");
    assert(prop);
    line = ((uint32_t*)prop->value)[0];
    opts = ((uint32_t*)prop->value)[1];
    role = ((uint32_t*)prop->value)[2];

    gpio = t8030_get_gpio_with_role(machine, role);
    if (gpio) {
        if (!find_dtb_prop(child, "function-iic_sda")) {
            uint32_t func[] = {
                APPLE_GPIO(gpio)->phandle,
                0x4750494F, /* GPIO */
                line,
                opts
            };
            prop = set_dtb_prop(child, "function-iic_sda", sizeof(func), (uint8_t*)func);
        }
        qdev_connect_gpio_out(gpio, line, qdev_get_gpio_in(i2c, BITBANG_I2C_SDA));
        qdev_connect_gpio_out(i2c, BITBANG_I2C_SDA, qdev_get_gpio_in(gpio, line));
    }

    sysbus_realize_and_unref(SYS_BUS_DEVICE(i2c), &error_fatal);
}

static void t8030_create_usb(MachineState *machine)
{
    T8030MachineState *tms = T8030_MACHINE(machine);
    DTBNode *child = find_dtb_node(tms->device_tree, "arm-io");
    DTBNode *drd = find_dtb_node(child, "usb-drd");
    DTBNode *dart_usb = find_dtb_node(child, "dart-usb");
    DTBNode *dart_usb_mapper = find_dtb_node(dart_usb, "mapper-usb-drd");
    DTBNode *phy, *complex, *device;
    DTBProp *prop;
    DeviceState *otg;
    AppleDARTState *dart;

    IOMMUMemoryRegion *iommu = NULL;
    uint32_t value;

    phy = get_dtb_node(child, "otgphyctrl");
    assert(phy);
    value = 0x2;
    set_dtb_prop(phy, "errata", sizeof(value), (uint8_t*)&value);
    set_dtb_prop(phy, "compatible", 37, (uint8_t*)"otgphyctrl,s8000\0otgphyctrl,s5l8960x\0");
    value = 1;
    set_dtb_prop(phy, "clock-mask", sizeof(value), (uint8_t*)&value);
    value = 0x37477bb3;
    set_dtb_prop(phy, "cfg0-device", sizeof(value), (uint8_t*)&value);
    set_dtb_prop(phy, "cfg0-host", 5, (uint8_t*)"##G7");
    value = 0x00020e0c;
    set_dtb_prop(phy, "cfg1-host", sizeof(value), (uint8_t*)&value);
    set_dtb_prop(phy, "cfg1-device", sizeof(value), (uint8_t*)&value);
    set_dtb_prop(phy, "device_type", 11, (uint8_t*)"otgphyctrl");
    value = 0x8c;
    set_dtb_prop(phy, "AAPL,phandle", sizeof(value), (uint8_t*)&value);
    {
        uint64_t reg[4] = {
            T8030_USB_OTG_BASE + 0x30,
            0x20,
            T8030_USB_OTG_BASE + 0x600000,
            0x1000
        };
        set_dtb_prop(phy, "reg", sizeof(reg), (uint8_t*)&reg);
    }

    complex = get_dtb_node(child, "usb-complex");
    assert(complex);
    //TODO: clock-gates, usb_widget
    set_dtb_prop(complex, "compatible", 39, (uint8_t*)"usb-complex,s8000\0usb-complex,s5l8960x");
    set_dtb_prop(complex, "ranges", 8*3,  (uint8_t*)&(uint64_t[]){0x0, T8030_USB_OTG_BASE, 0x600000});
    /* set_dtb_prop(complex, "reg", 16, (uint8_t*)&(uint64_t[]){ T8030_USB_OTG_BASE + 0x900000, 0xa0 }); */
    set_dtb_prop(complex, "AAPL,phandle", 4, (uint8_t*)&(uint32_t[]){ 0x8d });
    set_dtb_prop(complex, "#address-cells", 4, (uint8_t*)&(uint32_t[]){ 0x2 });
    set_dtb_prop(complex, "#size-cells", 4, (uint8_t*)&(uint32_t[]){ 0x2 });
    set_dtb_prop(complex, "clock-ids", 4, find_dtb_prop(drd, "clock-ids")->value);
    set_dtb_prop(complex, "device_type", 12, (uint8_t*)"usb-complex");
    value = 1;
    set_dtb_prop(complex, "no-pmu", 4, (uint8_t*)&value);

    device = get_dtb_node(complex, "usb-device");
    assert(device);
    set_dtb_prop(device, "disable-charger-detect", sizeof(value), (uint8_t *)&value);
    set_dtb_prop(device, "phy-interface", 4, (uint8_t*)&(uint32_t[]){ 0x8 });
    set_dtb_prop(device, "publish-criteria", 4, (uint8_t*)&(uint32_t[]){ 0x3 });
    prop = find_dtb_prop(drd, "configuration-string");
    assert(prop);
    set_dtb_prop(device, "configuration-string", prop->length, prop->value);
    prop = find_dtb_prop(drd, "iommu-parent");
    assert(prop);
    set_dtb_prop(device, "iommu-parent", prop->length, prop->value);
    set_dtb_prop(device, "AAPL,phandle", 4, (uint8_t*)&(uint32_t[]){ 0x8e });
    set_dtb_prop(device, "host-mac-address", 6, (uint8_t*)"\0\0\0\0\0\0");
    set_dtb_prop(device, "device-mac-address", 6, (uint8_t*)"\0\0\0\0\0\0");
    set_dtb_prop(device, "num-of-eps", 4, (uint8_t*)&(uint32_t[]){ 0x0e });
    set_dtb_prop(device, "interrupt-parent", 4, (uint8_t*)&(uint32_t[]){ APPLE_AIC(tms->aic)->phandle });
    set_dtb_prop(device, "compatible", 37, (uint8_t*)"usb-device,t7000\0usb-device,s5l8900x");

    set_dtb_prop(device, "interrupts", 4, (uint8_t*)&(uint32_t[]){ ((uint32_t*)find_dtb_prop(drd, "interrupts")->value)[0] });
    set_dtb_prop(device, "ahb-burst", 4, (uint8_t*)&(uint32_t[]){ 0xe });
    set_dtb_prop(device, "clock-mask", 4, (uint8_t*)&(uint32_t[]){ 0x2 });
    set_dtb_prop(device, "fifo-depth", 4, (uint8_t*)&(uint32_t[]){ 0x820 });
    set_dtb_prop(device, "eps-dir-bitmap", 4, (uint8_t*)&(uint32_t[]){ 0x264 });
    set_dtb_prop(device, "device-type", 11, (uint8_t*)"usb-device");
    set_dtb_prop(device, "reg", 16, (uint8_t*)&(uint64_t[]){
        0x100000,
        0x10000,
    });


    prop = find_dtb_prop(dart_usb_mapper, "reg");
    assert(prop);
    assert(prop->length == 4);
    dart = APPLE_DART(object_property_get_link(OBJECT(machine),
                      "dart-usb", &error_fatal));
    iommu = apple_dart_iommu_mr(dart, *(uint32_t *)prop->value);
    assert(iommu);

    otg = apple_otg_create(complex);
    object_property_add_child(OBJECT(machine), "otg", OBJECT(otg));
    assert(object_property_add_const_link(OBJECT(otg), "dma-mr",
                                          OBJECT(iommu)));
    prop = find_dtb_prop(phy, "reg");
    assert(prop);
    sysbus_mmio_map(SYS_BUS_DEVICE(otg), 0,
                    tms->soc_base_pa + ((uint64_t*)prop->value)[0]);
    sysbus_mmio_map(SYS_BUS_DEVICE(otg), 1,
                    tms->soc_base_pa + ((uint64_t*)prop->value)[2]);
    sysbus_mmio_map(SYS_BUS_DEVICE(otg), 2,
                    tms->soc_base_pa
                    + ((uint64_t*)find_dtb_prop(complex, "ranges")->value)[1]
                    + ((uint64_t*)find_dtb_prop(device, "reg")->value)[0]);
    sysbus_realize_and_unref(SYS_BUS_DEVICE(otg), &error_fatal);

    prop = find_dtb_prop(device, "interrupts");
    assert(prop);
    sysbus_connect_irq(SYS_BUS_DEVICE(otg), 0,
                       qdev_get_gpio_in(DEVICE(tms->aic),
                       ((uint32_t *)prop->value)[0]));
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
    assert(prop->length == 8);
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

    for (int i = 0; i < 3; i++) {
        sysbus_mmio_map(SYS_BUS_DEVICE(spmi), i,
                        tms->soc_base_pa + reg[i * 2]);
    }

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
    T8030MachineState *tms = T8030_MACHINE(machine);
    SysBusDevice *smc;
    DTBNode *child = find_dtb_node(tms->device_tree, "arm-io");

    assert(child != NULL);
    child = find_dtb_node(child, "smc");
    assert(child != NULL);

    smc = apple_smc_create(child, tms->build_version);
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

    prop = find_dtb_prop(child, "interrupts");
    assert(prop);
    ints = (uint32_t*)prop->value;

    for(i = 0; i < prop->length / sizeof(uint32_t); i++) {
        sysbus_connect_irq(smc, i, qdev_get_gpio_in(DEVICE(tms->aic), ints[i]));
    }

    sysbus_realize_and_unref(smc, &error_fatal);
}

static void t8030_cpu_reset(void *opaque)
{
    MachineState *machine = MACHINE(opaque);
    T8030MachineState *tms = T8030_MACHINE(machine);
    CPUState *cpu;
    CPUState *cs;
    CPUARMState *env;
    bool found_first = false;

    CPU_FOREACH(cpu) {
        T8030CPUState *tcpu = (T8030CPUState *)object_dynamic_cast(OBJECT(cpu),
                                                               TYPE_T8030_CPU);
        if (tcpu) {
            ARM_CPU(cpu)->rvbar = tms->bootinfo.entry & ~0xfff;
            cpu_reset(cpu);
            if (!found_first) {
                found_first = true;
                cs = CPU(first_cpu);
                env = &ARM_CPU(cs)->env;
                env->xregs[0] = tms->bootinfo.bootargs_pa;
                env->pc = tms->bootinfo.entry;
            }
        }
    }

}

static void t8030_machine_reset(MachineState* machine)
{
    T8030MachineState *tms = T8030_MACHINE(machine);

    qemu_devices_reset();
    t8030_memory_setup(machine);
    t8030_cpu_reset(tms);
}

static void t8030_machine_init(MachineState *machine)
{
    T8030MachineState *tms = T8030_MACHINE(machine);
    struct mach_header_64 *hdr;
    uint64_t kernel_low = 0, kernel_high = 0;
    uint32_t build_version;
    DTBNode *child;
    DTBProp *prop;
    hwaddr *ranges;

    tms->sysmem = get_system_memory();
    allocate_ram(tms->sysmem, "DRAM", T8030_DRAM_BASE, machine->ram_size, 0);

    hdr = macho_load_file(machine->kernel_filename);
    assert(hdr);
    tms->kernel = hdr;
    xnu_header = hdr;
    build_version = macho_build_version(hdr);
    fprintf(stderr, "Loading %s %u.%u...\n", macho_platform_string(hdr),
                                             BUILD_VERSION_MAJOR(build_version),
                                             BUILD_VERSION_MINOR(build_version));
    tms->build_version = build_version;
    macho_highest_lowest(hdr, &kernel_low, &kernel_high);
    fprintf(stderr, "kernel_low: 0x" TARGET_FMT_lx "\nkernel_high: 0x" TARGET_FMT_lx "\n", kernel_low, kernel_high);

    g_virt_base = kernel_low;
    g_phys_base = (hwaddr)macho_get_buffer(hdr);

    t8030_patch_kernel(hdr);

    tms->device_tree = load_dtb_from_file(machine->dtb);
    child = find_dtb_node(tms->device_tree, "arm-io");
    assert(child != NULL);

    prop = find_dtb_prop(child, "ranges");
    assert(prop != NULL);

    ranges = (hwaddr *)prop->value;
    tms->soc_base_pa = ranges[1];
    tms->soc_size = ranges[2];

    t8030_cpu_setup(machine);

    t8030_create_aic(machine);

    t8030_create_s3c_uart(tms, serial_hd(0));

    t8030_pmgr_setup(machine);

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

static void t8030_machine_class_init(ObjectClass *oc, void *data)
{
    MachineClass *mc = MACHINE_CLASS(oc);

    mc->desc = "T8030";
    mc->init = t8030_machine_init;
    mc->reset = t8030_machine_reset;
    mc->max_cpus = T8030_MAX_CPU;
    // this disables the error message "Failed to query for block devices!"
    // when starting qemu - must keep at least one device
    mc->no_sdcard = 1;
    mc->no_floppy = 1;
    mc->no_cdrom = 1;
    mc->no_parallel = 1;
    mc->default_cpu_type = TYPE_T8030_CPU;
    mc->minimum_page_bits = 14;

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
