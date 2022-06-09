/*
 * iPhone 11 - T8030
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

#ifndef HW_ARM_T8030_H
#define HW_ARM_T8030_H

#include "qemu-common.h"
#include "exec/hwaddr.h"
#include "hw/boards.h"
#include "hw/arm/boot.h"
#include "hw/arm/xnu.h"
#include "exec/memory.h"
#include "cpu.h"
#include "sysemu/kvm.h"
#include "hw/arm/apple_a13.h"

#define TYPE_T8030 "t8030"

#define TYPE_T8030_MACHINE MACHINE_TYPE_NAME(TYPE_T8030)

#define T8030_MACHINE(obj) \
    OBJECT_CHECK(T8030MachineState, (obj), TYPE_T8030_MACHINE)

typedef struct
{
    MachineClass parent;
} T8030MachineClass;

typedef enum BootMode {
    kBootModeAuto = 0,
    kBootModeManual,
    kBootModeEnterRecovery,
    kBootModeExitRecovery,
} BootMode;

typedef struct
{
    MachineState parent;
    hwaddr soc_base_pa;
    hwaddr soc_size;

    unsigned long dram_size;
    AppleA13State *cpus[A13_MAX_CPU];
    AppleA13Cluster clusters[A13_MAX_CLUSTER];
    SysBusDevice *aic;
    MemoryRegion *sysmem;
    struct mach_header_64 *kernel;
    DTBNode *device_tree;
    uint8_t *trustcache;
    struct macho_boot_info bootinfo;
    video_boot_args video;
    char *trustcache_filename;
    char *ticket_filename;
    BootMode boot_mode;
    uint32_t rtbuddyv2_protocol_version;
    uint32_t build_version;
    Notifier init_done_notifier;
    hwaddr panic_base;
    hwaddr panic_size;
    uint8_t pmgr_reg[0x100000];
    MemoryRegion amcc;
    uint8_t amcc_reg[0x100000];
    bool kaslr_off;
} T8030MachineState;
#endif
