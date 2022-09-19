/*
 * iPhone 6s - s8000
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

#ifndef HW_ARM_S8000_H
#define HW_ARM_S8000_H

#include "qemu/osdep.h"
#include "exec/hwaddr.h"
#include "hw/boards.h"
#include "hw/arm/boot.h"
#include "hw/arm/xnu.h"
#include "exec/memory.h"
#include "cpu.h"
#include "sysemu/kvm.h"
#include "hw/cpu/cluster.h"
#include "hw/arm/apple_a9.h"

#define TYPE_S8000 "s8000"

#define TYPE_S8000_MACHINE MACHINE_TYPE_NAME(TYPE_S8000)

#define S8000_MACHINE(obj) \
    OBJECT_CHECK(S8000MachineState, (obj), TYPE_S8000_MACHINE)

typedef struct
{
    MachineClass parent;
} S8000MachineClass;

typedef struct
{
    MachineState parent;
    hwaddr soc_base_pa;
    hwaddr soc_size;

    unsigned long dram_size;
    AppleA9State *cpus[A9_MAX_CPU];
    CPUClusterState cluster;
    SysBusDevice *aic;
    MemoryRegion *sysmem;
    struct mach_header_64 *kernel;
    DTBNode *device_tree;
    struct macho_boot_info bootinfo;
    video_boot_args video;
    uint32_t build_version;
    Notifier init_done_notifier;
    hwaddr panic_base;
    hwaddr panic_size;
    char pmgr_reg[0x100000];
    bool force_dfu;
} S8000MachineState;
#endif
