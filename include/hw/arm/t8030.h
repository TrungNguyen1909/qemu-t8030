/*
 * iPhone 11 - t8030
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

#define TYPE_T8030 "t8030"

#define TYPE_T8030_MACHINE MACHINE_TYPE_NAME(TYPE_T8030)

#define T8030_MACHINE(obj) \
    OBJECT_CHECK(T8030MachineState, (obj), TYPE_T8030_MACHINE)

#define T8030_CPREG_VAR_NAME(name) cpreg_##name
#define T8030_CPREG_VAR_DEF(name) uint64_t T8030_CPREG_VAR_NAME(name)

#define MAX_CPU 1
#define NUM_ECORE 2
#define NUM_PCORE 2
typedef struct
{
    MachineClass parent;
} T8030MachineClass;

typedef struct {
    ARMCPU* cpu;
    AddressSpace* nsas;
    MemoryRegion* impl_reg;
    uint32_t cpu_id;
    T8030_CPREG_VAR_DEF(ARM64_REG_HID11);
    T8030_CPREG_VAR_DEF(ARM64_REG_HID3);
    T8030_CPREG_VAR_DEF(ARM64_REG_HID5);
    T8030_CPREG_VAR_DEF(ARM64_REG_HID4);
    T8030_CPREG_VAR_DEF(ARM64_REG_EHID4);
    T8030_CPREG_VAR_DEF(ARM64_REG_HID8);
    T8030_CPREG_VAR_DEF(ARM64_REG_HID7);
    T8030_CPREG_VAR_DEF(ARM64_REG_LSU_ERR_STS);
    T8030_CPREG_VAR_DEF(PMC0);
    T8030_CPREG_VAR_DEF(PMC1);
    T8030_CPREG_VAR_DEF(PMCR1);
    T8030_CPREG_VAR_DEF(PMSR);
    T8030_CPREG_VAR_DEF(L2ACTLR_EL1);
    T8030_CPREG_VAR_DEF(ARM64_REG_APCTL_EL1);
    T8030_CPREG_VAR_DEF(ARM64_REG_KERNELKEYLO_EL1);
    T8030_CPREG_VAR_DEF(ARM64_REG_KERNELKEYHI_EL1);
    T8030_CPREG_VAR_DEF(S3_4_c15_c0_5);
    T8030_CPREG_VAR_DEF(S3_4_c15_c1_3);
    T8030_CPREG_VAR_DEF(S3_4_c15_c1_4);
    T8030_CPREG_VAR_DEF(ARM64_REG_IPI_SR);
    T8030_CPREG_VAR_DEF(ARM64_REG_CYC_OVRD);
    T8030_CPREG_VAR_DEF(ARM64_REG_ACC_CFG);
    T8030_CPREG_VAR_DEF(ARM64_REG_VMSA_LOCK_EL1);
    //SPRR
    T8030_CPREG_VAR_DEF(S3_6_c15_c1_0);
    T8030_CPREG_VAR_DEF(S3_6_c15_c1_1);
    T8030_CPREG_VAR_DEF(S3_6_c15_c1_2);
    T8030_CPREG_VAR_DEF(S3_6_c15_c1_5);
    T8030_CPREG_VAR_DEF(S3_6_c15_c1_6);
    T8030_CPREG_VAR_DEF(S3_6_c15_c1_7);
    T8030_CPREG_VAR_DEF(S3_6_c15_c3_0);
    T8030_CPREG_VAR_DEF(S3_6_c15_c3_1);
    T8030_CPREG_VAR_DEF(S3_6_c15_c8_0);
    T8030_CPREG_VAR_DEF(S3_6_c15_c8_1);
    T8030_CPREG_VAR_DEF(S3_6_c15_c8_2);
    T8030_CPREG_VAR_DEF(S3_6_c15_c8_3);
    T8030_CPREG_VAR_DEF(S3_6_c15_c9_1);
    T8030_CPREG_VAR_DEF(UPMPCM);
    T8030_CPREG_VAR_DEF(UPMCR0);
    T8030_CPREG_VAR_DEF(UPMSR);
} T8030CPU;

typedef struct {
    hwaddr base;
    uint32_t id;
    uint16_t type;
    MemoryRegion* mr;
} cluster;

typedef struct
{
    MachineState parent;
    hwaddr extra_data_pa;
    hwaddr kpc_pa;
    hwaddr kbootargs_pa;
    hwaddr soc_base_pa;
    hwaddr dram_base;
    unsigned long dram_size;
    T8030CPU cpus[MAX_CPU];
    cluster clusters[2];
    MemoryRegion* sysmem;
    MemoryRegion* tagmem;
    struct arm_boot_info bootinfo;
    char ramdisk_filename[1024];
    char kernel_filename[1024];
    char dtb_filename[1024];
    char driver_filename[1024];
    char kern_args[1024];
    FileMmioDev ramdisk_file_dev;
    DTBNode *device_tree;
    bool use_ramfb;
} T8030MachineState;

typedef struct
{
    uint8_t ramfb[RAMFB_SIZE];
} __attribute__((packed)) AllocatedData;

#endif
