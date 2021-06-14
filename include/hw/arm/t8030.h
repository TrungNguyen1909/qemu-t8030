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

#define MAX_CPU 6
#define MAX_CLUSTER 2
#define NUM_ECORE 2
#define NUM_PCORE 4
typedef struct
{
    MachineClass parent;
} T8030MachineClass;

typedef struct T8030CPUState{
    ARMCPU* cpu;
    AddressSpace* nsas;
    MemoryRegion* impl_reg;
    MemoryRegion* coresight_reg;
    MemoryRegion* memory;
    MemoryRegion* sysmem;
    MachineState* machine;
    uint32_t cpu_id;
    uint32_t phys_id;
    uint32_t cluster_id;
    uint64_t mpidr;
    uint64_t ipi_sr;
    qemu_irq fast_ipi;
    T8030_CPREG_VAR_DEF(ARM64_REG_EHID4);
    T8030_CPREG_VAR_DEF(ARM64_REG_EHID10);
    T8030_CPREG_VAR_DEF(ARM64_REG_HID0);
    T8030_CPREG_VAR_DEF(ARM64_REG_HID3);
    T8030_CPREG_VAR_DEF(ARM64_REG_HID4);
    T8030_CPREG_VAR_DEF(ARM64_REG_HID5);
    T8030_CPREG_VAR_DEF(ARM64_REG_HID7);
    T8030_CPREG_VAR_DEF(ARM64_REG_HID8);
    T8030_CPREG_VAR_DEF(ARM64_REG_HID9);
    T8030_CPREG_VAR_DEF(ARM64_REG_HID11);
    T8030_CPREG_VAR_DEF(ARM64_REG_HID13);
    T8030_CPREG_VAR_DEF(ARM64_REG_HID14);
    T8030_CPREG_VAR_DEF(ARM64_REG_HID16);
    T8030_CPREG_VAR_DEF(ARM64_REG_LSU_ERR_STS);
    T8030_CPREG_VAR_DEF(PMC0);
    T8030_CPREG_VAR_DEF(PMC1);
    T8030_CPREG_VAR_DEF(PMCR1);
    T8030_CPREG_VAR_DEF(PMSR);
    T8030_CPREG_VAR_DEF(ARM64_REG_APCTL_EL1);
    T8030_CPREG_VAR_DEF(ARM64_REG_KERNELKEYLO_EL1);
    T8030_CPREG_VAR_DEF(ARM64_REG_KERNELKEYHI_EL1);
    T8030_CPREG_VAR_DEF(S3_4_c15_c0_5);
    T8030_CPREG_VAR_DEF(S3_4_c15_c1_3);
    T8030_CPREG_VAR_DEF(S3_4_c15_c1_4);
    T8030_CPREG_VAR_DEF(ARM64_REG_CYC_OVRD);
    T8030_CPREG_VAR_DEF(ARM64_REG_ACC_CFG);
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
    T8030_CPREG_VAR_DEF(GXF_ENTER_EL1);
    T8030_CPREG_VAR_DEF(S3_6_c15_c8_2);
    T8030_CPREG_VAR_DEF(S3_6_c15_c8_3);
    //uncore
    T8030_CPREG_VAR_DEF(UPMPCM);
    T8030_CPREG_VAR_DEF(UPMCR0);
    T8030_CPREG_VAR_DEF(UPMSR);
    //ktrr
    T8030_CPREG_VAR_DEF(ARM64_REG_CTRR_A_LWR_EL1);
    T8030_CPREG_VAR_DEF(ARM64_REG_CTRR_A_UPR_EL1);
    T8030_CPREG_VAR_DEF(ARM64_REG_CTRR_CTL_EL1);
    T8030_CPREG_VAR_DEF(ARM64_REG_CTRR_LOCK_EL1);
} T8030CPUState;

#define MPIDR_AFF0_SHIFT 0
#define MPIDR_AFF0_WIDTH 8
#define MPIDR_AFF0_MASK  (((1 << MPIDR_AFF0_WIDTH) - 1) << MPIDR_AFF0_SHIFT)
#define MPIDR_AFF1_SHIFT 8
#define MPIDR_AFF1_WIDTH 8
#define MPIDR_AFF1_MASK  (((1 << MPIDR_AFF1_WIDTH) - 1) << MPIDR_AFF1_SHIFT)
#define MPIDR_AFF2_SHIFT 16
#define MPIDR_AFF2_WIDTH 8
#define MPIDR_AFF2_MASK  (((1 << MPIDR_AFF2_WIDTH) - 1) << MPIDR_AFF2_SHIFT)

#define MPIDR_CPU_ID(mpidr_el1_val)             (((mpidr_el1_val) & MPIDR_AFF0_MASK) >> MPIDR_AFF0_SHIFT)
#define MPIDR_CLUSTER_ID(mpidr_el1_val)         (((mpidr_el1_val) & MPIDR_AFF1_MASK) >> MPIDR_AFF1_SHIFT)

#define IPI_SR_SRC_CPU_SHIFT 8
#define IPI_SR_SRC_CPU_WIDTH 8
#define IPI_SR_SRC_CPU_MASK  (((1 << IPI_SR_SRC_CPU_WIDTH) - 1) << IPI_SR_SRC_CPU_SHIFT)
#define IPI_SR_SRC_CPU(ipi_sr_val)         (((ipi_sr_val) & IPI_SR_SRC_CPU_MASK) >> IPI_SR_SRC_CPU_SHIFT)

#define IPI_RR_TARGET_CLUSTER_SHIFT 16
#define ARM64_REG_IPI_RR_TYPE_IMMEDIATE (0 << 28)
#define ARM64_REG_IPI_RR_TYPE_RETRACT   (1 << 28)
#define ARM64_REG_IPI_RR_TYPE_DEFERRED  (2 << 28)
#define ARM64_REG_IPI_RR_TYPE_NOWAKE    (3 << 28)

typedef struct {
    QemuMutex mutex;
    hwaddr base;
    uint8_t id;
    uint8_t type;
    MemoryRegion* mr;
    MachineState* machine;
    T8030CPUState* cpus[MAX_CPU];
    int deferredIPI[MAX_CPU][MAX_CPU];
    int noWakeIPI[MAX_CPU][MAX_CPU];
    uint64_t tick;
} cluster;

#define kDeferredIPITimerDefault 64000

typedef struct
{
    MachineState parent;
    hwaddr extra_data_pa;
    hwaddr kpc_pa;
    hwaddr kbootargs_pa;
    hwaddr soc_base_pa;
    hwaddr soc_size;
    hwaddr dram_base;
    unsigned long dram_size;
    T8030CPUState* cpus[MAX_CPU];
    cluster* clusters[MAX_CLUSTER];
    QEMUTimer* ipicr_timer;
    uint64_t ipi_cr;
    //store the pending IPI_SR value
    uint64_t pendingIPI[MAX_CPU];
    bool pendingWakeup[MAX_CPU];
    SysBusDevice* aic;
    MemoryRegion* sysmem;
    struct arm_boot_info bootinfo;
    char ramdisk_filename[1024];
    char kernel_filename[1024];
    char dtb_filename[1024];
    char driver_filename[1024];
    char trustcache_filename[1024];
    char kern_args[1024];
    FileMmioDev ramdisk_file_dev;
    struct mach_header_64 *kernel;
    DTBNode *device_tree;
    bool use_ramfb;
    QemuMutex mutex;
    uint32_t build_version;
} T8030MachineState;

typedef struct
{
    uint8_t ramfb[RAMFB_SIZE];
} __attribute__((packed)) AllocatedData;

#define NSEC_PER_USEC   1000ull         /* nanoseconds per microsecond */
#define USEC_PER_SEC    1000000ull      /* microseconds per second */
#define NSEC_PER_SEC    1000000000ull   /* nanoseconds per second */
#define NSEC_PER_MSEC   1000000ull      /* nanoseconds per millisecond */
#define RTCLOCK_SEC_DIVISOR     24000000ull

static void
absolutetime_to_nanoseconds(uint64_t   abstime,
    uint64_t * result)
{
	uint64_t        t64;

	*result = (t64 = abstime / RTCLOCK_SEC_DIVISOR) * NSEC_PER_SEC;
	abstime -= (t64 * RTCLOCK_SEC_DIVISOR);
	*result += (abstime * NSEC_PER_SEC) / RTCLOCK_SEC_DIVISOR;
}

static void
nanoseconds_to_absolutetime(uint64_t   nanosecs,
    uint64_t * result)
{
	uint64_t        t64;

	*result = (t64 = nanosecs / NSEC_PER_SEC) * RTCLOCK_SEC_DIVISOR;
	nanosecs -= (t64 * NSEC_PER_SEC);
	*result += (nanosecs * RTCLOCK_SEC_DIVISOR) / NSEC_PER_SEC;
}
#endif
