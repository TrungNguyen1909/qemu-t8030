/*
 *
 * Copyright (c) 2019 Jonathan Afek <jonyafek@me.com>
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

#ifndef HW_ARM_XNU_H
#define HW_ARM_XNU_H

#include "qemu-common.h"
#include "hw/arm/boot.h"
#include "hw/arm/xnu_mem.h"
#include "hw/arm/xnu_dtb.h"
#include "hw/arm/xnu_file_mmio_dev.h"
#include "hw/arm/xnu_fb_cfg.h"

// pexpert/pexpert/arm64/boot.h
#define xnu_arm64_kBootArgsRevision2 2 /* added boot_args.bootFlags */
#define xnu_arm64_kBootArgsVersion2 2
#define xnu_arm64_BOOT_LINE_LENGTH 608

#define LC_SEGMENT_64   0x19
#define LC_UNIXTHREAD   0x5

struct segment_command_64
{
    uint32_t cmd;
    uint32_t cmdsize;
    char segname[16];
    uint64_t vmaddr;
    uint64_t vmsize;
    uint64_t fileoff;
    uint64_t filesize;
    uint32_t /*vm_prot_t*/ maxprot;
    uint32_t /*vm_prot_t*/ initprot;
    uint32_t nsects;
    uint32_t flags;
};

#define MACH_MAGIC_64   0xFEEDFACFu

struct mach_header_64 {
    uint32_t    magic;      /* mach magic number identifier */
    uint32_t /*cpu_type_t*/  cputype;    /* cpu specifier */
    uint32_t /*cpu_subtype_t*/   cpusubtype; /* machine specifier */
    uint32_t    filetype;   /* type of file */
    uint32_t    ncmds;      /* number of load commands */
    uint32_t    sizeofcmds; /* the size of all the load commands */
    uint32_t    flags;      /* flags */
    uint32_t    reserved;   /* reserved */
};

struct load_command {
    uint32_t cmd;       /* type of load command */
    uint32_t cmdsize;   /* total size of command in bytes */
};

typedef struct xnu_arm64_video_boot_args {
    unsigned long v_baseAddr; /* Base address of video memory */
    unsigned long v_display;  /* Display Code (if Applicable */
    unsigned long v_rowBytes; /* Number of bytes per pixel row */
    unsigned long v_width;    /* Width */
    unsigned long v_height;   /* Height */
    unsigned long v_depth;    /* Pixel Depth and other parameters */
} video_boot_args;

typedef struct xnu_arm64_monitor_boot_args {
	uint64_t	version;                        /* structure version - this is version 2 */
	uint64_t	virtBase;                       /* virtual base of memory assigned to the monitor */
	uint64_t	physBase;                       /* physical address corresponding to the virtual base */
	uint64_t	memSize;                        /* size of memory assigned to the monitor */
	uint64_t	kernArgs;                       /* physical address of the kernel boot_args structure */
	uint64_t	kernEntry;                      /* kernel entrypoint */
	uint64_t	kernPhysBase;                   /* physical base of the kernel's address space */
	uint64_t	kernPhysSlide;                  /* offset from kernPhysBase to kernel load address */
	uint64_t	kernVirtSlide;                  /* virtual slide applied to kernel at load time */
} monitor_boot_args;

struct xnu_arm64_boot_args {
    uint16_t           Revision;                                   /* Revision of boot_args structure */
    uint16_t           Version;                                    /* Version of boot_args structure */
    uint64_t           virtBase;                                   /* Virtual base of memory */
    uint64_t           physBase;                                   /* Physical base of memory */
    uint64_t           memSize;                                    /* Size of memory */
    uint64_t           topOfKernelData;                            /* Highest physical address used in kernel data area */
    video_boot_args    Video;                                      /* Video Information */
    uint32_t           machineType;                                /* Machine Type */
    uint64_t           deviceTreeP;                                /* Base of flattened device tree */
    uint32_t           deviceTreeLength;                           /* Length of flattened tree */
    char               CommandLine[xnu_arm64_BOOT_LINE_LENGTH];    /* Passed in command line */
    uint64_t           bootFlags;                                  /* Additional flags specified by the bootloader */
    uint64_t           memSizeActual;                              /* Actual size of memory */
};

void macho_file_highest_lowest(const char *filename, hwaddr *lowest,
                                    hwaddr *highest);

void macho_tz_setup_bootargs(const char *name, AddressSpace *as,
                             MemoryRegion *mem, hwaddr bootargs_addr,
                             hwaddr virt_base, hwaddr phys_base,
                             hwaddr mem_size, hwaddr kern_args,
                             hwaddr kern_entry, hwaddr kern_phys_base);

void macho_setup_bootargs(const char *name, AddressSpace *as,
                          MemoryRegion *mem, hwaddr bootargs_pa,
                          hwaddr virt_base, hwaddr phys_base, hwaddr mem_size,
                          hwaddr top_of_kernel_data_pa, hwaddr dtb_va,
                          hwaddr dtb_size, video_boot_args v_bootargs,
                          char *kern_args);

void arm_load_macho(char *filename, AddressSpace *as, MemoryRegion *mem,
                    const char *name, hwaddr phys_base, hwaddr virt_base, hwaddr *pc);

void macho_map_raw_file(const char *filename, AddressSpace *as, MemoryRegion *mem,
                         const char *name, hwaddr file_pa, uint64_t *size);

void macho_load_raw_file(const char *filename, AddressSpace *as, MemoryRegion *mem,
                         const char *name, hwaddr file_pa, uint64_t *size);
                         
DTBNode* load_dtb_from_file(char *filename);

void macho_load_dtb(DTBNode *root, AddressSpace *as, MemoryRegion *mem,
                    const char *name, hwaddr dtb_pa, uint64_t *size,
                    hwaddr ramdisk_addr, hwaddr ramdisk_size,
                    hwaddr trustcache_addr, hwaddr trustcache_size,
                    hwaddr dram_base, unsigned long dram_size);

void macho_load_trustcache(const char *filename, AddressSpace *as, MemoryRegion *mem,
                            hwaddr pa, uint64_t *size);
void macho_load_ramdisk(const char *filename, AddressSpace *as, MemoryRegion *mem,
                            hwaddr pa, uint64_t *size);
#endif
