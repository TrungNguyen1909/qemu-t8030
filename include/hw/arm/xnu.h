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

#include "qemu/osdep.h"
#include "hw/arm/boot.h"
#include "hw/arm/xnu_mem.h"
#include "hw/arm/xnu_dtb.h"

// pexpert/pexpert/arm64/boot.h
#define xnu_arm64_kBootArgsRevision2 2 /* added boot_args.bootFlags */
#define xnu_arm64_kBootArgsVersion2 2
#define xnu_arm64_BOOT_LINE_LENGTH 608

#define LC_UNIXTHREAD       0x5
#define LC_SEGMENT_64       0x19
#define LC_SOURCE_VERSION   0x2A
#define LC_BUILD_VERSION    0x32

struct segment_command_64 { /* for 64-bit architectures */
    uint32_t    cmd;        /* LC_SEGMENT_64 */
    uint32_t    cmdsize;    /* includes sizeof section_64 structs */
    char        segname[16];/* segment name */
    uint64_t    vmaddr;     /* memory address of this segment */
    uint64_t    vmsize;     /* memory size of this segment */
    uint64_t    fileoff;    /* file offset of this segment */
    uint64_t    filesize;   /* amount to map from the file */
    uint32_t    maxprot;    /* maximum VM protection */
    uint32_t    initprot;   /* initial VM protection */
    uint32_t    nsects;     /* number of sections in segment */
    uint32_t    flags;      /* flags */
};
struct section_64 { /* for 64-bit architectures */
    char        sectname[16];   /* name of this section */
    char        segname[16];    /* segment this section goes in */
    uint64_t    addr;           /* memory address of this section */
    uint64_t    size;           /* size in bytes of this section */
    uint32_t    offset;         /* file offset of this section */
    uint32_t    align;          /* section alignment (power of 2) */
    uint32_t    reloff;         /* file offset of relocation entries */
    uint32_t    nreloc;         /* number of relocation entries */
    uint32_t    flags;          /* flags (section type and attributes)*/
    uint32_t    reserved1;      /* reserved (for offset or index) */
    uint32_t    reserved2;      /* reserved (for count or sizeof) */
    uint32_t    reserved3;      /* reserved */
};
struct source_version_command {
    uint32_t  cmd;  /* LC_SOURCE_VERSION */
    uint32_t  cmdsize;  /* 16 */
    uint64_t  version;  /* A.B.C.D.E packed as a24.b10.c10.d10.e10 */
};

#define PLATFORM_MACOS 1
#define PLATFORM_IOS 2
#define PLATFORM_TVOS 3
#define PLATFORM_WATCHOS 4
#define PLATFORM_BRIDGEOS 5

#define BUILD_VERSION_MAJOR(_v) ((_v) & 0xffff0000) >> 16
#define BUILD_VERSION_MINOR(_v) ((_v) & 0x0000ff00) >> 8

struct build_version_command {
    uint32_t    cmd;        /* LC_BUILD_VERSION */
    uint32_t    cmdsize;    /* sizeof(struct build_version_command) plus */
                            /* ntools * sizeof(struct build_tool_version) */
    uint32_t    platform;   /* platform */
    uint32_t    minos;      /* X.Y.Z is encoded in nibbles xxxx.yy.zz */
    uint32_t    sdk;        /* X.Y.Z is encoded in nibbles xxxx.yy.zz */
    uint32_t    ntools;     /* number of tool entries following this */
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

extern struct mach_header_64 *xnu_header;

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
    uint64_t    version;                        /* structure version - this is version 2 */
    uint64_t    virtBase;                       /* virtual base of memory assigned to the monitor */
    uint64_t    physBase;                       /* physical address corresponding to the virtual base */
    uint64_t    memSize;                        /* size of memory assigned to the monitor */
    uint64_t    kernArgs;                       /* physical address of the kernel boot_args structure */
    uint64_t    kernEntry;                      /* kernel entrypoint */
    uint64_t    kernPhysBase;                   /* physical base of the kernel's address space */
    uint64_t    kernPhysSlide;                  /* offset from kernPhysBase to kernel load address */
    uint64_t    kernVirtSlide;                  /* virtual slide applied to kernel at load time */
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

#define kCacheableView 0x400000000ULL

struct mach_header_64 *macho_load_file(const char *filename);

struct mach_header_64 *macho_parse(uint8_t *data, uint32_t len);

uint8_t *macho_get_buffer(struct mach_header_64 *hdr);

void macho_free(struct mach_header_64 *hdr);

uint32_t macho_build_version(struct mach_header_64 *mh);

uint32_t macho_platform(struct mach_header_64 *mh);

char *macho_platform_string(struct mach_header_64 *mh);

void macho_highest_lowest(struct mach_header_64 *mh, uint64_t *lowaddr,
                          uint64_t *highaddr);

void macho_text_base(struct mach_header_64 *mh, uint64_t *text_base);

struct segment_command_64* macho_get_segment(struct mach_header_64* header, const char* segname);

struct section_64 *macho_get_section(struct segment_command_64 *seg, const char *name);

uint64_t xnu_slide_hdr_va(struct mach_header_64 *header, uint64_t hdr_va);

uint64_t xnu_slide_value(struct mach_header_64 *header);

void *xnu_va_to_ptr(uint64_t va);

uint64_t xnu_ptr_to_va(void *ptr);

uint64_t xnu_rebase_va(uint64_t va);

uint64_t kext_rebase_va(uint64_t va);

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

hwaddr arm_load_macho(struct mach_header_64 *mh, AddressSpace *as, MemoryRegion *mem,
                      const char *name, hwaddr phys_base, hwaddr virt_base);

void macho_map_raw_file(const char *filename, AddressSpace *as, MemoryRegion *mem,
                         const char *name, hwaddr file_pa, uint64_t *size);

void macho_load_raw_file(const char *filename, AddressSpace *as, MemoryRegion *mem,
                         const char *name, hwaddr file_pa, uint64_t *size);

DTBNode *load_dtb_from_file(char *filename);

void macho_load_dtb(DTBNode *root, AddressSpace *as, MemoryRegion *mem,
                    const char *name, hwaddr dtb_pa, uint64_t *size,
                    hwaddr ramdisk_addr, hwaddr ramdisk_size,
                    hwaddr trustcache_addr, hwaddr trustcache_size,
                    hwaddr bootargs_addr,
                    hwaddr dram_base, unsigned long dram_size,
                    void* nvram_data, unsigned long nvram_size);

void macho_load_trustcache(const char *filename, AddressSpace *as, MemoryRegion *mem,
                            hwaddr pa, uint64_t *size);
void macho_load_ramdisk(const char *filename, AddressSpace *as, MemoryRegion *mem,
                            hwaddr pa, uint64_t *size);
#endif
