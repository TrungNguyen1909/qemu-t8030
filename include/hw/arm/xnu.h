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


#define	LC_SYMTAB           0x2
#define LC_UNIXTHREAD       0x5
#define	LC_DYSYMTAB         0xb
#define LC_SEGMENT_64       0x19
#define LC_SOURCE_VERSION   0x2A
#define LC_BUILD_VERSION    0x32
#define LC_REQ_DYLD         0x80000000
#define LC_DYLD_CHAINED_FIXUPS (0x34 | LC_REQ_DYLD) /* used with linkedit_data_command */
#define LC_FILESET_ENTRY      (0x35 | LC_REQ_DYLD) /* used with fileset_entry_command */

struct symtab_command {
	uint32_t	cmd;		/* LC_SYMTAB */
	uint32_t	cmdsize;	/* sizeof(struct symtab_command) */
	uint32_t	symoff;		/* symbol table offset */
	uint32_t	nsyms;		/* number of symbol table entries */
	uint32_t	stroff;		/* string table offset */
	uint32_t	strsize;	/* string table size in bytes */
};

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

#define SECTION_TYPE         0x000000ff /* 256 section types */
#define S_NON_LAZY_SYMBOL_POINTERS  0x6 /* section with only non-lazy
                                           symbol pointers */

struct fileset_entry_command {
    uint32_t        cmd;        /* LC_FILESET_ENTRY */
    uint32_t        cmdsize;    /* includes id string */
    uint64_t        vmaddr;     /* memory address of the dylib */
    uint64_t        fileoff;    /* file offset of the dylib */
    uint32_t        entry_id;   /* contained entry id */
    uint32_t        reserved;   /* entry_id is 32-bits long, so this is the reserved padding */
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

/* constants for the filetype field of mach_header_64 */
#define MH_EXECUTE      0x2
#define MH_FILESET      0xc

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

struct nlist_64 {
    union {
        uint32_t  n_strx; /* index into the string table */
    } n_un;
    uint8_t n_type;        /* type flag, see below */
    uint8_t n_sect;        /* section number or NO_SECT */
    uint16_t n_desc;       /* see <mach-o/stab.h> */
    uint64_t n_value;      /* value of this symbol (or stab offset) */
};

#define	N_STAB	0xe0  /* if any of these bits set, a symbolic debugging entry */
#define	N_PEXT	0x10  /* private external symbol bit */
#define	N_TYPE	0x0e  /* mask for the type bits */
#define	N_EXT	0x01  /* external symbol bit, set for external symbols */


typedef struct xnu_arm64_video_boot_args {
    unsigned long v_baseAddr; /* Base address of video memory */
    unsigned long v_display;  /* Display Code (if Applicable */
    unsigned long v_rowBytes; /* Number of bytes per pixel row */
    unsigned long v_width;    /* Width */
    unsigned long v_height;   /* Height */
    unsigned long v_depth;    /* Pixel Depth and other parameters */
} video_boot_args;

typedef struct xnu_arm64_monitor_boot_args {
    uint64_t    version;         /* structure version - this is version 2 */
    uint64_t    virtBase;        /* virtual base of memory assigned to the monitor */
    uint64_t    physBase;        /* physical address corresponding to the virtual base */
    uint64_t    memSize;         /* size of memory assigned to the monitor */
    uint64_t    kernArgs;        /* physical address of the kernel boot_args structure */
    uint64_t    kernEntry;       /* kernel entrypoint */
    uint64_t    kernPhysBase;    /* physical base of the kernel's address space */
    uint64_t    kernPhysSlide;   /* offset from kernPhysBase to kernel load address */
    uint64_t    kernVirtSlide;   /* virtual slide applied to kernel at load time */
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

#define EMBEDDED_PANIC_HEADER_OSVERSION_LEN                      32
#define EMBEDDED_PANIC_HEADER_FLAG_COREDUMP_COMPLETE             0x01
#define EMBEDDED_PANIC_HEADER_FLAG_STACKSHOT_SUCCEEDED           0x02
#define EMBEDDED_PANIC_HEADER_FLAG_STACKSHOT_FAILED_DEBUGGERSYNC 0x04
#define EMBEDDED_PANIC_HEADER_FLAG_STACKSHOT_FAILED_ERROR        0x08
#define EMBEDDED_PANIC_HEADER_FLAG_STACKSHOT_FAILED_INCOMPLETE   0x10
#define EMBEDDED_PANIC_HEADER_FLAG_STACKSHOT_FAILED_NESTED       0x20
#define EMBEDDED_PANIC_HEADER_FLAG_NESTED_PANIC                  0x40
#define EMBEDDED_PANIC_HEADER_FLAG_BUTTON_RESET_PANIC            0x80
#define EMBEDDED_PANIC_HEADER_FLAG_COPROC_INITIATED_PANIC        0x100
#define EMBEDDED_PANIC_HEADER_FLAG_COREDUMP_FAILED               0x200
#define EMBEDDED_PANIC_HEADER_FLAG_COMPRESS_FAILED               0x400
#define EMBEDDED_PANIC_HEADER_FLAG_STACKSHOT_DATA_COMPRESSED     0x800

#define EMBEDDED_PANIC_HEADER_CURRENT_VERSION 2
#define EMBEDDED_PANIC_MAGIC 0x46554E4B /* FUNK */
struct QEMU_PACKED xnu_embedded_panic_header {
    uint32_t eph_magic;                /* EMBEDDED_PANIC_MAGIC if valid */
    uint32_t eph_crc;                  /* CRC of everything following the ph_crc in the header and the contents */
    uint32_t eph_version;              /* embedded_panic_header version */
    uint64_t eph_panic_flags;          /* Flags indicating any state or relevant details */
    uint32_t eph_panic_log_offset;     /* Offset of the beginning of the panic log from the beginning of the header */
    uint32_t eph_panic_log_len;        /* length of the panic log */
    uint32_t eph_stackshot_offset;     /* Offset of the beginning of the panic stackshot from the beginning of the header */
    uint32_t eph_stackshot_len;        /* length of the panic stackshot (0 if not valid ) */
    uint32_t eph_other_log_offset;     /* Offset of the other log (any logging subsequent to the stackshot) from the beginning of the header */
    uint32_t eph_other_log_len;        /* length of the other log */
    union {
        struct {
            uint64_t eph_x86_power_state:8,
                eph_x86_efi_boot_state:8,
                eph_x86_system_state:8,
                eph_x86_unused_bits:40;
        }; // anonymous struct to group the bitfields together.
        uint64_t eph_x86_do_not_use; /* Used for offsetof/sizeof when parsing header */
    };
    char eph_os_version[EMBEDDED_PANIC_HEADER_OSVERSION_LEN];
    char eph_macos_version[EMBEDDED_PANIC_HEADER_OSVERSION_LEN];
};

typedef struct QEMU_PACKED xnu_iop_segment_range {
    uint64_t phys;
    uint64_t virt;
    uint64_t remap;
    uint32_t size;
    uint32_t flag;
} xnu_iop_segment_range;

#define XNU_MAX_NVRAM_SIZE  (0xFFFF * 0x10)
#define XNU_BNCH_SIZE       (32)

typedef struct macho_boot_info {
    hwaddr entry;
    hwaddr dtb_pa;
    uint64_t dtb_size;
    hwaddr ramdisk_pa;
    uint64_t ramdisk_size;
    hwaddr trustcache_pa;
    uint64_t trustcache_size;
    hwaddr bootargs_pa;
    hwaddr dram_base;
    uint64_t dram_size;
    uint8_t nvram_data[XNU_MAX_NVRAM_SIZE];
    uint64_t nvram_size;
    char *ticket_data;
    uint64_t ticket_length;
    uint8_t boot_nonce_hash[XNU_BNCH_SIZE];
} *macho_boot_info_t;

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

struct fileset_entry_command *macho_get_fileset(struct mach_header_64 *header, const char *entry);

struct mach_header_64 *macho_get_fileset_header(struct mach_header_64 *header, const char *entry);

struct segment_command_64* macho_get_segment(struct mach_header_64* header, const char* segname);

struct section_64 *macho_get_section(struct segment_command_64 *seg, const char *name);

uint64_t xnu_slide_hdr_va(struct mach_header_64 *header, uint64_t hdr_va);

uint64_t xnu_slide_value(struct mach_header_64 *header);

void *xnu_va_to_ptr(uint64_t va);

uint64_t xnu_ptr_to_va(void *ptr);

uint64_t xnu_rebase_va(uint64_t va);

uint64_t kext_rebase_va(uint64_t va);

bool xnu_contains_boot_arg(const char *bootArgs, const char *arg, bool prefixmatch);

void macho_setup_bootargs(const char *name, AddressSpace *as,
                          MemoryRegion *mem, hwaddr bootargs_pa,
                          hwaddr virt_base, hwaddr phys_base, hwaddr mem_size,
                          hwaddr top_of_kernel_data_pa, hwaddr dtb_va,
                          hwaddr dtb_size, video_boot_args v_bootargs,
                          const char *cmdline);

void macho_allocate_segment_records(DTBNode *memory_map,
                                    struct mach_header_64 *mh);

hwaddr arm_load_macho(struct mach_header_64 *mh, AddressSpace *as, MemoryRegion *mem,
                      DTBNode *memory_map, hwaddr phys_base, hwaddr virt_slide);

void macho_map_raw_file(const char *filename, AddressSpace *as, MemoryRegion *mem,
                         const char *name, hwaddr file_pa, uint64_t *size);

void macho_load_raw_file(const char *filename, AddressSpace *as, MemoryRegion *mem,
                         const char *name, hwaddr file_pa, uint64_t *size);

DTBNode *load_dtb_from_file(char *filename);

void macho_populate_dtb(DTBNode *root, macho_boot_info_t info);

void macho_load_dtb(DTBNode *root, AddressSpace *as, MemoryRegion *mem,
                    const char *name, macho_boot_info_t info);

uint8_t *load_trustcache_from_file(const char *filename, uint64_t *size);
void macho_load_trustcache(void *trustcache, uint64_t size,
                           AddressSpace *as, MemoryRegion *mem, hwaddr pa);

void macho_load_ramdisk(const char *filename, AddressSpace *as, MemoryRegion *mem,
                            hwaddr pa, uint64_t *size);
#endif
