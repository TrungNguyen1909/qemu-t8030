#ifndef HW_ARM_XNU_PF_H
#define HW_ARM_XNU_PF_H

#include "hw/arm/xnu.h"
typedef struct xnu_pf_range {
    uint64_t va;
    uint64_t size;
    uint8_t *cacheable_base;
} xnu_pf_range_t;

struct xnu_pf_patchset;

typedef struct xnu_pf_patch {
    bool (*pf_callback)(struct xnu_pf_patch *patch, void *cacheable_stream);
    bool is_required;
    bool has_fired;
    bool should_match;
    void (*pf_match)(struct xnu_pf_patch *patch, uint8_t access_type, void *preread, void *cacheable_stream);
    struct xnu_pf_patch *next_patch;
    uint8_t pf_data[0];
    const char  *name;

    //            patch->pf_match(XNU_PF_ACCESS_32BIT, reads, &stream[index], &dstream[index]);

} xnu_pf_patch_t;

typedef bool (*xnu_pf_patch_callback)(struct xnu_pf_patch *patch, void *cacheable_stream);

typedef struct xnu_pf_patchset {
    xnu_pf_patch_t *patch_head;
    uint64_t p0;
    uint8_t accesstype;
    bool is_required;
} xnu_pf_patchset_t;

#define XNU_PF_ACCESS_8BIT 0x8
#define XNU_PF_ACCESS_16BIT 0x10
#define XNU_PF_ACCESS_32BIT 0x20
#define XNU_PF_ACCESS_64BIT 0x40

xnu_pf_range_t *xnu_pf_range_from_va(uint64_t va, uint64_t size);

xnu_pf_range_t *xnu_pf_segment(struct mach_header_64 *header, const char *segment_name);

xnu_pf_range_t *xnu_pf_section(struct mach_header_64 *header, const char *segment, const char *section_name);

xnu_pf_range_t *xnu_pf_all(struct mach_header_64 *header);

xnu_pf_range_t *xnu_pf_all_x(struct mach_header_64 *header);

void xnu_pf_disable_patch(xnu_pf_patch_t *patch);

void xnu_pf_enable_patch(xnu_pf_patch_t *patch);

struct mach_header_64 *xnu_pf_get_first_kext(struct mach_header_64 *kheader);

xnu_pf_patch_t *xnu_pf_ptr_to_data(xnu_pf_patchset_t *patchset, uint64_t slide,
                                   xnu_pf_range_t *range, void *data, size_t datasz,
                                   bool required, xnu_pf_patch_callback callback);

xnu_pf_patch_t *xnu_pf_maskmatch(xnu_pf_patchset_t *patchset, const char *name,
                                 uint64_t *matches, uint64_t *masks, uint32_t entryc,
                                 bool required, xnu_pf_patch_callback callback);

void xnu_pf_apply(xnu_pf_range_t *range, xnu_pf_patchset_t *patchset);

xnu_pf_patchset_t *xnu_pf_patchset_create(uint8_t pf_accesstype);

void xnu_pf_patchset_destroy(xnu_pf_patchset_t *patchset);

struct mach_header_64 *xnu_pf_get_kext_header(struct mach_header_64 *kheader, const char *kext_bundle_id);

void xnu_pf_apply_each_kext(struct mach_header_64 *kheader, xnu_pf_patchset_t *patchset);

void kpf(void);
#endif
