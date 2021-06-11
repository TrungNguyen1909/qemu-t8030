#include "hw/arm/xnu.h"
#include "hw/arm/xnu_pf.h"

xnu_pf_range_t *xnu_pf_range_from_va(uint64_t va, uint64_t size)
{
    xnu_pf_range_t *range = malloc(sizeof(xnu_pf_range_t));
    range->va = va;
    range->size = size;
    range->cacheable_base = ((uint8_t *)(va - g_virt_base + g_phys_slide + kCacheableView));
    return range;
}

xnu_pf_range_t *xnu_pf_segment(struct mach_header_64 *header, const char *segment_name)
{
    struct segment_command_64 *seg = macho_get_segment(header, segment_name);
    if (!seg) {
        return NULL;
    }

    if (header != xnu_header) {
        return xnu_pf_range_from_va(xnu_slide_value(xnu_header) + (0xffff000000000000 | seg->vmaddr), seg->filesize);
    }
    return xnu_pf_range_from_va(xnu_slide_hdr_va(header, seg->vmaddr), seg->filesize);
}

xnu_pf_range_t *xnu_pf_section(struct mach_header_64 *header, const char *segment_name, const char *section_name)
{
    struct segment_command_64 *seg = macho_get_segment(header, segment_name);
    if (!seg) {
        return NULL;
    }
    struct section_64 *sec = macho_get_section(seg, section_name);
    if (!sec) {
        return NULL;
    }

    if (header != xnu_header) {
        return xnu_pf_range_from_va(xnu_slide_value(xnu_header) + (0xffff000000000000 | sec->addr), sec->size);
    }

    return xnu_pf_range_from_va(xnu_slide_hdr_va(header, sec->addr), sec->size);
}

struct mach_header_64 *xnu_pf_get_first_kext(struct mach_header_64 *kheader)
{
    xnu_pf_range_t *kmod_start_range = xnu_pf_section(kheader, "__PRELINK_INFO", "__kmod_start");
    if (!kmod_start_range) {
        kmod_start_range = xnu_pf_section(kheader, "__PRELINK_TEXT", "__text");
        if (!kmod_start_range) {
            error_report("unsupported xnu");
        }
        struct mach_header_64 *rv = (struct mach_header_64 *)kmod_start_range->cacheable_base;
        free(kmod_start_range);
        return rv;
    }

    uint64_t *start = (uint64_t *)(kmod_start_range->cacheable_base);
    uint64_t kextb = xnu_slide_value(kheader) + (0xffff000000000000 | start[0]);

    free(kmod_start_range);
    return (struct mach_header_64 *)xnu_va_to_ptr(kextb);
}

struct mach_header_64 *xnu_pf_get_kext_header(struct mach_header_64 *kheader, const char *kext_bundle_id)
{
    xnu_pf_range_t *kmod_info_range = xnu_pf_section(kheader, "__PRELINK_INFO", "__kmod_info");
    if (!kmod_info_range) {
        char kname[256];
        xnu_pf_range_t *kext_info_range = xnu_pf_section(kheader, "__PRELINK_INFO", "__info");
        if (!kext_info_range) {
            error_report("unsupported xnu");
        }

        const char *prelinkinfo = strstr((const char *)kext_info_range->cacheable_base, "PrelinkInfoDictionary");
        const char *last_dict = strstr(prelinkinfo, "<array>") + 7;
        while (last_dict) {
            const char *end_dict = strstr(last_dict, "</dict>");
            if (!end_dict) {
                break;
            }

            const char *nested_dict = strstr(last_dict + 1, "<dict>");
            while (nested_dict) {
                if (nested_dict > end_dict) {
                    break;
                }

                nested_dict = strstr(nested_dict + 1, "<dict>");
                end_dict = strstr(end_dict + 1, "</dict>");
            }


            const char *ident = memmem(last_dict, end_dict - last_dict, "CFBundleIdentifier", strlen("CFBundleIdentifier"));
            if (ident) {
                const char *value = strstr(ident, "<string>");
                if (value) {
                    value += strlen("<string>");
                    const char *value_end = strstr(value, "</string>");
                    if (value_end) {
                        memcpy(kname, value, value_end - value);
                        kname[value_end - value] = 0;
                        if (strcmp(kname, kext_bundle_id) == 0) {
                            const char *addr = memmem(last_dict, end_dict - last_dict, "_PrelinkExecutableLoadAddr", strlen("_PrelinkExecutableLoadAddr"));
                            if (addr) {
                                const char *avalue = strstr(addr, "<integer");
                                if (avalue) {
                                    avalue = strstr(avalue, ">");
                                    if (avalue) {
                                        avalue++;
                                        free(kext_info_range);
                                        return xnu_va_to_ptr(xnu_slide_value(kheader) + strtoull(avalue, 0, 0));
                                    }
                                }
                            }
                        }
                    }
                }
            }

            last_dict = strstr(end_dict, "<dict>");
        }

        free(kext_info_range);
        return NULL;
    }
    xnu_pf_range_t *kmod_start_range = xnu_pf_section(kheader, "__PRELINK_INFO", "__kmod_start");
    if (!kmod_start_range) {
        return NULL;
    }

    uint64_t *info = (uint64_t *)(kmod_info_range->cacheable_base);
    uint64_t *start = (uint64_t *)(kmod_start_range->cacheable_base);
    uint32_t count = kmod_info_range->size / 8;
    for (uint32_t i = 0; i < count; i++) {
        const char *kext_name = (const char *)xnu_va_to_ptr(xnu_slide_value(kheader) + (0xffff000000000000 | info[i])) + 0x10;
        if (strcmp(kext_name, kext_bundle_id) == 0) {
            free(kmod_info_range);
            free(kmod_start_range);
            return (struct mach_header_64 *) xnu_va_to_ptr(xnu_slide_value(kheader) + (0xffff000000000000 | start[i]));
        }
    }

    free(kmod_info_range);
    free(kmod_start_range);
    return NULL;
}

void xnu_pf_apply_each_kext(struct mach_header_64 *kheader, xnu_pf_patchset_t *patchset)
{
    xnu_pf_range_t *kmod_start_range = xnu_pf_section(kheader, "__PRELINK_INFO", "__kmod_start");
    if (!kmod_start_range) {
        xnu_pf_range_t *kext_text_exec_range = xnu_pf_section(kheader, "__PLK_TEXT_EXEC", "__text");
        if (!kext_text_exec_range) {
            error_report("unsupported xnu");
        }
        xnu_pf_apply(kext_text_exec_range, patchset);
        free(kext_text_exec_range);
        return;
    }

    bool is_required = patchset->is_required;
    patchset->is_required = false;

    uint64_t *start = (uint64_t *)(kmod_start_range->cacheable_base);
    uint32_t count = kmod_start_range->size / 8;
    for (uint32_t i = 0; i < count; i++) {
        struct mach_header_64 *kexth = (struct mach_header_64 *)xnu_va_to_ptr(xnu_slide_value(kheader) + (0xffff000000000000 | start[i]));
        xnu_pf_range_t *apply_range = xnu_pf_section(kexth, "__TEXT_EXEC", "__text");
        if (apply_range) {
            xnu_pf_apply(apply_range, patchset);
            free(apply_range);
        }
    }
    free(kmod_start_range);

    patchset->is_required = is_required;
    if (is_required) {
        for (xnu_pf_patch_t *patch = patchset->patch_head; patch; patch = patch->next_patch) {
            if (patch->is_required && !patch->has_fired) {
                error_report("Missing patch: %s", patch->name);
            }
        }
    }
}

xnu_pf_range_t *xnu_pf_all(struct mach_header_64 *header)
{
    return NULL;
}

xnu_pf_range_t *xnu_pf_all_x(struct mach_header_64 *header)
{
    return NULL;
}

xnu_pf_patchset_t *xnu_pf_patchset_create(uint8_t pf_accesstype)
{
    xnu_pf_patchset_t *r = malloc(sizeof(xnu_pf_patchset_t));
    r->patch_head = NULL;
    r->accesstype = pf_accesstype;
    r->is_required = true;
    return r;
}

struct xnu_pf_maskmatch {
    xnu_pf_patch_t patch;
    uint32_t pair_count;
    uint64_t pairs[][2];
};

static inline bool xnu_pf_maskmatch_match_8(struct xnu_pf_maskmatch *patch, uint8_t access_type, uint8_t *preread, uint8_t *cacheable_stream)
{
    uint32_t count = patch->pair_count;
    for (uint32_t i = 0; i < count; i++) {
        if (count < 8) {
            if ((preread[i] & patch->pairs[i][1]) != patch->pairs[i][0]) {
                return false;
            }
        } else {
            if ((cacheable_stream[i] & patch->pairs[i][1]) != patch->pairs[i][0]) {
                return false;
            }
        }
    }
    return true;
}

static inline bool xnu_pf_maskmatch_match_16(struct xnu_pf_maskmatch *patch, uint8_t access_type, uint16_t *preread, uint16_t *cacheable_stream)
{
    uint32_t count = patch->pair_count;
    for (uint32_t i = 0; i < count; i++) {
        if (count < 8) {
            if ((preread[i] & patch->pairs[i][1]) != patch->pairs[i][0]) {
                return false;
            }
        } else {
            if ((cacheable_stream[i] & patch->pairs[i][1]) != patch->pairs[i][0]) {
                return false;
            }
        }
    }
    return true;
}

static inline bool xnu_pf_maskmatch_match_32(struct xnu_pf_maskmatch *patch, uint8_t access_type, uint32_t *preread, uint32_t *cacheable_stream)
{
    uint32_t count = patch->pair_count;
    for (uint32_t i = 0; i < count; i++) {
        if (count < 8) {
            if ((preread[i] & patch->pairs[i][1]) != patch->pairs[i][0]) {
                return false;
            }
        } else {
            if ((cacheable_stream[i] & patch->pairs[i][1]) != patch->pairs[i][0]) {
                return false;
            }
        }
    }
    return true;
}

static inline bool xnu_pf_maskmatch_match_64(struct xnu_pf_maskmatch *patch, uint8_t access_type, uint64_t *preread, uint64_t *cacheable_stream)
{
    uint32_t count = patch->pair_count;
    for (uint32_t i = 0; i < count; i++) {
        if (count < 8) {
            if ((preread[i] & patch->pairs[i][1]) != patch->pairs[i][0]) {
                return false;
            }
        } else {
            if ((cacheable_stream[i] & patch->pairs[i][1]) != patch->pairs[i][0]) {
                return false;
            }
        }
    }
    return true;
}

static void xnu_pf_maskmatch_match(struct xnu_pf_maskmatch *patch, uint8_t access_type, void *preread, void *cacheable_stream)
{
    bool val = false;
    switch (access_type) {
    case XNU_PF_ACCESS_8BIT:
        val = xnu_pf_maskmatch_match_8(patch, access_type, preread, cacheable_stream);
        break;
    case XNU_PF_ACCESS_16BIT:
        val = xnu_pf_maskmatch_match_16(patch, access_type, preread, cacheable_stream);
        break;
    case XNU_PF_ACCESS_32BIT:
        val = xnu_pf_maskmatch_match_32(patch, access_type, preread, cacheable_stream);
        break;
    case XNU_PF_ACCESS_64BIT:
        val = xnu_pf_maskmatch_match_64(patch, access_type, preread, cacheable_stream);
        break;
    default:
        break;
    }
    if (val) {
        if (patch->patch.pf_callback((struct xnu_pf_patch *)patch, cacheable_stream)) {
            patch->patch.has_fired = true;
        }
    }
}

struct xnu_pf_ptr_to_datamatch {
    xnu_pf_patch_t patch;
    void *data;
    size_t datasz;
    uint64_t slide;
    xnu_pf_range_t *range;
};

static void xnu_pf_ptr_to_data_match(struct xnu_pf_ptr_to_datamatch *patch, uint8_t access_type, void *preread, void *cacheable_stream)
{
    uint64_t pointer = *(uint64_t *)preread;
    pointer |= 0xffff000000000000;
    pointer += patch->slide;

    if (pointer >= patch->range->va && pointer < (patch->range->va + patch->range->size)) {
        if (memcmp(patch->data, (void *)(pointer - patch->range->va + patch->range->cacheable_base), patch->datasz) == 0) {
            if (patch->patch.pf_callback((struct xnu_pf_patch *)patch, cacheable_stream)) {
                patch->patch.has_fired = true;
            }
        }
    }
}

xnu_pf_patch_t *xnu_pf_maskmatch(xnu_pf_patchset_t *patchset, const char *name,
                                 uint64_t *matches, uint64_t *masks,
                                 uint32_t entryc, bool required,
                                 xnu_pf_patch_callback callback)
{
    /* Sanity check */
    for (uint32_t i = 0; i < entryc; i++) {
        if ((matches[i] & masks[i]) != matches[i]) {
            error_report("Bad maskmatch: %s (index %u)", name, i);
        }
    }

    struct xnu_pf_maskmatch *mm = malloc(sizeof(struct xnu_pf_maskmatch) + 16 * entryc);
    memset(mm, 0, sizeof(struct xnu_pf_maskmatch));
    mm->patch.should_match = true;
    mm->patch.pf_callback = (void *)callback;
    mm->patch.pf_match = (void *)xnu_pf_maskmatch_match;
    mm->patch.is_required = required;
    mm->patch.name = name;
    mm->pair_count = entryc;

    uint32_t loadc = entryc;
    if (loadc > 8) {
        loadc = 8;
    }

    for (uint32_t i = 0; i < entryc; i++) {
        mm->pairs[i][0] = matches[i];
        mm->pairs[i][1] = masks[i];
    }

    mm->patch.next_patch = patchset->patch_head;
    patchset->patch_head = &mm->patch;
    return &mm->patch;
}

xnu_pf_patch_t *xnu_pf_ptr_to_data(xnu_pf_patchset_t *patchset, uint64_t slide,
                                   xnu_pf_range_t *range,
                                   void *data, size_t datasz, bool required,
                                   xnu_pf_patch_callback callback)
{
    struct xnu_pf_ptr_to_datamatch *mm = malloc(sizeof(struct xnu_pf_ptr_to_datamatch));
    memset(mm, 0, sizeof(struct xnu_pf_ptr_to_datamatch));
    mm->patch.should_match = true;
    mm->patch.pf_callback = (void *)callback;
    mm->patch.pf_match = (void *)xnu_pf_ptr_to_data_match;
    mm->patch.is_required = required;

    mm->slide = slide;
    mm->range = range;
    mm->data = data;
    mm->datasz = datasz;

    mm->patch.next_patch = patchset->patch_head;
    patchset->patch_head = &mm->patch;
    return &mm->patch;
}

void xnu_pf_disable_patch(xnu_pf_patch_t *patch)
{
    if (!patch->should_match) {
        return;
    }
    patch->should_match = false;
}

void xnu_pf_enable_patch(xnu_pf_patch_t *patch)
{
    if (patch->should_match) {
        return;
    }
    patch->should_match = true;
}

static inline void xnu_pf_apply_8(xnu_pf_range_t *range, xnu_pf_patchset_t *patchset)
{
    uint8_t *stream = (uint8_t *)range->cacheable_base;
    uint8_t reads[8];
    uint32_t stream_iters = range->size;
    for (int i = 0; i < 8; i++) {
        reads[i] = stream[i];
    }
    for (uint32_t index = 0; index < stream_iters; index++) {
        xnu_pf_patch_t *patch = patchset->patch_head;

        while (patch) {
            if (patch->should_match) {
                patch->pf_match(patch, XNU_PF_ACCESS_8BIT, reads, &stream[index]);
            }
            patch = patch->next_patch;
        }

        for (int i = 0; i < 7; i++) {
            reads[i] = reads[i + 1];
        }
        reads[7] = stream[index + 8];
    }
}

static inline void xnu_pf_apply_16(xnu_pf_range_t *range, xnu_pf_patchset_t *patchset)
{
    uint16_t *stream = (uint16_t *)range->cacheable_base;
    uint16_t reads[8];
    uint32_t stream_iters = range->size >> 1;
    for (int i = 0; i < 8; i++) {
        reads[i] = stream[i];
    }
    for (uint32_t index = 0; index < stream_iters; index++) {
        xnu_pf_patch_t *patch = patchset->patch_head;

        while (patch) {
            if (patch->should_match) {
                patch->pf_match(patch, XNU_PF_ACCESS_16BIT, reads, &stream[index]);
            }
            patch = patch->next_patch;
        }

        for (int i = 0; i < 7; i++) {
            reads[i] = reads[i + 1];
        }
        reads[7] = stream[index + 8];
    }
}

static inline void xnu_pf_apply_32(xnu_pf_range_t *range, xnu_pf_patchset_t *patchset)
{
    uint32_t *stream = (uint32_t *)range->cacheable_base;
    uint32_t reads[8];
    uint32_t stream_iters = range->size >> 2;
    for (int i = 0; i < 8; i++) {
        reads[i] = stream[i];
    }
    for (uint32_t index = 0; index < stream_iters; index++) {
        xnu_pf_patch_t *patch = patchset->patch_head;

        while (patch) {
            if (patch->should_match) {
                patch->pf_match(patch, XNU_PF_ACCESS_32BIT, reads, &stream[index]);
            }
            patch = patch->next_patch;
        }

        for (int i = 0; i < 7; i++) {
            reads[i] = reads[i + 1];
        }
        reads[7] = stream[index + 8];
    }
}

static inline void xnu_pf_apply_64(xnu_pf_range_t *range, xnu_pf_patchset_t *patchset)
{
    uint64_t *stream = (uint64_t *)range->cacheable_base;
    uint64_t reads[8];
    uint32_t stream_iters = range->size >> 2;
    for (int i = 0; i < 8; i++) {
        reads[i] = stream[i];
    }
    for (uint32_t index = 0; index < stream_iters; index++) {
        xnu_pf_patch_t *patch = patchset->patch_head;

        while (patch) {
            if (patch->should_match) {
                patch->pf_match(patch, XNU_PF_ACCESS_64BIT, reads, &stream[index]);
            }
            patch = patch->next_patch;
        }

        for (int i = 0; i < 7; i++) {
            reads[i] = reads[i + 1];
        }
        reads[7] = stream[index + 8];
    }
}

void xnu_pf_apply(xnu_pf_range_t *range, xnu_pf_patchset_t *patchset)
{

    switch (patchset->accesstype) {
    case XNU_PF_ACCESS_8BIT:
        xnu_pf_apply_8(range, patchset);
        break;
    case XNU_PF_ACCESS_16BIT:
        xnu_pf_apply_16(range, patchset);
        break;
    case XNU_PF_ACCESS_32BIT:
        xnu_pf_apply_32(range, patchset);
        break;
    case XNU_PF_ACCESS_64BIT:
        xnu_pf_apply_64(range, patchset);
        break;
    default:
        break;
    }
    if (patchset->is_required) {
        for (xnu_pf_patch_t *patch = patchset->patch_head; patch; patch = patch->next_patch) {
            if (patch->is_required && !patch->has_fired) {
                error_report("Missing patch: %s", patch->name);
            }
        }
    }
}

void xnu_pf_patchset_destroy(xnu_pf_patchset_t *patchset)
{
    xnu_pf_patch_t *o_patch;
    xnu_pf_patch_t *patch = patchset->patch_head;
    while (patch) {
        o_patch = patch;
        patch = patch->next_patch;
        free(o_patch);
    }
    free(patchset);
}
