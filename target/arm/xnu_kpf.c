#include "hw/arm/xnu.h"
#include "hw/arm/xnu_pf.h"

#define NOP 0xd503201f
#define RET 0xd65f03c0
#define RETAB 0xd65f0fff
#define PACIBSP 0xd503237f

static uint32_t *find_next_insn(uint32_t *from, uint32_t num, uint32_t insn, uint32_t mask)
{
    while (num) {
        if ((*from & mask) == (insn & mask)) {
            return from;
        }
        from++;
        num--;
    }

    /* not found */
    return NULL;
}

static uint32_t *find_prev_insn(uint32_t *from, uint32_t num, uint32_t insn, uint32_t mask)
{
    while (num) {
        if ((*from & mask) == (insn & mask)) {
            return from;
        }
        from--;
        num--;
    }

    /* not found */
    return NULL;
}

static bool kpf_apfs_rootauth(struct xnu_pf_patch *patch, uint32_t *opcode_stream)
{
    opcode_stream[0] = NOP;
    opcode_stream[1] = 0x52800000; /* mov w0, 0 */

    puts("KPF: found handle_eval_rootauth");
    return true;
}

static bool kpf_apfs_vfsop_mount(struct xnu_pf_patch *patch, uint32_t *opcode_stream)
{
    opcode_stream[0] = 0x52800000; /* mov w0, 0 */
    puts("KPF: found apfs_vfsop_mount");
    return true;
}

static void kpf_apfs_patches(xnu_pf_patchset_t *patchset)
{
    /*
     * This patch bypass root authentication
     * address for kernelcache.research.iphone12b of 15.0 (19A5261w)
     * handle_eval_rootauth:
     * 086040f9       ldr x8, [x0, 0xc0]
     * 08e14039       ldrb w8, [x8, 0x38]
     * 68002837       tbnz w8, 5, 0xfffffff0095ade9c <- find this
     * 000a8052       mov w0, 0x50 -> mov w0, 0
     * c0035fd6       ret
     * d5ccfd17       b  _authapfs_seal_is_broken_full
     */
    uint64_t matches[] = {
        0x37280068, // tbnz w8, 5, 0xc
        0x52800a00, // mov w0, 0x50
        0xd65f03c0  // ret
    };
    uint64_t masks[] = {
        0xffffffff,
        0xffffffff,
        0xffffffff
    };

    /* apfs_vfsop_mount:
     * This patch allows mount -urw /
     * vfs_flags() & MNT_ROOTFS
     * 0xfffffff009046d50      e0147037       tbnz w0, 0xe, 0xfffffff009046fec
     * 0xfffffff009046d54      e83b40b9       ldr w8, [sp, 0x38]  ; 5
     * 0xfffffff009046d58      08791f12       and w8, w8, 0xfffffffe
     * 0xfffffff009046d5c      e83b00b9       str w8, [sp, 0x38]
     */
    uint64_t matches2[] = {
        0x37700000, // tbnz w0, 0xe, *
        0xb94003a0, // ldr x*, [x29/sp, *]
        0x121f7800, // and w*, w*, 0xfffffffe
        0xb90003a0, // str x*, [x29/sp, *]
    };

    uint64_t masks2[] = {
        0xfff8001f,
        0xfffe03a0,
        0xfffffc00,
        0xffc003a0,
    };

    xnu_pf_maskmatch(patchset, "handle_eval_rootauth", matches, masks,
                     sizeof(masks) / sizeof(uint64_t), false,
                     (void *)kpf_apfs_rootauth);

    xnu_pf_maskmatch(patchset, "apfs_vfsop_mount", matches2, masks2,
                     sizeof(masks2) / sizeof(uint64_t), false,
                     (void *)kpf_apfs_vfsop_mount);
}

bool kpf_has_done_mac_mount;
static bool kpf_mac_mount_callback(struct xnu_pf_patch *patch, uint32_t *opcode_stream)
{
    puts("KPF: Found mac_mount");
    uint32_t *mac_mount = &opcode_stream[0];
    /* search for tbnz w*, 5, *
     * and nop it (enable MNT_UNION mounts)
     */
    uint32_t *mac_mount_1 = find_prev_insn(mac_mount, 0x40, 0x37280000, 0xfffe0000);

    if (!mac_mount_1) {
        mac_mount_1 = find_next_insn(mac_mount, 0x40, 0x37280000, 0xfffe0000);
    }
    if (!mac_mount_1) {
        kpf_has_done_mac_mount = false;
        puts("kpf_mac_mount_callback: failed to find NOP point");
        return false;
    }

    mac_mount_1[0] = NOP;
    /* search for ldrb w8, [x*, 0x71] */
    mac_mount_1 = find_prev_insn(mac_mount, 0x40, 0x3941c408, 0xfffffc1f);
    if (!mac_mount_1) {
        mac_mount_1 = find_next_insn(mac_mount, 0x40, 0x3941c408, 0xfffffc1f);
    }
    if (!mac_mount_1) {
        kpf_has_done_mac_mount = false;
        puts("kpf_mac_mount_callback: failed to find xzr point");
        return false;
    }

    /* replace with a mov x8, xzr */
    /* this will bypass the (vp->v_mount->mnt_flag & MNT_ROOTFS) check */
    mac_mount_1[0] = 0xaa1f03e8;
    kpf_has_done_mac_mount = true;
    xnu_pf_disable_patch(patch);

    puts("KPF: Found mac_mount");
    return true;
}

static void kpf_mac_mount_patch(xnu_pf_patchset_t *xnu_text_exec_patchset)
{
    /*
     * This patch makes sure that we can remount the rootfs and that we can UNION mount
     * we first search for a pretty unique instruction movz/orr w9, 0x1ffe
     * then we search for a tbnz w*, 5, * (0x20 is MNT_UNION) and nop it
     * After that we search for a ldrb w8, [x8, 0x71] and replace it with a movz x8, 0
     * at 0x70 there are the flags and MNT_ROOTFS is 0x00004000 -> 0x4000 >> 8 -> 0x40 -> bit 6 -> the check is right below
     * that way we can also perform operations on the rootfs
     */
    uint64_t matches[] = {
        0x321f2fe9, /* orr w9, wzr, 0x1ffe */
    };
    uint64_t masks[] = {
        0xFFFFFFFF,
    };

    xnu_pf_maskmatch(xnu_text_exec_patchset, "mac_mount_patch1",
                     matches, masks, sizeof(matches) / sizeof(uint64_t),
                     false, (void *)kpf_mac_mount_callback);
    matches[0] = 0x5283ffc9; /* movz w9, 0x1ffe */
    xnu_pf_maskmatch(xnu_text_exec_patchset, "mac_mount_patch2",
                     matches, masks, sizeof(matches) / sizeof(uint64_t),
                     false, (void *)kpf_mac_mount_callback);
}

void kpf(void)
{
    struct mach_header_64 *hdr = xnu_header;
    xnu_pf_patchset_t *xnu_text_exec_patchset = xnu_pf_patchset_create(XNU_PF_ACCESS_32BIT);
    g_autofree xnu_pf_range_t *text_exec_range = xnu_pf_section(hdr, "__TEXT_EXEC", "__text");
    struct mach_header_64 *first_kext = xnu_pf_get_first_kext(hdr);
    xnu_pf_patchset_t *apfs_patchset;
    struct mach_header_64 *apfs_header;
    g_autofree xnu_pf_range_t *apfs_text_exec_range;

    if (first_kext) {
        g_autofree xnu_pf_range_t *first_kext_text_exec_range = xnu_pf_section(first_kext, "__TEXT_EXEC", "__text");

        if (first_kext_text_exec_range) {
            uint64_t text_exec_end_real;
            uint64_t text_exec_end = text_exec_end_real = ((uint64_t) (text_exec_range->va)) + text_exec_range->size;
            uint64_t first_kext_p = ((uint64_t) (first_kext_text_exec_range->va));

            if (text_exec_end > first_kext_p
                && first_kext_text_exec_range->va > text_exec_range->va) {
                text_exec_end = first_kext_p;
            }

            text_exec_range->size -= text_exec_end_real - text_exec_end;
        }
    }

    apfs_patchset = xnu_pf_patchset_create(XNU_PF_ACCESS_32BIT);
    apfs_header = xnu_pf_get_kext_header(hdr, "com.apple.filesystems.apfs");
    apfs_text_exec_range = xnu_pf_section(apfs_header, "__TEXT_EXEC", "__text");

    kpf_apfs_patches(apfs_patchset);
    xnu_pf_apply(apfs_text_exec_range, apfs_patchset);
    xnu_pf_patchset_destroy(apfs_patchset);

    kpf_mac_mount_patch(xnu_text_exec_patchset);
    xnu_pf_apply(text_exec_range, xnu_text_exec_patchset);
    xnu_pf_patchset_destroy(xnu_text_exec_patchset);
}
