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

static bool kpf_amfi_callback(struct xnu_pf_patch *patch, uint32_t *opcode_stream)
{
    /* possibly AMFI patch
     * this is here to patch out the trustcache checks
     *  so that AMFI thinks that everything is in trustcache
     * there are two different versions of the trustcache function
     *  either it's just a leaf that's branched to or it's a function with a real prolog
     * the first portion of this function here will try to detect the prolog
     *  and if it fails has_frame will be false
     * if that's the case it will just make it return null
     *  otherwise it has to respect the epilog so it will search for all the movs
     *  that move into x0 and then turn them into a movz x0, 1
     */
    char has_frame = 0;
    for (int x = 0; x < 128; x++) {
        uint32_t opcde = opcode_stream[-x];
        if (opcde == RET || opcde == RETAB
            /* unconditional branch */
            || (opcde & 0xfc000000) == 0x14000000
            || (opcde & 0xfc000000) == 0x94000000) {
            break;
        }
        if (opcde == PACIBSP
            /*ldp/stp???*/
            || (opcde & 0x3e000000) == 0x28000000
            || (opcde & 0x3e000000) == 0x2c000000) {
            has_frame = 1;
            break;
        }
    }
    if (!has_frame) {
        puts("KPF: Found AMFI (Leaf)");
        opcode_stream[0] = 0xd2800020;
        opcode_stream[1] = RET;
    } else {
        bool found_something = false;
        uint32_t *patchpoint = NULL;
        uint32_t *retpoint = find_next_insn(&opcode_stream[0], 0x180, RETAB, 0xffffffff);

        if (retpoint == NULL) {
            retpoint = find_next_insn(&opcode_stream[0], 0x180, RET, 0xffffffff);
        }
        if (retpoint == NULL) {
            puts("kpf_amfi_callback: failed to find retpoint");
            return false;
        }

        patchpoint = find_next_insn(retpoint, 0x40, 0x32000000, 0xff80001f);
        /* __PPLTEXT:__text:0xfffffff0097eded4      00010032       orr w0, w8, 1 */
        if (patchpoint != NULL) {
            patchpoint[0] = 0xd2800020;
            found_something = true;
        }

        patchpoint = find_prev_insn(retpoint, 0x40, 0xAA0003E0, 0xffe0ffff);
        /* __TEXT_EXEC:__text:FFFFFFF007CDDFDC      E00313AA       MOV X0, X19 */
        if (patchpoint != NULL) {
            patchpoint[0] = 0xd2800020;
            found_something = true;
        }

        patchpoint = find_prev_insn(retpoint, 0x40, 0x52800000, 0xffffffff);
        /* __PPLTEXT:__text:0xfffffff0097edeac      00008052       mov w0, 0 */
        if (patchpoint != NULL) {
            patchpoint[0] = 0xd2800020;
            found_something = true;
        }

        if (!found_something) {
            puts("kpf_amfi_callback: failed to find anything");
            return false;
        }
        puts("KPF: Found AMFI (Routine)");
    }
    return true;
}

static void kpf_amfi_patch(xnu_pf_patchset_t *xnu_text_exec_patchset)
{
    /* This patch leads to AMFI believing that everything is in trustcache
     * this is done by searching for the sequence below (example from an iPhone 7, 13.3):
     * 0xfffffff0072382b0      29610091       add x9, x9, 0x18
     * 0xfffffff0072382b4      ca028052       movz w10, 0x16
     * 0xfffffff0072382b8      0bfd41d3       lsr x11, x8, 1
     * 0xfffffff0072382bc      6c250a9b       madd x12, x11, x10, x9
     * then the callback checks if this is just a leaf instead of a full routinue
     * if it's a leave it will just replace the above with a movz x0,1;ret
     * if it isn't a leaf it searches for all the places where a return happens
     *  and patches them to return true
     * To find the patch in r2 use:
     * /x 0000009100028052000000d30000009b:000000FF00FFFFFF000000FF000000FF
     */
    uint64_t matches[] = {
            0x91000000, // add x*
            0x52800200, // mov w*, 0x16
            0xd3000000, // lsr *
            0x9b000000  // madd *
    };
    uint64_t masks[] = {
            0xFF000000,
            0xFFFFFF00,
            0xFF000000,
            0xFF000000
    };
    xnu_pf_maskmatch(xnu_text_exec_patchset, "amfi_patch", matches, masks,
                     sizeof(matches)/sizeof(uint64_t), true, (void *)kpf_amfi_callback);
}

static bool kpf_amfi_sha1(struct xnu_pf_patch *patch, uint32_t *opcode_stream)
{
    uint32_t* cmp = find_next_insn(opcode_stream, 0x10, 0x7100081f, 0xFFFFFFFF); /* cmp w0, 2 */
    if (!cmp) {
        puts("kpf_amfi_sha1: failed to find cmp");
        return false;
    }
    puts("KPF: Found AMFI hashtype check");
    xnu_pf_disable_patch(patch);
    *cmp = 0x6b00001f; /* cmp w0, w0 */
    return true;
}

static void kpf_amfi_kext_patches(xnu_pf_patchset_t *patchset)
{
    /* this patch allows us to run binaries with SHA1 signatures
     * this is done by searching for the sequence below
     *  and then finding the cmp w0, 2 (hashtype) and turning that into a cmp w0, w0
     * Example from i7 13.3:
     * 0xfffffff005f36b30      2201d036       tbz w2, 0x1a, 0xfffffff005f36b54
     * 0xfffffff005f36b34      f30305aa       mov x19, x5
     * 0xfffffff005f36b38      f40304aa       mov x20, x4
     * 0xfffffff005f36b3c      f50303aa       mov x21, x3
     * 0xfffffff005f36b40      f60300aa       mov x22, x0
     * 0xfffffff005f36b44      e00301aa       mov x0, x1
     * 0xfffffff005f36b48      a1010094       bl sym.stub._csblob_get_hashtype
     * 0xfffffff005f36b4c      1f080071       cmp w0, 2
     * 0xfffffff005f36b50      61000054       b.ne 0xfffffff005f36b5c
     * to find this in r2 run (make sure to check if the address is aligned):
     * /x 0200d036:1f00f8ff
     */
    uint64_t i_matches[] = {
            0x36d00002, // tbz w2, 0x1a, *
    };
    uint64_t i_masks[] = {
            0xfff8001f,
    };
    xnu_pf_maskmatch(patchset, "amfi_sha1", i_matches, i_masks,
                     sizeof(i_matches)/sizeof(uint64_t), true, (void *)kpf_amfi_sha1);
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

static bool kpf_aksuc_handle(struct xnu_pf_patch *patch, uint32_t *opcode_stream)
{
    uint32_t *frame = NULL;
    uint32_t *start = NULL;
    bool pac = false;

    // Most reliable marker of a stack frame seems to be "add x29, sp, 0x...".
    frame = find_prev_insn(opcode_stream, 200, 0x910003fd, 0xff8003ff);
    if(!frame) return false;

    // Now find the insn that decrements sp. This can be either
    // "stp ..., ..., [sp, -0x...]!" or "sub sp, sp, 0x...".
    // Match top bit of imm on purpose, since we only want negative offsets.
    start = find_prev_insn(frame, 10, 0xa9a003e0, 0xffe003e0);
    if(!start) start = find_prev_insn(frame, 10, 0xd10003ff, 0xff8003ff);
    if(!start) return false;

    pac = find_prev_insn(start, 5, PACIBSP, 0xffffffff) != NULL;

   start[0] = 0x52800000; /* MOV W0, 0 */
   start[1] = (pac ? RETAB : RET);

   fprintf(stderr, "KPF: Found AppleKeyStoreUserClient::handleUserClientCommandGated\n");
   return true;
}

static void kpf_aks_kext_patches(xnu_pf_patchset_t *patchset)
{
    /* TODO: SEP
     * AppleKeyStoreUserClient::handleUserClientCommandGated:
     * Example from iPhone 11, iOS 14.0b5 (18A5351d)
     * 0xfffffff008f6f83c      57588052       mov w23, 0x2c2
     * 0xfffffff008f6f840      1700bc72       movk w23, 0xe000, lsl 16
     * 0xfffffff008f6f844      1fae01f1       cmp x16, 0x6b
     * 0xfffffff008f6f848      10929f9a       csel x16, x16, xzr, ls
     * 0xfffffff008f6f84c      b1ac0210       adr x17, 0xfffffff008f74de0
     */
    uint64_t i_matches[] = {
            0x52805840, /* mov x*, 0x2c2 */
            0x72bc0000, /* movk w*, 0xe000, lsl 16 */
            0xf100001f, /* cmp x*, #* */
            0x9a809000, /* csel x*, x*, x*, LS */
            0x10000000, /* adr x*, * */
    };
    uint64_t i_masks[] = {
            0xffffffe0,
            0xffffffe0,
            0xffc0001f,
            0xffe0fc00,
            0xff000000,
    };
    xnu_pf_maskmatch(patchset, "AKSUC_handle", i_matches, i_masks,
                     sizeof(i_matches)/sizeof(uint64_t), true, (void *)kpf_aksuc_handle);
}

void kpf(void)
{
    struct mach_header_64 *hdr = xnu_header;
    xnu_pf_patchset_t *xnu_text_exec_patchset = xnu_pf_patchset_create(XNU_PF_ACCESS_32BIT);
    g_autofree xnu_pf_range_t *text_exec_range = xnu_pf_section(hdr, "__TEXT_EXEC", "__text");
    xnu_pf_patchset_t *xnu_ppl_text_patchset = xnu_pf_patchset_create(XNU_PF_ACCESS_32BIT);
    g_autofree xnu_pf_range_t *ppltext_exec_range = xnu_pf_section(hdr, "__PPLTEXT", "__text");
    struct mach_header_64 *first_kext = xnu_pf_get_first_kext(hdr);

    xnu_pf_patchset_t *apfs_patchset;
    struct mach_header_64 *apfs_header;
    g_autofree xnu_pf_range_t *apfs_text_exec_range;

    struct mach_header_64 *amfi_header;
    xnu_pf_patchset_t *amfi_patchset;
    g_autofree xnu_pf_range_t *amfi_text_exec_range;

    struct mach_header_64 *aks_header;
    xnu_pf_patchset_t *aks_patchset;
    g_autofree xnu_pf_range_t *aks_text_exec_range;

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

    amfi_patchset = xnu_pf_patchset_create(XNU_PF_ACCESS_32BIT);
    amfi_header = xnu_pf_get_kext_header(hdr, "com.apple.driver.AppleMobileFileIntegrity");
    amfi_text_exec_range = xnu_pf_section(amfi_header, "__TEXT_EXEC", "__text");
    kpf_amfi_kext_patches(amfi_patchset);
    xnu_pf_apply(amfi_text_exec_range, amfi_patchset);
    xnu_pf_patchset_destroy(amfi_patchset);

    kpf_amfi_patch(xnu_text_exec_patchset);
    kpf_mac_mount_patch(xnu_text_exec_patchset);
    xnu_pf_apply(text_exec_range, xnu_text_exec_patchset);
    xnu_pf_patchset_destroy(xnu_text_exec_patchset);

    kpf_amfi_patch(xnu_ppl_text_patchset);
    xnu_pf_apply(ppltext_exec_range, xnu_ppl_text_patchset);
    xnu_pf_patchset_destroy(xnu_ppl_text_patchset);

    aks_patchset = xnu_pf_patchset_create(XNU_PF_ACCESS_32BIT);
    aks_header = xnu_pf_get_kext_header(hdr, "com.apple.driver.AppleSEPKeyStore");
    aks_text_exec_range = xnu_pf_section(aks_header, "__TEXT_EXEC", "__text");
    kpf_aks_kext_patches(aks_patchset);
    xnu_pf_apply(aks_text_exec_range, aks_patchset);
    xnu_pf_patchset_destroy(aks_patchset);
}
