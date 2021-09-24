#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>

#include <pongo.h>

#include <asm/asm.h>
#include <common/common.h>
#include <pf/offsets.h>
#include <pf/pf_common.h>

uint64_t g_kalloc_external_addr = 0;
uint64_t g_kfree_ext_addr = 0;

/* Confirmed working 14.0 - 15.0 */
bool kalloc_external_finder_14(xnu_pf_patch_t *patch, void *cacheable_stream){
    /* We've landed somewhere inside AMFI, kalloc_external is the
     * branch six instructions down */
    xnu_pf_disable_patch(patch);

    uint32_t *opcode_stream = cacheable_stream;
    uint32_t *kalloc_external = get_branch_dst_ptr(opcode_stream + 6);

    g_kalloc_external_addr = xnu_ptr_to_va(kalloc_external);

    printf("%s: kalloc_external @ %#llx\n", __func__,g_kalloc_external_addr-kernel_slide);
    puts("xnuspy: found kalloc_external");

    return true;
}

/* Confirmed working 14.0 - 15.0 */
bool kfree_ext_finder_14(xnu_pf_patch_t *patch, void *cacheable_stream){
    /* For 14.x, we've landed somewhere in mach_gss_accept_sec_context,
     * kfree_ext is the branch three instructions down.
     *
     * For 15.x, the matches/masks get two hits, but in both cases, the
     * branch to kfree_ext is four instructions down. */
    xnu_pf_disable_patch(patch);

    uint32_t *opcode_stream = cacheable_stream;

    uint32_t limit = 8;
    for (int i = 0; i < limit; i++){
        if ((opcode_stream[i] & 0xfc000000) == 0x94000000){
            uint32_t *kfree_ext = get_branch_dst_ptr(opcode_stream + i);

            g_kfree_ext_addr = xnu_ptr_to_va(kfree_ext);
            printf("%s: kfree_ext @ %#llx\n", __func__,g_kfree_ext_addr-kernel_slide);

            puts("xnuspy: found kfree_ext");
            return true;
        }
    }

    return false;
}

/* confirmed working 14.0-14.6 */
bool ExceptionVectorsBase_finder_14(xnu_pf_patch_t *patch,
        void *cacheable_stream){
    xnu_pf_disable_patch(patch);

    uint32_t *opcode_stream = cacheable_stream;

    g_ExceptionVectorsBase_stream = cacheable_stream;

    uint32_t limit = PAGE_SIZE / sizeof(uint32_t);

    /* go backwords one opcode, we'll hit the stream of values that clang
     * decided to page align ExceptionVectorsBase with */
    opcode_stream--;

    uintptr_t orig_opcode_stream = (uintptr_t)opcode_stream;
    uint32_t filler_opcode = *opcode_stream;

    /* go backwords until we hit an instruction */
    while(limit-- != 0){
        uint32_t cur = *opcode_stream;

        if(cur != filler_opcode)
            break;

        opcode_stream--;
    }

    /* get off this instruction, now we point to the beginning of unused
     * executable code */
    opcode_stream++;

    g_exec_scratch_space_size = orig_opcode_stream - (uintptr_t)opcode_stream;
    g_exec_scratch_space_addr = xnu_ptr_to_va(opcode_stream);

    puts("xnuspy: found unused executable code");

    return true;
}

/* confirmed working 14.0-14.6 */
bool sysctl__kern_children_and_register_oid_finder_14(xnu_pf_patch_t *patch,
        void *cacheable_stream){
    xnu_pf_disable_patch(patch);

    /* We've landed inside corecrypto_kext_start. There's a stream of
     * ADRP, BL _sysctl_register_oid right above where we are. I know that the
     * first ADRP in this stream is how we can get sysctl__kern_children, so
     * let's find the beginning. Search up, looking for STUR X8, [X29, n] */
    uint32_t *opcode_stream = cacheable_stream;
    uint32_t limit = 500;

    while((*opcode_stream & 0xffe00fff) != 0xf80003a8){
        if(limit-- == 0)
            return false;

        opcode_stream--;
    }

    /* Now we're on the STUR. The first ADRP,BL pair is actually a kprintf
     * call, so skip the next four instructions */
    opcode_stream += 4;

    g_sysctl__kern_children_addr = *(uint64_t *)get_pc_rel_target(opcode_stream);
    g_sysctl__kern_children_addr |= ((uint64_t)0xffff << 48);
    g_sysctl__kern_children_addr = kext_rebase_va(g_sysctl__kern_children_addr);

    uint32_t *sysctl_register_oid = get_branch_dst_ptr(opcode_stream + 2);

    g_sysctl_register_oid_addr = xnu_ptr_to_va(sysctl_register_oid);
    
    puts("xnuspy: found sysctl__kern_children");
    puts("xnuspy: found sysctl_register_oid");

    return true;
}

/* confirmed working 14.0-14.6 */
bool lck_grp_alloc_init_finder_14(xnu_pf_patch_t *patch,
        void *cacheable_stream){
    xnu_pf_disable_patch(patch);

    uint32_t *opcode_stream = cacheable_stream;

    uint32_t *lck_grp_alloc_init = get_branch_dst_ptr(opcode_stream + 15);

    g_lck_grp_alloc_init_addr = xnu_ptr_to_va(lck_grp_alloc_init);

    puts("xnuspy: found lck_grp_alloc_init");

    return true;
}

/* confirmed working 14.0-14.6 */
bool lck_rw_alloc_init_finder_14(xnu_pf_patch_t *patch,
        void *cacheable_stream){
    xnu_pf_disable_patch(patch);

    uint32_t *opcode_stream = cacheable_stream;

    uint32_t *lck_rw_alloc_init = get_branch_dst_ptr(opcode_stream);

    g_lck_rw_alloc_init_addr = xnu_ptr_to_va(lck_rw_alloc_init);

    puts("xnuspy: found lck_rw_alloc_init");

    return true;
}

/* confirmed working on all KTRR kernels 14.0-14.6 */
bool ktrr_lockdown_patcher_14(xnu_pf_patch_t *patch, void *cacheable_stream){
    /* This also hits rorgn_lockdown, where the AMCC CTRR patches are,
     * but it's easier for me to separate them since the instruction
     * sequences are so different */
    static int count = 1;
    uint32_t *opcode_stream = cacheable_stream;

    *opcode_stream = 0xd503201f;
    opcode_stream[1] = 0xd503201f;
    opcode_stream[3] = 0xd503201f;

    if(count == 2){
        xnu_pf_disable_patch(patch);
        puts("xnuspy: disabled KTRR MMU lockdown");
    }

    count++;

    return true;
}

/* confirmed working on all KTRR kernels 14.0-14.6 */
bool amcc_ctrr_lockdown_patcher_14(xnu_pf_patch_t *patch,
        void *cacheable_stream){
    /* On 14.x A10+ there doesn't seem to be a specific lock for
     * RoRgn, instead we've got these AMCC CTRR registers. We are
     * patching three of them: lock, enable, and write-disable. See
     * find_lock_group_data and rorgn_lockdown for more info. */
    static int count = 1;
    uint32_t *opcode_stream = cacheable_stream;

    /* str w0, [x16, x17] --> str wzr, [x16, x17] */
    opcode_stream[5] = 0xb8316a1f;

    if(count == 3){
        xnu_pf_disable_patch(patch);
        puts("xnuspy: disabled AMCC CTRR MMU lockdown");
    }

    count++;

    return true;
}

/* confirmed working 14.0-14.6 */
bool name2oid_and_its_dependencies_finder_14(xnu_pf_patch_t *patch,
        void *cacheable_stream){
    /* This finds name2oid and three other things:
     *      sysctl_geometry_lock (needs to be held when we call name2oid)
     *      lck_rw_lock_shared
     *      lck_rw_done
     *
     * We are currently sitting on a branch to lck_rw_lock_shared.
     * The first ADRP we see before this point is getting the address
     * of sysctl_geometry_lock. Four instructions down is a branch to
     * name2oid, and seven instructions down is a branch to lck_rw_done.
     */
    xnu_pf_disable_patch(patch);

    bool already_found = g_lck_rw_lock_shared_addr != 0;

    uint32_t *opcode_stream = cacheable_stream;

    uint32_t *lck_rw_lock_shared = get_branch_dst_ptr(opcode_stream);
    uint32_t *name2oid = get_branch_dst_ptr(opcode_stream + 4);
    uint32_t *lck_rw_done = get_branch_dst_ptr(opcode_stream + 7);

    /* Find the first ADRP or ADR before this point */
    uint32_t instr_limit = 20;

    while((*opcode_stream & 0x1f000000) != 0x10000000){
        if(instr_limit-- == 0)
            return false;

        opcode_stream--;
    }

    uint32_t *sysctl_geometry_lock_addr = (uint32_t *)get_pc_rel_target(opcode_stream);

    g_sysctl_geometry_lock_addr = xnu_ptr_to_va(sysctl_geometry_lock_addr);
    g_lck_rw_lock_shared_addr = xnu_ptr_to_va(lck_rw_lock_shared);
    g_name2oid_addr = xnu_ptr_to_va(name2oid);
    g_lck_rw_done_addr = xnu_ptr_to_va(lck_rw_done);

    if(!already_found)
        puts("xnuspy: found lck_rw_lock_shared");

    puts("xnuspy: found name2oid");
    puts("xnuspy: found lck_rw_done");
    puts("xnuspy: found sysctl_geometry_lock");

    return true;
}
