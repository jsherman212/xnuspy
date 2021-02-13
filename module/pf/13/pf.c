#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/sysctl.h>

#include "../offsets.h"
#include "../pf_common.h"

#include "../../common/asm.h"
#include "../../common/common.h"
#include "../../common/pongo.h"

uint64_t g_sysent_addr = 0;
uint64_t g_kalloc_canblock_addr = 0;
uint64_t g_kfree_addr_addr = 0;
uint64_t g_sysctl__kern_children_addr = 0;
uint64_t g_sysctl_register_oid_addr = 0;
uint64_t g_sysctl_handle_long_addr = 0;
uint64_t g_name2oid_addr = 0;
uint64_t g_sysctl_geometry_lock_addr = 0;
uint64_t g_lck_rw_done_addr = 0;
uint64_t g_h_s_c_sbn_branch_addr = 0;
uint64_t g_h_s_c_sbn_epilogue_addr = 0;
uint64_t g_lck_grp_alloc_init_addr = 0;
uint64_t g_lck_rw_alloc_init_addr = 0;
uint64_t g_exec_scratch_space_addr = 0;
/* don't count the first opcode */
uint64_t g_exec_scratch_space_size = -sizeof(uint32_t);
uint32_t *g_ExceptionVectorsBase_stream = NULL;
uint64_t g_bcopy_phys_addr = 0;
uint64_t g_phystokv_addr = 0;
uint64_t g_copyin_addr = 0;
uint64_t g_copyout_addr = 0;
uint64_t g_IOSleep_addr = 0;
uint64_t g_kprintf_addr = 0;
uint64_t g_vm_map_unwire_addr = 0;
uint64_t g_vm_deallocate_addr = 0;
uint64_t g_kernel_map_addr = 0;
uint64_t g_kernel_thread_start_addr = 0;
uint64_t g_thread_deallocate_addr = 0;
uint64_t g_mach_make_memory_entry_64_addr = 0;
uint64_t g_offsetof_struct_thread_map = 0;
uint64_t g_current_proc_addr = 0;
uint64_t g_proc_list_lock_addr = 0;
uint64_t g_proc_ref_locked_addr = 0;
uint64_t g_proc_list_mlock_addr = 0;
uint64_t g_lck_mtx_unlock_addr = 0;
uint64_t g_proc_rele_locked_addr = 0;
uint64_t g_proc_uniqueid_addr = 0;
uint64_t g_proc_pid_addr = 0;
uint64_t g_allproc_addr = 0;
uint64_t g_lck_rw_lock_shared_addr = 0;
uint64_t g_lck_rw_lock_shared_to_exclusive_addr = 0;
uint64_t g_lck_rw_lock_exclusive_addr = 0;
uint64_t g_vm_map_wire_external_addr = 0;
uint64_t g_mach_vm_map_external_addr = 0;
uint64_t g_ipc_port_release_send_addr = 0;
uint64_t g_lck_rw_free_addr = 0;
uint64_t g_lck_grp_free_addr = 0;
int g_patched_doprnt_hide_pointers = 0;
uint64_t g_copyinstr_addr = 0;
uint64_t g_thread_terminate_addr = 0;
int g_patched_pinst_set_tcr = 0;
int g_patched_all_msr_tcr_el1_x18;
uint64_t g_snprintf_addr;
uint64_t g_strlen_addr;
uint64_t g_proc_name_addr;
uint64_t g_strncmp_addr;
uint64_t g_memset_addr;
uint64_t g_memmove_addr;
uint64_t g_memcmp_addr;
uint64_t g_strnstr_addr;
uint64_t g_panic_addr;
uint64_t g_xnuspy_sysctl_mib_ptr = 0;
uint64_t g_xnuspy_sysctl_mib_count_ptr = 0;
uint64_t g_xnuspy_ctl_callnum = 0;

/* confirmed working on all kernels 13.0-14.4 */
bool sysent_finder_13(xnu_pf_patch_t *patch, void *cacheable_stream){
    uint32_t *opcode_stream = cacheable_stream;

    /* if we're in the right place, sysent will be the first ADRP/ADD
     * pair we find when we go forward */
    uint32_t instr_limit = 10;

    while((*opcode_stream & 0x9f000000) != 0x90000000){
        if(instr_limit-- == 0)
            return false;

        opcode_stream++;
    }

    /* make sure this is actually sysent. to do this, we can check if
     * the first entry is the indirect system call */
    uint64_t maybe_sysent = get_pc_rel_target(opcode_stream);

    if(*(uint64_t *)maybe_sysent != 0 &&
            *(uint64_t *)(maybe_sysent + 0x8) == 0 &&
            *(uint32_t *)(maybe_sysent + 0x10) == 1 &&
            *(uint16_t *)(maybe_sysent + 0x14) == 0 &&
            *(uint16_t *)(maybe_sysent + 0x16) == 0){
        xnu_pf_disable_patch(patch);

        g_sysent_addr = maybe_sysent;

        puts("xnuspy: found sysent");

        return true;
    }

    return false;
}

/* confirmed working on all kernels 13.0-13.7 */
bool kalloc_canblock_finder_13(xnu_pf_patch_t *patch, void *cacheable_stream){
    uint32_t *opcode_stream = cacheable_stream;

    /* if we're in the right place, we should find kalloc_canblock's prologue
     * no more than 10 instructions before
     *
     * looking for sub sp, sp, n
     */
    uint32_t instr_limit = 10;

    while((*opcode_stream & 0xffc003ff) != 0xd10003ff){
        if(instr_limit-- == 0)
            return false;

        opcode_stream--;
    }

    xnu_pf_disable_patch(patch);

    g_kalloc_canblock_addr = xnu_ptr_to_va(opcode_stream);

    puts("xnuspy: found kalloc_canblock");

    return true;
}

/* confirmed working on all kernels 13.0-13.7 */
bool kfree_addr_finder_13(xnu_pf_patch_t *patch, void *cacheable_stream){
    xnu_pf_disable_patch(patch);

    uint32_t *opcode_stream = cacheable_stream;

    /* Find kfree_addr's prologue, looking for sub sp, sp, n */
    uint32_t instr_limit = 200;

    while((*opcode_stream & 0xffc003ff) != 0xd10003ff){
        if(instr_limit-- == 0)
            return false;

        opcode_stream--;
    }

    g_kfree_addr_addr = xnu_ptr_to_va(opcode_stream);

    puts("xnuspy: found kfree_addr");

    return true;
}

/* confirmed working on all kernels 13.0-13.7 */
bool ExceptionVectorsBase_finder_13(xnu_pf_patch_t *patch,
        void *cacheable_stream){
    /* According to XNU source, _ExceptionVectorsBase is page aligned. We're
     * going to abuse that fact and use the executable free space before
     * it to write our code.
     *
     * For all the devices I've tested this with, the free space before
     * _ExceptionVectorsBase is filled with NOPs, but I don't want to assume
     * that will be the case for all kernels. The exc_vectors_table will be
     * before _ExceptionVectorsBase, so I'll search up until I hit something
     * which looks like a kernel pointer.
     *
     * see osfmk/arm64/locore.s inside XNU source
     */
    xnu_pf_disable_patch(patch);

    uint32_t *opcode_stream = cacheable_stream;

    g_ExceptionVectorsBase_stream = cacheable_stream;

    uint32_t limit = PAGE_SIZE / 4;
    bool got_exc_vectors_table = false;

    while(limit-- != 0){
        uint32_t cur = *opcode_stream;

        /* in case of tagged pointers */
        cur |= (0xffff << 16);

        if(cur == 0xfffffff0){
            got_exc_vectors_table = true;
            break;
        }

        g_exec_scratch_space_size += sizeof(uint32_t);
        opcode_stream--;
    }

    if(!got_exc_vectors_table){
        puts("xnuspy: didn't find");
        puts("     exc_vectors_table?");

        xnuspy_fatal_error();
    }

    /* we're currently at the upper 32 bits of the last pointer in
     * exc_vectors_table */
    opcode_stream++;

    g_exec_scratch_space_size -= sizeof(uint32_t);
    g_exec_scratch_space_addr = xnu_ptr_to_va(opcode_stream);

    puts("xnuspy: found unused executable code");

    return true;
}

/* confirmed working on all kernels 13.0-13.7 */
bool sysctl__kern_children_finder_13(xnu_pf_patch_t *patch,
        void *cacheable_stream){
    uint32_t *opcode_stream = cacheable_stream;

    xnu_pf_disable_patch(patch);

    /* we should have landed right inside _kmeminit.
     *
     * The ADRP X20, n or ADR X20, n will lead us to sysctl__kern_children.
     */
    /* advance to the ADRP X20, n or ADR X20 */
    opcode_stream += 2;

    g_sysctl__kern_children_addr = *(uint64_t *)get_pc_rel_target(opcode_stream);

    /* Always untag, no need for a branch */
    g_sysctl__kern_children_addr |= ((uint64_t)0xffff << 48);
    g_sysctl__kern_children_addr = xnu_rebase_va(g_sysctl__kern_children_addr);

    puts("xnuspy: found sysctl__kern_children");

    return true;
}

/* confirmed working on all kernels 13.0-13.7 */
bool sysctl_register_oid_finder_13(xnu_pf_patch_t *patch,
        void *cacheable_stream){
    xnu_pf_disable_patch(patch);

    uint32_t *opcode_stream = cacheable_stream;

    /* the BL we matched is guarenteed to be sysctl_register_oid */
    uint32_t *sysctl_register_oid = get_branch_dst_ptr(opcode_stream + 5);

    g_sysctl_register_oid_addr = xnu_ptr_to_va(sysctl_register_oid);

    puts("xnuspy: found sysctl_register_oid");

    return true;
}

/* confirmed working on all kernels 13.0-14.4 */
bool sysctl_handle_long_finder_13(xnu_pf_patch_t *patch,
        void *cacheable_stream){
    uint32_t *opcode_stream = cacheable_stream;

    xnu_pf_disable_patch(patch);

    /* The patchfinder landed us at sysctl_handle_long or sysctl_handle_quad,
     * whichever came first in the kernelcache, because these functions are
     * pretty much identical. Both of them can act as sysctl_handle_long and
     * be fine. */
    g_sysctl_handle_long_addr = xnu_ptr_to_va(opcode_stream);

    puts("xnuspy: found sysctl_handle_long");

    return true;
}

/* confirmed working on all kernels 13.0-14.4 */
bool name2oid_and_its_dependencies_finder_13(xnu_pf_patch_t *patch,
        void *cacheable_stream){
    uint32_t *opcode_stream = cacheable_stream;

    /* This finds name2oid and two other things:
     *      sysctl_geometry_lock (needs to be held when we call name2oid)
     *      lck_rw_done
     *
     * I can only do a maskmatch with 8 matches/masks, but I need 10.
     * Those last two matches differentiate the right/wrong place because
     * the first 8 matches/masks match two places in the kernel. I'll just
     * manually check if the two instrs after the 8 we just matched are LDR/BL
     */
    uint32_t eigth = opcode_stream[8];
    uint32_t ninth = opcode_stream[9];

    if((eigth & 0xffc0001f) != 0xf9400000 && (ninth & 0xfc000000) != 0x94000000)
        return false;

    xnu_pf_disable_patch(patch);

    uint32_t *sysctl_geometry_lock_addr = (uint32_t *)get_pc_rel_target(opcode_stream);
    uint32_t *name2oid = get_branch_dst_ptr(opcode_stream + 6);
    uint32_t *lck_rw_done = get_branch_dst_ptr(opcode_stream + 9);

    g_sysctl_geometry_lock_addr = xnu_ptr_to_va(sysctl_geometry_lock_addr);
    g_name2oid_addr = xnu_ptr_to_va(name2oid);
    g_lck_rw_done_addr = xnu_ptr_to_va(lck_rw_done);

    puts("xnuspy: found sysctl_geometry_lock");
    puts("xnuspy: found name2oid");
    puts("xnuspy: found lck_rw_done");

    return true;
}

/* confirmed working on all kernels 13.0-14.4 */
bool hook_system_check_sysctlbyname_finder_13(xnu_pf_patch_t *patch,
        void *cacheable_stream){
    uint32_t *opcode_stream = cacheable_stream;

    xnu_pf_disable_patch(patch);

    /* we've landed inside hook_system_check_sysctlbyname, find the first
     * instruction after its prologue and the beginning of its epilogue
     *
     * search up, looking for sub sp, sp, n or add x29, sp, n
     */
    uint32_t instr_limit = 300;

    while((*opcode_stream & 0xffc003ff) != 0xd10003ff &&
            (*opcode_stream & 0xffc003ff) != 0x910003fd){
        if(instr_limit-- == 0)
            return false;

        opcode_stream--;
    }

    /* advance to the first instruction after the prologue */
    opcode_stream++;

    g_h_s_c_sbn_branch_addr = xnu_ptr_to_va(opcode_stream);

    puts("xnuspy: found h_s_c_sbn branch addr");

    /* now we need to find the beginning of its epilogue
     *
     * search down, looking for add sp, sp, n or ldp x29, x30, [sp, n]
     */
    instr_limit = 300;

    while((*opcode_stream & 0xffc003ff) != 0x910003ff &&
            (*opcode_stream & 0xffc07fff) != 0xa9407bfd){
        if(instr_limit-- == 0)
            return false;

        opcode_stream++;
    }

    g_h_s_c_sbn_epilogue_addr = xnu_ptr_to_va(opcode_stream);

    puts("xnuspy: found h_s_c_sbn epilogue");

    return true;
}

/* confirmed working on all kernels 13.0-13.7 */
bool lck_grp_alloc_init_finder_13(xnu_pf_patch_t *patch,
        void *cacheable_stream){
    xnu_pf_disable_patch(patch);

    /* the BL we matched is guarenteed to be branching to lck_grp_alloc_init */
    uint32_t *blp = ((uint32_t *)cacheable_stream) + 2;

    uint32_t *lck_grp_alloc_init = get_branch_dst_ptr(blp);

    g_lck_grp_alloc_init_addr = xnu_ptr_to_va(lck_grp_alloc_init);

    puts("xnuspy: found lck_grp_alloc_init");

    return true;
}

/* confirmed working on all kernels 13.0-13.7 */
bool lck_rw_alloc_init_finder_13(xnu_pf_patch_t *patch,
        void *cacheable_stream){
    xnu_pf_disable_patch(patch);

    uint32_t *opcode_stream = cacheable_stream;

    /* the second BL we matched is branching to lck_rw_alloc_init */
    uint32_t instr_limit = 25;
    uint32_t bl_cnt = 0;

    for(;;){
        if(instr_limit-- == 0){
            puts("xnuspy:");
            puts("   lck_rw_alloc_init_finder:");
            puts("   no BLs?");
            return false;
        }

        if((*opcode_stream & 0xfc000000) == 0x94000000){
            bl_cnt++;

            if(bl_cnt == 2)
                break;
        }

        opcode_stream++;
    }

    uint32_t *lck_rw_alloc_init = get_branch_dst_ptr(opcode_stream);

    g_lck_rw_alloc_init_addr = xnu_ptr_to_va(lck_rw_alloc_init);

    puts("xnuspy: found lck_rw_alloc_init");

    return true;
}

/* confirmed working on all kernels 13.0-14.4 */
bool bcopy_phys_finder_13(xnu_pf_patch_t *patch, void *cacheable_stream){
    uint32_t *opcode_stream = cacheable_stream;

    /* search up for:
     *  mov w3, n
     *  b 4
     *
     * for bcopy_phys
     */
    uint32_t instr_limit = 200;

    while(*opcode_stream != 0x14000001 &&
            (opcode_stream[-1] & 0xffe0001f) != 0x52800003){
        if(instr_limit-- == 0)
            return false;

        opcode_stream--;
    }

    /* get on the mov w3, n */
    opcode_stream--;

    /* make sure we are actually on bcopy_phys. Check for sub sp, sp, n
     * two instructions down */
    if((opcode_stream[2] & 0xffc003ff) != 0xd10003ff)
        return false;

    xnu_pf_disable_patch(patch);

    g_bcopy_phys_addr = xnu_ptr_to_va(opcode_stream);
    
    puts("xnuspy: found bcopy_phys");

    return true;
}

/* confirmed working on all kernels 13.0-14.4 */
bool phystokv_finder_13(xnu_pf_patch_t *patch, void *cacheable_stream){
    xnu_pf_disable_patch(patch);

    uint32_t *opcode_stream = cacheable_stream;

    /* We've landed inside arm_vm_init; the 5th instruction from this point
     * is branching to phystokv */
    uint32_t *phystokv = get_branch_dst_ptr(opcode_stream + 5);

    g_phystokv_addr = xnu_ptr_to_va(phystokv);

    puts("xnuspy: found phystokv");

    return true;
}

/* The KTRR & AMCC patchfinder for 13.0-13.7 is from KTRW, @bazad */

/* confirmed working on all KTRR kernels 13.0-13.7 */
bool ktrr_lockdown_patcher_13(xnu_pf_patch_t *patch, void *cacheable_stream){
    xnu_pf_disable_patch(patch);

    uint32_t *opcode_stream = cacheable_stream;

    *opcode_stream = 0xd503201f;
    opcode_stream[2] = 0xd503201f;
    opcode_stream[4] = 0xd503201f;

    puts("xnuspy: disabled KTRR MMU lockdown");

    return true;
}

/* confirmed working on all KTRR kernels 13.0-13.7 */
bool amcc_lockdown_patcher_13(xnu_pf_patch_t *patch, void *cacheable_stream){
    xnu_pf_disable_patch(patch);

    uint32_t *opcode_stream = cacheable_stream;

    *opcode_stream = 0xd503201f;
    opcode_stream[2] = 0xd503201f;
    opcode_stream[3] = 0xd503201f;
    opcode_stream[4] = 0xd503201f;

    puts("xnuspy: disabled AMCC MMU lockdown");

    return true;
}

/* confirmed working on all kernels 13.0-14.4 */
bool copyin_finder_13(xnu_pf_patch_t *patch, void *cacheable_stream){
    xnu_pf_disable_patch(patch);

    uint32_t *opcode_stream = cacheable_stream;

    /* we've landed inside copyin, find its prologue
     *
     * looking for stp x22, x21, [sp, -0x30]!
     */
    uint32_t instr_limit = 100;

    while(*opcode_stream != 0xa9bd57f6){
        if(instr_limit-- == 0)
            return false;

        opcode_stream--;
    }

    g_copyin_addr = xnu_ptr_to_va(opcode_stream);

    puts("xnuspy: found copyin");

    return true;
}

/* confirmed working on all kernels 13.0-14.4 */
bool copyout_finder_13(xnu_pf_patch_t *patch, void *cacheable_stream){
    uint32_t *opcode_stream = cacheable_stream;

    /* We may have landed inside copyout. Unfortunately, clang decided to
     * make the order of the three ignored instructions different across
     * kernels. On some kernels, the matches/masks combo matches two places,
     * so we need to make sure we're inside copyout. We're inside copyout if
     * the eighth instruction from this point is cmp w0, 0x12. */
    if(opcode_stream[8] != 0x7100481f)
        return false;

    xnu_pf_disable_patch(patch);

    /* If we're here, then we've landed inside copyout. Find its prologue
     *
     * looking for stp x22, x21, [sp, -0x30]!
     */
    uint32_t instr_limit = 100;

    while(*opcode_stream != 0xa9bd57f6){
        if(instr_limit-- == 0)
            return false;

        opcode_stream--;
    }

    g_copyout_addr = xnu_ptr_to_va(opcode_stream);

    puts("xnuspy: found copyout");

    return true;
}

/* confirmed working on all kernels 13.0-14.4 */
bool IOSleep_finder_13(xnu_pf_patch_t *patch, void *cacheable_stream){
    xnu_pf_disable_patch(patch);

    g_IOSleep_addr = xnu_ptr_to_va(cacheable_stream);

    puts("xnuspy: found IOSleep");

    return true;
}

/* confirmed working on all kernels 13.0-14.4 */
bool kprintf_finder_13(xnu_pf_patch_t *patch, void *cacheable_stream){
    xnu_pf_disable_patch(patch);

    /* We've landed inside kprintf, search up for the start of its prologue */
    uint32_t *opcode_stream = cacheable_stream;

    uint32_t instr_limit = 20;

    while((*opcode_stream & 0xffc003ff) != 0xd10003ff){
        if(instr_limit-- == 0)
            return false;

        opcode_stream--;
    }

    g_kprintf_addr = xnu_ptr_to_va(opcode_stream);

    puts("xnuspy: found kprintf");

    return true;
}

/* confirmed working on all kernels 13.0-14.4 */
bool kernel_map_vm_deallocate_vm_map_unwire_finder_13(xnu_pf_patch_t *patch,
        void *cacheable_stream){
    xnu_pf_disable_patch(patch);

    /* If we're 13.x, we've landed inside profile_release, if we're 14.x,
     * we've landed inside _profile_destroy. For vm_map_unwire, it'll be the
     * branch we're currently sitting at. */
    uint32_t *opcode_stream = cacheable_stream;

    uint32_t *vm_map_unwire = get_branch_dst_ptr(opcode_stream);
    uint32_t *vm_deallocate = get_branch_dst_ptr(opcode_stream + 3);

    g_vm_map_unwire_addr = xnu_ptr_to_va(vm_map_unwire);
    g_vm_deallocate_addr = xnu_ptr_to_va(vm_deallocate);

    /* Finally, we can find kernel_map by searching up for the first ADRP
     * or ADR from where we initially landed */
    uint32_t instr_limit = 150;

    while((*opcode_stream & 0x1f000000) != 0x10000000){
        if(instr_limit-- == 0)
            return false;

        opcode_stream--;
    }

    /* The ADRP,LDR pairs require another level of indirection for this */
    if(((opcode_stream[1] >> 25) & 5) == 4){
        g_kernel_map_addr = *(uint64_t *)get_adrp_ldr_target(opcode_stream);
        g_kernel_map_addr |= ((uint64_t)0xffff << 48);
        g_kernel_map_addr = kext_rebase_va(g_kernel_map_addr);
    }
    else{
        uint64_t kernel_map_addr;

        if(*opcode_stream & 0x80000000)
            kernel_map_addr = get_adrp_add_target(opcode_stream);
        else
            kernel_map_addr = get_adr_target(opcode_stream);

        g_kernel_map_addr = xnu_ptr_to_va((void *)kernel_map_addr);
    }

    puts("xnuspy: found vm_map_unwire");
    puts("xnuspy: found vm_deallocate");
    puts("xnuspy: found kernel_map");

    return true;
}

/* confirmed working on all kernels 13.0-14.4 */
bool kernel_thread_start_thread_deallocate_finder_13(xnu_pf_patch_t *patch,
        void *cacheable_stream){
    /* There's two hits for this, but they're identical, so whatever is
     * matched first will do */
    xnu_pf_disable_patch(patch);

    uint32_t *opcode_stream = cacheable_stream;

    uint32_t *kernel_thread_start = get_branch_dst_ptr(opcode_stream);
    uint32_t *thread_deallocate = get_branch_dst_ptr(opcode_stream + 8);

    g_kernel_thread_start_addr = xnu_ptr_to_va(kernel_thread_start);
    g_thread_deallocate_addr = xnu_ptr_to_va(thread_deallocate);

    puts("xnuspy: found kernel_thread_start");
    puts("xnuspy: found thread_deallocate");

    return true;
}

/* confirmed working on all kernels 13.0-14.4 */
bool mach_make_memory_entry_64_finder_13(xnu_pf_patch_t *patch,
        void *cacheable_stream){
    xnu_pf_disable_patch(patch);

    g_mach_make_memory_entry_64_addr = xnu_ptr_to_va(cacheable_stream);

    puts("xnuspy: found mach_make_memory_entry_64");

    return true;
}

/* confirmed working on all kernels 13.0-14.4 */
bool offsetof_struct_thread_map_finder_13(xnu_pf_patch_t *patch,
        void *cacheable_stream){
    /* We landed in mmap, the first LDR we matched contains the offset
     * of the map pointer inside struct thread */
    xnu_pf_disable_patch(patch);

    uint32_t *opcode_stream = cacheable_stream;

    uint32_t ldr = opcode_stream[1];
    uint64_t imm12 = (ldr & 0x3ffc00) >> 10;
    uint32_t size = ldr >> 30;

    g_offsetof_struct_thread_map = (uint64_t)(imm12 << size);

    puts("xnuspy: found offsetof(struct thread, map)");

    return true;
}

/* confirmed working on all kernels 13.0-14.4 */
bool proc_stuff0_finder_13(xnu_pf_patch_t *patch, void *cacheable_stream){
    /* We've landed in proc_self. This finds:
     *      - current_proc
     *      - proc_list_lock
     *      - proc_ref_locked
     *      - proc_list_mlock
     *      - lck_mtx_unlock
     *      - proc_rele_locked
     * Right above proc_self is proc_rele_locked. proc_list_unlock
     * has been inlined so aggressively that there are no xrefs to the actual
     * function, which is obnoxious */
    xnu_pf_disable_patch(patch);

    uint32_t *opcode_stream = cacheable_stream;

    uint32_t *current_proc = get_branch_dst_ptr(opcode_stream + 1);
    uint32_t *proc_list_lock = get_branch_dst_ptr(opcode_stream + 3);
    uint32_t *proc_ref_locked = get_branch_dst_ptr(opcode_stream + 5);

    g_current_proc_addr = xnu_ptr_to_va(current_proc);
    g_proc_list_lock_addr = xnu_ptr_to_va(proc_list_lock);
    g_proc_ref_locked_addr = xnu_ptr_to_va(proc_ref_locked);

    /* Go down until we hit an ADRP or ADR, this will be proc_list_mlock, and
     * the first bl below that will be lck_mtx_unlock */
    uint32_t instr_limit = 50;

    while((*opcode_stream & 0x1f000000) != 0x10000000){
        if(instr_limit-- == 0)
            return false;

        opcode_stream++;
    }

    g_proc_list_mlock_addr = xnu_ptr_to_va((void *)get_pc_rel_target(opcode_stream));

    instr_limit = 20;

    while((*opcode_stream & 0xfc000000) != 0x94000000){
        if(instr_limit-- == 0)
            return false;

        opcode_stream++;
    }

    uint32_t *lck_mtx_unlock = get_branch_dst_ptr(opcode_stream);

    g_lck_mtx_unlock_addr = xnu_ptr_to_va(lck_mtx_unlock);

    /* Finally, search up for proc_rele_locked. We'll look until we hit
     * ldr w8, [x0, n]. On some kernels, clang did not place the prologue
     * at the beginning of this function, but at the bottom for a call to
     * panic. So, we could either have ldr w8, [x0, n] or stp x29, x30, [sp, -0x10]!
     * at the beginning, but the ldr is guarenteed to be somewhere close
     * to the start so we'll look for that. */
    instr_limit = 250;

    while((*opcode_stream & 0xffc003ff) != 0xb9400008){
        if(instr_limit-- == 0)
            return false;

        opcode_stream--;
    }

    /* We're at the ldr, and if we're at the beginning of proc_rele_locked,
     * we will not see mov x29, sp. If we see that, the beginning is two
     * instructions behind this point. */
    if(opcode_stream[-1] == 0x910003fd)
        opcode_stream -= 2;

    g_proc_rele_locked_addr = xnu_ptr_to_va(opcode_stream);

    puts("xnuspy: found current_proc");
    puts("xnuspy: found proc_list_lock");
    puts("xnuspy: found proc_ref_locked");
    puts("xnuspy: found proc_list_mlock");
    puts("xnuspy: found lck_mtx_unlock");
    puts("xnuspy: found proc_rele_locked");

    return true;
}

/* confirmed working on all kernels 13.0-14.4 */
bool proc_stuff1_finder_13(xnu_pf_patch_t *patch, void *cacheable_stream){
    /* We've landed in sandbox_reference_retain. This finds:
     *      - proc_pid
     *      - proc_uniqueid
     *
     * The first branch we see while searching up will be proc_uniqueid, and
     * the branch before that one will be proc_pid */
    xnu_pf_disable_patch(patch);

    uint32_t *opcode_stream = cacheable_stream;
    uint32_t instr_limit = 50;

    while((*opcode_stream & 0xfc000000) != 0x94000000){
        if(instr_limit-- == 0)
            return false;

        opcode_stream--;
    }

    uint32_t *proc_uniqueid = get_branch_dst_ptr(opcode_stream);

    /* Get off the branch to proc_uniqueid */
    opcode_stream--;

    while((*opcode_stream & 0xfc000000) != 0x94000000){
        if(instr_limit-- == 0)
            return false;

        opcode_stream--;
    }

    uint32_t *proc_pid = get_branch_dst_ptr(opcode_stream);

    g_proc_uniqueid_addr = xnu_ptr_to_va(proc_uniqueid);
    g_proc_pid_addr = xnu_ptr_to_va(proc_pid);

    puts("xnuspy: found proc_uniqueid");
    puts("xnuspy: found proc_pid");

    return true;
}

/* confirmed working on all kernels 13.0-14.4 */
bool allproc_finder_13(xnu_pf_patch_t *patch, void *cacheable_stream){
    /* The ADRP three instructions past this point is for allproc */
    xnu_pf_disable_patch(patch);

    uint32_t *opcode_stream = cacheable_stream;

    g_allproc_addr = xnu_ptr_to_va((void *)get_pc_rel_target(opcode_stream + 3));

    puts("xnuspy: found allproc");

    return true;
}

/* confirmed working on all kernels 13.0-14.4 */
bool misc_lck_stuff_finder_13(xnu_pf_patch_t *patch, void *cacheable_stream){
    /* We've landed in sflt_initsock. This finds:
     *      - lck_rw_lock_shared
     *      - lck_rw_lock_shared_to_exclusive
     *      - lck_rw_lock_exclusive
     *
     * From a programming perspective, lck_rw_lock would satisfy both the
     * first and third, but from a patchfinding perspective, it's so much
     * easier to get all three of these at once. */
    uint32_t *opcode_stream = cacheable_stream;

    uint32_t *lck_rw_lock_shared = get_branch_dst_ptr(opcode_stream);
    uint32_t *lck_rw_lock_shared_to_exclusive = get_branch_dst_ptr(opcode_stream + 4);
    uint32_t *lck_rw_lock_exclusive = get_branch_dst_ptr(opcode_stream + 7);

    g_lck_rw_lock_shared_addr = xnu_ptr_to_va(lck_rw_lock_shared);
    g_lck_rw_lock_shared_to_exclusive_addr =
        xnu_ptr_to_va(lck_rw_lock_shared_to_exclusive);
    g_lck_rw_lock_exclusive_addr = xnu_ptr_to_va(lck_rw_lock_exclusive);

    puts("xnuspy: found lck_rw_lock_shared");
    puts("xnuspy: found lck_rw_lock_shared_to_exclusive");
    puts("xnuspy: found lck_rw_lock_exclusive");

    return true;
}

/* confirmed working on all kernels 13.0-14.4 */
bool vm_map_wire_external_finder_13(xnu_pf_patch_t *patch,
        void *cacheable_stream){
    /* We've matched a ton of places, we're in vm_map_wire_external if
     * the 14th/15th instrs from this point are mov x6, 0 and mov x7, 0 */
    uint32_t *opcode_stream = cacheable_stream;

    if(opcode_stream[14] != 0xd2800006 && opcode_stream[15] != 0xd2800007)
        return false;

    xnu_pf_disable_patch(patch);

    /* We're inside vm_map_wire_external, find the beginning. Looking for
     * sub sp, sp, n */
    uint32_t instr_limit = 50;

    while((*opcode_stream & 0xffc003ff) != 0xd10003ff){
        if(instr_limit-- == 0)
            return false;

        opcode_stream--;
    }
    
    g_vm_map_wire_external_addr = xnu_ptr_to_va(opcode_stream);

    puts("xnuspy: found vm_map_wire_external");

    return true;
}

/* confirmed working on all kernels 13.0-14.4 */
bool mach_vm_map_external_finder_13(xnu_pf_patch_t *patch,
        void *cacheable_stream){
    /* We've matched a couple places, we are in mach_vm_map_external if the
     * 6th instruction from this point is mov x8, x5 */
    uint32_t *opcode_stream = cacheable_stream;

    if(opcode_stream[6] != 0xaa0503e8)
        return false;

    xnu_pf_disable_patch(patch);

    /* Find mach_vm_map_external's start. Searching for sub sp, sp, n */
    uint32_t instr_limit = 50;

    while((*opcode_stream & 0xffc003ff) != 0xd10003ff){
        if(instr_limit-- == 0)
            return false;

        opcode_stream--;
    }

    g_mach_vm_map_external_addr = xnu_ptr_to_va(opcode_stream);

    puts("xnuspy: found mach_vm_map_external");

    return true;
}

/* confirmed working on all kernels 13.0-14.4 */
bool ipc_port_release_send_finder_13(xnu_pf_patch_t *patch,
        void *cacheable_stream){
    /* We've landed inside exception_deliver, the 4th instruction from
     * this point is a BL to ipc_port_release_send */
    xnu_pf_disable_patch(patch);

    uint32_t *opcode_stream = cacheable_stream;

    uint32_t *ipc_port_release_send = get_branch_dst_ptr(opcode_stream + 3);

    g_ipc_port_release_send_addr = xnu_ptr_to_va(ipc_port_release_send);

    puts("xnuspy: found ipc_port_release_send");

    return true;
}

/* confirmed working on all kernels 13.0-14.4 */
bool lck_rw_free_finder_13(xnu_pf_patch_t *patch, void *cacheable_stream){
    /* We've landed inside IORWLockFree, the unconditional branch is to
     * lck_rw_free */
    xnu_pf_disable_patch(patch);

    uint32_t *opcode_stream = cacheable_stream;

    uint32_t *lck_rw_free = get_branch_dst_ptr(opcode_stream + 2);

    g_lck_rw_free_addr = xnu_ptr_to_va(lck_rw_free);

    puts("xnuspy: found lck_rw_free");

    return true;
}

/* confirmed working on all kernels 13.0-14.4 */
bool lck_grp_free_finder_13(xnu_pf_patch_t *patch, void *cacheable_stream){
    /* We've landed inside ipf_init, the 5th instruction from this point
     * is branching to lck_grp_free */
    xnu_pf_disable_patch(patch);

    uint32_t *opcode_stream = cacheable_stream;

    uint32_t *lck_grp_free = get_branch_dst_ptr(opcode_stream + 5);

    g_lck_grp_free_addr = xnu_ptr_to_va(lck_grp_free);

    puts("xnuspy: found lck_grp_free");

    return true;
}

/* confirmed working on all kernels 13.0-14.4 */
bool doprnt_hide_pointers_patcher_13(xnu_pf_patch_t *patch,
        void *cacheable_stream){
    /* XNU only respects -show_pointers when debug_enabled is non-zero,
     * so I need to patch doprnt_hide_pointers manually. We've landed in
     * __doprnt, the next ADR/ADRP will be to doprnt_hide_pointers */
    xnu_pf_disable_patch(patch);

    uint32_t *opcode_stream = cacheable_stream;

    uint32_t instr_limit = 40;

    while((*opcode_stream & 0x1f000000) != 0x10000000){
        if(instr_limit-- == 0)
            return false;

        opcode_stream++;
    }

    *(uint32_t *)get_pc_rel_target(opcode_stream) = 0;

    g_patched_doprnt_hide_pointers = 1;

    puts("xnuspy: unset doprnt_hide_pointers");

    return true;
}

/* confirmed working on all kernels 13.0-14.4 */
bool copyinstr_finder_13(xnu_pf_patch_t *patch, void *cacheable_stream){
    /* We've landed inside copyinstr, find its prologue. Looking for
     * sub sp, sp, n */
    xnu_pf_disable_patch(patch);

    uint32_t *opcode_stream = cacheable_stream;
    uint32_t instr_limit = 50;

    while((*opcode_stream & 0xffc003ff) != 0xd10003ff){
        if(instr_limit-- == 0)
            return false;

        opcode_stream--;
    }

    g_copyinstr_addr = xnu_ptr_to_va(opcode_stream);

    puts("xnuspy: found copyinstr");

    return true;
}

/* confirmed working on all kernels 13.0-14.4 */
bool thread_terminate_finder_13(xnu_pf_patch_t *patch,
        void *cacheable_stream){
    /* We landed inside of _Call_continuation, the branch four
     * instructions down is for thread_terminate */
    xnu_pf_disable_patch(patch);

    uint32_t *opcode_stream = cacheable_stream;

    uint32_t *thread_terminate = get_branch_dst_ptr(opcode_stream + 4);

    g_thread_terminate_addr = xnu_ptr_to_va(thread_terminate);

    puts("xnuspy: found thread_terminate");

    return true;
}

/* confirmed working on all kernels 13.0-14.4 */
bool pinst_set_tcr_patcher_13(xnu_pf_patch_t *patch, void *cacheable_stream){
    /* We need to keep TCR_EL1.HPD0 and TCR_EL1.HPD1 set if we want
     * A10+ to respect PTE permission bits as they are. We landed inside
     * of pinst_set_tcr, and we are replacing it with:
     *  orr x0, x0, 0x60000000000
     *  msr tcr_el1, x0
     *  ret
     *
     * A9(x) does not contain a pinst segment.
     */
    xnu_pf_disable_patch(patch);

    uint32_t *opcode_stream = cacheable_stream;

    *opcode_stream++ = 0xb2570400;
    *opcode_stream++ = 0xd5182040;
    *opcode_stream++ = 0xd65f03c0;

    g_patched_pinst_set_tcr = 1;

    puts("xnuspy: patched pinst_set_tcr");

    return true;
}

/* confirmed working on all kernels 13.0-14.4 */
bool msr_tcr_el1_x18_patcher_13(xnu_pf_patch_t *patch,
        void *cacheable_stream){
    /* These patches don't need to be done on A9(x) */
    if(socnum < 0x8010){
        xnu_pf_disable_patch(patch);
        return true;
    }

    static int count = 1;
    uint32_t *opcode_stream = cacheable_stream;

    /* We are either in exception_return_unint_tpidr_x3{_dont_trash_x18} or
     * one of the exception vectors for exceptions from EL0. Either way,
     * we are sitting at msr tcr_el1, x18, and the value copied to x18 is
     * either TCR_EL1_USER or TCR_EL1_BOOT. Both of these constants don't
     * have TCR_EL1.HPD0 or TCR_EL1.HPD1 set, so we need to modify the
     * value copied to x18 ourselves. Right before where we are sitting is
     * this:
     *  movk x18, n, lsl 48
     *  movk x18, n, lsl 32
     *  movk x18, n, lsl 16
     *  movk x18, n
     *
     * HPD0 is the 41st bit and HPD1 is the 42nd bit of TCR_EL1, so patch
     * the immediate of the second movk. */
    opcode_stream[-3] |= (0x600 << 5);

    if(count == 5){
        xnu_pf_disable_patch(patch);
        puts("xnuspy: patched all occurrences of msr tcr_el1, x18");
        g_patched_all_msr_tcr_el1_x18 = 1;
    }

    count++;

    return true;
}

/* confirmed working on all kernels 13.0-14.4 */
bool proc_name_snprintf_strlen_finder_13(xnu_pf_patch_t *patch,
        void *cacheable_stream){
    xnu_pf_disable_patch(patch);

    uint32_t *opcode_stream = cacheable_stream;

    uint32_t *snprintf = get_branch_dst_ptr(opcode_stream - 2);
    uint32_t *strlen = get_branch_dst_ptr(opcode_stream);
    uint32_t *proc_name = get_branch_dst_ptr(opcode_stream + 4);

    g_snprintf_addr = xnu_ptr_to_va(snprintf);
    g_strlen_addr = xnu_ptr_to_va(strlen);
    g_proc_name_addr = xnu_ptr_to_va(proc_name);

    puts("xnuspy: found snprintf");
    puts("xnuspy: found strlen");
    puts("xnuspy: found proc_name");

    return true;
}

/* confirmed working on all kernels 13.0-14.4 */
bool strncmp_finder_13(xnu_pf_patch_t *patch, void *cacheable_stream){
    xnu_pf_disable_patch(patch);

    g_strncmp_addr = xnu_ptr_to_va(cacheable_stream);

    puts("xnuspy: found strncmp");

    return true;
}

/* confirmed working on all kernels 13.0-14.4 */
bool memset_finder_13(xnu_pf_patch_t *patch, void *cacheable_stream){
    xnu_pf_disable_patch(patch);

    uint32_t *opcode_stream = cacheable_stream;

    /* Look for the start of memset's prologue, trying to match
     * stp x29, x30, [sp, -0x10]! */
    uint32_t instr_limit = 20;

    while(*opcode_stream != 0xa9bf7bfd){
        if(instr_limit-- == 0)
            return false;

        opcode_stream--;
    }

    g_memset_addr = xnu_ptr_to_va(opcode_stream);

    puts("xnuspy: found memset");

    return true;
}

/* confirmed working on all kernels 13.0-14.4 */
bool memmove_finder_13(xnu_pf_patch_t *patch, void *cacheable_stream){
    xnu_pf_disable_patch(patch);

    uint32_t *opcode_stream = cacheable_stream;

    /* Look for the start of memmove's prologue, trying to match
     * stp x29, x30, [sp, -0x10]! */
    uint32_t instr_limit = 20;

    while(*opcode_stream != 0xa9bf7bfd){
        if(instr_limit-- == 0)
            return false;

        opcode_stream--;
    }

    g_memmove_addr = xnu_ptr_to_va(opcode_stream);

    puts("xnuspy: found memmove");

    return true;
}

/* confirmed working on all kernels 13.0-14.4 */
bool memcmp_finder_13(xnu_pf_patch_t *patch, void *cacheable_stream){
    xnu_pf_disable_patch(patch);

    g_memcmp_addr = xnu_ptr_to_va(cacheable_stream);

    puts("xnuspy: found memcmp");

    return true;
}

bool strnstr_finder_13(xnu_pf_patch_t *patch, void *cacheable_stream){
    xnu_pf_disable_patch(patch);

    uint32_t *opcode_stream = cacheable_stream;

    /* Look for the start of strnstr's prologue, trying to match
     * stp x24, x23, [sp, -0x40]! */
    uint32_t instr_limit = 50;

    while(*opcode_stream != 0xa9bc5ff8){
        if(instr_limit-- == 0)
            return true;

        opcode_stream--;
    }

    g_strnstr_addr = xnu_ptr_to_va(opcode_stream);

    puts("xnuspy: found strnstr");

    return true;
}

bool panic_finder_13(xnu_pf_patch_t *patch, void *cacheable_stream){
    xnu_pf_disable_patch(patch);

    uint32_t *opcode_stream = cacheable_stream;

    /* Look for the start of panic's prologue, trying to match
     * sub sp, sp, n */
    uint32_t instr_limit = 50;

    while((*opcode_stream & 0xffc003ff) != 0xd10003ff){
        if(instr_limit-- == 0)
            return false;

        opcode_stream--;
    }

    g_panic_addr = xnu_ptr_to_va(opcode_stream);

    puts("xnuspy: found panic");
    printf("%s: panic @ %#llx\n", __func__, g_panic_addr-kernel_slide);

    return true;
}
