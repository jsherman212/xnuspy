#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>

#include <pongo.h>

#include <asm/asm.h>
#include <common/common.h>
#include <pf/offsets.h>
#include <pf/pf_common.h>

uint64_t g_vm_map_unwire_nested_addr = 0;
uint64_t g_iolog_addr = 0;

/* Confirmed working 15.0 */
bool ipc_port_release_send_finder_15(xnu_pf_patch_t *patch, 
        void *cacheable_stream){
    /* will land in _exception_deliver in iOS 15. There is a sequence
     * where they lock/release 4 IPC ports if they are non-null. This
     * patchfinder will take us here, then it's just a matter of
     * resolving the branches. We get about 26 hits for these matches
     * and masks, so let's make sure we're actually in _exception_deliver.
     * If we are, then the two instructions behind where we landed will be
     * mov x27, #0 and mov x26, x0 */
    uint32_t *opcode_stream = cacheable_stream;

    if(opcode_stream[-1] != 0xd280001b && opcode_stream[-2] != 0xaa0003fa)
        return false;

    xnu_pf_disable_patch(patch);

    uint32_t *ipc_port_release_send_and_unlock = get_branch_dst_ptr(opcode_stream + 6);
    uint32_t *ipc_object_lock = get_branch_dst_ptr(opcode_stream + 4);

    g_ipc_port_release_send_addr = xnu_ptr_to_va(ipc_port_release_send_and_unlock);

    /* TODO: will be more clear inside kernel code if I call io_lock
     * for 14.x/ipc_object_lock for 15.x and export them as two different
     * things inside the cache */
    g_io_lock_addr = xnu_ptr_to_va(ipc_object_lock);

    puts("xnuspy: found ipc_port_release_send_and_unlock");
    puts("xnuspy: found ipc_object_lock");

    /* printf("%s: ipc_port_release_send_and_unlock: %#llx\n",__func__, */
    /*         g_ipc_port_release_send_addr-kernel_slide); */
    /* printf("%s: ipc_object_lock: %#llx\n", __func__, */
    /*         g_io_lock_addr-kernel_slide); */

    return true;
}

bool proc_name_snprintf_strlen_finder_15(xnu_pf_patch_t *patch,
        void *cacheable_stream){
    /* will land in AppleEmbeddedUSBDevice::setAuthenticationProperites */
    xnu_pf_disable_patch(patch);

    uint32_t *opcode_stream = cacheable_stream;

    uint32_t *snprintf = get_branch_dst_ptr(opcode_stream + 2);
    uint32_t *strlen = get_branch_dst_ptr(opcode_stream + 4);
    uint32_t *proc_name = get_branch_dst_ptr(opcode_stream + 8);

    g_snprintf_addr = xnu_ptr_to_va(snprintf);
    g_strlen_addr = xnu_ptr_to_va(strlen);
    g_proc_name_addr = xnu_ptr_to_va(proc_name);

    puts("xnuspy: found snprintf");
    puts("xnuspy: found strlen");
    puts("xnuspy: found proc_name");

    return true;
}

bool current_proc_finder_15(xnu_pf_patch_t *patch, void *cacheable_stream){
    /* will land directly at the start of _current_proc, or an 
     * inlined copy of it */

    uint32_t *opcode_stream = cacheable_stream;

    uint32_t *current_proc = opcode_stream - 3;

    uint32_t func_size = 0;
    while (*opcode_stream != 0xd65f03c0 /* ret */){
        func_size++;

        opcode_stream++;
    }

    /* definitely not the best patchfind, but _current_proc itself is
     * a very specific size (it's also the smallest match but this is
     * harder to check for). we get many matches on this patch as 
     * it's inlined in many places */
    if (func_size != 0x12){
        return false;
    }

    xnu_pf_disable_patch(patch);

    g_current_proc_addr = xnu_ptr_to_va(current_proc);

    puts("xnuspy: found current_proc");

    return true;
}

bool vm_map_unwire_nested_finder_15(xnu_pf_patch_t *patch, 
        void *cacheable_stream){
    /* will land in mach_port_space_info, on the _vm_map_unwire_nested call */
    xnu_pf_disable_patch(patch);

    uint32_t *opcode_stream = cacheable_stream;

    uint32_t *vm_map_unwire_nested = get_branch_dst_ptr(opcode_stream);

    g_vm_map_unwire_nested_addr = xnu_ptr_to_va(vm_map_unwire_nested);
    
    puts("xnuspy: found vm_map_unwire_nested");

    return true;
}

bool kernel_map_finder_15(xnu_pf_patch_t *patch, void *cacheable_stream){
    /* will land in _panic_kernel, on adrp/ldr for _kernel_map */
    xnu_pf_disable_patch(patch);

    uint32_t *opcode_stream = cacheable_stream;

    uint32_t *kernel_map = (uint32_t *)get_pc_rel_target(opcode_stream);

    g_kernel_map_addr = xnu_ptr_to_va(kernel_map);
    
    puts("xnuspy: found kernel_map");
    
    return true;
}

bool vm_deallocate_finder_15(xnu_pf_patch_t *patch, void *cacheable_stream){
    /* will land in ipc_kmsg_clean_partial. we can only 
     * search for 8 intructions at a time, so we check
     * for the 9th instruction (bl _vm_deallocate) */
    xnu_pf_disable_patch(patch);

    uint32_t *opcode_stream = cacheable_stream;

    if ((opcode_stream[8] & 0xfc000000) != 0x94000000){
        return false;
    }

    uint32_t *vm_deallocate = get_branch_dst_ptr(opcode_stream + 8);

    g_vm_deallocate_addr = xnu_ptr_to_va(vm_deallocate);

    puts("xnuspy: found vm_deallocate");

    return true;
}

/* NOTE: if this patch breaks see note in `proc_list_mlock_finder_15` */
bool lck_mtx_lock_unlock_finder_15(xnu_pf_patch_t *patch, void *cacheable_stream){
    /* will land at the end of ipc_task_init */
    xnu_pf_disable_patch(patch);

    uint32_t *opcode_stream = cacheable_stream;

    uint32_t *lck_mtx_lock = get_branch_dst_ptr(opcode_stream);
    uint32_t *lck_mtx_unlock = get_branch_dst_ptr(opcode_stream + 5);

    g_lck_mtx_lock_addr = xnu_ptr_to_va(lck_mtx_lock);
    g_lck_mtx_unlock_addr = xnu_ptr_to_va(lck_mtx_unlock);

    puts("xnuspy: found lck_mtx_lock");
    puts("xnuspy: found lck_mtx_unlock");

    return true;
}

/* NOTE: lock_mtx_{un}lock are also nearby, so could be integrated into this patch if necessary */
/* TODO ^ do this */
bool proc_list_mlock_finder_15(xnu_pf_patch_t *patch, void *cacheable_stream){
    /* will land in _posix_spawn. we can only search
     * for 8 instructions at a time, so we check for 
     * the 9th instruction (bl _lck_mtx_unlock) */
    xnu_pf_disable_patch(patch);
    
    uint32_t *opcode_stream = cacheable_stream;
    
    if ((opcode_stream[8] & 0xfc000000) != 0x94000000){
        return false;
    }

    uint32_t *proc_list_mlock = (uint32_t *)get_pc_rel_target(opcode_stream);

    g_proc_list_mlock_addr = xnu_ptr_to_va(proc_list_mlock);

    puts("xnuspy: found proc_list_mlock");

    return true;
}

bool lck_grp_free_finder_15(xnu_pf_patch_t *patch, void *cacheable_stream){
    /* will land in _mcache_destroy. we match a pattern 
     * of 3x calls to _lck_grp_free, so we can check
     * these BL's all point to the same place to ensure
     * we're looking at the right code */

    uint32_t *opcode_stream = cacheable_stream;

    uint32_t *branches[3] = { 
        get_branch_dst_ptr(opcode_stream + 3),
        get_branch_dst_ptr(opcode_stream + 5),
        get_branch_dst_ptr(opcode_stream + 7),
    };

    if (branches[0] != branches[1] ||
        branches[0] != branches[2])
        return false;

    xnu_pf_disable_patch(patch);

    uint32_t *lck_grp_free = get_branch_dst_ptr(opcode_stream + 3);
    
    g_lck_grp_free_addr = xnu_ptr_to_va(lck_grp_free);
    
    puts("xnuspy: found lck_grp_free");
    
    return true;
}

/* TODO: confirm if this works on 13 and 14 */
bool iolog_finder_15(xnu_pf_patch_t *patch, void *cacheable_stream){
    uint32_t *opcode_stream = cacheable_stream;

    /* check for BL */
    if ((opcode_stream[8] & 0xfc000000) != 0x94000000){
        return false;
    }

    /* somewhat unorthodox, but check the string matches 
     * a specific log message we're looking for. this 
     * stops us matching against other logging macro's, 
     * like kprintf, which may use a similar call site */

    const char *match_string = "%s: not registry member at registerService()";

    const char *str_ptr = (const char *)get_pc_rel_target(opcode_stream + 6);

    if (strncmp(str_ptr, match_string, strlen(match_string)) != 0){
        return false;
    }

    xnu_pf_disable_patch(patch);

    uint32_t *iolog_addr = get_branch_dst_ptr(opcode_stream + 8);

    g_iolog_addr = xnu_ptr_to_va(iolog_addr);
    
    puts("xnuspy: found iolog");

    return true;
}
