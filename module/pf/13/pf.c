#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/sysctl.h>

#include "../disas.h"
#include "../macho.h"
#include "../offsets.h"
#include "../pf_common.h"

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
uint64_t g_lck_rw_lock_shared_addr = 0;
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
uint64_t g_xnuspy_sysctl_name_ptr = 0;
uint64_t g_xnuspy_sysctl_descr_ptr = 0;
uint64_t g_xnuspy_sysctl_fmt_ptr = 0;
uint64_t g_xnuspy_sysctl_mib_ptr = 0;
uint64_t g_xnuspy_sysctl_mib_count_ptr = 0;
uint64_t g_xnuspy_ctl_callnum = 0;

/* confirmed working on all kernels 13.0-14.3 */
bool sysent_finder_13(xnu_pf_patch_t *patch, void *cacheable_stream){
    uint32_t *opcode_stream = cacheable_stream;

    /* if we're in the right place, sysent will be the first ADRP/ADD
     * pair we find when we go forward
     */
    uint32_t instr_limit = 10;

    while((*opcode_stream & 0x9f000000) != 0x90000000){
        if(instr_limit-- == 0)
            return false;

        opcode_stream++;
    }

    /* make sure this is actually sysent. to do this, we can check if
     * the first entry is the indirect system call
     */
    uint64_t addr_va = 0;

    if(bits(*opcode_stream, 31, 31) == 0)
        addr_va = get_adr_va_target(opcode_stream);
    else
        addr_va = get_adrp_add_va_target(opcode_stream);

    uint64_t maybe_sysent = (uint64_t)xnu_va_to_ptr(addr_va);

    if(*(uint64_t *)maybe_sysent != 0 &&
            *(uint64_t *)(maybe_sysent + 0x8) == 0 &&
            *(uint32_t *)(maybe_sysent + 0x10) == 1 &&
            *(uint16_t *)(maybe_sysent + 0x14) == 0 &&
            *(uint16_t *)(maybe_sysent + 0x16) == 0){
        xnu_pf_disable_patch(patch);

        g_sysent_addr = addr_va;

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
    uint32_t *opcode_stream = cacheable_stream;

    /* we should have landed inside kfree_addr, but just to make sure,
     * look for "kfree on an address not in the kernel" from this point on
     */
    uint32_t instr_limit = 200;
    bool inside_kfree_addr = 0;

    while(instr_limit-- != 0){
        /* ADRP/ADD or ADR/NOP */
        if((*opcode_stream & 0x1f000000) == 0x10000000){
            uint64_t addr_va = 0;

            if(bits(*opcode_stream, 31, 31) == 0)
                addr_va = get_adr_va_target(opcode_stream);
            else
                addr_va = get_adrp_add_va_target(opcode_stream);

            char *string = xnu_va_to_ptr(addr_va);

            const char *match = "kfree on an address not in the kernel";
            size_t matchlen = strlen(match);

            if(memmem(string, matchlen + 1, match, matchlen)){
                inside_kfree_addr = true;
                break;
            }
        }

        opcode_stream++;
    }

    if(!inside_kfree_addr)
        return false;

    xnu_pf_disable_patch(patch);

    /* find kfree_addr's prologue
     *
     * looking for sub sp, sp, n
     */
    instr_limit = 200;

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
     * exc_vectors_table
     */
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

    uint64_t addr_va = 0;

    if(bits(*opcode_stream, 31, 31) == 0)
        addr_va = get_adr_va_target(opcode_stream);
    else
        addr_va = get_adrp_add_va_target(opcode_stream);

    g_sysctl__kern_children_addr = *(uint64_t *)xnu_va_to_ptr(addr_va);

    /* tagged pointer */
    if((g_sysctl__kern_children_addr & 0xffff000000000000) != 0xffff000000000000){
        /* untag and slide */
        g_sysctl__kern_children_addr |= ((uint64_t)0xffff << 48);
        g_sysctl__kern_children_addr += kernel_slide;
    }

    puts("xnuspy: found sysctl__kern_children");

    return true;
}

/* confirmed working on all kernels 13.0-13.7 */
bool sysctl_register_oid_finder_13(xnu_pf_patch_t *patch,
        void *cacheable_stream){
    xnu_pf_disable_patch(patch);

    uint32_t *opcode_stream = cacheable_stream;

    /* the BL we matched is guarenteed to be sysctl_register_oid */
    uint32_t *sysctl_register_oid = get_branch_dst_ptr(opcode_stream[5],
            opcode_stream + 5);

    g_sysctl_register_oid_addr = xnu_ptr_to_va(sysctl_register_oid);

    puts("xnuspy: found sysctl_register_oid");

    return true;
}

/* confirmed working on all kernels 13.0-14.3 */
bool sysctl_handle_long_finder_13(xnu_pf_patch_t *patch,
        void *cacheable_stream){
    uint32_t *opcode_stream = cacheable_stream;

    xnu_pf_disable_patch(patch);

    /* the patchfinder landed us at sysctl_handle_long or sysctl_handle_quad,
     * whichever came first in the kernelcache, because these functions are
     * pretty much identical. Both of them can act as sysctl_handle_long and
     * be fine.
     */
    g_sysctl_handle_long_addr = xnu_ptr_to_va(opcode_stream);

    puts("xnuspy: found sysctl_handle_long");
    printf("%s: sysctl_handle_long @ %#llx\n", __func__,
            g_sysctl_handle_long_addr - kernel_slide);

    return true;
}

/* confirmed working on all kernels 13.0-14.3 */
bool name2oid_and_its_dependencies_finder_13(xnu_pf_patch_t *patch,
        void *cacheable_stream){
    uint32_t *opcode_stream = cacheable_stream;

    /* This finds name2oid and three other things:
     *      sysctl_geometry_lock (needs to be held when we call name2oid)
     *      lck_rw_lock_shared
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

    g_sysctl_geometry_lock_addr = get_adrp_ldr_va_target(opcode_stream);

    uint32_t *lck_rw_lock_shared = get_branch_dst_ptr(opcode_stream[2],
            opcode_stream + 2);

    g_lck_rw_lock_shared_addr = xnu_ptr_to_va(lck_rw_lock_shared);

    uint32_t *name2oid = get_branch_dst_ptr(opcode_stream[6],
            opcode_stream + 6);

    g_name2oid_addr = xnu_ptr_to_va(name2oid);

    uint32_t *lck_rw_done = get_branch_dst_ptr(opcode_stream[9],
            opcode_stream + 9);

    g_lck_rw_done_addr = xnu_ptr_to_va(lck_rw_done);

    puts("xnuspy: found sysctl_geometry_lock");
    puts("xnuspy: found lck_rw_lock_shared");
    puts("xnuspy: found name2oid");
    puts("xnuspy: found lck_rw_done");

    return true;
}

/* confirmed working on all kernels 13.0-14.3 */
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

    uint32_t *lck_grp_alloc_init = get_branch_dst_ptr(*blp, blp);

    g_lck_grp_alloc_init_addr = xnu_ptr_to_va(lck_grp_alloc_init);

    printf("%s: lck_grp_alloc_init @ %#llx [unslid %#llx]\n", __func__,
            g_lck_grp_alloc_init_addr, g_lck_grp_alloc_init_addr - kernel_slide);
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

    uint32_t *lck_rw_alloc_init = get_branch_dst_ptr(*opcode_stream,
            opcode_stream);

    g_lck_rw_alloc_init_addr = xnu_ptr_to_va(lck_rw_alloc_init);

    puts("xnuspy: found lck_rw_alloc_init");

    return true;
}

/* confirmed working on all kernels 13.0-14.3 */
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
     * two instructions down
     */
    if((opcode_stream[2] & 0xffc003ff) != 0xd10003ff)
        return false;

    xnu_pf_disable_patch(patch);

    g_bcopy_phys_addr = xnu_ptr_to_va(opcode_stream);
    
    puts("xnuspy: found bcopy_phys");
    printf("%s: bcopy_phys @ %#llx\n", __func__, g_bcopy_phys_addr - kernel_slide);

    return true;
}

/* confirmed working on all kernels 13.0-14.3 */
bool phystokv_finder_13(xnu_pf_patch_t *patch, void *cacheable_stream){
    xnu_pf_disable_patch(patch);

    uint32_t *opcode_stream = cacheable_stream;

    /* We've landed inside arm_vm_init; the 5th instruction from this point
     * is branching to phystokv
     */
    uint32_t *phystokv = get_branch_dst_ptr(opcode_stream[5], opcode_stream + 5);

    g_phystokv_addr = xnu_ptr_to_va(phystokv);

    puts("xnuspy: found phystokv");
    printf("%s: phystokv @ %#llx\n", __func__, g_phystokv_addr - kernel_slide);

    return true;
}

/* confirmed working on all KPP kernels 13.0-14.3 */
bool kpp_patcher_13(xnu_pf_patch_t *patch, void *cacheable_stream){
    xnu_pf_disable_patch(patch);

    uint32_t *opcode_stream = cacheable_stream;

    /* We do not want the kernel telling KPP to enforce kernel integrity,
     * so we patch monitor_call's smc 0x11 to NOP.
     */
    /* XXX 14.3 panics with this NOP patch */
    /* *opcode_stream = 0xd503201f; */
    /* *opcode_stream = 0xD2800000; */

    /* if we don't lock down it panics with SError 0xbf575403 */
    /* uint32_t *p = xnu_va_to_ptr(0xFFFFFFF00716798C + kernel_slide); */
    /* *p = 0xd503201f; */

    /* uint32_t *p = xnu_va_to_ptr(0xFFFFFFF00716797C + kernel_slide); */
    /* mov w0, 0x802 */
    /* *p = 0x52810040; */

    /* uint32_t *p = xnu_va_to_ptr(0xFFFFFFF0072412F0 + kernel_slide); */
    /* *p = 0xD2800001; */

    /* asm volatile("mov w0, 0x800"); */
    /* asm volatile("mov w1, 0"); */
    /* asm volatile("mov w2, 0"); */
    /* asm volatile("mov w3, 0"); */
    /* asm volatile("smc 0x11"); */

    /* printf("%s: %#llx\n", __func__, xnu_ptr_to_va(opcode_stream) - kernel_slide); */
    puts("xnuspy: disabled KPP");

    return true;
}

/* The KTRR & AMCC patchfinder for 13.0-13.7 is from KTRW, @bazad */

/* confirmed working on all KTRR kernels 13.0-13.7 */
bool ktrr_lockdown_patcher_13(xnu_pf_patch_t *patch, void *cacheable_stream){
    xnu_pf_disable_patch(patch);

    uint32_t *opcode_stream = cacheable_stream;

    /* all to NOP */
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

    /* all to NOP */
    *opcode_stream = 0xd503201f;
    opcode_stream[2] = 0xd503201f;
    opcode_stream[3] = 0xd503201f;
    opcode_stream[4] = 0xd503201f;

    puts("xnuspy: disabled AMCC MMU lockdown");

    return true;
}

/* confirmed working on all kernels 13.0-14.3 */
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
    /* printf("%s: copyin @ %#llx\n", __func__, g_copyin_addr - kernel_slide); */

    return true;
}

/* confirmed working on all kernels 13.0-14.3 */
bool copyout_finder_13(xnu_pf_patch_t *patch, void *cacheable_stream){
    uint32_t *opcode_stream = cacheable_stream;

    /* We may have landed inside copyout. Unfortunately, clang decided to
     * make the order of the three ignored instructions different across
     * kernels. On some kernels, the matches/masks combo matches two places,
     * so we need to make sure we're inside copyout. We're inside copyout if
     * the eighth instruction from this point is cmp w0, 0x12.
     */
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
    /* printf("%s: copyout @ %#llx\n", __func__, g_copyout_addr - kernel_slide); */

    return true;
}

/* confirmed working on all kernels 13.0-14.3 */
bool PAN_disabler_13(xnu_pf_patch_t *patch, void *cacheable_stream){
    /* replaces all msr PAN, #1 with msr PAN, #0 */
    *(uint32_t *)cacheable_stream = 0xd500409f;

    return true;
}

/* confirmed working on all kernels 13.0-14.3 */
bool IOSleep_finder_13(xnu_pf_patch_t *patch, void *cacheable_stream){
    xnu_pf_disable_patch(patch);

    g_IOSleep_addr = xnu_ptr_to_va(cacheable_stream);

    puts("xnuspy: found IOSleep");
    /* printf("%s: IOSleep @ %#llx\n", __func__, g_IOSleep_addr - kernel_slide); */

    return true;
}

/* confirmed working on all kernels 13.0-14.3 */
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
    printf("%s: kprintf @ %#llx\n", __func__, g_kprintf_addr - kernel_slide);
    return true;
}

#if 0
/* confirmed working on all kernels 13.0-14.3 */
bool DAIFSet_patcher_13(xnu_pf_patch_t *patch, void *cacheable_stream){
    /* Because we are using hardware breakpoints to synchronize access
     * to code we're modifying, we need to make sure PSTATE.D is never
     * masked. PSTATE.D being unmasked is one of the conditions for hardware
     * breakpoints to fire inside EL1.
     *
     * DAIFSet controls the setting of PSTATE.{D,A,I,F} to 1, so for every
     * msr DAIFSet, #n we find, we turn off the bit that represents PSTATE.D
     * in its immediate.
     */
    *(uint32_t *)cacheable_stream &= ~0x800;

    return true;
}

/* confirmed working on all kernels 13.0-14.3 */
bool LowResetVectorBase_patcher_13(xnu_pf_patch_t *patch, void *cacheable_stream){
    /* PSTATE.D is masked before the device returns to LowResetVectorBase
     * upon reset. See the pseudocode for AArch64.TakeReset in the ARMv8
     * reference manual. In order to keep our hardware breakpoints alive,
     * we need to unmask PSTATE.D.
     *
     * This decides if we're at LowResetVectorBase. If we are, we modify it to 
     * look like this:
     *      MSR DAIFClr, #0x8
     *      B _reset_vector
     */
    uint32_t *opcode_stream = cacheable_stream;
    uint32_t *maybe_reset_vector = get_branch_dst_ptr(*opcode_stream, opcode_stream);

    /* first instruction is msr oslar_el1, xzr? */
    if(*maybe_reset_vector != 0xd510109f)
        return false;

    /* third instruction is not mov x0, x20? */
    if(maybe_reset_vector[2] == 0xaa0003f4)
        return false;

    xnu_pf_disable_patch(patch);

    /* if we're here, we found LowResetVectorBase */
    uint32_t *LowResetVectorBase = opcode_stream;

    uint32_t saved_branch = *LowResetVectorBase;

    /* msr DAIFClr, #0x8 */
    *LowResetVectorBase = 0xd50348ff;

    /* the branch is now 4 bytes closer to reset_vector, so update its
     * immediate
     */
    int32_t new_imm26 = bits(saved_branch, 0, 25) - 1;

    saved_branch &= ~0x3ffffff;
    saved_branch |= new_imm26;

    LowResetVectorBase[1] = saved_branch;

    puts("xnuspy: patched LowResetVectorBase");

    return true;
}
#endif
