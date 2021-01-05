#include <mach-o/nlist.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/sysctl.h>

#include "common/common.h"
#include "common/pongo.h"
#include "common/xnuspy_structs.h"

#include "el1/hook_system_check_sysctlbyname_hook_instrs.h"
#include "el1/xnuspy_ctl_tramp_instrs.h"

#include "pf/disas.h"
#include "pf/macho.h"
#include "pf/offsets.h"
#include "pf/pf_common.h"

static void DumpMemory(void *startaddr, void *data, size_t size){
    char ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    int putloc = 0;
    void *curaddr = startaddr;
    for (i = 0; i < size; ++i) {
        if(!putloc){
            if(startaddr != (void *)-1){
                printf("%#llx: ", curaddr);
                curaddr += 0x10;
            }

            putloc = 1;
        }

        printf("%02X ", ((unsigned char*)data)[i]);
        if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
            ascii[i % 16] = ((unsigned char*)data)[i];
        } else {
            ascii[i % 16] = '.';
        }
        if ((i+1) % 8 == 0 || i+1 == size) {
            printf(" ");
            if ((i+1) % 16 == 0) {
                printf("|  %s \n", ascii);
                putloc = 0;
            } else if (i+1 == size) {
                ascii[(i+1) % 16] = '\0';
                if ((i+1) % 16 <= 8) {
                    printf(" ");
                }
                for (j = (i+1) % 16; j < 16; ++j) {
                    printf("   ");
                }
                printf("|  %s \n", ascii);
                putloc = 0;
            }
        }
    }
}

static uint64_t g_xnuspy_ctl_addr = 0;

/* address of start of __TEXT_EXEC in xnuspy_ctl image */
static uint64_t g_xnuspy_ctl_img_codestart = 0;

/* how many bytes to we need to mark as executable inside xnuspy_ctl_tramp? */
static uint64_t g_xnuspy_ctl_img_codesz = 0;

static uint64_t g_xnuspy_tramp_page_addr = 0;

/* needed for when we are too far away for an immediate branch */
static uint64_t g_xnuspy_tramp_page_end = 0;

static uint64_t g_first_reflector_page = 0;

uint64_t *xnuspy_cache_base = NULL;

#define WRITE_INSTR_TO_SCRATCH_SPACE(opcode) \
    do { \
        if(num_free_instrs < 2){ \
            printf("xnuspy: ran out\n" \
                    "  of executable scratch\n" \
                    "  space in function %s\n", \
                    __func__); \
            xnuspy_fatal_error(); \
        } \
        *scratch_space = (opcode); \
        scratch_space++; \
        num_free_instrs--; \
    } while (0) \

#define WRITE_QWORD_TO_SCRATCH_SPACE(qword) \
    do { \
        if(num_free_instrs < 2){ \
            printf("xnuspy: ran out\n" \
                    "  of executable scratch\n" \
                    "  space in function %s\n", \
                    __func__); \
            xnuspy_fatal_error(); \
        } \
        *(uint64_t *)scratch_space = (qword); \
        scratch_space += 2; \
        num_free_instrs -= 2; \
    } while (0); \

#define XNUSPY_CACHE_WRITE(thing) \
    do { \
        *xnuspy_cache_cursor++ = (thing); \
    } while (0) \

static struct xnuspy_ctl_kernel_symbol {
    const char *symbol;
    uint64_t *valp;
} g_xnuspy_ctl_needed_symbols[] = {
    { "_allprocp", &g_allproc_addr },
    { "_bcopy_phys", &g_bcopy_phys_addr },
    { "_copyin", &g_copyin_addr },
    { "_copyout", &g_copyout_addr },
    { "_current_proc", &g_current_proc_addr },
    { "_first_reflector_page", &g_first_reflector_page },
    { "_iOS_version", &g_kern_version_major },
    { "_IOSleep", &g_IOSleep_addr },
    { "_ipc_port_release_send", &g_ipc_port_release_send_addr },
    { "_kalloc_canblock", &g_kalloc_canblock_addr },
    { "_kalloc_external", &g_kalloc_external_addr },
    { "_kernel_mapp", &g_kernel_map_addr },
    { "_kernel_slide", &kernel_slide },
    { "_kernel_thread_start", &g_kernel_thread_start_addr },
    { "_kfree_addr", &g_kfree_addr_addr },
    { "_kfree_ext", &g_kfree_ext_addr },
    { "_kprintf", &g_kprintf_addr },
    { "_lck_grp_alloc_init", &g_lck_grp_alloc_init_addr },
    { "_lck_grp_free", &g_lck_grp_free_addr },
    { "_lck_mtx_unlock", &g_lck_mtx_unlock_addr },
    { "_lck_rw_alloc_init", &g_lck_rw_alloc_init_addr },
    { "_lck_rw_done", &g_lck_rw_done_addr },
    { "_lck_rw_free", &g_lck_rw_free_addr },
    { "_lck_rw_lock_exclusive", &g_lck_rw_lock_exclusive_addr },
    { "_lck_rw_lock_shared", &g_lck_rw_lock_shared_addr },
    { "_lck_rw_lock_shared_to_exclusive", &g_lck_rw_lock_shared_to_exclusive_addr },
    { "__mach_make_memory_entry_64", &g_mach_make_memory_entry_64_addr },
    { "_mach_vm_map_external", &g_mach_vm_map_external_addr },
    { "_offsetof_struct_thread_map", &g_offsetof_struct_thread_map },
    { "_phystokv", &g_phystokv_addr },
    { "_proc_list_lock", &g_proc_list_lock_addr },
    { "_proc_list_mlockp", &g_proc_list_mlock_addr },
    { "_proc_pid", &g_proc_pid_addr },
    { "_proc_ref_locked", &g_proc_ref_locked_addr },
    { "_proc_rele_locked", &g_proc_rele_locked_addr },
    { "_proc_uniqueid", &g_proc_uniqueid_addr },
    { "_thread_deallocate", &g_thread_deallocate_addr },
    { "__vm_deallocate", &g_vm_deallocate_addr },
    { "_vm_map_wire_external", &g_vm_map_wire_external_addr },
    { "_vm_map_unwire", &g_vm_map_unwire_addr },
    { "_xnuspy_tramp_page", &g_xnuspy_tramp_page_addr },
    { "_xnuspy_tramp_page_end", &g_xnuspy_tramp_page_end },
};

static uint32_t *write_h_s_c_sbn_h_instrs(uint32_t *scratch_space,
        uint64_t *num_free_instrsp){
    uint64_t num_free_instrs = *num_free_instrsp;
    WRITE_HOOK_SYSTEM_CHECK_SYSCTLBYNAME_HOOK_INSTRS;
    *num_free_instrsp = num_free_instrs;
    return scratch_space;
}

static void anything_missing(void){
    static int printed_err_hdr = 0;

#define chk(expression, msg) \
    do { \
        if(expression){ \
            if(!printed_err_hdr){ \
                printf("xnuspy: error(s) before\n" \
                        "  we continue:\n"); \
                printed_err_hdr = 1; \
            } \
            printf("  "msg); \
        } \
    } while (0) \

    chk(!g_sysent_addr, "sysent not found\n");

    if(g_kern_version_major == iOS_13_x){
        chk(!g_kalloc_canblock_addr, "kalloc_canblock not found\n");
        chk(!g_kfree_addr_addr, "kfree_addr not found\n");
    }
    else{
        chk(!g_kalloc_external_addr, "kalloc_external not found\n");
        chk(!g_kfree_ext_addr, "kfree_ext not found\n");
    }

    chk(!g_sysctl__kern_children_addr, "sysctl__kern_children\n"
            "  not found\n");
    chk(!g_sysctl_register_oid_addr, "sysctl_register_oid not found\n");
    chk(!g_sysctl_handle_long_addr, "sysctl_handle_long not found\n");
    chk(!g_name2oid_addr, "name2oid not found\n");
    chk(!g_sysctl_geometry_lock_addr, "sysctl_geometry_lock not found\n");
    chk(!g_lck_rw_done_addr, "lck_rw_done not found\n");
    chk(!g_h_s_c_sbn_branch_addr, "did not find hscsbn branch addr\n");
    chk(!g_h_s_c_sbn_epilogue_addr, "hscsbn epilogue not found\n");
    chk(!g_lck_grp_alloc_init_addr, "lck_grp_alloc_init not found\n");
    chk(!g_lck_rw_alloc_init_addr, "lck_rw_alloc_init not found\n");
    chk(!g_exec_scratch_space_addr, "unused executable code not found\n");
    chk(!g_bcopy_phys_addr, "bcopy_phys not found\n");
    chk(!g_phystokv_addr, "phystokv not found\n");
    chk(!g_copyin_addr, "copyin not found\n");
    chk(!g_copyout_addr, "copyout not found\n");
    chk(!g_IOSleep_addr, "IOSleep not found\n");
    chk(!g_kprintf_addr, "kprintf not found\n");
    chk(!g_vm_map_unwire_addr, "vm_map_unwire not found\n");
    chk(!g_vm_deallocate_addr, "vm_deallocate not found\n");
    chk(!g_kernel_map_addr, "kernel_map not found\n");
    chk(!g_kernel_thread_start_addr, "kernel_thread_start not found\n");
    chk(!g_thread_deallocate_addr, "thread_deallocate not found\n");
    chk(!g_mach_make_memory_entry_64_addr, "mach_make_memory_entry_64 not found\n");
    chk(!g_offsetof_struct_thread_map, "offsetof(struct thread, map) not found\n");
    chk(!g_current_proc_addr, "current_proc not found\n");
    chk(!g_proc_list_lock_addr, "proc_list_lock not found\n");
    chk(!g_proc_ref_locked_addr, "proc_ref_locked not found\n");
    chk(!g_proc_list_mlock_addr, "address of proc_list_mlock not found\n");
    chk(!g_lck_mtx_unlock_addr, "lck_mtx_unlock not found\n");
    chk(!g_proc_rele_locked_addr, "proc_rele_locked not found\n");
    chk(!g_proc_uniqueid_addr, "proc_uniqueid not found\n");
    chk(!g_proc_pid_addr, "proc_pid not found\n");
    chk(!g_allproc_addr, "address of allproc not found\n");
    chk(!g_lck_rw_lock_shared_addr, "lck_rw_lock_shared not found\n");
    chk(!g_lck_rw_lock_shared_to_exclusive_addr,
            "lck_rw_lock_shared_to_exclusive not found\n");
    chk(!g_lck_rw_lock_exclusive_addr, "lck_rw_lock_exclusive not found\n");
    chk(!g_vm_map_wire_external_addr, "vm_map_wire_external not found\n");
    chk(!g_mach_vm_map_external_addr, "mach_vm_map_external not found\n");
    chk(!g_ipc_port_release_send_addr, "ipc_port_release_send not found\n");
    chk(!g_lck_rw_free_addr, "lck_rw_free not found\n");
    chk(!g_lck_grp_free_addr, "lck_grp_free not found\n");
    chk(!g_patched_doprnt_hide_pointers, "doprnt_hide_pointers wasn't patched\n");

    /* if we printed the error header, something is missing */
    if(printed_err_hdr)
        xnuspy_fatal_error();
}

static void initialize_xnuspy_cache(void){
    uint64_t *xnuspy_cache_cursor = xnuspy_cache_base;

    XNUSPY_CACHE_WRITE(g_sysctl__kern_children_addr);
    XNUSPY_CACHE_WRITE(g_sysctl_register_oid_addr);
    XNUSPY_CACHE_WRITE(g_sysctl_handle_long_addr);
    XNUSPY_CACHE_WRITE(g_name2oid_addr);
    XNUSPY_CACHE_WRITE(g_sysctl_geometry_lock_addr);
    XNUSPY_CACHE_WRITE(g_lck_rw_lock_shared_addr);
    XNUSPY_CACHE_WRITE(g_lck_rw_done_addr);

    /* DID_REGISTER_SYSCTL */
    XNUSPY_CACHE_WRITE(0);

    XNUSPY_CACHE_WRITE(g_h_s_c_sbn_epilogue_addr);
    XNUSPY_CACHE_WRITE(g_xnuspy_sysctl_name_ptr);
    XNUSPY_CACHE_WRITE(g_xnuspy_sysctl_descr_ptr);
    XNUSPY_CACHE_WRITE(g_xnuspy_sysctl_fmt_ptr);
    XNUSPY_CACHE_WRITE(g_xnuspy_sysctl_mib_ptr);
    XNUSPY_CACHE_WRITE(g_xnuspy_sysctl_mib_count_ptr);
    XNUSPY_CACHE_WRITE(g_xnuspy_ctl_callnum);
    XNUSPY_CACHE_WRITE(g_kern_version_major);
    XNUSPY_CACHE_WRITE(g_xnuspy_ctl_addr);
    XNUSPY_CACHE_WRITE(g_xnuspy_ctl_img_codestart);
    XNUSPY_CACHE_WRITE(g_xnuspy_ctl_img_codesz);

    /* Used inside xnuspy_ctl_tramp.s, initialize to false */
    XNUSPY_CACHE_WRITE(0);

    XNUSPY_CACHE_WRITE(g_phystokv_addr);

    XNUSPY_CACHE_WRITE(g_bcopy_phys_addr);

    if(g_kern_version_major == iOS_13_x){
        XNUSPY_CACHE_WRITE(g_kalloc_canblock_addr);
        XNUSPY_CACHE_WRITE(g_kfree_addr_addr);
    }
    else{
        XNUSPY_CACHE_WRITE(g_kalloc_external_addr);
        XNUSPY_CACHE_WRITE(g_kfree_ext_addr);
    }

    /* new PTE space, zero it out */
    XNUSPY_CACHE_WRITE(0);

    puts("xnuspy: initialized xnuspy cache");
}

static uint32_t *install_h_s_c_sbn_hook(uint32_t *scratch_space,
        uint64_t *num_free_instrsp){
    uint64_t num_free_instrs = *num_free_instrsp;

    /* allow hook_system_check_sysctlbyname_hook access to xnuspy cache */
    WRITE_QWORD_TO_SCRATCH_SPACE(xnu_ptr_to_va(xnuspy_cache_base));

    uint32_t *h_s_c_sbn_hook_addr = (uint32_t *)xnu_ptr_to_va(scratch_space);
    uint32_t *h_s_c_sbn_branch_from = xnu_va_to_ptr(g_h_s_c_sbn_branch_addr);

    scratch_space = write_h_s_c_sbn_h_instrs(scratch_space, &num_free_instrs);

    /* restore the five instructions we overwrote at the end of
     * system_check_sysctlbyname_hook to the end of `not_ours`
     * in hook_system_check_sysctlbyname_hook.s */
    WRITE_INSTR_TO_SCRATCH_SPACE(h_s_c_sbn_branch_from[0]);
    WRITE_INSTR_TO_SCRATCH_SPACE(h_s_c_sbn_branch_from[1]);
    WRITE_INSTR_TO_SCRATCH_SPACE(h_s_c_sbn_branch_from[2]);
    WRITE_INSTR_TO_SCRATCH_SPACE(h_s_c_sbn_branch_from[3]);
    WRITE_INSTR_TO_SCRATCH_SPACE(h_s_c_sbn_branch_from[4]);
    WRITE_INSTR_TO_SCRATCH_SPACE(0xd65f03c0);    /* ret */
    
    write_blr(8, (uint64_t)h_s_c_sbn_branch_from, (uint64_t)h_s_c_sbn_hook_addr);

    *num_free_instrsp = num_free_instrs;

    return scratch_space;
}

static uint32_t *write_xnuspy_ctl_tramp_instrs(uint32_t *scratch_space,
        uint64_t *num_free_instrsp){
    uint64_t num_free_instrs = *num_free_instrsp;
    WRITE_XNUSPY_CTL_TRAMP_INSTRS;
    *num_free_instrsp = num_free_instrs;
    return scratch_space;
}

/* This function will replace an _enosys sysent with the address of
 * xnuspy_ctl_tramp. For the reason we need a trampoline, see
 * module/el1/xnuspy_ctl_tramp.s */
static uint32_t *install_xnuspy_ctl_tramp(uint32_t *scratch_space,
        uint64_t *num_free_instrsp){
    uint64_t num_free_instrs = *num_free_instrsp;

    uint8_t *sysent_stream = (uint8_t *)xnu_va_to_ptr(g_sysent_addr);
    size_t sizeof_struct_sysent = 0x18;

    bool tagged_ptr = false;
    uint16_t old_tag = 0;

    uint32_t limit = 1000;

    for(uint32_t i=0; i<limit; i++){
        uint64_t sy_call = *(uint64_t *)sysent_stream;

        /* tagged pointer */
        if((sy_call & 0xffff000000000000) != 0xffff000000000000){
            old_tag = (sy_call >> 48);

            sy_call |= 0xffff000000000000;
            sy_call += kernel_slide;

            tagged_ptr = true;
        }

        /* mov w0, ENOSYS; ret */
        if(*(uint64_t *)xnu_va_to_ptr(sy_call) == 0xd65f03c0528009c0){
            g_xnuspy_ctl_callnum = i;

            /* allow xnuspy_ctl_tramp access to xnuspy cache */
            WRITE_QWORD_TO_SCRATCH_SPACE(xnu_ptr_to_va(xnuspy_cache_base));

            /* sy_call */
            if(!tagged_ptr)
                *(uint64_t *)sysent_stream = xnu_ptr_to_va(scratch_space);
            else{
                uint64_t untagged = (xnu_ptr_to_va(scratch_space) &
                        0xffffffffffff) - kernel_slide;

                /* re-tag */
                uint64_t new_sy_call = untagged | ((uint64_t)old_tag << 48);

                *(uint64_t *)sysent_stream = new_sy_call;
            }

            /* no 32 bit processes on iOS 11+, so no argument munger */
            *(uint64_t *)(sysent_stream + 0x8) = 0;

            /* this syscall will return an integer */
            *(int32_t *)(sysent_stream + 0x10) = 1; /* _SYSCALL_RET_INT_T */

            /* this syscall has four arguments */
            *(int16_t *)(sysent_stream + 0x14) = 4;

            /* four 64 bit arguments, so arguments total 32 bytes */
            *(uint16_t *)(sysent_stream + 0x16) = 0x20;

            *num_free_instrsp = num_free_instrs;

            return scratch_space;
        }

        sysent_stream += sizeof_struct_sysent;
    }

    puts("xnuspy: didn't");
    puts("  find a sysent entry");
    puts("  with enosys?");

    xnuspy_fatal_error();
}

static void initialize_xnuspy_callnum_sysctl_offsets(void){
    uint8_t *sysctl_stuff = (uint8_t *)xnuspy_cache_base + (PAGE_SIZE / 2);

    /* sysctl name for the system call number */
    const char *sysctl_name = "kern.xnuspy_ctl_callnum";
    strcpy((char *)sysctl_stuff, sysctl_name);

    char *sysctl_namep = (char *)sysctl_stuff;

    const char *sysctl_descr = "query for xnuspy_ctl's system call number";
    size_t sysctl_name_len = strlen(sysctl_name);
    char *sysctl_descrp = (char *)(sysctl_stuff + sysctl_name_len + 1);
    strcpy(sysctl_descrp, sysctl_descr);

    /* how sysctl should format the call number, long */
    size_t sysctl_descr_len = strlen(sysctl_descr);
    char *sysctl_fmtp = sysctl_descrp + strlen(sysctl_descr) + 1;
    strcpy(sysctl_fmtp, "L");

    uint32_t *sysctl_mibp = (uint32_t *)((uint64_t)(sysctl_fmtp + 8) & ~7);
    uint32_t *sysctl_mib_countp = (uint32_t *)(sysctl_mibp + CTL_MAXNAME);

    g_xnuspy_sysctl_name_ptr = xnu_ptr_to_va(sysctl_namep);
    g_xnuspy_sysctl_descr_ptr = xnu_ptr_to_va(sysctl_descrp);
    g_xnuspy_sysctl_fmt_ptr = xnu_ptr_to_va(sysctl_fmtp);
    g_xnuspy_sysctl_mib_ptr = xnu_ptr_to_va(sysctl_mibp);
    g_xnuspy_sysctl_mib_count_ptr = xnu_ptr_to_va(sysctl_mib_countp);
}

static void initialize_xnuspy_ctl_image_koff(char *ksym, uint64_t *va){
    const size_t num_needed_symbols = sizeof(g_xnuspy_ctl_needed_symbols) /
        sizeof(*g_xnuspy_ctl_needed_symbols);

    for(size_t i=0; i<num_needed_symbols; i++){
        if(strcmp(ksym, g_xnuspy_ctl_needed_symbols[i].symbol) == 0){
            /* printf("%s: replacing '%s' with %#llx (unslid %#llx)\n", __func__, */
            /*         ksym, *g_xnuspy_ctl_needed_symbols[i].val, */
            /*         *g_xnuspy_ctl_needed_symbols[i].val - kernel_slide); */
            
            *va = *g_xnuspy_ctl_needed_symbols[i].valp;
            return;
        }
    }
}

/* fill in all our kernel offsets in __koff, initialize g_xnuspy_ctl_addr
 * and g_xnuspy_ctl_img_codesz */
static void process_xnuspy_ctl_image(void *xnuspy_ctl_image){
    struct mach_header_64 *mh = xnuspy_ctl_image;
    struct load_command *lc = (struct load_command *)(mh + 1);
    struct symtab_command *st = NULL;
    
    for(int i=0; i<mh->ncmds; i++){
        if(lc->cmd == LC_SYMTAB)
            st = (struct symtab_command *)lc;
        else if(lc->cmd == LC_SEGMENT_64){
            struct segment_command_64 *sc = (struct segment_command_64 *)lc;

            if(strcmp(sc->segname, "__TEXT_EXEC") == 0){
                g_xnuspy_ctl_img_codestart = xnu_ptr_to_va(mh) + sc->vmaddr;
                g_xnuspy_ctl_img_codesz = sc->vmsize;
            }
        }

        if(st && g_xnuspy_ctl_img_codesz)
            break;

        lc = (struct load_command *)((uint8_t *)lc + lc->cmdsize);
    }

    if(!st || !g_xnuspy_ctl_img_codesz){
        printf("xnuspy: could not find\n");

        if(!st)
            printf("   symtab\n");

        if(!g_xnuspy_ctl_img_codesz)
            printf("   g_xnuspy_ctl_img_codesz\n");

        xnuspy_fatal_error();
    }

    struct nlist_64 *symtab = (struct nlist_64 *)((uint8_t *)xnuspy_ctl_image +
        st->symoff);

    char *strtab = (char *)xnuspy_ctl_image + st->stroff;

    for(int i=0; i<st->nsyms; i++){
        char *sym = strtab + symtab[i].n_un.n_strx;
        uint64_t *va = (uint64_t *)((uint8_t *)xnuspy_ctl_image +
                symtab[i].n_value);

        if(strcmp(sym, "_xnuspy_ctl") == 0)
            g_xnuspy_ctl_addr = xnu_ptr_to_va(va);
        else
            initialize_xnuspy_ctl_image_koff(sym, va);
    }

    printf("%s: g_xnuspy_ctl_addr @ %#llx, code start @ %#llx, code size %#llx\n",
            __func__, g_xnuspy_ctl_addr, g_xnuspy_ctl_img_codestart,
            g_xnuspy_ctl_img_codesz);
    printf("%s: image @ %#llx [unslid %#llx]\n", __func__, xnu_ptr_to_va(mh),
            xnu_ptr_to_va(mh) - kernel_slide);
}

void (*next_preboot_hook)(void);

void xnuspy_preboot_hook(void){
    anything_missing();

    /* We are going to allocate a bunch of pages that xnuspy will use
     * to reflect the user's replacement code on. Allocating them inside of
     * the module will relieve the system from the stress of doing a bunch
     * of page sized allocations.
     *
     * We need to figure out *how* much static memory can be allocated before
     * we hit the limit and panic. From the output in checkra1n's KPF, the
     * ramdisk is 0x110000 bytes, so we need to make sure there's space for
     * that.  Unfortunately alloc_static_current and alloc_static_end aren't
     * exported so we need to calculate them ourselves. These calculations are
     * the ones done inside src/kernel/std.c. I don't think anything before
     * us has called alloc_static so these calculations are fine here. */
    uint64_t alloc_static_current =
        (kCacheableView - 0x800000000 + gBootArgs->topOfKernelData) & ~0x3fff;
    uint64_t alloc_static_base = alloc_static_current;
    uint64_t alloc_static_end = 0x417fe0000;
    uint64_t alloc_static_hardcap = alloc_static_base + (1024 * 1024 * 64);

    if(alloc_static_end > alloc_static_hardcap)
        alloc_static_end = alloc_static_hardcap;

    printf("%s: alloc static current %#llx hardcap %#llx end %#llx\n", __func__,
            alloc_static_current, alloc_static_hardcap, alloc_static_end);

    uint64_t free_static_memory = alloc_static_end - alloc_static_current;

    printf("%s: starting with %#llx bytes of static memory\n", __func__,
            free_static_memory);

    /* make sure the ramdisk is accounted for, +- a couple pages for safety */
    free_static_memory -= 0x110000 + (PAGE_SIZE * 6);

    void *xnuspy_tramp_page = alloc_static(PAGE_SIZE);

    free_static_memory -= PAGE_SIZE;

    /* For every function someone wants to hook, I will write a single
     * unconditional immediate branch into some point on the above page
     * ONLY if this memory is within 128MB of the base of the kernelcache.
     * If this memory is not within that range, we cannot assume every
     * branch will fall within 128MB, and we'll have to default to unused
     * r-x code already in the kernelcache.
     *
     * TODO actually write the logic to default to the unused r-x code
     */
    if(!xnuspy_tramp_page){
        puts("xnuspy: alloc_static");
        puts("   returned NULL while");
        puts("   allocating xnuspy");
        puts("   trampoline page");

        xnuspy_fatal_error();
    }

#define _128MB (134217728)

    /* XXX why am I doing a conversion */
    uint64_t dist_from_kcbase = xnu_ptr_to_va(xnuspy_tramp_page) -
        xnu_ptr_to_va(mh_execute_header);
   
    printf("%s: trampoline page is %#llx bytes away from kc base\n", __func__,
            dist_from_kcbase);

    if(dist_from_kcbase > _128MB){
        printf("%s: dist_from_kcbase > 128MB, unimplemented, try again\n", __func__);
        xnuspy_fatal_error();
    }

    memset(xnuspy_tramp_page, 0, PAGE_SIZE);

    g_xnuspy_tramp_page_addr = xnu_ptr_to_va(xnuspy_tramp_page);
    g_xnuspy_tramp_page_end = g_xnuspy_tramp_page_addr + PAGE_SIZE;

    xnuspy_cache_base = alloc_static(PAGE_SIZE);

    free_static_memory -= PAGE_SIZE;

    if(!xnuspy_cache_base){
        puts("xnuspy: alloc_static");
        puts("   returned NULL while");
        puts("   allocating for xnuspy");
        puts("   cache");

        xnuspy_fatal_error();
    }

    printf("%s: xnuspy_ctl img is %#x bytes\n", __func__,
            loader_xfer_recv_count);

    /* DumpMemory(loader_xfer_recv_data, loader_xfer_recv_data, 0x100); */

    void *xnuspy_ctl_image = alloc_static(loader_xfer_recv_count);

    if(!xnuspy_ctl_image){
        puts("xnuspy: alloc_static");
        puts("   returned NULL while");
        puts("   allocating pages for");
        puts("   xnuspy_ctl image");

        xnuspy_fatal_error();
    }

    free_static_memory -= (loader_xfer_recv_count + PAGE_SIZE) & ~(PAGE_SIZE - 1);


    /* printf("%s: xnuspy_ctl image %#llx loader_xfer_recv_data %#llx\n", __func__, */
    /*         xnuspy_ctl_image, loader_xfer_recv_data); */

    memcpy(xnuspy_ctl_image, loader_xfer_recv_data, loader_xfer_recv_count);

    printf("%s: left with %#llx bytes of static memory\n", __func__,
            free_static_memory);

    if(free_static_memory > 0x800000){
        printf("%s: too much static memory left, defaulting to 512 more pages\n",
                __func__);
        free_static_memory = 0x800000;
    }

    uint64_t reflector_pages_allocsz = (free_static_memory / PAGE_SIZE) *
        sizeof(struct xnuspy_reflector_page);

    printf("%s: reflector_pages_allocsz %#llx\n", __func__, reflector_pages_allocsz);

    /* Now we can start to create the linked list of pages xnuspy will
     * use to hold user code. alloc_static rounds up to the nearest page */
    struct xnuspy_reflector_page *reflector_pages = alloc_static(reflector_pages_allocsz);

    if(!reflector_pages){
        puts("xnuspy: alloc_static");
        puts("   returned NULL while");
        puts("   allocating reflector");
        puts("   pages linked list");

        xnuspy_fatal_error();
    }

    free_static_memory -= (reflector_pages_allocsz + PAGE_SIZE) & ~(PAGE_SIZE - 1);

    /* Build the linked list of reflector pages */
    uint64_t num_reflector_pages = free_static_memory / PAGE_SIZE;
    struct xnuspy_reflector_page *curpage = reflector_pages;

    printf("%s: %lld pages for reflection\n", __func__, num_reflector_pages);

    while(num_reflector_pages > 0){
        curpage->next = (struct xnuspy_reflector_page *)xnu_ptr_to_va(curpage + 1);
        curpage->used = 0;
        curpage->page = alloc_static(PAGE_SIZE);

        if(!curpage->page){
            puts("xnuspy: alloc_static");
            puts("   returned NULL while");
            puts("   allocating single");
            puts("   reflector page");

            xnuspy_fatal_error();
        }

        curpage->page = (struct xnuspy_reflector_page *)xnu_ptr_to_va(curpage->page);

        curpage++;
        num_reflector_pages--;
    }

    /* Terminate this linked list */
    curpage--;
    curpage->next = NULL;

    g_first_reflector_page = xnu_ptr_to_va(reflector_pages);

    free_static_memory = 0;

    process_xnuspy_ctl_image(xnuspy_ctl_image);

    /* install our hook for hook_system_check_sysctlbyname */
    uint64_t num_free_instrs = g_exec_scratch_space_size / sizeof(uint32_t);
    uint32_t *scratch_space = xnu_va_to_ptr(g_exec_scratch_space_addr);

    scratch_space = install_h_s_c_sbn_hook(scratch_space, &num_free_instrs);

    initialize_xnuspy_callnum_sysctl_offsets();

    /* replace an enosys sysent with xnuspy_ctl_tramp */
    scratch_space = install_xnuspy_ctl_tramp(scratch_space, &num_free_instrs);

    printf("%s: xnuspy_ctl_tramp @ %#llx\n", __func__,
            xnu_ptr_to_va(scratch_space)-kernel_slide);

    /* write the code for xnuspy_ctl_tramp */
    scratch_space = write_xnuspy_ctl_tramp_instrs(scratch_space,
            &num_free_instrs);

    initialize_xnuspy_cache();

    printf("%s: KERNEL SLIDE %#llx\n", __func__, kernel_slide);

    /* iphone se 2016 14.3 */
    /* volatile uint64_t *CPU0_IORVBar = (volatile uint64_t *)0x202050000; */
    /* uint64_t kppphys = *CPU0_IORVBar & 0xfffffffff; */
    /* printf("%s: kpp is @ %#llx (phys)\n", __func__, kppphys); */

    /* map_range(0xc10000000, kppphys, 0xc000, 3, 0, true); */

    /* uint8_t *kpp = (uint8_t *)0xc10000000; */
    /* printf("%#x\n", *(uint32_t *)(kpp + 0x4428)); */
    /* printf("%#x\n", *(uint32_t *)(kpp + 0x5988)); */
    /* *(uint32_t *)(kpp + 0x4428) = 0xd503201f; */
    /* *(uint32_t *)(kpp + 0x5988) = 0x52800028; */



    /* memset(kpp, 0, 0xc000); */

    /* volatile uint64_t *CPU0_IORVBar = (volatile uint64_t *)0x202050000; */
    /* volatile uint64_t *CPU1_IORVBar = (volatile uint64_t *)0x202150000; */

    /* uint64_t kppphys = *CPU0_IORVBar & 0xfffffffff; */
    /* printf("%s: kpp is @ %#llx (phys)\n", __func__, kppphys); */

    /* map_range(0xc10000000, kppphys, 0xc000, 3, 0, true); */

    /* uint8_t *kpp = (uint8_t *)0xc10000000; */

    /* for(int i=0; i<0xc000; i++){ */
    /*     kpp[i] = '\0'; */
    /* } */

    if(next_preboot_hook)
        next_preboot_hook();

    /* combat short read */
    asm volatile(".align 12");
}
