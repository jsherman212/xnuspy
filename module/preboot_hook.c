#include <mach-o/nlist.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/sysctl.h>

#include <pongo.h>

#include <asm/asm.h>
#include <asm/asm_support.h>
#include <common/common.h>
#include <pf/offsets.h>
#include <pf/pf_common.h>
#include <xnuspy/xnuspy_structs.h>

#include <xnuspy/el1/hook_system_check_sysctlbyname_hook_instrs.h>
#include <xnuspy/el1/xnuspy_ctl_tramp_instrs.h>

static uint64_t g_xnuspy_ctl_addr = 0;
/* address of start of __TEXT_EXEC in xnuspy_ctl image */
static uint64_t g_xnuspy_ctl_img_codestart = 0;
/* how many bytes to we need to mark as executable inside xnuspy_ctl_tramp? */
static uint64_t g_xnuspy_ctl_img_codesz = 0;
static uint64_t g_xnuspy_tramp_mem_addr = 0;
static uint64_t g_xnuspy_tramp_mem_end = 0;
/* Assume we're in range until we do the check */
static uint64_t g_hookme_in_range = 1;

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

#define XNUSPY_CACHE_WRITE(thing) \
    do { \
        printf("writing " #thing " = %llx\n", (uint64_t)thing); \
        *xnuspy_cache_cursor++ = (thing); \
    } while (0) \

static struct xnuspy_ctl_kernel_symbol {
    const char *symbol;
    uint64_t *valp;
} g_xnuspy_ctl_needed_symbols[] = {
    { "_allprocp", &g_allproc_addr },
    { "_bcopy_phys", &g_bcopy_phys_addr },
    { "_copyin", &g_copyin_addr },
    { "_copyinstr", &g_copyinstr_addr },
    { "_copyout", &g_copyout_addr },
    { "_current_proc", &g_current_proc_addr },
    { "_hookme_in_range", &g_hookme_in_range },
    { "_io_lock", &g_io_lock_addr },
    { "_iOS_version", &g_kern_version_major },
    { "_IOSleep", &g_IOSleep_addr },
    { "_ipc_port_release_send", &g_ipc_port_release_send_addr },
    { "_kalloc_canblock", &g_kalloc_canblock_addr },
    { "_kalloc_external", &g_kalloc_external_addr },
    { "_kern_version_minor", &g_kern_version_minor },
    { "_kernel_mapp", &g_kernel_map_addr },
    { "_kernel_slide", &kernel_slide },
    { "_kernel_thread_start", &g_kernel_thread_start_addr },
    { "_kfree_addr", &g_kfree_addr_addr },
    { "_kfree_ext", &g_kfree_ext_addr },
    { "_kprintf", &g_kprintf_addr },
    { "_lck_grp_alloc_init", &g_lck_grp_alloc_init_addr },
    { "_lck_grp_free", &g_lck_grp_free_addr },
    { "_lck_mtx_lock", &g_lck_mtx_lock_addr },
    { "_lck_mtx_unlock", &g_lck_mtx_unlock_addr },
    { "_lck_rw_alloc_init", &g_lck_rw_alloc_init_addr },
    { "_lck_rw_done", &g_lck_rw_done_addr },
    { "_lck_rw_free", &g_lck_rw_free_addr },
    { "_lck_rw_lock_exclusive", &g_lck_rw_lock_exclusive_addr },
    { "_lck_rw_lock_shared", &g_lck_rw_lock_shared_addr },
    { "_lck_rw_lock_shared_to_exclusive", &g_lck_rw_lock_shared_to_exclusive_addr },
    { "__mach_make_memory_entry_64", &g_mach_make_memory_entry_64_addr },
    { "_mach_to_bsd_errno", &g_mach_to_bsd_errno_addr },
    { "_mach_vm_map_external", &g_mach_vm_map_external_addr },
    { "__memmove", &g_memmove_addr },
    { "__memset", &g_memset_addr },
    { "_offsetof_struct_thread_map", &g_offsetof_struct_thread_map },
    { "_offsetof_struct_vm_map_refcnt", &g_offsetof_struct_vm_map_refcnt },
    { "__panic", &g_panic_addr },
    { "_phystokv", &g_phystokv_addr },
    // { "_proc_list_lock", &g_proc_list_lock_addr },
    { "_proc_list_mlockp", &g_proc_list_mlock_addr },
    { "_proc_name", &g_proc_name_addr },
    { "_proc_pid", &g_proc_pid_addr },
    { "_proc_ref_locked", &g_proc_ref_locked_addr },
    { "_proc_rele_locked", &g_proc_rele_locked_addr },
    { "_proc_uniqueid", &g_proc_uniqueid_addr },
    { "__snprintf", &g_snprintf_addr },
    { "__strlen", &g_strlen_addr },
    { "__strncmp", &g_strncmp_addr },
    { "_thread_deallocate", &g_thread_deallocate_addr },
    { "__thread_terminate", &g_thread_terminate_addr },
    { "__vm_deallocate", &g_vm_deallocate_addr },
    { "_vm_allocate_external", &g_vm_allocate_external_addr },
    { "_vm_map_deallocate", &g_vm_map_deallocate_addr },
    { "_vm_map_unwire", &g_vm_map_unwire_addr },
    { "_vm_map_unwire_nested", &g_vm_map_unwire_nested_addr },
    { "_vm_map_wire_external", &g_vm_map_wire_external_addr },
    { "_xnuspy_tramp_mem", &g_xnuspy_tramp_mem_addr },
    { "_xnuspy_tramp_mem_end", &g_xnuspy_tramp_mem_end },
    { "_IOLog", &g_iolog_addr },
};

static void anything_missing(void){
    static bool printed_err_hdr = false;

#define chk(expression, msg) \
    do { \
        if(expression){ \
            if(!printed_err_hdr){ \
                printf("xnuspy: error(s) before\n" \
                        "  we continue:\n"); \
                printed_err_hdr = true; \
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
    chk(!g_vm_map_unwire_addr && !g_vm_map_unwire_nested_addr, "vm_map_unwire{_nested} not found\n");
    chk(!g_vm_deallocate_addr, "vm_deallocate not found\n");
    chk(!g_kernel_map_addr, "kernel_map not found\n");
    chk(!g_kernel_thread_start_addr, "kernel_thread_start not found\n");
    chk(!g_thread_deallocate_addr, "thread_deallocate not found\n");
    chk(!g_mach_make_memory_entry_64_addr, "mach_make_memory_entry_64 not found\n");
    chk(!g_offsetof_struct_thread_map, "offsetof(struct thread, map) not found\n");
    chk(!g_current_proc_addr, "current_proc not found\n");
    // chk(!g_proc_list_lock_addr, "proc_list_lock not found\n");
    // chk(!g_proc_ref_locked_addr, "proc_ref_locked not found\n");
    chk(!g_proc_list_mlock_addr, "address of proc_list_mlock not found\n");
    chk(!g_lck_mtx_lock_addr, "lck_mtx_lock not found\n");
    chk(!g_lck_mtx_unlock_addr, "lck_mtx_unlock not found\n");
    // chk(!g_proc_rele_locked_addr, "proc_rele_locked not found\n");
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
    chk(!g_copyinstr_addr, "copyinstr not found\n");
    chk(!g_thread_terminate_addr, "thread_terminate not found\n");
    chk(!g_iolog_addr, "iolog not found\n");

    /* Specific to A10+. On A9(x), we don't need to keep TCR_EL1.HPD0 and
     * TCR_EL1.HPD1 set */
    if(socnum >= 0x8010){
        chk(!g_patched_pinst_set_tcr, "pinst_set_tcr wasn't patched\n");
        chk(!g_patched_all_msr_tcr_el1_x18, "did not patch all msr tcr_el1, x18\n");
    }

    chk(!g_proc_name_addr, "proc_name not found\n");
    chk(!g_snprintf_addr, "snprintf not found\n");
    chk(!g_strlen_addr, "strlen not found\n");
    chk(!g_strncmp_addr, "strncmp not found\n");
    chk(!g_memset_addr, "memset not found\n");
    chk(!g_memmove_addr, "memmove not found\n");
    chk(!g_panic_addr, "panic not found\n");
    chk(!g_mach_to_bsd_errno_addr, "mach_to_bsd_errno not found\n");

    if(is_14_5_and_above__pongo())
        chk(!g_io_lock_addr, "io_lock not found\n");

    chk(!g_vm_allocate_external_addr, "vm_allocate_external not found\n");
    chk(!g_vm_map_deallocate_addr, "vm_map_deallocate not found\n");
    chk(!g_offsetof_struct_vm_map_refcnt, "offsetof(vm_map_t, refcnt) not found\n");

    /* If we printed the error header, something is missing */
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

    /* DID_REGISTER_SYSCTL, used inside hook_system_check_sysctlbyname_hook,
     * initialize to false */
    XNUSPY_CACHE_WRITE(0);

    XNUSPY_CACHE_WRITE(g_h_s_c_sbn_epilogue_addr);
    XNUSPY_CACHE_WRITE(g_xnuspy_sysctl_mib_ptr);
    XNUSPY_CACHE_WRITE(g_xnuspy_sysctl_mib_count_ptr);
    XNUSPY_CACHE_WRITE(g_xnuspy_ctl_callnum);
    XNUSPY_CACHE_WRITE(g_kern_version_major);
    XNUSPY_CACHE_WRITE(g_xnuspy_ctl_addr);
    XNUSPY_CACHE_WRITE(g_xnuspy_ctl_img_codestart);
    XNUSPY_CACHE_WRITE(g_xnuspy_ctl_img_codesz);

    /* XNUSPY_CTL_IS_RX, used inside xnuspy_ctl_tramp.s, initialize to false */
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

    XNUSPY_CACHE_WRITE(g_kern_version_minor);

    puts("xnuspy: initialized xnuspy cache");
}

static uint32_t *install_h_s_c_sbn_hook(uint32_t *scratch_space,
        uint64_t *num_free_instrsp){
    uint64_t num_free_instrs = *num_free_instrsp;

    uint64_t h_s_c_sbn_hook_len =
        g_hook_system_check_sysctlbyname_hook_len / sizeof(uint32_t);
    uint32_t *h_s_c_sbn_hook_cursor =
        (uint32_t *)g_hook_system_check_sysctlbyname_hook;
    uint32_t *h_s_c_sbn_hook_end = h_s_c_sbn_hook_cursor + h_s_c_sbn_hook_len;

    uint64_t h_s_c_sbn_hook_addr = xnu_ptr_to_va(scratch_space);
    uint32_t *h_s_c_sbn_branch_from = xnu_va_to_ptr(g_h_s_c_sbn_branch_addr);
    uint32_t *h_s_c_sbn_branch_from_orig = h_s_c_sbn_branch_from;

    while(h_s_c_sbn_hook_cursor < h_s_c_sbn_hook_end){
        if(*(uint64_t *)h_s_c_sbn_hook_cursor == QWORD_PLACEHOLDER)
            *(uint64_t *)h_s_c_sbn_hook_cursor = xnu_ptr_to_va(xnuspy_cache_base);
        else if(*h_s_c_sbn_hook_cursor == OPCODE_PLACEHOLDER)
            *h_s_c_sbn_hook_cursor = *h_s_c_sbn_branch_from++;

        WRITE_INSTR_TO_SCRATCH_SPACE(*h_s_c_sbn_hook_cursor++);
    }

    /* Use x8 */
    write_blr(8, h_s_c_sbn_branch_from_orig, h_s_c_sbn_hook_addr);

    *num_free_instrsp = num_free_instrs;

    return scratch_space;
}

static uint32_t *write_xnuspy_ctl_tramp_instrs(uint32_t *scratch_space,
        uint64_t *num_free_instrsp){
    uint64_t num_free_instrs = *num_free_instrsp;

    uint64_t xnuspy_ctl_tramp_len = g_xnuspy_ctl_tramp_len / sizeof(uint32_t);
    uint32_t *xnuspy_ctl_tramp_cursor = (uint32_t *)g_xnuspy_ctl_tramp;
    uint32_t *xnuspy_ctl_tramp_end = xnuspy_ctl_tramp_cursor + xnuspy_ctl_tramp_len;

    while(xnuspy_ctl_tramp_cursor < xnuspy_ctl_tramp_end){
        if(*(uint64_t *)xnuspy_ctl_tramp_cursor == QWORD_PLACEHOLDER)
            *(uint64_t *)xnuspy_ctl_tramp_cursor = xnu_ptr_to_va(xnuspy_cache_base);

        WRITE_INSTR_TO_SCRATCH_SPACE(*xnuspy_ctl_tramp_cursor++);
    }

    *num_free_instrsp = num_free_instrs;

    return scratch_space;
}

/* This function will replace an _enosys sysent with the address of
 * xnuspy_ctl_tramp. For the reason we need a trampoline, see
 * module/el1/xnuspy_ctl_tramp.s */
static uint32_t *install_xnuspy_ctl_tramp(uint32_t *scratch_space,
        uint64_t *num_free_instrsp){
    struct sysent *sysent_stream = (struct sysent *)g_sysent_addr;

    bool tagged_ptr = false;
    uint16_t old_tag = 0;

    uint32_t limit = 1000;

    for(uint32_t i=0; i<limit; i++){
        uint64_t sy_call = sysent_stream->sy_call;

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

            uint64_t new_sy_call;

            /* sy_call */
            if(!tagged_ptr)
                new_sy_call = xnu_ptr_to_va(scratch_space);
            else{
                uint64_t untagged = (xnu_ptr_to_va(scratch_space) &
                        0xffffffffffff) - kernel_slide;

                /* re-tag */
                new_sy_call = untagged | ((uint64_t)old_tag << 48);
            }

            sysent_stream->sy_call = new_sy_call;

            /* no 32 bit processes on iOS 11+, so no argument munger */
            sysent_stream->sy_arg_munge32 = NULL;

            /* this syscall will return an integer */
            sysent_stream->sy_return_type = 1; /* _SYSCALL_RET_INT_T */

            /* this syscall has four arguments */
            sysent_stream->sy_narg = 4;

            /* four 64 bit arguments, so arguments total 32 bytes */
            sysent_stream->sy_arg_bytes = sizeof(uint64_t) * sysent_stream->sy_narg;

            return write_xnuspy_ctl_tramp_instrs(scratch_space,
                    num_free_instrsp);
        }

        sysent_stream++;
    }

    puts("xnuspy: didn't");
    puts("  find a sysent entry");
    puts("  with enosys?");

    xnuspy_fatal_error();
}

static void initialize_xnuspy_callnum_sysctl_offsets(void){
    uint32_t *sysctl_mibp = (uint32_t *)((uint8_t *)xnuspy_cache_base + (PAGE_SIZE / 2));
    uint32_t *sysctl_mib_countp = (uint32_t *)(sysctl_mibp + CTL_MAXNAME);

    g_xnuspy_sysctl_mib_ptr = xnu_ptr_to_va(sysctl_mibp);
    g_xnuspy_sysctl_mib_count_ptr = xnu_ptr_to_va(sysctl_mib_countp);
}

static void initialize_xnuspy_ctl_image_koff(char *ksym, uint64_t *va){
    const size_t num_needed_symbols = sizeof(g_xnuspy_ctl_needed_symbols) /
        sizeof(*g_xnuspy_ctl_needed_symbols);

    for(size_t i=0; i<num_needed_symbols; i++){
        if(strcmp(ksym, g_xnuspy_ctl_needed_symbols[i].symbol) == 0){
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

        printf("  This may be happening\n"
               "  due to a short read,\n"
               "  try adding some code to\n"
               "  module/el1/xnuspy_ctl/xnuspy_ctl.c\n"
               "  to increase image size.\n");

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
        else if(strcmp(sym, "__hookme") == 0){
            uint64_t _hookme_kva = xnu_ptr_to_va(va);
            uint64_t ceil = g_xnuspy_tramp_mem_end;
            int64_t dist = ceil - _hookme_kva;

            if(dist < 0)
                dist = -dist;

            if(dist > 0x8000000){
                g_hookme_in_range = 0;

                printf("xnuspy: hookme is unable\n"
                       " to be hooked, XNUSPY_CALL_HOOKME\n"
                       " is disabled.\n");
            }

            /* In case we've already seen _hookme_in_range, initialize this
             * symbol again */
            initialize_xnuspy_ctl_image_koff("_hookme_in_range",
                    &g_hookme_in_range);
        }
        else{
            initialize_xnuspy_ctl_image_koff(sym, va);
        }
    }
}

#ifndef XNUSPY_TRAMP_PAGES
#define XNUSPY_TRAMP_PAGES 1
#endif

void (*next_preboot_hook)(void);

void xnuspy_preboot_hook(void){
    anything_missing();
    
    puts("xnuspy_preboot_hook reached!");

    printf("====== DUMPING SYMBOLS ======\n");

    const size_t num_needed_symbols = sizeof(g_xnuspy_ctl_needed_symbols) /
    sizeof(*g_xnuspy_ctl_needed_symbols);

    for(size_t i=0; i<num_needed_symbols; i++){
        struct xnuspy_ctl_kernel_symbol *item = &g_xnuspy_ctl_needed_symbols[i];
        printf("%s = %llx\n", item->symbol, *item->valp);
    }

    uint64_t xnuspy_tramp_mem_size = PAGE_SIZE * XNUSPY_TRAMP_PAGES;
    void *xnuspy_tramp_mem = alloc_static(xnuspy_tramp_mem_size);
    printf("xnuspy_tramp_mem = %llx\n", xnu_ptr_to_va(xnuspy_tramp_mem));

    if(!xnuspy_tramp_mem){
        puts("xnuspy: alloc_static");
        puts("   returned NULL while");
        puts("   allocating xnuspy");
        puts("   trampoline mem");

        xnuspy_fatal_error();
    }

    memset(xnuspy_tramp_mem, 0, xnuspy_tramp_mem_size);

    /* For every function which gets hooked, a single unconditional
     * immediate branch is written targeting some point on the
     * xnuspy_tramp_page. So that page must be within 128MB from the first
     * code in the kernelcache. If it's is not within that range, we cannot
     * assume every branch will fall within 128MB, and will fall back to
     * the unused r-x page we found earlier. We need to figure out the
     * address of the first page of code. */

    /* I hope this is right */
    struct segment_command_64 *__PRELINK_TEXT = macho_get_segment(mh_execute_header,
            "__PRELINK_TEXT");
    struct segment_command_64 *__TEXT_EXEC = macho_get_segment(mh_execute_header,
            "__TEXT_EXEC");

    struct section_64 *sec64 = (struct section_64 *)(__TEXT_EXEC + 1);

    /* codestart already slid on all kernels when reading from __TEXT:HEADER */
    uint64_t codestart = UINT64_MAX;

    for(uint32_t i=0; i<__TEXT_EXEC->nsects; i++){
        if(sec64->addr < codestart)
            codestart = sec64->addr;

        sec64++;
    }
    printf("codestart = %llx\n", codestart);

    /* Old style kc */
    if(__PRELINK_TEXT && __PRELINK_TEXT->vmsize > 0){
        printf("this is an old style kc\n");
        struct segment_command_64 *__PRELINK_INFO = macho_get_segment(mh_execute_header,
                "__PRELINK_INFO");

        if(!__PRELINK_INFO){
            printf("xnuspy: no prelink info\n"
                   "  segment???\n");

            xnuspy_fatal_error();
        }

        struct section_64 *__info = macho_get_section(__PRELINK_INFO, "__info");

        if(!__info){
            printf("xnuspy: no prelink info\n"
                   "  dict?\n");

            xnuspy_fatal_error();
        }

        /* __info->addr already slid */
        char *infodict = xnu_va_to_ptr(__info->addr);
        char *cursor;

        while((cursor = strstr(infodict, "_PrelinkExecutableLoadAddr"))){
            char *loadaddr_s = strstr(cursor, "0xfffffff");

            if(!loadaddr_s)
                goto next;

            uint64_t loadaddr = strtoul(loadaddr_s, NULL, 0) + kernel_slide;
            struct mach_header_64 *mh64 = xnu_va_to_ptr(loadaddr);
            __TEXT_EXEC = macho_get_segment(mh64, "__TEXT_EXEC");

            if(__TEXT_EXEC)
                break;

next:
            infodict = cursor + 1;
        }

        struct section_64 *__text = macho_get_section(__TEXT_EXEC, "__text");

        if(!__text){
            printf("xnuspy: no __text section\n"
                   "  in __TEXT_EXEC??\n");

            xnuspy_fatal_error();
        }

        /* __text->addr not slid */
        if(__text->addr + kernel_slide < codestart)
            codestart = __text->addr + kernel_slide;
    }

    uint64_t ceil = xnu_ptr_to_va(xnuspy_tramp_mem) + xnuspy_tramp_mem_size;
    uint64_t dist = ceil - codestart;

    bool fallback = false;

    if(dist > 0x8000000){
        printf("xnuspy: distance from first\n"
               "  code to end of tramp mem is larger\n"
               "  than 128 MB. Falling back to\n"
               "  the unused r-x page already in\n"
               "  the kernelcache. As a result,\n"
               "  there are less hooks you can\n"
               "  install simultaneously.\n");

        fallback = true;
    }
    else{
        g_xnuspy_tramp_mem_addr = xnu_ptr_to_va(xnuspy_tramp_mem);
        g_xnuspy_tramp_mem_end = g_xnuspy_tramp_mem_addr + xnuspy_tramp_mem_size;
    }

    xnuspy_cache_base = alloc_static(PAGE_SIZE);
    printf("xnuspy_cache_base = %llx\n", xnu_ptr_to_va(xnuspy_cache_base));
    printf("loader_xref_recv_count: %x\n", loader_xfer_recv_count);

    if(!xnuspy_cache_base){
        puts("xnuspy: alloc_static");
        puts("   returned NULL while");
        puts("   allocating for xnuspy");
        puts("   cache");

        xnuspy_fatal_error();
    }

    void *xnuspy_ctl_image = alloc_static(loader_xfer_recv_count);
    printf("xnuspy_ctl_image = %llx\n", xnu_ptr_to_va(xnuspy_ctl_image));

    if(!xnuspy_ctl_image){
        puts("xnuspy: alloc_static");
        puts("   returned NULL while");
        puts("   allocating pages for");
        puts("   xnuspy_ctl image");

        xnuspy_fatal_error();
    }

    memcpy(xnuspy_ctl_image, loader_xfer_recv_data, loader_xfer_recv_count);

    printf("g_exec_scratch_space_addr = %llx\n", g_exec_scratch_space_addr);

    uint64_t num_free_instrs = g_exec_scratch_space_size / sizeof(uint32_t);
    uint32_t *scratch_space = xnu_va_to_ptr(g_exec_scratch_space_addr);

    scratch_space = install_h_s_c_sbn_hook(scratch_space, &num_free_instrs);
    scratch_space = install_xnuspy_ctl_tramp(scratch_space, &num_free_instrs);

    if(fallback){
        /* Use the rest of the scratch space for the xnuspy_tramp structs.
         * This page will be marked as rwx inside xnuspy_init */
        uint8_t *rxpage_unaligned = (uint8_t *)scratch_space;
        uint8_t *rxpage = (uint8_t *)(((uintptr_t)rxpage_unaligned + 8) & ~7);
        uint8_t *rxpage_end = (uint8_t *)(((uintptr_t)rxpage + PAGE_SIZE) & ~(PAGE_SIZE - 1));

        /* We do this so checkra1n kpf doesn't use this space for shellcode */
        memset(rxpage_unaligned, '$', rxpage_end - rxpage_unaligned);

        g_xnuspy_tramp_mem_addr = xnu_ptr_to_va(rxpage);
        g_xnuspy_tramp_mem_end = xnu_ptr_to_va(rxpage_end);
    }

    process_xnuspy_ctl_image(xnuspy_ctl_image);

    initialize_xnuspy_callnum_sysctl_offsets();
    initialize_xnuspy_cache();

    if(next_preboot_hook)
        next_preboot_hook();
}
