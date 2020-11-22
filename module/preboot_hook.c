#include <mach-o/nlist.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/sysctl.h>

#include "common/common.h"
#include "common/pongo.h"

#include "el1/hook_system_check_sysctlbyname_hook_instrs.h"
#include "el1/xnuspy_ctl_tramp_instrs.h"

#include "pf/disas.h"
#include "pf/macho.h"
#include "pf/offsets.h"
#include "pf/pf_common.h"

static uint64_t g_xnuspy_ctl_addr = 0;

/* address of start of __TEXT_EXEC in xnuspy_ctl image */
static uint64_t g_xnuspy_ctl_img_codestart = 0;

/* how many bytes to we need to mark as executable inside xnuspy_ctl_tramp? */
static uint64_t g_xnuspy_ctl_img_codesz = 0;

/* XXX for debugging */
/* iphone 8 13.6.1 */
/* static uint64_t g_IOLog_addr = 0xFFFFFFF008134654; */
/* iphone 8 13.6.1 */
/* static uint64_t g_IOSleep_addr = 0xFFFFFFF00813462C; */
/* iphone 8 13.6.1 */
/* static uint64_t g_kprintf_addr = 0xFFFFFFF0081D28E0; */
/* iphone x 13.3.1 */
static uint64_t g_kprintf_addr = 0xFFFFFFF0081A08F4;

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

static struct xnuspy_ctl_offset {
    const char *name;
    uint64_t *val;
} g_xnuspy_ctl_needed_offsets[] = {
    { "_bcopy_phys", &g_bcopy_phys_addr },
    { "_copyin", &g_copyin_addr },
    { "_copyout", &g_copyout_addr },
    { "_iOS_version", &g_kern_version_major },
    { "_kalloc_canblock", &g_kalloc_canblock_addr },
    { "_kalloc_external", &g_kalloc_external_addr },
    { "_kernel_slide", &kernel_slide },
    { "_kfree_addr", &g_kfree_addr_addr },
    { "_kfree_ext", &g_kfree_ext_addr },
    { "_lck_grp_alloc_init", &g_lck_grp_alloc_init_addr },
    { "_lck_rw_alloc_init", &g_lck_rw_alloc_init_addr },
    { "_lck_rw_done", &g_lck_rw_done_addr },
    { "_lck_rw_lock_shared", &g_lck_rw_lock_shared_addr },
    { "_phystokv", &g_phystokv_addr },
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
    chk(!g_lck_rw_lock_shared_addr, "lck_rw_lock_shared not found\n");
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

    /* iphone 8 13.6.1 */
    /* uint64_t kvtophys = 0xFFFFFFF007CF83B8 + kernel_slide; */
    /* iphone 7 14.2 */
    /* uint64_t kvtophys = 0xFFFFFFF00727F0C0 + kernel_slide; */
    /* iphone 7 14.1 */
    /* XXX this offset seems wrong */
    /* uint64_t kvtophys = 0xFFFFFFF007272AF0 + kernel_slide; */
    /* XNUSPY_CACHE_WRITE(kvtophys); */

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

    /* iphone 8 13.6.1 */
    /* uint64_t IOLog = 0xFFFFFFF008134654 + kernel_slide; */
    /* XNUSPY_CACHE_WRITE(IOLog); */


    /* iphone 8 13.6.1 */
    /* uint64_t flush_mmu_tlb_region = 0xFFFFFFF007CF85F0 + kernel_slide; */
    /* XNUSPY_CACHE_WRITE(flush_mmu_tlb_region); */

    /* ios 14.2 iphone 7 ktrr/amcc lockdown patches */
    /* uint32_t *ktrr_p0 = xnu_va_to_ptr(0xFFFFFFF00727E468 + kernel_slide); */
    /* uint32_t *ktrr_p1 = xnu_va_to_ptr(0xFFFFFFF00727E46C + kernel_slide); */
    /* uint32_t *ktrr_p2 = xnu_va_to_ptr(0xFFFFFFF00727E474 + kernel_slide); */

    /* all to NOP */
    /* *ktrr_p0 = 0xd503201f; */
    /* *ktrr_p1 = 0xd503201f; */
    /* *ktrr_p2 = 0xd503201f; */

    /* uint32_t *ktrr_p3 = xnu_va_to_ptr(0xFFFFFFF00714445C + kernel_slide); */
    /* uint32_t *ktrr_p4 = xnu_va_to_ptr(0xFFFFFFF007144460 + kernel_slide); */
    /* uint32_t *ktrr_p5 = xnu_va_to_ptr(0xFFFFFFF007144468 + kernel_slide); */

    /* *ktrr_p3 = 0xd503201f; */
    /* *ktrr_p4 = 0xd503201f; */
    /* *ktrr_p5 = 0xd503201f; */

    /* phone won't boot with these three patches below */
    /* uint32_t *ctrr_p0 = xnu_va_to_ptr(0xFFFFFFF00727E408 + kernel_slide); */
    /* uint32_t *ctrr_p1 = xnu_va_to_ptr(0xFFFFFFF00727E42C + kernel_slide); */
    /* uint32_t *ctrr_p2 = xnu_va_to_ptr(0xFFFFFFF00727E450 + kernel_slide); */

    /* *ctrr_p0 = 0xd503201f; */
    /* *ctrr_p1 = 0xd503201f; */
    /* *ctrr_p2 = 0xd503201f; */

    /* phone won't boot with this patch */
    /* uint32_t *ctrr_p3 = xnu_va_to_ptr(0xFFFFFFF00727E404 + kernel_slide); */
    /* mov w0, 0 */
    /* *ctrr_p3 = 0x52800000; */
    
    /* phone won't boot with this patch */
    /* uint32_t *ctrr_p4 = xnu_va_to_ptr(0xFFFFFFF00727E38C + kernel_slide); */
    /* mov w9, 0 */
    /* *ctrr_p4 = 0x52800009; */

    /* phone panicks with this patch */
    /* uint32_t *ctrr_p5 = xnu_va_to_ptr(0xFFFFFFF00727DCC8 + kernel_slide); */
    /* mov w8, 1 */
    /* *ctrr_p5 = 0x52800028; */

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
     * in hook_system_check_sysctlbyname_hook.s
     */
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
 * module/el1/xnuspy_ctl_tramp.s
 */
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
    const size_t num_needed_offsets = sizeof(g_xnuspy_ctl_needed_offsets) /
        sizeof(*g_xnuspy_ctl_needed_offsets);

    for(size_t i=0; i<num_needed_offsets; i++){
        if(strcmp(ksym, g_xnuspy_ctl_needed_offsets[i].name) == 0){
            /* printf("%s: replacing '%s' with %#llx (unslid %#llx)\n", __func__, */
            /*         ksym, *g_xnuspy_ctl_needed_offsets[i].val, */
            /*         *g_xnuspy_ctl_needed_offsets[i].val - kernel_slide); */
            
            *va = *g_xnuspy_ctl_needed_offsets[i].val;

            return;
        }
        /* XXX For debugging only, all but kprintf are specific to iphone 8 13.6.1 */
        /* else if(strcmp(ksym, "_IOLog") == 0){ */
        /*     *va = g_IOLog_addr + kernel_slide; */
        /*     return; */
        /* } */
        else if(strcmp(ksym, "_kprintf") == 0){
            *va = g_kprintf_addr + kernel_slide;
            return;
        }
        /* else if(strcmp(ksym, "_IOSleep") == 0){ */
        /*     *va = g_IOSleep_addr + kernel_slide; */
        /*     return; */
        /* } */
        else if(strcmp(ksym, "_mh_execute_header") == 0){
            *va = (uint64_t)mh_execute_header;
            return;
        }
        else if(strcmp(ksym, "_machine_thread_set_state") == 0){
            /* iphone 8 13.6.1 */
            /* *va = 0xFFFFFFF007D14578 + kernel_slide; */
            *va = 0x4141414141;
            return;
        }
        /* else if(strcmp(ksym, "____osLog") == 0){ */
        /*     *va = 0xFFFFFFF00957C7E0 + kernel_slide; */
        /*     return; */
        /* } */
        /* else if(strcmp(ksym, "__os_log_default") == 0){ */
        /*     *va = 0xFFFFFFF00925AF2C + kernel_slide; */
        /*     return; */
        /* } */
        /* else if(strcmp(ksym, "_os_log_internal") == 0){ */
        /*     *va = 0xFFFFFFF0081188CC + kernel_slide; */
        /*     return; */
        /* } */
    }
}

/* fill in all our kernel offsets in __koff, initialize g_xnuspy_ctl_addr
 * and g_xnuspy_ctl_img_codesz
 */
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

        /* printf("%s: got symbol '%s' @ %#llx\n", __func__, sym, va); */
    }

    printf("%s: g_xnuspy_ctl_addr @ %#llx, code start @ %#llx, code size %#llx\n",
            __func__, g_xnuspy_ctl_addr, g_xnuspy_ctl_img_codestart,
            g_xnuspy_ctl_img_codesz);
}

static void patch_exception_vectors(void){
    /* PSTATE.D is masked upon taking an exception. See the pseudocode for
     * AArch64.TakeException in the ARMv8 reference manual. The hardware masks
     * this bit before it branches to the appropriate exception handler specified
     * by VBAR_EL1. In order to keep our hardware breakpoints alive, we need to
     * modify each exception handler to unmask PSTATE.D and the D bit of SPSR_EL1.
     *
     * Each handler follows this format:
     *      [NOP]   <repeats n times>
     *      MRS X18, TPIDR_EL1 or MRS X18, TTBR0_EL1
     *      ...
     *      BR X18
     *      [NOP]   <repeats n times>
     *
     * In all, X18 is the only used register.
     *
     * It'll be easy to figure out where each start/end. We will patch
     * each to:
     *      MSR DAIFClr, #0x8
     *      MRS X18, SPSR_EL1
     *      AND X18, X18, ~0x200
     *      MSR SPSR_EL1, X18
     *      [original handler code]
     *
     * All the handlers are aligned on 0x80 byte boundries so we have enough
     * space. XNU seems to only have 12 handlers, but I'd like to not hardcode
     * that limit. XNU aligns the page the handlers are on to a 4K boundry.
     */
    /* we already checked if this was missing */
    uint32_t *opcode_stream = g_ExceptionVectorsBase_stream;

    uint32_t patches[] = {
        0xd50348ff,
        0xd5384012,
        0x9276fa52,
        0xd5184012,
    };

    const size_t num_patches = sizeof(patches) / sizeof(*patches);

    uint32_t instr_limit = 0x1000 / sizeof(uint32_t);

    while(instr_limit > 0){
        /* are we at the beginning of a handler? */
        if(*opcode_stream != 0xd538d092 && *opcode_stream != 0xd5382012){
            /* nope, carry on */
            opcode_stream++;
            instr_limit--;
        }
        else{
            /* yep, figure out the bounds of this handler */
            uint32_t *handler_start = opcode_stream;
            uint32_t *handler_end = handler_start;

            /* search for br x18 */
            while(*handler_end != 0xd61f0240)
                handler_end++;

            /* get off the br x18 */
            handler_end++;

            size_t len_in_instrs = handler_end - handler_start;
            printf("%s: %zu instrs in this handler\n", __func__, len_in_instrs);

            /* Hardcoded so ___chkstk_darwin calls are not generated.
             * This is more than enough.
             */
            uint32_t orig_instrs[0x20];
            memcpy(orig_instrs, handler_start, sizeof(uint32_t) * len_in_instrs);

            /* insert our patches */
            memcpy(handler_start, patches, sizeof(patches));

            /* restore original instrs */
            memcpy(handler_start + num_patches, orig_instrs,
                    sizeof(uint32_t) * len_in_instrs);

            opcode_stream += len_in_instrs + num_patches;

            instr_limit -= len_in_instrs + num_patches;
        }
    }

    puts("xnuspy: patched exception handlers");
}

void (*next_preboot_hook)(void);

void xnuspy_preboot_hook(void){
    anything_missing();

    /* XXX check if there's enough executable free space */

    xnuspy_cache_base = alloc_static(PAGE_SIZE);

    if(!xnuspy_cache_base){
        puts("xnuspy: alloc_static");
        puts("   returned NULL while");
        puts("   allocating for stalker");
        puts("   cache");

        xnuspy_fatal_error();
    }

    /* printf("%s: xnuspy_ctl img is %#llx bytes\n", __func__, */
    /*         loader_xfer_recv_count); */

    void *xnuspy_ctl_image = alloc_static(loader_xfer_recv_count);

    if(!xnuspy_ctl_image){
        puts("xnuspy: alloc_static");
        puts("   returned NULL while");
        puts("   allocating pages for");
        puts("   compiled xnuspy_ctl");

        xnuspy_fatal_error();
    }

    /* printf("%s: xnuspy_ctl image %#llx loader_xfer_recv_data %#llx\n", __func__, */
    /*         xnuspy_ctl_image, loader_xfer_recv_data); */

    memcpy(xnuspy_ctl_image, loader_xfer_recv_data, loader_xfer_recv_count);

    process_xnuspy_ctl_image(xnuspy_ctl_image);

    /* install our hook for hook_system_check_sysctlbyname */
    uint64_t num_free_instrs = g_exec_scratch_space_size / sizeof(uint32_t);
    uint32_t *scratch_space = xnu_va_to_ptr(g_exec_scratch_space_addr);

    scratch_space = install_h_s_c_sbn_hook(scratch_space, &num_free_instrs);

    initialize_xnuspy_callnum_sysctl_offsets();

    /* replace an enosys sysent with xnuspy_ctl_tramp */
    scratch_space = install_xnuspy_ctl_tramp(scratch_space, &num_free_instrs);

    printf("%s: xnuspy_ctl_tramp @ %#llx\n", __func__, xnu_ptr_to_va(scratch_space)-kernel_slide);
    /* write the code for xnuspy_ctl_tramp */
    scratch_space = write_xnuspy_ctl_tramp_instrs(scratch_space,
            &num_free_instrs);

    patch_exception_vectors();

    initialize_xnuspy_cache();

    /* combat short read */
    printf("xnuspy: handing it off to checkra1n...\n");
    /* printf("xnuspy: handing it off to checkra1n...\n"); */
    /* printf("xnuspy: handing it off to checkra1n...\n"); */
    /* printf("xnuspy: handing it off to checkra1n...\n"); */
    /* printf("xnuspy: handing it off to checkra1n...\n"); */
    /* printf("xnuspy: handing it off to checkra1n...\n"); */
    /* printf("xnuspy: handing it off to checkra1n...\n"); */
    /* printf("xnuspy: handing it off to checkra1n...\n"); */
    /* printf("xnuspy: handing it off to checkra1n...\n"); */
    /* printf("xnuspy: handing it off to checkra1n...\n"); */
    /* printf("xnuspy: handing it off to checkra1n...\n"); */
    /* printf("xnuspy: handing it off to checkra1n...\n"); */
    /* printf("xnuspy: handing it off to checkra1n...\n"); */
    /* printf("xnuspy: handing it off to checkra1n...\n"); */
    /* printf("xnuspy: handing it off to checkra1n...\n"); */
    /* printf("xnuspy: handing it off to checkra1n...\n"); */
    /* printf("xnuspy: handing it off to checkra1n...\n"); */
    /* printf("xnuspy: handing it off to checkra1n...\n"); */
    /* printf("xnuspy: handing it off to checkra1n...\n"); */
    /* printf("xnuspy: handing it off to checkra1n...\n"); */

    /* iphone 8 13.6.1 */
    uint32_t *doprnt_hide_pointers = xnu_va_to_ptr(0xFFFFFFF0090B0624 + kernel_slide);
    /* *doprnt_hide_pointers = 0; */
    
    /* iphone 8 13.6.1
     *
     * machine_thread_set_state patch so it doesn't mask out any bits in
     * the debug_state's bcrs
     */
    /* uint32_t *mtss_patch0 = xnu_va_to_ptr(0xFFFFFFF007D14F2C + kernel_slide); */
    /* uint32_t *mtss_patch1 = xnu_va_to_ptr(0xFFFFFFF007D14F30 + kernel_slide); */
    /* both nops */
    /* *mtss_patch0 = 0xD503201F; */
    /* *mtss_patch1 = 0xD503201F; */
    /* uint32_t *mtss_patch = xnu_va_to_ptr(0xFFFFFFF007D14F10 + kernel_slide); */
    /* mov x9, 16 */
    /* *mtss_patch = 0xD2800209; */

    /* uint32_t *c = xnu_va_to_ptr(0xFFFFFFF007D129EC + kernel_slide); */
    /* *c = 0xD4200000; */

    if(next_preboot_hook)
        next_preboot_hook();
}
