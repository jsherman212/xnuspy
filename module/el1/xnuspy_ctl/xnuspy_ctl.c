#include <errno.h>
#include <mach/mach.h>
#include <mach-o/loader.h>
#include <stdbool.h>
#include <stdint.h>

#include "asm.h"
#include "mem.h"
#include "pte.h"
#include "queue.h"
#include "tramp.h"

#undef current_task

#define XNUSPY_INSTALL_HOOK         (0)
#define XNUSPY_UNINSTALL_HOOK       (1)
#define XNUSPY_CHECK_IF_PATCHED     (2)
#define XNUSPY_GET_FUNCTION         (3)
#define XNUSPY_DUMP_TTES            (4)
#define XNUSPY_KREAD                (5)
#define XNUSPY_GET_CURRENT_TASK     (6)
#define XNUSPY_MAX_FLAVOR           XNUSPY_GET_CURRENT_TASK

/* values for XNUSPY_GET_FUNCTION */
#define KPROTECT                    (0)
#define COPYOUT                     (1)
#define KPRINTF                     (2)
#define IOSLEEP                     (3)
#define MAX_FUNCTION                IOSLEEP

#define MARK_AS_KERNEL_OFFSET __attribute__((section("__DATA,__koff")))

/* XXX For debugging only */
MARK_AS_KERNEL_OFFSET void (*kprintf)(const char *fmt, ...);
MARK_AS_KERNEL_OFFSET void (*IOSleep)(unsigned int millis);

MARK_AS_KERNEL_OFFSET uint64_t iOS_version = 0;
MARK_AS_KERNEL_OFFSET void *(*kalloc_canblock)(vm_size_t *sizep, bool canblock,
        void *site);
MARK_AS_KERNEL_OFFSET void *(*kalloc_external)(vm_size_t sz);
MARK_AS_KERNEL_OFFSET void (*kfree_addr)(void *addr);
MARK_AS_KERNEL_OFFSET void (*kfree_ext)(void *addr, vm_size_t sz);
MARK_AS_KERNEL_OFFSET void (*lck_rw_lock_shared)(void *lock);
MARK_AS_KERNEL_OFFSET uint32_t (*lck_rw_done)(void *lock);
MARK_AS_KERNEL_OFFSET void *(*lck_grp_alloc_init)(const char *grp_name,
        void *attr);
MARK_AS_KERNEL_OFFSET void *(*lck_rw_alloc_init)(void *grp, void *attr);
MARK_AS_KERNEL_OFFSET void (*bcopy_phys)(uint64_t src, uint64_t dst,
        vm_size_t bytes);
MARK_AS_KERNEL_OFFSET uint64_t (*phystokv)(uint64_t pa);
MARK_AS_KERNEL_OFFSET int (*copyin)(const uint64_t uaddr, void *kaddr,
        vm_size_t nbytes);
MARK_AS_KERNEL_OFFSET int (*copyout)(const void *kaddr, uint64_t uaddr,
        vm_size_t nbytes);
MARK_AS_KERNEL_OFFSET uint32_t *ncpusp;
MARK_AS_KERNEL_OFFSET struct cpu_data_entry *CpuDataEntriesp;
MARK_AS_KERNEL_OFFSET vm_offset_t (*ml_io_map)(vm_offset_t phys_addr,
        vm_size_t size);
MARK_AS_KERNEL_OFFSET void *mh_execute_header;
MARK_AS_KERNEL_OFFSET uint64_t kernel_slide;

MARK_AS_KERNEL_OFFSET void (*flush_mmu_tlb_region)(uint64_t va, uint32_t len);
MARK_AS_KERNEL_OFFSET void (*flush_mmu_tlb_region_asid_async)(uint64_t va,
        uint32_t len, void *pmap);
MARK_AS_KERNEL_OFFSET void (*InvalidatePoU_IcacheRegion)(uint64_t va, uint32_t len);
MARK_AS_KERNEL_OFFSET void *(*current_task)(void);
MARK_AS_KERNEL_OFFSET uint64_t (*pmap_map)(uint64_t virt, vm_offset_t start,
        vm_offset_t end, vm_prot_t prot, unsigned int flags);
MARK_AS_KERNEL_OFFSET void *kernel_pmap;
MARK_AS_KERNEL_OFFSET int (*pmap_expand)(void *pmap, uint64_t v, unsigned int options,
        unsigned int level);
MARK_AS_KERNEL_OFFSET void (*_disable_preemption)(void);
MARK_AS_KERNEL_OFFSET void (*_enable_preemption)(void);
MARK_AS_KERNEL_OFFSET kern_return_t (*kernel_memory_allocate)(void *map, uint64_t *addrp,
        vm_size_t size, vm_offset_t mask, int flags, int tag);
MARK_AS_KERNEL_OFFSET void *kernel_map;

/* flags for kernel_memory_allocate */
#define KMA_HERE        0x01
#define KMA_NOPAGEWAIT  0x02
#define KMA_KOBJECT     0x04
#define KMA_LOMEM       0x08
#define KMA_GUARD_FIRST 0x10
#define KMA_GUARD_LAST  0x20
#define KMA_PERMANENT   0x40
#define KMA_NOENCRYPT   0x80
#define KMA_KSTACK      0x100
#define KMA_VAONLY      0x200
#define KMA_COMPRESSOR  0x400   /* Pages belonging to the compressor are not on the paging queues, nor are they counted as wired. */
#define KMA_ATOMIC      0x800
#define KMA_ZERO        0x1000
#define KMA_PAGEABLE    0x2000

struct pmap_statistics {
    integer_t	resident_count;	/* # of pages mapped (total)*/
    integer_t	resident_max;	/* # of pages mapped (peak) */
    integer_t	wired_count;	/* # of pages wired */
    integer_t	device;
    integer_t	device_peak;
    integer_t	internal;
    integer_t	internal_peak;
    integer_t	external;
    integer_t	external_peak;
    integer_t	reusable;
    integer_t	reusable_peak;
    uint64_t	compressed __attribute__((aligned(8)));
    uint64_t	compressed_peak __attribute__((aligned(8)));
    uint64_t	compressed_lifetime __attribute__((aligned(8)));
};

struct queue_entry {
    struct queue_entry *next;
    struct queue_entry *prev;
};

typedef struct queue_entry queue_chain_t;
typedef struct queue_entry queue_head_t;

struct pmap {
    uint64_t *tte;
    uint64_t ttep;
    uint64_t min;
    uint64_t max;
    void *ledger;
    struct {
        uint64_t lock_data;
        uint64_t type;
    } lock;
    struct pmap_statistics stats;
    queue_chain_t pmaps;
};

struct vm_map_links {
    struct vm_map_entry *prev;
    struct vm_map_entry *next;
    uint64_t start;
    uint64_t end;
};

struct vm_map_entry {
    struct vm_map_links links;
#define vme_prev		links.prev
#define vme_next		links.next
#define vme_start		links.start
#define vme_end			links.end
};

struct vm_map_header {
    struct vm_map_links links;
};

struct _vm_map {
    char lck[16];
    /* struct { */
    /*     struct { */
    /*         void *prev; */
    /*         void *next; */
    /*         uint64_t start; */
    /*         uint64_t end; */
    /*     } links; */
    /* } hdr; */
    struct vm_map_header hdr;
};

MARK_AS_KERNEL_OFFSET struct pmap *(*get_task_pmap)(void *task);
MARK_AS_KERNEL_OFFSET queue_head_t *map_pmap_list;

#define tt1_index(pmap, addr)								\
	(((addr) & ARM_TT_L1_INDEX_MASK) >> ARM_TT_L1_SHIFT)
#define tt2_index(pmap, addr)								\
	(((addr) & ARM_TT_L2_INDEX_MASK) >> ARM_TT_L2_SHIFT)
#define tt3_index(pmap, addr)								\
	(((addr) & ARM_TT_L3_INDEX_MASK) >> ARM_TT_L3_SHIFT)

/* shorter macros so I can stay under 80 column lines */
#define DIST_FROM_REFCNT_TO(x) __builtin_offsetof(struct xnuspy_tramp, x) - \
    __builtin_offsetof(struct xnuspy_tramp, refcnt)

/* This structure represents a function hook. Every xnuspy_tramp struct resides
 * on writeable, executable memory. */
struct xnuspy_tramp {
    /* Kernel virtual address of copied userland replacement */
    uint64_t replacement;
    /* The trampoline for a hooked function. When the user installs a hook
     * on a function, the first instruction of that function is replaced
     * with a branch to here. An xnuspy trampoline looks like this:
     *  tramp[0]    ADR X16, <replacementp>
     *  tramp[1]    LDR X16, [X16]
     *  tramp[2]    BR X16
     */
    uint32_t tramp[3];
    /* An abstraction that represents the original function. It's just another
     * trampoline, but it can take on one of five forms. The most common
     * form is this:
     *  orig[0]     <original first instruction of the hooked function>
     *  orig[1]     ADR X16, #0xc
     *  orig[2]     LDR X16, [X16]
     *  orig[3]     BR X16
     *  orig[4]     <address of second instruction of the hooked function>[31:0]
     *  orig[5]     <address of second instruction of the hooked function>[63:32]
     *
     * The above form is taken when the original first instruction of the hooked
     * function is not an immediate conditional branch (b.cond), an immediate
     * compare and branch (cbz/cbnz), an immediate test and branch (tbz/tbnz),
     * or an ADR.
     * These are special cases because the immediates do not contain enough
     * bits for me to just "fix up", so I need to emit an equivalent sequence
     * of instructions.
     *
     * If the first instruction was B.cond <label>
     *  orig[0]     ADR X16, #0x14
     *  orig[1]     ADR X17, #0x18
     *  orig[2]     CSEL X16, X16, X17, <cond>
     *  orig[3]     LDR X16, [X16]
     *  orig[4]     BR X16
     *  orig[5]     <destination if condition holds>[31:0]
     *  orig[6]     <destination if condition holds>[63:32]
     *  orig[7]     <address of second instruction of the hooked function>[31:0]
     *  orig[8]     <address of second instruction of the hooked function>[63:32]
     *
     * If the first instruction was CBZ Rn, <label> or CBNZ Rn, <label>
     *  orig[0]     ADR X16, #0x18
     *  orig[1]     ADR X17, #0x1c
     *  orig[2]     CMP Rn, #0
     *  orig[3]     CSEL X16, X16, X17, <if CBZ, eq, if CBNZ, ne>
     *  orig[4]     LDR X16, [X16]
     *  orig[5]     BR X16
     *  orig[6]     <destination if condition holds>[31:0]
     *  orig[7]     <destination if condition holds>[63:32]
     *  orig[8]     <address of second instruction of the hooked function>[31:0]
     *  orig[9]     <address of second instruction of the hooked function>[63:32]
     *
     * If the first instruction was TBZ Rn, #n, <label> or TBNZ Rn, #n, <label>
     *  orig[0]     ADR X16, #0x18
     *  orig[1]     ADR X17, #0x1c
     *  orig[2]     TST Rn, #(1 << n)
     *  orig[3]     CSEL X16, X16, X17, <if TBZ, eq, if TBNZ, ne>
     *  orig[4]     LDR X16, [X16]
     *  orig[5]     BR X16
     *  orig[6]     <destination if condition holds>[31:0]
     *  orig[7]     <destination if condition holds>[63:32]
     *  orig[8]     <address of second instruction of the hooked function>[31:0]
     *  orig[9]     <address of second instruction of the hooked function>[63:32]
     *
     * If the first instruction was ADR Rn, #n
     *  orig[0]     ADRP Rn, #n@PAGE
     *  orig[1]     ADD Rn, Rn, #n@PAGEOFF
     *  orig[2]     ADR X16, #0xc
     *  orig[3]     LDR X16, [X16]
     *  orig[4]     BR X16
     *  orig[5]     <address of second instruction of the hooked function>[31:0]
     *  orig[6]     <address of second instruction of the hooked function>[63:32]
     */
    uint32_t orig[10];
};

static void desc_xnuspy_tramp(struct xnuspy_tramp *t, uint32_t orig_tramp_len){
    kprintf("This xnuspy_tramp is @ %#llx\n", (uint64_t)t);
    kprintf("Replacement: %#llx\n", t->replacement);
    
    kprintf("Replacement trampoline:\n");
    for(int i=0; i<sizeof(t->tramp)/sizeof(t->tramp[0]); i++)
        kprintf("\ttramp[%d]    %#x\n", i, t->tramp[i]);

    kprintf("Original trampoline:\n");
    for(int i=0; i<orig_tramp_len; i++)
        kprintf("\ttramp[%d]    %#x\n", i, t->orig[i]);
}

MARK_AS_KERNEL_OFFSET struct xnuspy_tramp *xnuspy_tramp_page;
MARK_AS_KERNEL_OFFSET uint8_t *xnuspy_tramp_page_end;

/* Contiguous "array" of pages */
MARK_AS_KERNEL_OFFSET uint8_t *usercode_reflector_pages_start;
MARK_AS_KERNEL_OFFSET uint8_t *usercode_reflector_pages_end;

static int xnuspy_init_flag = 0;

static void xnuspy_init(void){
    /* Mark the xnuspy_tramp page as writeable/executable */
    vm_prot_t prot = VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE;
    kprotect((uint64_t)xnuspy_tramp_page, 0x4000, prot);

    /* Do the same for the pages which will hold user code */
    uint64_t len = usercode_reflector_pages_end - usercode_reflector_pages_start;
    kprotect((uint64_t)usercode_reflector_pages_start, len, prot);

    /* Zero out PAN in case no instruction did it before us. After our kernel
     * patches, the PAN bit cannot be set to 1 again.
     *
     * msr pan, #0
     *
     * XXX XXX NEED TO CHECK IF THE HARDWARE SUPPORTS THIS BIT
     */
    asm volatile(".long 0xd500409f");
    asm volatile("isb sy");

    /* combat short read of this image */
    asm volatile(".align 14");
    /* asm volatile(".align 14"); */

    xnuspy_init_flag = 1;

    kprintf("%s: xnuspy inited\n", __func__);
}

void disable_preemption(void){
    _disable_preemption();
}

void enable_preemption(void){
    _enable_preemption();
}

/* #undef strcmp */
int strcmp(const char *s1, const char *s2){
    while(*s1 && (*s1 == *s2)){
        s1++;
        s2++;
    }

    return *(const unsigned char *)s1 - *(const unsigned char *)s2;
}

/* Copy the calling process' __TEXT and __DATA onto a contiguous set
 * of the pages we reserved before booting XNU. Lame, but safe. Swapping
 * translation table base registers and changing PTE OutputAddress'es
 * was hacky.
 *
 * Returns the kernel virtual address of the start of the user's
 * replacement function, or 0 upon failure.
 */
static uint64_t copy_caller_segments(struct mach_header_64 *umh,
        uint64_t replacement){
    uint64_t replacement_kva = 0;
    uint64_t aslr_slide = (uintptr_t)umh - 0x100000000;

    struct load_command *lc = umh + 1;

    /* XXX temporary: future implementation will alloc a contiguous
     * set of n pages */
    uint8_t *curpage = usercode_reflector_pages_start;

    for(int i=0; i<umh->ncmds; i++){
        kprintf("%s: got cmd %d\n", __func__, lc->cmd);

        if(lc->cmd != LC_SEGMENT_64)
            goto next;

        struct segment_command_64 *sc64 = (struct segment_command_64 *)lc;

        int is_text = strcmp(sc64->segname, "__TEXT") == 0;

        if(is_text || strcmp(sc64->segname, "__DATA") == 0){
            /* These will always be page aligned */
            uint64_t start = sc64->vmaddr + aslr_slide;
            uint64_t end = start + sc64->vmsize;

            kprintf("%s: segment '%s' start %#llx end %#llx\n", __func__,
                    sc64->segname, start, end);

            /* Copy the segment into kernelspace */
            while(start < end){
                uint64_t *us = (uint64_t *)start;
                uint64_t *ks = (uint64_t *)curpage;
                uint64_t *ke = (uint64_t *)(curpage + 0x4000);

                kprintf("%s: us %#llx ks %#llx ke %#llx\n", __func__, us, ks, ke);

                while(ks < ke){
                    *ks++ = *us++;
                }

                start += 0x4000;
                curpage += 0x4000;
            }

            /* __TEXT includes the mach header, so we can just add the
             * distance from the header to the user's replacement function
             * to the first page we used */
            if(is_text && !replacement_kva){
                uint64_t dist = replacement - (uintptr_t)umh;
                kprintf("%s: dist %#llx replacement %#llx umh %#llx\n", __func__,
                        dist, replacement, (uint64_t)umh);
                /* XXX temporary */
                replacement_kva = usercode_reflector_pages_start + dist;
            }
        }

next:
        lc = (struct load_command *)((uintptr_t)lc + lc->cmdsize);
    }

    return replacement_kva;
}

static int xnuspy_install_hook(uint64_t target, uint64_t replacement,
        uint64_t /* __user */ origp){
    kprintf("%s: called with target %#llx replacement %#llx origp %#llx\n",
            __func__, target, replacement, origp);

    /* slide target */
    target += kernel_slide;

    /* Find a free xnuspy_tramp inside the trampoline page */
    struct xnuspy_tramp *tramp = xnuspy_tramp_page;

    while((uint8_t *)tramp < xnuspy_tramp_page_end){
        if(!tramp->replacement)
            break;

        tramp++;
    }

    if(!tramp){
        kprintf("%s: no free xnuspy_tramp structs\n", __func__);
        return ENOSPC;
    }

    kprintf("%s: got free xnuspy_ctl struct @ %#llx\n", __func__, tramp);

    /* Build the trampoline to the replacement as well as the trampoline
     * that represents the original function */
    uint32_t orig_tramp_len = 0;

    generate_replacement_tramp(tramp->tramp);
    generate_original_tramp(target + 4, tramp->orig, &orig_tramp_len);

    /* copyout the original function trampoline before the replacement
     * is called */
    uint32_t *orig_tramp = tramp->orig;
    int err = copyout(&orig_tramp, origp, sizeof(origp));

    uint64_t tpidr_el1;
    asm volatile("mrs %0, tpidr_el1" : "=r" (tpidr_el1));
    /* cpuDatap offset found in _machine_switch_context */
    void *cpudata = *(void **)(tpidr_el1 + 0x478);
    uint16_t curcpu = *(uint16_t *)cpudata;


    /* struct pmap *pmap = get_task_pmap(current_task()); */

    /* kprintf("%s: pmap min %#llx max %#llx\n", __func__, pmap->min, pmap->max); */

    /* Offset found in mmap */
    struct _vm_map *current_map = *(struct _vm_map **)(tpidr_el1 + 0x320);

    kprintf("%s: current map %#llx\n", __func__, current_map);

    if(!current_map)
        return 0;

    kprintf("%s: start %#llx end %#llx\n", __func__, current_map->hdr.links.start,
            current_map->hdr.links.end);

    /* Mach header of the calling process */
    struct mach_header_64 *umh = (struct mach_header_64 *)current_map->hdr.links.start;

    uint64_t replacement_kva = copy_caller_segments(umh, replacement);

    kprintf("%s: replacment kva @ %#llx\n", __func__, replacement_kva);

    tramp->replacement = replacement_kva;

    desc_xnuspy_tramp(tramp, orig_tramp_len);
    /* uint32_t *cursor = (uint32_t *)replacement_kva; */
    /* for(int i=0; i<200; i++){ */
    /*     kprintf("%s: %#llx:      %#x\n", __func__, cursor+i, cursor[i]); */
    /* } */

    IOSleep(10000);

    /* All the trampolines are set up, write the branch */
    kprotect(target, 0x4000, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);

    *(uint32_t *)target = assemble_b(target, (uint64_t)tramp->tramp);

    asm volatile("dc cvau, %0" : : "r" (target));
    asm volatile("dsb ish");
    asm volatile("ic ivau, %0" : : "r" (target));
    asm volatile("dsb ish");
    asm volatile("isb sy");

    return 0;
}

static int xnuspy_uninstall_hook(uint64_t target){
    kprintf("%s: XNUSPY_UNINSTALL_HOOK is not implemented yet\n", __func__);
    return ENOSYS;
}

static int xnuspy_get_function(uint64_t which, uint64_t /* __user */ outp){
    kprintf("%s: XNUSPY_GET_FUNCTION called with which %lld origp %#llx\n",
            __func__, which, outp);

    if(which > MAX_FUNCTION)
        return ENOENT;

    switch(which){
        case KPROTECT:
            which = (uint64_t)kprotect;
            break;
        case COPYOUT:
            which = (uint64_t)copyout;
            break;
        case KPRINTF:
            which = (uint64_t)kprintf;
            break;
        case IOSLEEP:
            which = (uint64_t)IOSleep;
            break;
        default:
            break;
    };

    return copyout(&which, outp, sizeof(outp));
}

static int xnuspy_dump_ttes(uint64_t addr, uint64_t el){
    uint64_t ttbr;

    if(el == 0)
        asm volatile("mrs %0, ttbr0_el1" : "=r" (ttbr));
    else
        asm volatile("mrs %0, ttbr1_el1" : "=r" (ttbr));

    uint64_t l1_table = phystokv(ttbr & 0xfffffffffffe);
    uint64_t l1_idx = (addr >> ARM_TT_L1_SHIFT) & 0x7;
    uint64_t *l1_ttep = (uint64_t *)(l1_table + (0x8 * l1_idx));

    uint64_t l2_table = phystokv(*l1_ttep & ARM_TTE_TABLE_MASK);
    uint64_t l2_idx = (addr >> ARM_TT_L2_SHIFT) & 0x7ff;
    uint64_t *l2_ttep = (uint64_t *)(l2_table + (0x8 * l2_idx));

    uint64_t l3_table = phystokv(*l2_ttep & ARM_TTE_TABLE_MASK);
    uint64_t l3_idx = (addr >> ARM_TT_L3_SHIFT) & 0x7ff;
    uint64_t *l3_ptep = (uint64_t *)(l3_table + (0x8 * l3_idx));

    kprintf("%s: TTE dump for %#llx:\n", __func__, addr);
    kprintf("\tL1 TTE @ %#llx (phys = %#llx): %#llx\n"
            "\tL2 TTE @ %#llx (phys = %#llx): %#llx\n"
            "\tL3 PTE @ %#llx (phys = %#llx): %#llx\n",
            l1_ttep, kvtophys((uint64_t)l1_ttep), *l1_ttep,
            l2_ttep, kvtophys((uint64_t)l2_ttep), *l2_ttep,
            l3_ptep, kvtophys((uint64_t)l3_ptep), *l3_ptep);

    return 0;
}

struct xnuspy_ctl_args {
    uint64_t flavor;
    uint64_t arg1;
    uint64_t arg2;
    uint64_t arg3;
};

int xnuspy_ctl(void *p, struct xnuspy_ctl_args *uap, int *retval){
    uint64_t flavor = uap->flavor;

    if(flavor > XNUSPY_MAX_FLAVOR){
        kprintf("%s: bad flavor %d\n", __func__, flavor);
        *retval = -1;
        return EINVAL;
    }

    /* kprintf("%s: got flavor %d\n", __func__, flavor); */
    /* kprintf("%s: kslide %#llx\n", __func__, kernel_slide); */
    /* kprintf("%s: xnuspy_ctl @ %#llx (unslid)\n", __func__, */
    /*         (uint64_t)xnuspy_ctl - kernel_slide); */
    /* kprintf("%s: xnuspy_ctl tramp page @ [%#llx,%#llx] (unslid)\n", __func__, */
    /*         (uint64_t)xnuspy_tramp_page - kernel_slide, */
    /*         (uint64_t)xnuspy_tramp_page_end - kernel_slide); */

    if(!xnuspy_init_flag)
        xnuspy_init();

    int res;

    switch(flavor){
        case XNUSPY_CHECK_IF_PATCHED:
            *retval = 999;
            return 0;
        case XNUSPY_INSTALL_HOOK:
            res = xnuspy_install_hook(uap->arg1, uap->arg2, uap->arg3);
            break;
        case XNUSPY_UNINSTALL_HOOK:
            res = xnuspy_uninstall_hook(uap->arg1);
            break;
            /* XXX below will be replaced with XNUSPY_MAKE_CALLABLE */
        case XNUSPY_GET_FUNCTION:
            res = xnuspy_get_function(uap->arg1, uap->arg2);
            break;
        case XNUSPY_DUMP_TTES:
            res = xnuspy_dump_ttes(uap->arg1, uap->arg2);
            break;
        case XNUSPY_KREAD:
            res = copyout(uap->arg1, uap->arg2, uap->arg3);
            break;
        case XNUSPY_GET_CURRENT_TASK:
            {
                void *ct = current_task();
                res = copyout(&ct, uap->arg1, sizeof(void *));
                break;
            }
        default:
            *retval = -1;
            return EINVAL;
    };

    if(res)
        *retval = -1;

    return res;
}
