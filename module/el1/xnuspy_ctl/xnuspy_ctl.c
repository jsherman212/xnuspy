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
#define MAX_FUNCTION                KPRINTF

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
    _Atomic uint32_t refcnt;
    /* The trampoline for a hooked function. When the user installs a hook
     * on a function, the first instruction of that function is replaced
     * with a branch to here. An xnuspy trampoline looks like this:
     *  tramp[0]    ADR X16, <refcntp>
     *  tramp[1]    B _save_original_state0
     *  tramp[2]    B _reftramp0
     *  tramp[3]    ADR X16, <replacementp>
     *  tramp[4]    LDR X16, [X16]
     *  tramp[5]    BR X16
     */
    uint32_t tramp[6];
    /* An abstraction that represents the original function. It's just another
     * trampoline, but it can take on one of five forms. Every form starts
     * with this header:
     *  orig[0]     B _save_original_state1
     *  orig[1]     B _reftramp1
     *
     * Continuing from that header, the most common form is:
     *  orig[2]     <original first instruction of the hooked function>
     *  orig[3]     ADR X16, #0xc
     *  orig[4]     LDR X16, [X16]
     *  orig[5]     BR X16
     *  orig[6]     <address of second instruction of the hooked function>[31:0]
     *  orig[7]     <address of second instruction of the hooked function>[63:32]
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
     *  orig[2]     ADR X16, #0x14
     *  orig[3]     ADR X17, #0x18
     *  orig[4]     CSEL X16, X16, X17, <cond>
     *  orig[5]     LDR X16, [X16]
     *  orig[6]     BR X16
     *  orig[7]     <destination if condition holds>[31:0]
     *  orig[8]     <destination if condition holds>[63:32]
     *  orig[9]     <address of second instruction of the hooked function>[31:0]
     *  orig[10]    <address of second instruction of the hooked function>[63:32]
     *
     * If the first instruction was CBZ Rn, <label> or CBNZ Rn, <label>
     *  orig[2]     ADR X16, #0x18
     *  orig[3]     ADR X17, #0x1c
     *  orig[4]     CMP Rn, #0
     *  orig[5]     CSEL X16, X16, X17, <if CBZ, eq, if CBNZ, ne>
     *  orig[6]     LDR X16, [X16]
     *  orig[7]     BR X16
     *  orig[8]     <destination if condition holds>[31:0]
     *  orig[9]     <destination if condition holds>[63:32]
     *  orig[10]    <address of second instruction of the hooked function>[31:0]
     *  orig[11]    <address of second instruction of the hooked function>[63:32]
     *
     * If the first instruction was TBZ Rn, #n, <label> or TBNZ Rn, #n, <label>
     *  orig[2]     ADR X16, #0x18
     *  orig[3]     ADR X17, #0x1c
     *  orig[4]     TST Rn, #(1 << n)
     *  orig[5]     CSEL X16, X16, X17, <if TBZ, eq, if TBNZ, ne>
     *  orig[6]     LDR X16, [X16]
     *  orig[7]     BR X16
     *  orig[8]     <destination if condition holds>[31:0]
     *  orig[9]     <destination if condition holds>[63:32]
     *  orig[10]    <address of second instruction of the hooked function>[31:0]
     *  orig[11]    <address of second instruction of the hooked function>[63:32]
     *
     * If the first instruction was ADR Rn, #n
     *  orig[2]     ADRP Rn, #n@PAGE
     *  orig[3]     ADD Rn, Rn, #n@PAGEOFF
     *  orig[4]     ADR X16, #0xc
     *  orig[5]     LDR X16, [X16]
     *  orig[6]     BR X16
     *  orig[7]     <address of second instruction of the hooked function>[31:0]
     *  orig[8]     <address of second instruction of the hooked function>[63:32]
     */
    uint32_t orig[12];
};

static void desc_xnuspy_tramp(struct xnuspy_tramp *t, uint32_t orig_tramp_len){
    kprintf("This xnuspy_tramp is @ %#llx\n", (uint64_t)t);
    kprintf("Replacement: %#llx\n", t->replacement);
    kprintf("Refcount:    %d\n", t->refcnt);
    
    kprintf("Replacement trampoline:\n");
    for(int i=0; i<5; i++)
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

/* If you decide to edit the functions marked as naked, you need to make
 * sure clang isn't clobbering registers. */

/* reletramp: release a reference, using the reference count pointer held
 * inside DBGBVR2_EL1.
 *
 * TODO actually sever the branch from the hooked function to the tramp
 * when the count hits zero
 *
 * reletramp0 and reletramp1 will call reletramp_common to drop a reference,
 * and then they'll branch back to their original callers. Because we're
 * restoring LR in both those functions, using BL is safe.
 */
__attribute__ ((naked)) void reletramp_common(void){
    asm volatile(""
            "mrs x16, dbgbvr2_el1\n"
            "1:\n"
            "ldaxr w14, [x16]\n"
            "mov x15, x14\n"
            "sub w14, w15, #1\n"
            "stlxr w15, w14, [x16]\n"
            "cbnz w15, 1b\n"
            "ret\n"
            );
}

/* This function is only called when the replacement code returns back to
 * its caller. We are always returning back kernel code if we're here. */
__attribute__ ((naked)) void reletramp0(void){
    asm volatile(""
            "mov x19, x0\n"
            "bl _reletramp_common\n"
            "mov x0, x19\n"
            "mrs x29, dbgbvr1_el1\n"
            "mrs x30, dbgbvr0_el1\n"
            "ret\n"
            );
}

/* This function is only called when the original function returns back
 * to the user's replacement code. We are always returning back to the user's
 * code if we're here. */ 
__attribute__ ((naked)) void reletramp1(void){
    asm volatile(""
            "mov x19, x0\n"
            "bl _reletramp_common\n"
            "mov x0, x19\n"
            "mrs x29, dbgbvr4_el1\n"
            "mrs x30, dbgbvr3_el1\n"
            "ret\n"
            /* : : [ttbr0_el1_dist] "r" (DIST_FROM_REFCNT_TO(ttbr0_el1)) */
            );
}

/* save_original_state0: save this CPU's original FP, LR, and
 * X16, and set LR to the appropriate 'reletramp' routine. This is only called
 * when the kernel calls the hooked function. X16 holds a pointer to the refcnt
 * of an xnuspy_tramp when this is called.
 *
 * For both save_original_state functions, I need a way to persist data. For
 * save_original_state0, I need to save a pointer to the reference count of
 * whatever xnuspy_tramp struct X16 holds. For both, I also need to save the
 * current stack frame because I set LR to 'reletramp' and have to be able to
 * branch back to the original caller.
 *
 * Normally, I would just use the stack, but functions like
 * kprintf rely on some arguments being passed on the stack. If I were
 * to modify it, the parameters would be incorrect inside of the user's
 * replacement code. Instead of using the stack, I will use the first five
 * debug breakpoint value registers in the following way:
 *  
 * DBGBVR0_EL1: Original link register when the kernel calls the hooked function.
 * DBGBVR1_EL1: Original frame pointer when the kernel calls the hooked function.
 * DBGBVR2_EL1: A pointer to the current xnuspy_tramp's reference count.
 * DBGBVR3_EL1: Original link register when the user calls the original function.
 * DBGBVR4_EL1: Original frame pointer when the user calls the original function.
 *
 * Because I am using these registers, you CANNOT set any hardware breakpoints
 * if you're debugging something while xnuspy is doing its thing. You can set
 * software breakpoints, though. You're able to specify whether you want a
 * software breakpoint or a hardware breakpoint inside of LLDB.
 */
__attribute__ ((naked)) void save_original_state0(void){
    asm volatile(""
            /* turn off PAN bit */
            ".long 0xd500409f\n"
            /* turn off SCTLR_EL1.WXN */
            /* "mrs x9, sctlr_el1\n" */
            /* "and x9, x9, ~0x80000\n" */
            /* "msr sctlr_el1, x9\n" */
            /* "mrs x9, DAIF\n" */
            /* "msr dbgwvr0_el1, x9\n" */
            /* "msr DAIFSet, #0xf\n" */
            "msr dbgbvr0_el1, x30\n"
            "msr dbgbvr1_el1, x29\n"
            "msr dbgbvr2_el1, x16\n"
            /* "mov x21, %[tramp_plus_2_dist]\n" */
            "mov x30, %[reletramp0]\n"
            /* branch back to tramp+2 */
            /* "add x16, x16, x21\n" */
            "add x16, x16, %[tramp_plus_2_dist]\n"
            "br x16\n"
            : : [reletramp0] "r" (reletramp0),
            [tramp_plus_2_dist] "r" (DIST_FROM_REFCNT_TO(tramp[2]))
            /* [disable_preemption] "r" (_disable_preemption) */
            );
}

/* save_original_state1: save this CPU's FP and LR. This is only called when
 * the user calls the original function from their replacement code. */
__attribute__ ((naked)) void save_original_state1(void){
    asm volatile(""
            "msr dbgbvr3_el1, x30\n"
            "msr dbgbvr4_el1, x29\n"
            /* "mov x21, %[orig_plus_1_dist]\n" */
            /* "mov x20, %[reletramp1]\n" */
            /* "mov x19, %[enable_preemption]\n" */
            /* "blr x19\n" */
            /* "mov x30, x20\n" */
            "mov x30, %[reletramp1]\n"
            /* "mrs x16, dbgwvr0_el1\n" */
            /* "msr DAIF, x16\n" */
            "mrs x16, dbgbvr2_el1\n"
            /* branch back to orig+1 */
            /* "add x16, x16, x21\n" */
            "add x16, x16, %[orig_plus_1_dist]\n"
            "br x16\n"
            : : [orig_plus_1_dist] "r" (DIST_FROM_REFCNT_TO(orig[1])),
            [reletramp1] "r" (reletramp1)
            /* [enable_preemption] "r" (_enable_preemption) */
            );
}

/* reftramp0 and reftramp1: take a reference on an xnuspy_tramp.
 *
 * reftramp0 is called when the kernel calls the hooked function.
 *
 * reftramp1 is called when the original function, called through the 'orig'
 * trampoline, is called by the user.
 *
 * Sadly, these can't be merged into one function because we cannot modify
 * LR and we have no way of knowing what context (tramp or orig) it would be
 * called from.
 */
__attribute__ ((naked)) void reftramp0(void){
    asm volatile(""
            "mrs x16, dbgbvr2_el1\n"
            "1:\n"
            "ldaxr w14, [x16]\n"
            "mov x15, x14\n"
            "add w14, w15, #1\n"
            "stlxr w15, w14, [x16]\n"
            "cbnz w15, 1b\n"
            /* branch back to tramp+3 */
            "add x16, x16, %[tramp_plus_3_dist]\n"
            "br x16\n"
            : : [tramp_plus_3_dist] "r" (DIST_FROM_REFCNT_TO(tramp[3]))
            );
}

__attribute__ ((naked)) void reftramp1(void){
    asm volatile(""
            "mrs x16, dbgbvr2_el1\n"
            "1:\n"
            "ldaxr w14, [x16]\n"
            "mov x15, x14\n"
            "add w14, w15, #1\n"
            "stlxr w15, w14, [x16]\n"
            "cbnz w15, 1b\n"
            /* branch back to orig+2 */
            "add x16, x16, %[orig_plus_2_dist]\n"
            "br x16\n"
            : : [orig_plus_2_dist] "r" (DIST_FROM_REFCNT_TO(orig[2]))
            );
}

struct xnuspy_ctl_args {
    uint64_t flavor;
    uint64_t arg1;
    uint64_t arg2;
    uint64_t arg3;
};
int xnuspy_ctl(void *, struct xnuspy_ctl_args *, int *);

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
 * was hacky and left me at the mercy of the scheduler.
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

            /* __builtin_memcpy(sc64, start, 0x4); */

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

            /* for(int k=0; k<sc64->vmsize/0x4000; k++){ */
            /*     __builtin_memcpy(curpage, start, 0x4000); */

            /*     start += 0x4000; */
            /*     curpage += 0x4000; */
            /* } */
        }

next:
        lc = (struct load_command *)((uintptr_t)lc + lc->cmdsize);
    }

    return replacement_kva;
}

static int xnuspy_install_hook2(uint64_t target, uint64_t replacement,
        uint64_t /* __user */ origp){
    kprintf("%s: called with target %#llx replacement %#llx origp %#llx\n",
            __func__, target, replacement, origp);

    /* slide target */
    target += kernel_slide;

    /* Find a free xnuspy_tramp inside the trampoline page */
    struct xnuspy_tramp *tramp = xnuspy_tramp_page;

    while((uint8_t *)tramp < xnuspy_tramp_page_end){
        if(!tramp->refcnt)
            break;

        tramp++;
    }

    if(!tramp){
        kprintf("%s: no free xnuspy_tramp structs\n", __func__);
        return ENOSPC;
    }

    kprintf("%s: got free xnuspy_ctl struct @ %#llx\n", __func__, tramp);

    /* +1 for creation */
    tramp->refcnt = 1;
    /* tramp->replacement = replacement; */

    /* Build the trampoline to the replacement as well as the trampoline
     * that represents the original function */

    uint32_t orig_tramp_len = 0;

    generate_replacement_tramp(save_original_state0, reftramp0, tramp->tramp);
    generate_original_tramp(target + 4, save_original_state1, reftramp1,
            tramp->orig, &orig_tramp_len);

    /* copyout the original function trampoline before the replacement
     * is called */
    uint32_t *orig_tramp = tramp->orig;
    int err = copyout(&orig_tramp, origp, sizeof(origp));

    uint64_t tpidr_el1;
    asm volatile("mrs %0, tpidr_el1" : "=r" (tpidr_el1));
    /* cpuDatap offset found in _machine_switch_context */
    void *cpudata = *(void **)(tpidr_el1 + 0x478);
    uint16_t curcpu = *(uint16_t *)cpudata;
    desc_xnuspy_tramp(tramp, orig_tramp_len);

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

    /* uint32_t *cursor = (uint32_t *)replacement_kva; */
    /* for(int i=0; i<200; i++){ */
    /*     kprintf("%s: %#llx:      %#x\n", __func__, cursor+i, cursor[i]); */
    /* } */

    /* All the trampolines are set up, write the branch */
    kprotect(target, 0x4000, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);

    *(uint32_t *)target = assemble_b(target, (uint64_t)tramp->tramp);

    asm volatile("dc cvau, %0" : : "r" (target));
    asm volatile("dsb ish");
    asm volatile("ic ivau, %0" : : "r" (target));
    asm volatile("dsb ish");
    asm volatile("isb sy");
    /* struct vm_map_links *cur_links = &current_map->hdr.links; */
    /* struct vm_map_entry *cur_entry = (struct vm_map_entry *)1; */

    /* for(int i=0; i<20; i++){ */
    /*     if(!cur_entry) */
    /*         break; */



    /*     cur_entry = cur_entry */ 
    /* } */


    return 0;
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
        if(!tramp->refcnt)
            break;

        tramp++;
    }

    if(!tramp){
        kprintf("%s: no free xnuspy_tramp structs\n", __func__);
        return ENOSPC;
    }

    kprintf("%s: got free xnuspy_ctl struct @ %#llx\n", __func__, tramp);

    /* +1 for creation */
    tramp->refcnt = 1;
    /* tramp->replacement = replacement; */

    /* Build the trampoline to the replacement as well as the trampoline
     * that represents the original function */

    uint32_t orig_tramp_len = 0;

    /* generate_replacement_tramp(save_original_state0, reftramp0, swap_ttbr0, */
    /*         tramp->tramp); */
    generate_replacement_tramp(save_original_state0, reftramp0, tramp->tramp);

    /* generate_original_tramp(target + 4, save_original_state1, reftramp1, */
    /*         restore_ttbr0, tramp->orig, &orig_tramp_len); */
    generate_original_tramp(target + 4, save_original_state1, reftramp1,
            tramp->orig, &orig_tramp_len);

    /* copyout the original function trampoline before the replacement
     * is called */
    uint32_t *orig_tramp = tramp->orig;
    int err = copyout(&orig_tramp, origp, sizeof(origp));

    /* XXX do something if copyout fails */

    uint64_t ttbr0_el1;
    asm volatile("mrs %0, ttbr0_el1" : "=r" (ttbr0_el1));
    /* tramp->ttbr0_el1 = ttbr0_el1; */

    uint64_t tpidr_el1;
    asm volatile("mrs %0, tpidr_el1" : "=r" (tpidr_el1));
    /* cpuDatap offset found in _machine_switch_context */
    void *cpudata = *(void **)(tpidr_el1 + 0x478);
    uint16_t curcpu = *(uint16_t *)cpudata;
    desc_xnuspy_tramp(tramp, orig_tramp_len);

    uint64_t replacement_phys = uvtophys(replacement);
    uint64_t replacement_physpage = replacement_phys & ~0x3fffuLL;
    uint64_t replacement_pageoff = replacement_phys & 0x3fffuLL;

    kprintf("%s: replacement @ %#llx, replacement phys @ %#llx"
            ", replacement phys page @ %#llx, pageoff %#llx\n", __func__,
            replacement_phys, replacement_physpage, replacement_pageoff);

    pte_t *reflector_page_ptep = el1_ptep(usercode_reflector_pages_start);

    kprintf("%s: first reflector page @ %#llx ptep @ %#llx pte == %#llx\n", __func__,
            usercode_reflector_pages_start, reflector_page_ptep, *reflector_page_ptep);

    pte_t orig_reflector_page_pte = *reflector_page_ptep;

    pte_t new_reflector_page_pte = *reflector_page_ptep & ~0xfffffffff000uLL;
    new_reflector_page_pte |= replacement_physpage;
    new_reflector_page_pte &= ~(ARM_PTE_PNX | ARM_PTE_NX);

    kprintf("%s: new reflector page pte == %#llx\n", __func__,
            new_reflector_page_pte);

    kwrite(reflector_page_ptep, &new_reflector_page_pte,
            sizeof(new_reflector_page_pte));

    asm volatile("isb");
    asm volatile("dsb sy");
    asm volatile("tlbi vmalle1");
    asm volatile("dsb sy");
    asm volatile("isb");

    uint64_t reflected_user_code =
        (uint64_t)usercode_reflector_pages_start & ~0xfffuLL;
    reflected_user_code |= replacement_pageoff;

    tramp->replacement = reflected_user_code;

    uint32_t *userreplacement_cursor = (uint32_t *)reflected_user_code;

    for(int i=0; i<200; i++){
        kprintf("%s: %#llx:   %#x\n", __func__, (uint64_t)(userreplacement_cursor+i),
                userreplacement_cursor[i]);
    }


    /* IOSleep(5000); */

    /* void (*usercode_fxn)(void) = (void (*)(void))reflected_user_code; */
    /* int (*usercode_fxn)(void) = (int (*)(void))reflected_user_code; */
    /* int cur_cpu_id = usercode_fxn(); */
    /* usercode_fxn(); */
    /* kprintf("%s: user code returned CPU ID %d, correct CPU ID = %d\n", __func__, */
    /*         cur_cpu_id, curcpu); */

    /* kwrite(reflector_page_ptep, &orig_reflector_page_pte, */
    /*         sizeof(orig_reflector_page_pte)); */

    /* asm volatile("isb"); */
    /* asm volatile("dsb sy"); */
    /* asm volatile("tlbi vmalle1"); */
    /* asm volatile("dsb sy"); */
    /* asm volatile("isb"); */


    /* kprintf("%s: on this CPU, ttbr0_el1 == %#llx baddr phys %#llx baddr kva %#llx\n", */
    /*         __func__, ttbr0_el1, ttbr0_el1 & 0xfffffffffffe, */
    /*         phystokv(ttbr0_el1 & 0xfffffffffffe)); */


    /* kprintf("%s: xnuspy_ctl is @ %#llx (phys=%#llx)\n", __func__, (uint64_t)xnuspy_ctl, */
    /*         kvtophys((uint64_t)xnuspy_ctl)); */
    /* pte_t *xnuspy_ctl_ptep = el1_ptep((uint64_t)xnuspy_ctl); */
    /* pte_t *replacement_ptep = el0_ptep(replacement); */

    /* kprintf("%s: xnuspy_ctl pte @ %#llx phys %#llx pte == %#llx\n", __func__, */
    /*         xnuspy_ctl_ptep, kvtophys((uint64_t)xnuspy_ctl_ptep), */
    /*         *xnuspy_ctl_ptep); */
    /* uint64_t replacement_phys = uvtophys(replacement); */
    /* uint64_t replacement_kv = phystokv(replacement_phys); */
    /* kprintf("%s: replacement (%#llx, phys=%#llx (phystokv on that = %#llx))" */
    /*         " ptep @ %#llx phys ptep %#llx pte == %#llx\n", */
    /*         __func__, */
    /*         replacement, replacement_phys, replacement_kv, replacement_ptep, */
    /*         kvtophys((uint64_t)replacement_ptep), *replacement_ptep); */

    /* uint32_t *cursor = (uint32_t *)replacement_kv; */

    /* int pmap_expand_ret = pmap_expand(kernel_pmap, replacement_kv, 0, 3); */
    /* kprintf("%s: pmap_expand returned %d\n", __func__, pmap_expand_ret); */

    /* pte_t *replacement_kv_pte = el1_ptep(replacement_kv); */

    /* kprintf("%s: replacement_kv pte @ %#llx pte == %#llx\n", __func__, */
    /*         (uint64_t)replacement_kv_pte, *replacement_kv_pte); */

    /* kprintf("%s: gonna try and read from replacement_kv @ %#llx\n", __func__, */
    /*         replacement_kv); */

    /* *cursor = 0x41414141; */

    /* asm volatile("isb"); */
    /* asm volatile("dsb ish"); */
    /* asm volatile("tlbi vmalle1"); */
    /* asm volatile("dsb ish"); */
    /* asm volatile("isb"); */

    /* for(int i=0; i<15; i++){ */
    /*     kprintf("%s: %#llx:   %#x\n", __func__, (uint64_t)(cursor+i), cursor[i]); */
    /* } */

    /* pte_t new_replacement_pte = *replacement_ptep & ~ARM_PTE_PNX; */
    /* kwrite(replacement_ptep, &new_replacement_pte, sizeof(new_replacement_pte)); */

    /* asm volatile("isb"); */
    /* asm volatile("dsb ish"); */
    /* asm volatile("tlbi vmalle1"); */
    /* asm volatile("dsb ish"); */
    /* asm volatile("isb"); */

    /* asm volatile("mov x4, 0x5454"); */
    /* asm volatile("mov x5, %0" : : "r" (replacement_kv)); */
    /* asm volatile("br x5"); */

    /* size_t sz = 0x8000; */
    /* uint64_t mem = (uint64_t)kalloc_canblock(&sz, false, NULL); */

    /* if(!mem) */
    /*     return ENOMEM; */

    /* uint64_t mem = 0; */
    /* kern_return_t kret = kernel_memory_allocate(kernel_map, &mem, 0x4000, 0x3fff, */
    /*         KMA_LOMEM, 0); */

    /* if(kret){ */
    /*     kprintf("%s: kernel_memory_allocate failed: %#x\n", __func__, kret); */
    /*     return ENOMEM; */
    /* } */

    /* uint64_t mem = (uint64_t)xnuspy_tramp_page; */

    /* pte_t *mem_ptep = el1_ptep(mem); */

    /* kprintf("%s: mem @ %#llx phys @ %#llx ptep @ %#llx pte == %#llx\n", __func__, */
    /*         mem, kvtophys(mem), mem_ptep, *mem_ptep); */
    /* uint64_t replacement_physpage = replacement_phys & ~0x3fffuLL; */
    /* pte_t new_mem_pte = (*mem_ptep & ~0xfffffffff000uLL) | replacement_physpage; */
    /* new_mem_pte &= ~(ARM_PTE_NX | ARM_PTE_PNX); */
    /* pte_t new_mem_pte = *mem_ptep & ~(ARM_PTE_NX | ARM_PTE_PNX); */
    /* kprintf("%s: new_mem_pte == %#llx\n", __func__, new_mem_pte); */

    /* kwrite(mem_ptep, &new_mem_pte, sizeof(new_mem_pte)); */

    /* asm volatile("isb"); */
    /* asm volatile("dsb sy"); */
    /* asm volatile("tlbi vmalle1"); */
    /* asm volatile("dsb sy"); */
    /* asm volatile("isb"); */

    /* asm volatile("" */
    /*         "tlbi vmalle1\n" */
    /*         "ic iallu\n" */
    /*         "dsb sy\n" */
    /*         "isb sy\n" */
    /*         ); */

    /* uint64_t mem_phys = kvtophys(mem); */
    /* uint64_t mem_kv2 = phystokv(mem_phys); */
    /* pte_t *mem_kv2_ptep = el1_ptep(mem_kv2); */

    /* kprintf("%s: mem @ %#llx phys %#llx mem_kv2 %#llx ptep for mem_kv2 @ %#llx" */
    /*         " mem_kv2 PTE == %#llx\n", __func__, mem, mem_phys, mem_kv2, */
    /*         mem_kv2_ptep, *mem_kv2_ptep); */

    /* mem_ptep = el1_ptep(mem); */

    /* kprintf("%s: NOW: mem @ %#llx phys @ %#llx ptep @ %#llx pte == %#llx\n", __func__, */
    /*         mem, kvtophys(mem), mem_ptep, *mem_ptep); */

    /* kprintf("%s: gonna try and read the mem from kalloc_canblock:\n", __func__); */

    /* cursor = (uint32_t *)mem; */

    /* for(int i=0; i<4096; i++){ */
    /*     kprintf("%s: %#llx:   %#x\n", __func__, (uint64_t)(cursor+i), cursor[i]); */
    /* } */

    /* mem now reflects the userland replacement page, get the page offset
     * of the replacement function itself and try to branch to it */
    /* uint64_t target_kva = mem | (replacement & 0xfff); */

    /* *(uint32_t *)target_kva = 0x41424344; */

    /* void (*func)(void) = (void (*)(void))target_kva; */
    /* func(); */

    /* uint64_t target_kva = mem; */
    /* *(uint32_t *)mem = 0x41424344; */
    /* asm volatile("isb"); */
    /* asm volatile("dsb ish"); */
    /* asm volatile("tlbi vmalle1"); */
    /* asm volatile("dsb ish"); */
    /* asm volatile("isb"); */

    /* asm volatile("mov x3, 0x4141"); */

    /* void (*fxn)(void) = (void (*)(void))mem; */
    /* fxn(); */
    /* asm volatile("mov x4, %0" : "=r" (mem)); */
    /* asm volatile("br x4"); */



    /* replacement_phys &= ~0x3fff; */
    /* replacement_kv &= ~0x3fffuLL; */

    /* uint64_t pmap_map_ret = pmap_map(replacement_kv, replacement_phys, */
    /*         replacement_phys + 0x4000, VM_PROT_READ | VM_PROT_WRITE, 0); */

    /* kprintf("%s: pmap_map returned %#llx\n", __func__, pmap_map_ret); */

    /* return 0; */

    /* replacement_kv_pte = el1_ptep(replacement_kv); */

    /* kprintf("%s: after pmap_map, replacement_kv pte is @ %#llx, pte == %#llx\n", */
    /*         __func__, replacement_kv_pte, *replacement_kv_pte); */

    /* pte_t new_replacement_kv_pte = *replacement_kv_pte & */
    /*     ~(ARM_PTE_NS | ARM_PTE_ATTRINDXMASK); */
    /* new_replacement_kv_pte |= 1; */

    /* kwrite(replacement_kv_pte, &new_replacement_kv_pte, */
    /*         sizeof(new_replacement_kv_pte)); */
            
    /* asm volatile("isb"); */
    /* asm volatile("dsb ish"); */
    /* asm volatile("tlbi vmalle1"); */
    /* asm volatile("dsb ish"); */
    /* asm volatile("isb"); */

    /* asm volatile("mov x4, 0x5454"); */
    /* asm volatile("br %0" : : "r" (replacement_kv)); */

    /* uint64_t ttbr1_el1; */
    /* asm volatile("mrs %0, ttbr1_el1" : "=r" (ttbr1_el1)); */
    /* uint64_t l1_table = phystokv(ttbr1_el1 & 0xfffffffffffe); */
    /* uint64_t l1_idx = (replacement >> ARM_TT_L1_SHIFT) & 0x7; */
    /* uint64_t *l1_ttep = (uint64_t *)(l1_table + (0x8 * l1_idx)); */

    /* kprintf("%s: l1 tte from ttbr1_el1 with replacement %#llx == %#llx\n", */
    /*         __func__, replacement, (uint64_t)l1_ttep); */

    /* uint64_t l2_table = phystokv(*l1_ttep & ARM_TTE_TABLE_MASK); */
    /* uint64_t l2_idx = (replacement >> ARM_TT_L2_SHIFT) & 0x7ff; */
    /* uint64_t *l2_ttep = (uint64_t *)(l2_table + (0x8 * l2_idx)); */

    /* kprintf("%s: l2 tte from ttbr1_el1 with replacement %#llx == %#llx\n", */
    /*         __func__, replacement, (uint64_t)l2_ttep); */

    /* uint64_t l3_table = phystokv(*l2_ttep & ARM_TTE_TABLE_MASK); */
    /* uint64_t l3_idx = (replacement >> ARM_TT_L3_SHIFT) & 0x7ff; */
    /* uint64_t *l3_ptep = (uint64_t *)(l3_table + (0x8 * l3_idx)); */

    /* kprintf("%s: l3 tte from ttbr1_el1 with replacement %#llx == %#llx\n", */
    /*         __func__, replacement, (uint64_t)l3_ptep); */


    /* XXX we don't need to unset nG bit in user pte if we are just swapping ttbr0? */
    
    /* Mark the user replacement as executable from EL1. This function
     * will clear NX as well as PXN. */
    /* TODO We need to mark the entirety of the calling processes' __text
     * segment as executable from EL1 so the user can call other functions
     * they write inside their program from their kernel hook. */
    // XXX something like get_calling_process_text_segment
    /* uprotect(tramp->replacement, 0x4000, VM_PROT_READ | VM_PROT_EXECUTE); */

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
        default:
            break;
    };

    return copyout(&which, outp, sizeof(outp));
}

static int xnuspy_make_callable(uint64_t target, uint64_t /* __user */ origp){
    kprintf("%s: called with target %#llx origp %#llx\n", __func__, target, origp);

    /* slide target */
    target += kernel_slide;

    /* The problem we have is the following: we are swapping the current CPU's
     * TTBR0_EL1 with the TTBR0_EL1 from the CPU which installed a hook. The
     * user is allowed to call other kernel functions from within their
     * userland replacement. So what happens if some kernel function the user
     * calls within their replacement relies on seeing the original TTBR0_EL1?
     *
     * To solve this problem, an external kernel function will be represented
     * as an xnuspy_wrapper struct. Every xnuspy_wrapper struct resides on
     * writable, executable memory. The wrapper will contain a small trampoline
     * to restore the original TTBR0, call the actual kernel function, swap
     * back the TTBR0 of the CPU that installed the hook, and then return
     * back to the user's replacement code.
     *
     * Again, we cannot use the stack to persist data across function calls.
     * Since I'm already using most of the debug breakpoint value registers,
     * I'll just use callee-saved registers instead.
     *
     * An xnuspy_wrapper trampoline looks like this:
     *  wtramp[0]   MOV X28, X29
     *  wtramp[1]   MOV X27, X30
     *  wtramp[2]   MOV X26, X19
     *  wtramp[3]   MOV X25, X20
     *  wtramp[4]   MOV X24, X21
     *  wtramp[5]   MOV X23, X22
     *
     *  XXX here we have x19-x22 to work with
     *  
     *  ; FAR_EL1 is the register we're persisting the original value
     *  ; of TTBR0_EL1 with.
     *  wtramp[6]   MRS X19, FAR_EL1
     *
     *  ; Back up current TTBR0
     *  wtramp[7]   MRS X20, TTBR0_EL1
     *
     *  ; Set original TTBR0_EL1
     *  wtramp[8]   MSR TTBR0_EL1, X19
     *
     *  wtramp[9,13] barriers, invalidate TLBs
     *
     *  XXX stick a pointer to the kernel function in some register
     *
     *  wtramp[.]   BLR <kernel_functionp>
     *
     *  wtramp[.]   MSR TTBR0_EL1, X20
     *
     *  wtramp[...] barriers, invalidate TLBs
     *
     *  wtramp[.]   MOV X22, X23
     *  wtramp[.]   MOV X21, X24
     *  wtramp[.]   MOV X20, X25
     *  wtramp[.]   MOV X19, X26
     *  wtramp[.]   MOV X30, X27
     *  wtramp[.]   MOV X29, X28
     *  wtramp[.]   RET
     */

    return 0;
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
            /* res = xnuspy_install_hook(uap->arg1, uap->arg2, uap->arg3); */
            res = xnuspy_install_hook2(uap->arg1, uap->arg2, uap->arg3);
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
