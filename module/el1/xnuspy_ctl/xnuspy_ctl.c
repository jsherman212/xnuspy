#include <errno.h>
#include <mach/mach.h>
#include <stdbool.h>
#include <stdint.h>

#include "mem.h"
#include "pte.h"
#include "tramp.h"

#define XNUSPY_INSTALL_HOOK         (0)
#define XNUSPY_UNINSTALL_HOOK       (1)
#define XNUSPY_CHECK_IF_PATCHED     (2)
#define XNUSPY_MAX_FLAVOR           XNUSPY_CHECK_IF_PATCHED

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

/* This structure represents a function hook. Every xnuspy_tramp struct resides
 * on writeable, executable memory. */
struct xnuspy_tramp {
    /* Address of userland replacement */
    uint64_t replacement;
    _Atomic uint32_t refcnt;
    /* The trampoline for a hooked function. When the user installs a hook
     * on a function, the first instruction of that function is replaced
     * with a branch to here. An xnuspy trampoline looks like this:
     *  tramp[0]    ADR X16, <refcntp>
     *  tramp[1]    B _reftramp
     *  tramp[2]    ADR X16, <replacementp>
     *  tramp[3]    LDR X16, [X16]
     *  tramp[4]    BR X16
     */
    uint32_t tramp[5];
    /* An abstraction that represents the original function. It's just another
     * trampoline, but it can take on one of five forms. Every form starts
     * with this header:
     *  orig[0]     ADR X16, <refcntp>
     *  orig[1]     B _reftramp
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
     *  orig[2]     ADRP Rn, #n@pageoff
     *  orig[3]     ADD Rn, Rn, #n
     *  orig[4]     ADR X16, #0xc
     *  orig[5]     LDR X16, [X16]
     *  orig[6]     BR X16
     *  orig[7]     <address of second instruction of the hooked function>[31:0]
     *  orig[8]     <address of second instruction of the hooked function>[63:32]
     */
    uint32_t orig[12];
};

MARK_AS_KERNEL_OFFSET struct xnuspy_tramp *xnuspy_tramp_page;
MARK_AS_KERNEL_OFFSET uint8_t *xnuspy_tramp_page_end;

static int xnuspy_init_flag = 0;

static void xnuspy_init(void){
    /* Mark the xnuspy_tramp page as executable */
    vm_prot_t prot = VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE;
    kprotect((uint64_t)xnuspy_tramp_page, 0x4000, prot);

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
    asm volatile(".align 14");

    xnuspy_init_flag = 1;
}

/* reletramp: release a reference on an xnuspy_tramp.
 *
 * This function is called with a pointer to a reference count saved on
 * the stack when:
 *  - the user's replacement function returns
 *  - the original function, called through the 'orig' trampoline, returns
 *
 * When the reference count reaches zero, we restore the first instruction
 * of the hooked function and zero out this xnuspy_tramp structure, marking
 * it as free in the page it resides on.
 */
__attribute__ ((naked)) void reletramp(void){
    /* TODO actually deallocate when refcnt hits zero */
    asm volatile(""
            "ldr x16, [sp], 0x10\n"
            "1:\n"
            "ldaxr w9, [x16]\n"
            "mov x10, x9\n"
            "sub w9, w10, #1\n"
            "stlxr w10, w9, [x16]\n"
            "cbnz w10, 1b\n"
            "ldp x29, x30, [sp], 0x10\n"
            "ret"
            );
}

/* reftramp: take a reference on an xnuspy_tramp. 
 *
 * This function is called with a pointer to a reference count in X16 when:
 *  - the kernel calls the hooked function
 *  - the original function, called through the 'orig' trampoline, is called
 *    by the user
 *
 * After a reference is taken, X16 is pushed to the stack. To make sure
 * we release the reference we took, we set LR to reletramp. However, we need
 * to make sure we return back to the original caller, so we also save the
 * current stack frame. Finally, we branch back to tramp+2.
 */
__attribute__ ((naked)) void reftramp(void){
    asm volatile(""
            "1:\n"
            "ldaxr w9, [x16]\n"
            "mov x10, x9\n"
            "add w9, w10, #1\n"
            "stlxr w10, w9, [x16]\n"
            "cbnz w10, 1b\n"
            "stp x29, x30, [sp, -0x10]!\n"
            "str x16, [sp, -0x10]!\n"
            "mov x29, sp\n"
            "mov x30, %0\n"
            "add x16, x16, 0xc\n"
            "br x16" : : "r" (reletramp)
            );
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
        /* These structs are zeroed out when they're freed */
        if(!tramp->replacement)
            break;

        tramp++;
    }

    if(!tramp){
        kprintf("%s: no free xnuspy_tramp structs\n", __func__);
        return ENOSPC;
    }

    kprintf("%s: got free xnuspy_ctl struct @ %#llx\n", __func__, tramp);

    tramp->replacement = replacement;

    /* Build the trampoline to the replacement as well as the trampoline
     * that represents the original function */

    generate_replacement_tramp(reftramp, tramp->tramp);

    /* TODO We need to mark the entirety of the calling processes' __text
     * segment as executable from EL1 so the user can call other functions
     * they write inside their program from their kernel hook. */
    // XXX something like get_calling_process_text_segment



    kprintf("%s: tramp %#llx &tramp %#llx\n", __func__, tramp, &tramp);

    /* copyout original kernel function pointer to origp */
    uint32_t *orig_tramp = tramp->orig;

    return copyout(&orig_tramp, origp, sizeof(origp));
}

static int xnuspy_uninstall_hook(uint64_t target){
    kprintf("%s: XNUSPY_UNINSTALL_HOOK is not implemented yet\n", __func__);
    return ENOSYS;
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

    kprintf("%s: got flavor %d\n", __func__, flavor);
    kprintf("%s: kslide %#llx\n", __func__, kernel_slide);
    kprintf("%s: xnuspy_ctl @ %#llx (unslid)\n", __func__,
            (uint64_t)xnuspy_ctl - kernel_slide);
    kprintf("%s: xnuspy_ctl tramp page @ [%#llx,%#llx] (unslid)\n", __func__,
            (uint64_t)xnuspy_tramp_page - kernel_slide,
            (uint64_t)xnuspy_tramp_page_end - kernel_slide);

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
        default:
            *retval = -1;
            return EINVAL;
    };

    if(res)
        *retval = -1;

    return res;
}
