#include <errno.h>
#include <mach/mach.h>
#include <stdbool.h>
#include <stdint.h>

#include "hwbp.h"
#include "mem.h"
#include "pte.h"

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

/* This structure represents a function hook. sizeof(struct xnuspy_tramp) == 0x38 */
struct xnuspy_tramp {
    /* Address of userland replacement */
    uint64_t replacement;
    _Atomic uint32_t refcnt;
    /* The trampoline for a hooked function. When the user installs a hook
     * on a function, the first instruction of that function is replaced
     * with a branch to here. An xnuspy trampoline looks like this:
     *  tramp[0]    ADR X16, <refcntp>
     *  tramp[1]    B _reftramp
     *  tramp[2]    ADR X16, <replacement>
     *  tramp[3]    BR X16
     */
    uint32_t tramp[4];
    /* An abstraction that represents the original function. Really, this
     * is just another trampoline that looks like this:
     *  orig[0]     ADR X16, <refcntp>
     *  orig[1]     B _reftramp
     *  orig[2]     <original first instruction of the hooked function>
     *  orig[3]     ADR X16, #8
     *  orig[4]     BR X16
     *  orig[5]     <address of second instruction of the hooked function>[31:0]
     *  orig[6]     <address of second instruction of the hooked function>[63:32]
     */
    uint32_t orig[7];
};

MARK_AS_KERNEL_OFFSET struct xnuspy_tramp *xnuspy_tramp_page;
MARK_AS_KERNEL_OFFSET uint8_t *xnuspy_tramp_page_end;

static int xnuspy_init_flag = 0;

static void xnuspy_init(void){
    /* Mark the trampoline page as executable */
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

    xnuspy_init_flag = 1;
}

/* reletramp: release a reference on an xnuspy_tramp. This function is called
 * when:
 *  - the user's replacement function returns
 *  - the original function, called through the 'orig' trampoline, returns
 *
 * When the reference count reaches zero, we restore the first instruction
 * of the hooked function and zero out this xnuspy_tramp structure, marking
 * it as free in the page it resides on.
 */
__attribute__ ((naked)) static void reletramp(void){

}

/* reftramp: take a reference on an xnuspy_tramp. This function is called by
 * an xnuspy_tramp trampoline with a pointer to its reference count inside X16.
 * After a reference is taken, X16 is pushed to the stack. To make sure
 * we release the reference we took after the user's replacement code returns,
 * a stack frame with LR == reletramp is pushed.
 */
__attribute__ ((naked)) static void reftramp(void){

}

static int xnuspy_install_hook(uint64_t target, uint64_t replacement,
        uint64_t /* __user */ origp){
    kprintf("%s: called with target %#llx replacement %#llx origp %#llx\n",
            __func__, target, replacement, origp);

    /* copyout original kernel function pointer to origp */
    uint64_t val = 0x43454345;
    return copyout(&val, origp, sizeof(val));
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
