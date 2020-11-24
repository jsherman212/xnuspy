#include <errno.h>
#include <mach/mach.h>
#include <stdbool.h>
#include <stdint.h>

#include "hwbp.h"
#include "mem.h"
#include "pte.h"

#define MARK_AS_KERNEL_OFFSET __attribute__((section("__DATA,__koff")))

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

/* XXX would this be better as an array of xnuspy_tramp structs? */
MARK_AS_KERNEL_OFFSET uint8_t *xnuspy_tramp_page;
MARK_AS_KERNEL_OFFSET uint8_t *xnuspy_tramp_page_end;

/* XXX For debugging only */
MARK_AS_KERNEL_OFFSET void (*kprintf)(const char *fmt, ...);
MARK_AS_KERNEL_OFFSET void (*IOSleep)(unsigned int millis);

#define XNUSPY_INSTALL_HOOK         (0)
#define XNUSPY_UNINSTALL_HOOK       (1)
#define XNUSPY_CHECK_IF_PATCHED     (2)
#define XNUSPY_MAX_FLAVOR           XNUSPY_CHECK_IF_PATCHED

struct xnuspy_ctl_args {
    uint64_t flavor;
    uint64_t arg1;
    uint64_t arg2;
    uint64_t arg3;
};

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

    xnuspy_init_flag = 1;
}

int xnuspy_ctl(void *p, struct xnuspy_ctl_args *uap, int *retval){
    uint64_t flavor = uap->flavor;

    if(flavor > XNUSPY_MAX_FLAVOR){
        kprintf("%s: bad flavor %d\n", __func__, flavor);
        *retval = -1;
        return EINVAL;
    }

    kprintf("%s: got flavor %d\n", __func__, flavor);

    if(!xnuspy_init_flag)
        xnuspy_init();

    /* kprintf("%s: got flavor '%s'\n", __func__, g_flavors[flavor]); */

    if(flavor == XNUSPY_CHECK_IF_PATCHED){
        *retval = 999;
        return 0;
    }

    if(flavor == XNUSPY_UNINSTALL_HOOK){
        kprintf("%s: XNUSPY_UNINSTALL_HOOK is not implemented yet\n", __func__);
        *retval = -1;
        return ENOSYS;
    }

    kprintf("%s: kslide %#llx\n", __func__, kernel_slide);
    kprintf("%s: xnuspy_ctl @ %#llx (unslid)\n", __func__,
            (uint64_t)xnuspy_ctl - kernel_slide);
    kprintf("%s: xnuspy_ctl tramp page @ [%#llx,%#llx] (unslid)\n", __func__,
            (uint64_t)xnuspy_tramp_page - kernel_slide,
            (uint64_t)xnuspy_tramp_page_end - kernel_slide);


    *retval = 0;

    return 0;
}
