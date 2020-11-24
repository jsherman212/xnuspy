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

/* XXX freezes up if we try to access this array?? */
static const char *g_flavors[] = {
    "XNUSPY_INSTALL_HOOK",
    "XNUSPY_UNINSTALL_HOOK",
    "XNUSPY_CHECK_IF_PATCHED",
};

struct xnuspy_ctl_args {
    uint64_t flavor;
    uint64_t arg1;
    uint64_t arg2;
    uint64_t arg3;
};

static const size_t SIZEOF_CPUDATAENTRY = 0x10;

int xnuspy_ctl(void *p, struct xnuspy_ctl_args *uap, int *retval){
    uint64_t flavor = uap->flavor;

    if(flavor > XNUSPY_MAX_FLAVOR){
        kprintf("%s: bad flavor %d\n", __func__, flavor);
        *retval = -1;
        return EINVAL;
    }

    kprintf("%s: got flavor %d\n", __func__, flavor);

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

    /* uint64_t map_addr = kvtophys(0xfffffff00f004000 + kernel_slide); */
    /* kprintf("%s: 3 secs before ml_io_map with %#llx\n", __func__, map_addr); */
    /* IOSleep(3000); */

    /* vm_offset_t ml_io_map_ret = ml_io_map(map_addr, 0x4000); */

    /* kprintf("%s: ml_io_map returned %#llx\n", __func__, ml_io_map_ret); */

    /* zero out pan in case no instruction did it before us */
    /* msr pan, #0 */
    asm volatile(".long 0xd500409f");

    *(uint32_t *)xnuspy_tramp_page = 0x55667788;

    if(kprotect((uint64_t)xnuspy_tramp_page, 0x4000,
                VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE)){
        kprintf("%s: could not kprotect xnuspy_tramp_page\n", __func__);
        *retval = 0;
        return 0;
    }

    IOSleep(5000);

    *(uint32_t *)xnuspy_tramp_page = 0x41424344;
    asm volatile("br %0" : "=r" (xnuspy_tramp_page));

    *retval = 0;

    return 0;
}
