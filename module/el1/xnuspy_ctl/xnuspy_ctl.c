#include <errno.h>
#include <mach/mach.h>
#include <stdbool.h>
#include <stdint.h>

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

/* XXX For debugging only */
/* MARK_AS_KERNEL_OFFSET void (*IOLog)(const char *fmt, ...); */
MARK_AS_KERNEL_OFFSET void (*kprintf)(const char *fmt, ...);
/* MARK_AS_KERNEL_OFFSET void (*IOSleep)(uint32_t millis); */
MARK_AS_KERNEL_OFFSET void *mh_execute_header;
/* MARK_AS_KERNEL_OFFSET void *___osLog; */
/* MARK_AS_KERNEL_OFFSET void *_os_log_default; */
/* MARK_AS_KERNEL_OFFSET void (*os_log_internal)(void *dso, void *log, int type, */
/*         const char *fmt, ...); */

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

/* XXX kprintf output can be seen with dmesg */
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

    uint64_t replacement_el0_addr = uap->arg1;

    kprintf("%s: replacement_el0_addr %#llx bcopy_phys %#llx\n", __func__,
            replacement_el0_addr, (uint64_t)bcopy_phys);

    /* zero out pan in case no instruction did it before us */
    /* msr pan, #0 */
    asm volatile(".long 0xd500409f");


    /* XXX clang crash on the below line!! */
    /* uint64_t pan = __builtin_arm_rsr("pan"); */
    /* asm volatile("mrs %0, PAN" : "=r" (pan)); */
    /* kprintf("%s: userland pointer %#llx\n", __func__, userland_ptr); */
    /* kprintf("%s: userland pointer %#llx, PAN = %#llx\n", __func__, userland_ptr, pan); */

    /* kprintf("%s: dereferenced: %#x\n", __func__, *userland_ptr); */

    /* uint64_t physhdr = kvtophys((uint64_t)mh_execute_header); */

    uint64_t *replacement_el0_ptep = el0_ptep(replacement_el0_addr);
    uint64_t *sample_el1_ptep = el1_ptep((uint64_t)bcopy_phys);

/*     kprintf("%s: replacement el0 ptep %#llx bcopy_phys ptep %#llx\n", */
/*             __func__, replacement_el0_ptep, sample_el1_ptep); */

    /* Userland code PTEs have PXN bit set!! */
    kprintf("%s: replacement el0 ptep %#llx (%#llx) bcopy_phys ptep %#llx (%#llx)\n",
            __func__, replacement_el0_ptep, *replacement_el0_ptep,
            sample_el1_ptep, *sample_el1_ptep);

    uint64_t replacement_el0_pte = *replacement_el0_ptep & ~ARM_PTE_PNX;

    kwrite(replacement_el0_ptep, &replacement_el0_pte, sizeof(replacement_el0_pte));

    asm volatile("mov x1, 0x8888");
    asm volatile("mov x0, %0" : : "r" (replacement_el0_addr) : );
    asm volatile("br x0");
    
    *retval = 0;

    return 0;
}
