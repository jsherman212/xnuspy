#include <errno.h>
#include <stdbool.h>

#include "common.h"
#include "mem.h"
#include "pte.h"

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

    /* zero out pan in case no instruction did it before us */
    /* msr pan, #0 */
    asm volatile(".long 0xd500409f");

    /* asm volatile("mov x1, 0x8888"); */
    /* asm volatile("mov x0, %0" : : "r" (userland_code) : ); */
    /* asm volatile("br x0"); */

    /* XXX clang crash on the below line!! */
    /* uint64_t pan = __builtin_arm_rsr("pan"); */
    /* asm volatile("mrs %0, PAN" : "=r" (pan)); */
    /* kprintf("%s: userland pointer %#llx\n", __func__, userland_ptr); */
    /* kprintf("%s: userland pointer %#llx, PAN = %#llx\n", __func__, userland_ptr, pan); */

    /* kprintf("%s: dereferenced: %#x\n", __func__, *userland_ptr); */

    /* uint64_t physhdr = kvtophys((uint64_t)mh_execute_header); */

    uint64_t *replacement_el0_pte = el0_ptep(replacement_el0_addr);



    *retval = 0;

    return 0;
}
