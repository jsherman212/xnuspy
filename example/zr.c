#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "xnuspy_ctl.h"

static long SYS_xnuspy_ctl = 0;

static void (*kprintf)(const char *, ...);

static void (*zone_require_orig)(void *addr, void *expected_zone);

static void zone_require(void *addr, void *expected_zone){
    uint64_t mpidr_el1;
    asm volatile("mrs %0, mpidr_el1" : "=r" (mpidr_el1));
    uint8_t cpuid = mpidr_el1 & 0xff;

    uint64_t caller = (uint64_t)__builtin_return_address(0);

    char *zname = *(char **)((uint8_t *)expected_zone + 0x120);

    kprintf("CPU %d, caller %#llx: zone_require called with addr %#llx,"
            " expected zone", cpuid, caller, addr);

    if(zname)
        kprintf(" '%s'\n", zname);
    else
        kprintf(" %#llx\n", expected_zone);

    zone_require_orig(addr, expected_zone);
}

int main(int argc, char **argv){
    size_t oldlen = sizeof(long);
    int ret = sysctlbyname("kern.xnuspy_ctl_callnum", &SYS_xnuspy_ctl,
            &oldlen, NULL, 0);

    if(ret == -1){
        printf("sysctlbyname with kern.xnuspy_ctl_callnum failed: %s\n",
                strerror(errno));
        return 1;
    }

    syscall(SYS_xnuspy_ctl, XNUSPY_GET_FUNCTION, KPRINTF, &kprintf, 0);

    printf("got kprintf @ %#llx\n", kprintf);

    syscall(SYS_xnuspy_ctl, XNUSPY_INSTALL_HOOK, 0xFFFFFFF007C4B420,
            zone_require, &zone_require_orig);

    printf("zone_require_orig = %#llx\n", zone_require_orig);
    syscall(SYS_xnuspy_ctl, XNUSPY_INSTALL_HOOK, 0xFFFFFFF007C4B420,
            main, &zone_require_orig);

    printf("zone_require_orig = %#llx\n", zone_require_orig);

    printf("Ctrl C to quit\n");
    getchar();

    return 0;
}
