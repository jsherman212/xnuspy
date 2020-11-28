#include <errno.h>
#include <limits.h>
#include <mach/mach.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "xnuspy_ctl.h"

static long SYS_xnuspy_ctl = 0;

static int _concat_internal(char **dst, const char *src, va_list args){
    if(!src || !dst)
        return 0;

    size_t srclen = strlen(src), dstlen = 0;

    if(*dst)
        dstlen = strlen(*dst);

    /* Back up args before it gets used. Client calls va_end
     * on the parameter themselves when calling vconcat.
     */
    va_list args1;
    va_copy(args1, args);

    size_t total = srclen + dstlen + vsnprintf(NULL, 0, src, args) + 1;

    char *dst1 = malloc(total);

    if(!(*dst))
        *dst1 = '\0';
    else{
        strncpy(dst1, *dst, dstlen + 1);
        free(*dst);
        *dst = NULL;
    }

    int w = vsnprintf(dst1 + dstlen, total, src, args1);

    va_end(args1);

    *dst = realloc(dst1, strlen(dst1) + 1);

    return w;
}

static int concat(char **dst, const char *src, ...){
    va_list args;
    va_start(args, src);

    int w = _concat_internal(dst, src, args);

    va_end(args);

    return w;
}

static uint32_t *g_num_pointer = NULL;

/* static void open_replacement(void *p, void *uap, void *retval){ */
static void code(void){
    asm volatile("mov x0, 0x1234");
    asm volatile("mov x1, 0x5555");
    asm volatile("mov x2, 0x7979");
    asm volatile("ldr x5, [x0]");
}

static int (*copyout)(const void *, uint64_t, vm_size_t);
static int (*kprotect)(uint64_t, uint64_t, vm_prot_t);

struct sysctl_req {
    void            *p;
    int             lock;
    uint64_t        oldptr;         /* pointer to user supplied buffer */
    size_t          oldlen;         /* user buffer length (also returned) */
    size_t          oldidx;         /* total data iteratively copied out */
    int             (*oldfunc)(struct sysctl_req *, const void *, size_t);
    uint64_t        newptr;         /* buffer containing new value */
    size_t          newlen;         /* length of new value */
    size_t          newidx;         /* total data iteratively copied in */
    int             (*newfunc)(struct sysctl_req *, void *, size_t);
};

static int (*sysctl_handle_long_orig)(void *, void *, int, struct sysctl_req *);

static int sysctl_handle_long(void *oidp, void *arg1, int arg2,
        struct sysctl_req *req){
    /* (*kprotect)((uint64_t)arg1, 0x4000, VM_PROT_READ | VM_PROT_WRITE); */
    /* *(long *)arg1 = 0x123456789abcdef; */

    long nonsense = 1122334455667788;

    /* (*copyout)(&nonsense, req->oldptr, sizeof(nonsense)); */

    /* asm volatile("mov x19, %0" : : "r" (req)); */
    /* asm volatile("mov x20, %0" : : "r" (req->oldptr)); */
    /* asm volatile("brk 0"); */

    *(long *)req->oldptr = 1122334455667788;
    req->oldlen = sizeof(nonsense);
    req->oldidx = 8;
    return 0;
}

static kern_return_t (*host_kernel_version_orig)(void *, char *);

static kern_return_t _host_kernel_version(void *host, char *host_version){
    *host_version = 'H';
    host_version[1] = 'o';
    host_version[2] = 'o';
    host_version[3] = 'k';
    host_version[4] = 'e';
    host_version[5] = 'd';
    host_version[6] = '\0';

    return KERN_SUCCESS;
}

int main(int argc, char **argv){
    /* before we begin, figure out what system call was patched */
    size_t oldlen = sizeof(long);
    int ret = sysctlbyname("kern.xnuspy_ctl_callnum", &SYS_xnuspy_ctl,
            &oldlen, NULL, 0);

    if(ret == -1){
        printf("sysctlbyname with kern.xnuspy_ctl_callnum failed: %s\n",
                strerror(errno));
        return 1;
    }

    g_num_pointer = malloc(sizeof(uint32_t));
    *g_num_pointer = 0x41424344;

    /* first, was xnuspy_ctl patched correctly? For all my phones, the patched
     * system call is always number 8. It could be different for you.
     */
    ret = syscall(SYS_xnuspy_ctl, XNUSPY_CHECK_IF_PATCHED, 20, 30, 40);

    if(ret != 999){
        printf("xnuspy_ctl wasn't patched correctly\n");
        return 1;
    }

    printf("xnuspy_ctl was patched correctly\n");

    ret = syscall(SYS_xnuspy_ctl, XNUSPY_GET_FUNCTION, KPROTECT, &kprotect, 0);
    printf("got kprotect @ %#llx\n", kprotect);
    ret = syscall(SYS_xnuspy_ctl, XNUSPY_GET_FUNCTION, COPYOUT, &copyout, 0);
    printf("got copyout @ %#llx\n", copyout);
    /* printf("%llx\n", *kprotect); */

    /* ret = syscall(SYS_xnuspy_ctl, XNUSPY_INSTALL_HOOK, g_num_pointer, 0, 0); */

    /* try and hook kalloc_canblock */
    /* iphone 8 13.6.1 */
    /* uint64_t kalloc_canblock = 0xFFFFFFF007C031E4; */
    /* void *(*kalloc_canblock_orig)(size_t *, void *, bool) = NULL; */
    /* ret = syscall(SYS_xnuspy_ctl, XNUSPY_INSTALL_HOOK, kalloc_canblock, code, */
    /*         &kalloc_canblock_orig); */

    /* printf("kalloc_canblock_orig = %#llx\n", kalloc_canblock_orig); */

    /* uint64_t some_fxn_with_cbz_as_first = 0xFFFFFFF007E5FFCC; */
    /* void (*dummy)(void) = NULL; */
    /* ret = syscall(SYS_xnuspy_ctl, XNUSPY_INSTALL_HOOK, some_fxn_with_cbz_as_first, code, */
    /*         &dummy); */

    /* try and hook sysctl_handle_long */
    /* iphone 8 13.6.1 */
    /* for(;;){ */
    /* uint64_t sysctl_handle_long = 0xfffffff00800d508; */
    ret = syscall(SYS_xnuspy_ctl, XNUSPY_INSTALL_HOOK, 0xfffffff00800d508,
            sysctl_handle_long, &sysctl_handle_long_orig);

    printf("sysctl_handle_long_orig = %#llx\n", sysctl_handle_long_orig);
    /* ret = sysctlbyname("kern.xnuspy_ctl_callnum", &SYS_xnuspy_ctl, */
    /*         &oldlen, NULL, 0); */
    /* printf("ret %d\n", ret); */
    /* sleep(5); */
    /* } */

    /* char vers[0x200]; */
    /* kern_return_t kret = host_kernel_version(mach_host_self(), vers); */

    /* if(kret) */
    /*     printf("%s\n", mach_error_string(kret)); */
    /* else */
    /*     puts(vers); */

    /* ret = syscall(SYS_xnuspy_ctl, XNUSPY_INSTALL_HOOK, 0xFFFFFFF007BF9D88, */
    /*         _host_kernel_version, &host_kernel_version_orig); */

    /* printf("host_kernel_version_orig = %#llx\n", host_kernel_version_orig); */

    printf("Hit enter to quit\n");
    getchar();

    return 0;
}
