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
    uint64_t sysctl_handle_long = 0xfffffff00800d508;
    uint64_t (*sysctl_handle_long_orig)(void) = NULL;
    ret = syscall(SYS_xnuspy_ctl, XNUSPY_INSTALL_HOOK, sysctl_handle_long, code,
            &sysctl_handle_long_orig);

    printf("sysctl_handle_long_orig = %#llx\n", sysctl_handle_long_orig);
    /* ret = sysctlbyname("kern.xnuspy_ctl_callnum", &SYS_xnuspy_ctl, */
    /*         &oldlen, NULL, 0); */
    /* printf("ret %d\n", ret); */
    /* sleep(5); */
    /* } */

    printf("Hit enter to quit\n");
    getchar();

    return 0;
}
