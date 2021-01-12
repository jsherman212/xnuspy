#include <errno.h>
#include <mach/mach.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "xnuspy_ctl.h"

static int (*copyin)(const void *uaddr, void *kaddr, size_t len);
static int (*copyinstr)(const void *uaddr, void *kaddr, size_t len, size_t *done);
static int (*copyout)(const void *kaddr, void *uaddr, size_t len);
static void *(*current_proc)(void);
static void (*kprintf)(const char *, ...);
static void (*kwrite_instr)(uint64_t, uint32_t);
static pid_t (*proc_pid)(void *);
static void *(*unified_kalloc)(size_t sz);
static void (*unified_kfree)(void *ptr);

static uint64_t kernel_slide;

static uint8_t curcpu(void){
    uint64_t mpidr_el1;
    asm volatile("mrs %0, mpidr_el1" : "=r" (mpidr_el1));
    return (uint8_t)(mpidr_el1 & 0xff);
}

static pid_t caller_pid(void){
    return proc_pid(current_proc());
}

/* bsd/sys/uio.h */
enum uio_seg {
    UIO_USERSPACE       = 0,    /* kernel address is virtual,  to/from user virtual */
    UIO_SYSSPACE        = 2,    /* kernel address is virtual,  to/from system virtual */
    UIO_USERSPACE32     = 5,    /* kernel address is virtual,  to/from user 32-bit virtual */
    UIO_USERSPACE64     = 8,    /* kernel address is virtual,  to/from user 64-bit virtual */
    UIO_SYSSPACE32      = 11    /* deprecated */
};

#define UIO_SEG_IS_USER_SPACE( a_uio_seg )  \
    ( (a_uio_seg) == UIO_USERSPACE64 || (a_uio_seg) == UIO_USERSPACE32 || \
      (a_uio_seg) == UIO_USERSPACE )

/* bsd/sys/namei.h */
#define PATHBUFLEN 256

struct nameidata {
    char * /* __user */ ni_dirp;
    enum uio_seg ni_segflag;
    /* ... */
};

static int strcmp_(const char *s1, const char *s2){
    while(*s1 && (*s1 == *s2)){
        s1++;
        s2++;
    }

    return *(const unsigned char *)s1 - *(const unsigned char *)s2;
}

static int (*open1_orig)(void *vfsctx, struct nameidata *ndp, int uflags,
        void *vap, void *fp_zalloc, void *cra, int32_t *retval);

static int open1(void *vfsctx, struct nameidata *ndp, int uflags,
        void *vap, void *fp_zalloc, void *cra, int32_t *retval){
    if(!(ndp->ni_dirp && UIO_SEG_IS_USER_SPACE(ndp->ni_segflag)))
        goto orig;

    size_t sz = PATHBUFLEN;
    char *path = unified_kalloc(sz);

    if(!path)
        goto orig;

    size_t pathlen = 0;
    int res = copyinstr(ndp->ni_dirp, path, sz, &pathlen);

    if(res){
        unified_kfree(path);
        goto orig;
    }

    path[pathlen - 1] = '\0';

    uint8_t cpu = curcpu();
    pid_t caller = caller_pid();

    kprintf("%s: (CPU %d): process %d wants to open '%s'\n", __func__, cpu,
            caller, path);

    if(strcmp_(path, "/var/mobile/testfile.txt") == 0){
        kprintf("%s: denying open for '%s'\n", __func__, path);
        unified_kfree(path);
        *retval = -1;
        return ENOENT;
    }

    unified_kfree(path);

orig:
    return open1_orig(vfsctx, ndp, uflags, vap, fp_zalloc, cra, retval);
}

static long SYS_xnuspy_ctl = 0;

static int gather_kernel_offsets(void){
    int ret;

    ret = syscall(SYS_xnuspy_ctl, XNUSPY_CACHE_READ, COPYIN, &copyin, 0);

    if(ret){
        printf("Failed getting copyin\n");
        return ret;
    }

    ret = syscall(SYS_xnuspy_ctl, XNUSPY_CACHE_READ, COPYINSTR, &copyinstr, 0);

    if(ret){
        printf("Failed getting copyinstr\n");
        return ret;
    }

    ret = syscall(SYS_xnuspy_ctl, XNUSPY_CACHE_READ, COPYOUT, &copyout, 0);

    if(ret){
        printf("Failed getting copyout\n");
        return ret;
    }

    ret = syscall(SYS_xnuspy_ctl, XNUSPY_CACHE_READ, CURRENT_PROC,
            &current_proc, 0);

    if(ret){
        printf("Failed getting current_proc\n");
        return ret;
    }

    ret = syscall(SYS_xnuspy_ctl, XNUSPY_CACHE_READ, KPRINTF, &kprintf, 0);

    if(ret){
        printf("Failed getting kprintf\n");
        return ret;
    }

    ret = syscall(SYS_xnuspy_ctl, XNUSPY_CACHE_READ, KWRITE_INSTR,
            &kwrite_instr, 0);

    if(ret){
        printf("Failed getting kwrite_instr\n");
        return ret;
    }

    ret = syscall(SYS_xnuspy_ctl, XNUSPY_CACHE_READ, PROC_PID, &proc_pid, 0);

    if(ret){
        printf("Failed getting proc_pid\n");
        return ret;
    }

    ret = syscall(SYS_xnuspy_ctl, XNUSPY_CACHE_READ, KERNEL_SLIDE, &kernel_slide, 0);

    if(ret){
        printf("Failed getting kernel slide\n");
        return ret;
    }

    ret = syscall(SYS_xnuspy_ctl, XNUSPY_CACHE_READ, UNIFIED_KALLOC,
            &unified_kalloc, 0);

    if(ret){
        printf("Failed getting unified_kalloc\n");
        return ret;
    }

    ret = syscall(SYS_xnuspy_ctl, XNUSPY_CACHE_READ, UNIFIED_KFREE,
            &unified_kfree, 0);

    if(ret){
        printf("Failed getting unified_kfree\n");
        return ret;
    }

    return 0;
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

    ret = syscall(SYS_xnuspy_ctl, XNUSPY_CHECK_IF_PATCHED, 0, 0, 0);

    if(ret != 999){
        printf("xnuspy_ctl isn't present?\n");
        return 1;
    }

    ret = gather_kernel_offsets();

    if(ret){
        printf("something failed: %s\n", strerror(errno));
        return 1;
    }

    printf("kernel slide: %#llx\n", kernel_slide);
    printf("copyin @ %#llx\n", (uint64_t)copyin);
    printf("copyinstr @ %#llx\n", (uint64_t)copyinstr);
    printf("copyout @ %#llx\n", (uint64_t)copyout);
    printf("current_proc @ %#llx\n", (uint64_t)current_proc);
    printf("kprintf @ %#llx\n", (uint64_t)kprintf);
    printf("kwrite_instr @ %#llx\n", (uint64_t)kwrite_instr);
    printf("proc_pid @ %#llx\n", (uint64_t)proc_pid);
    printf("unified_kalloc @ %#llx\n", (uint64_t)unified_kalloc);
    printf("unified_kfree @ %#llx\n", (uint64_t)unified_kfree);

    if(ret){
        printf("Couldnt get adrp_test addr: %s\n", strerror(errno));
        return 1;
    }

    /* open1 for iphone 8 13.6.1 */
    /* ret = syscall(SYS_xnuspy_ctl, XNUSPY_INSTALL_HOOK, 0xfffffff007d99c1c, */
    /*         open1, &open1_orig); */
    /* iphone x 13.3.1 */
    /* ret = syscall(SYS_xnuspy_ctl, XNUSPY_INSTALL_HOOK, 0xFFFFFFF007D70534, */
    /*         open1, &open1_orig); */
    /* iphone 7 14.1 */
    /* ret = syscall(SYS_xnuspy_ctl, XNUSPY_INSTALL_HOOK, 0xFFFFFFF00730AA64, */
    /*         open1, &open1_orig); */
    /* iphone se 14.3 */
    ret = syscall(SYS_xnuspy_ctl, XNUSPY_INSTALL_HOOK, 0xFFFFFFF0072DA190,
            open1, &open1_orig);

    if(ret){
        printf("Could not hook open1: %s\n", strerror(errno));
        return 1;
    }

    for(;;){
        int fd = open("/var/mobile/testfile.txt", O_CREAT);

        if(fd == -1)
            printf("open failed: %s\n", strerror(errno));
        else{
            printf("Got valid fd? %d\n", fd);
            close(fd);
        }

        sleep(1);
    }

    return 0;
}
