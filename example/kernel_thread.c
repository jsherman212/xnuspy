#include <errno.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "xnuspy_ctl.h"

__attribute__ ((naked)) static void *current_thread(void){
    asm(""
        "mrs x0, tpidr_el1\n"
        "ret\n"
       );
}

typedef	void (*thread_continue_t)(void *param, int wait_result);

static int (*copyin)(const void *uaddr, void *kaddr, size_t len);
static int (*copyinstr)(const void *uaddr, void *kaddr, size_t len, size_t *done);
static int (*copyout)(const void *kaddr, void *uaddr, size_t len);
static void *(*current_proc)(void);
static void (*IOSleep)(unsigned int millis);
static kern_return_t (*kernel_thread_start)(thread_continue_t cont, void *param,
        void **thread);
static void (*kprintf)(const char *fmt, ...);
static pid_t (*proc_pid)(void *proc);
static void (*thread_deallocate)(void *thread);
static void (*_thread_terminate)(void *thread);
static void *(*unified_kalloc)(size_t sz);
static void (*unified_kfree)(void *ptr);

static uint64_t kernel_slide;
static uint64_t hookme_addr;

static int time_to_die = 0;

static void kernel_thread_fxn(void *param, int wait_result){
    while(!time_to_die){
        kprintf("%s: alive, but at what cost?\n", __func__);
        IOSleep(1000);
    }

    kprintf("%s: goodbye\n", __func__);

    void *thread = current_thread();
    uint32_t refcnt = *(uint32_t *)((uintptr_t)thread + 0xcc);

    kprintf("%s: this thread's refcnt is %d\n", __func__, refcnt);

    /* iphone 8 13.6.1, patchfind for this TODO */
    /* void (*thread_terminate)(void *thread) = */
    /*     (void (*)(void *))(0xfffffff007c3525c + kernel_slide); */

    _thread_terminate(thread);

    kprintf("%s: we are still alive??\n", __func__);
}

/* This is called by xnuspy when every kernel hook for this process has
 * been uninstalled. Do any cleanup you need to do in this function.
 * This function is not called asynchronously, so if you do something that
 * blocks you're preventing xnuspy's garbage collection thread from
 * executing. */
static void death_callback(void){
    kprintf("%s: called\n", __func__);
    time_to_die = 1;
}

static void hookme_hook(void){
    static int kernel_thread_made = 0;

    kprintf("%s: we were called!\n", __func__);

    if(!kernel_thread_made){
        void *thread;
        kern_return_t kret = kernel_thread_start(kernel_thread_fxn, NULL,
                &thread);

        if(kret)
            kprintf("%s: could not make kernel thread: %#x\n", __func__, kret);
        else{
            /* Throw away the reference from kernel_thread_start */
            thread_deallocate(thread);
            kernel_thread_made = 1;
            kprintf("%s: created kernel thread\n", __func__);
        }
    }
}

static long SYS_xnuspy_ctl = 0;

static int gather_kernel_offsets(void){
    int ret;

    ret = syscall(SYS_xnuspy_ctl, XNUSPY_CACHE_READ, COPYIN, &copyin, 0);

    if(ret){
        printf("Failed getting copyin\n");
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

    ret = syscall(SYS_xnuspy_ctl, XNUSPY_CACHE_READ, IOSLEEP, &IOSleep, 0);

    if(ret){
        printf("Failed getting IOSleep\n");
        return ret;
    }

    ret = syscall(SYS_xnuspy_ctl, XNUSPY_CACHE_READ, KERNEL_THREAD_START,
            &kernel_thread_start, 0);

    if(ret){
        printf("Failed getting kernel_thread_start\n");
        return ret;
    }

    ret = syscall(SYS_xnuspy_ctl, XNUSPY_CACHE_READ, THREAD_DEALLOCATE,
            &thread_deallocate, 0);

    if(ret){
        printf("Failed getting thread_deallocate\n");
        return ret;
    }

    ret = syscall(SYS_xnuspy_ctl, XNUSPY_CACHE_READ, THREAD_TERMINATE,
            &_thread_terminate, 0);

    if(ret){
        printf("Failed getting thread_terminate\n");
        return ret;
    }

    ret = syscall(SYS_xnuspy_ctl, XNUSPY_CACHE_READ, KPRINTF, &kprintf, 0);

    if(ret){
        printf("Failed getting kprintf\n");
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

    ret = syscall(SYS_xnuspy_ctl, XNUSPY_CACHE_READ, HOOKME, &hookme_addr, 0);

    if(ret){
        printf("Failed getting hookme\n");
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
    printf("copyout @ %#llx\n", (uint64_t)copyout);
    printf("current_proc @ %#llx\n", (uint64_t)current_proc);
    printf("kprintf @ %#llx\n", (uint64_t)kprintf);
    printf("proc_pid @ %#llx\n", (uint64_t)proc_pid);
    printf("IOSleep @ %#llx\n", (uint64_t)IOSleep);
    printf("kernel_thread_start @ %#llx\n", (uint64_t)kernel_thread_start);
    printf("thread_deallocate @ %#llx\n", (uint64_t)thread_deallocate);
    printf("unified_kalloc @ %#llx\n", (uint64_t)unified_kalloc);
    printf("unified_kfree @ %#llx\n", (uint64_t)unified_kfree);
    printf("hookme @ %#llx\n", (uint64_t)hookme_addr);

    /* xnuspy does not operate on slid addresses */
    hookme_addr -= kernel_slide;

    ret = syscall(SYS_xnuspy_ctl, XNUSPY_INSTALL_HOOK, hookme_addr,
            hookme_hook, NULL);

    if(ret){
        printf("Could not hook hookme: %s\n", strerror(errno));
        return 1;
    }

    ret = syscall(SYS_xnuspy_ctl, XNUSPY_REGISTER_DEATH_CALLBACK,
            death_callback, 0, 0);

    if(ret){
        printf("Could not register death callback: %s\n", strerror(errno));
        return 1;
    }

    syscall(SYS_xnuspy_ctl, XNUSPY_CALL_HOOKME, 0, 0, 0);

    printf("Ctrl C or enter to quit\n");
    getchar();

    return 0;
}
