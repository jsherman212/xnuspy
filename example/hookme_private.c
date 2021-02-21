#include <errno.h>
#include <fcntl.h>
#include <mach/mach.h>
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

static void (*IOSleep)(unsigned int millis);
static kern_return_t (*kernel_thread_start)(thread_continue_t cont, void *param,
        void **thread);
static void (*kprintf)(const char *fmt, ...);
static void (*thread_deallocate)(void *thread);
static void (*_thread_terminate)(void *thread);

static uint64_t kernel_slide, hookme_addr;

static int time_to_die = 0;

static void kernel_thread_fxn(void *param, int wait_result){
    while(!time_to_die){
        kprintf("%s: alive, but at what cost?\n", __func__);
        IOSleep(1000);
    }

    kprintf("%s: goodbye\n", __func__);

    _thread_terminate(current_thread());

    /* We shouldn't reach here */

    kprintf("%s: we are still alive?\n", __func__);
}

static void death_callback(void){
    kprintf("%s: called\n", __func__);
    time_to_die = 1;
}

static int kernel_thread_made = 0;

/*
 * PMCR2 controls watchpoint registers.
 *
 * PMCR3 controls breakpoints and address matching.
 *
 * PMCR4 controls opcode matching.
 */

#define PMCR2 "s3_1_c15_c2_0"
#define PMCR3 "s3_1_c15_c3_0"
#define PMCR4 "s3_1_c15_c4_0"

#define PMSR "s3_1_c15_c13_0"

static void hookme_hook(void){
    kprintf("%s: we were called!\n", __func__);

    uint64_t PMCR2_val, PMCR3_val, PMCR4_val;
    asm volatile("mrs %0, "PMCR2"" : "=r" (PMCR2_val));
    asm volatile("mrs %0, "PMCR3"" : "=r" (PMCR3_val));
    asm volatile("mrs %0, "PMCR4"" : "=r" (PMCR4_val));

    kprintf("%s: PMCR2 %p PMCR3 %p PMCR4 %p\n", __func__, PMCR2_val,
            PMCR3_val, PMCR4_val);

    /* if(kernel_thread_made) */
    /*     return; */

    /* void *thread; */
    /* kern_return_t kret = kernel_thread_start(kernel_thread_fxn, NULL, &thread); */

    /* if(kret) */
    /*     kprintf("%s: could not make kernel thread: %#x\n", __func__, kret); */
    /* else{ */
    /*     /1* Throw away the reference from kernel_thread_start *1/ */
    /*     thread_deallocate(thread); */
    /*     kernel_thread_made = 1; */
    /*     kprintf("%s: created kernel thread\n", __func__); */
    /* } */
}

static long SYS_xnuspy_ctl = 0;

static int gather_kernel_offsets(void){
    int ret;

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

    ret = syscall(SYS_xnuspy_ctl, XNUSPY_CACHE_READ, KERNEL_SLIDE,
            &kernel_slide, 0);

    if(ret){
        printf("Failed getting kernel slide\n");
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

    ret = syscall(SYS_xnuspy_ctl, XNUSPY_CALL_HOOKME, 0, 0, 0);

    if(ret){
        printf("Calling hookme not supported\n");
        return 1;
    }

    printf("Ctrl C or enter to quit and invoke death callback\n");
    getchar();

    return 0;
}
