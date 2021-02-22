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

#define SPYDBG(fmt, args...) do { kprintf("[HOOK] "fmt, ##args); } while(0)


__attribute__ ((naked)) static void *current_thread(void){
    asm(""
        "mrs x0, tpidr_el1\n"
        "ret\n"
       );
}

static uint8_t curcpu(void){
    uint64_t mpidr_el1;
    asm volatile("mrs %0, mpidr_el1" : "=r" (mpidr_el1));
    return (uint8_t)(mpidr_el1 & 0xff);
}

typedef	void (*thread_continue_t)(void *param, int wait_result);

static void (*IOSleep)(unsigned int millis);
static kern_return_t (*kernel_thread_start)(thread_continue_t cont, void *param,
        void **thread);
static void (*kprintf)(const char *fmt, ...);
static void (*thread_deallocate)(void *thread);
static void (*_thread_terminate)(void *thread);

static uint64_t kernel_slide, hookme_addr;
static uint64_t gSocPhys = 0;

static uint64_t (*ml_io_map)(uint64_t phys_addr, uint64_t size);

static void kdump(void *ptr, size_t size){
    char ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    int putloc = 0;
    uint64_t curaddr = (uint64_t)ptr;
    for (i = 0; i < size; ++i) {
        if(!putloc){
            SPYDBG("%#llx: ", curaddr);
            curaddr += 0x10;
            putloc = 1;
        }

        kprintf("%02X ", ((unsigned char*)ptr)[i]);
        if (((unsigned char*)ptr)[i] >= ' ' && ((unsigned char*)ptr)[i] <= '~') {
            ascii[i % 16] = ((unsigned char*)ptr)[i];
        } else {
            ascii[i % 16] = '.';
        }
        if ((i+1) % 8 == 0 || i+1 == size) {
            kprintf(" ");
            if ((i+1) % 16 == 0) {
                kprintf("|  %s \n", ascii);
                putloc = 0;
            } else if (i+1 == size) {
                ascii[(i+1) % 16] = '\0';
                if ((i+1) % 16 <= 8) {
                    kprintf(" ");
                }
                for (j = (i+1) % 16; j < 16; ++j) {
                    kprintf("   ");
                }
                kprintf("|  %s \n", ascii);
                putloc = 0;
            }
        }
    }
}

static int time_to_die = 0;

static void kernel_thread_fxn(void *param, int wait_result){
    if(!gSocPhys){
        gSocPhys = *(uint64_t *)(0xFFFFFFF00925D458 + kernel_slide);
    }

    SPYDBG("%s: gSocPhys %p\n", __func__, gSocPhys);

    uint64_t ct = (uint64_t)current_thread();
    uint64_t cpuDatap = *(uint64_t *)(ct + 0x478);

    SPYDBG("%s: cpudatap %p\n", __func__, cpuDatap);

    if(cpuDatap){
        uint64_t cpu_debug_interface_map = *(uint64_t *)(cpuDatap + 0x1a8);

        SPYDBG("%s: debug interface map %p\n", __func__,
                cpu_debug_interface_map);
    }

    /* iphone 8 13.6.1 */
    uint64_t light_em_up = ml_io_map(0x208040000, 0x10000);
    SPYDBG("%s: light em up mapped @ %p\n", __func__, light_em_up);

    if(light_em_up){
        kdump((void *)light_em_up, 0x1000);
    }
    uint64_t addr = 0xfffffff007004000 + kernel_slide;
    uint64_t bcr = 0x1e7;
    /* Should not fire as long as the control reg's E bit isn't set */
    asm volatile("msr dbgbcr0_el1, xzr");
    /* asm volatile("msr dbgbcr0_el1, %0" : : "r" (bcr)); */
    asm volatile("msr dbgbvr0_el1, %0" : : "r" (addr));

    while(!time_to_die){
        SPYDBG("%s: alive, but at what cost? CPU %d\n", __func__,
                (uint32_t)curcpu());

        uint64_t dbgbcr0, dbgbvr0;
        asm volatile("mrs %0, dbgbcr0_el1" : "=r" (dbgbcr0));
        asm volatile("mrs %0, dbgbvr0_el1" : "=r" (dbgbvr0));

        SPYDBG("%s: This CPU's dbgbcr0 %p dbgbvr0 %p\n", __func__,
                dbgbcr0, dbgbvr0);

nap:
        IOSleep(1000);
    }

    SPYDBG("%s: goodbye\n", __func__);
    _thread_terminate(current_thread());
    SPYDBG("%s: we are still alive?\n", __func__);
}

static void death_callback(void){
    SPYDBG("%s: called\n", __func__);
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
    SPYDBG("%s: we were called!\n", __func__);

    /* uint64_t PMCR2_val, PMCR3_val, PMCR4_val; */
    /* asm volatile("mrs %0, "PMCR2"" : "=r" (PMCR2_val)); */
    /* asm volatile("mrs %0, "PMCR3"" : "=r" (PMCR3_val)); */
    /* asm volatile("mrs %0, "PMCR4"" : "=r" (PMCR4_val)); */

    /* SPYDBG("%s: PMCR2 %p PMCR3 %p PMCR4 %p\n", __func__, PMCR2_val, */
    /*         PMCR3_val, PMCR4_val); */

    if(kernel_thread_made)
        return;

    void *thread;
    kern_return_t kret = kernel_thread_start(kernel_thread_fxn, NULL, &thread);

    if(kret)
        SPYDBG("%s: could not make kernel thread: %#x\n", __func__, kret);
    else{
        /* Throw away the reference from kernel_thread_start */
        thread_deallocate(thread);
        kernel_thread_made = 1;
        SPYDBG("%s: created kernel thread\n", __func__);
    }
}

static long SYS_xnuspy_ctl = 0;

static int gather_kernel_offsets(void){
    int ret;
#define GET(a, b) \
    do { \
        ret = syscall(SYS_xnuspy_ctl, XNUSPY_CACHE_READ, a, b, 0); \
        if(ret){ \
            printf("%s: failed getting %s\n", __func__, #a); \
            return ret; \
        } \
    } while (0)

    GET(IOSLEEP, &IOSleep);
    GET(KERNEL_THREAD_START, &kernel_thread_start);
    GET(THREAD_DEALLOCATE, &thread_deallocate);
    GET(THREAD_TERMINATE, &_thread_terminate);
    GET(KPRINTF, &kprintf);
    GET(KERNEL_SLIDE, &kernel_slide);
    GET(HOOKME, &hookme_addr);

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

    /* iphone 8 13.6.1 */
    ml_io_map = (uint64_t (*)(uint64_t, uint64_t))(0xFFFFFFF007D0E5C8 + kernel_slide);

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
