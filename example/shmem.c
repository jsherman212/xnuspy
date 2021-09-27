#include <errno.h>
#include <mach/mach.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <xnuspy/xnuspy_ctl.h>

static kuslck_t g_kuslck = KUSLCK_INITIALIZER;

static bool g_dead = false;
static bool g_go = false;
static bool g_made = false;
static bool g_kernel_racer_finished = false;

static uint64_t *g_kernel_valp = NULL;
static struct xnuspy_shmem g_kernel_valp_shmem;

__attribute__ ((naked)) static void *current_thread(void){
    asm(""
        "mrs x0, tpidr_el1\n"
        "ret\n"
       );
}

static uint64_t kernel_slide, hookme_addr;
static long SYS_xnuspy_ctl = 0;
static void *kernel_map;

typedef	void (*thread_continue_t)(void *param, int wait_result);

static void (*IOSleep)(unsigned int millis);
static kern_return_t (*kernel_thread_start)(thread_continue_t cont, void *param,
        void **thread);
static void (*kprintf)(const char *fmt, ...);
static void (*thread_deallocate)(void *thread);
static void (*_thread_terminate)(void *thread);

static int (*mkshmem_ktou)(uint64_t kaddr, uint64_t sz, vm_prot_t prot,
        struct xnuspy_shmem *shmemp);
static int (*mkshmem_utok)(uint64_t uaddr, uint64_t sz, vm_prot_t prot,
        struct xnuspy_shmem *shmemp);
static int (*mkshmem_raw)(uint64_t addr, uint64_t sz, vm_prot_t prot,
        void *from, void *to, struct xnuspy_shmem *shmemp);
static int (*shmem_destroy)(struct xnuspy_shmem *);

static kern_return_t (*vm_allocate_external)(void *map, uint64_t *address,
        uint64_t size, int flags);

static void kernel_racer(void *param, int wait_result){
    while(!g_go){
        if(g_dead)
            break;
    }

    for(int i=0; i<500; i++){
        kuslck_lock(g_kuslck);
        (*g_kernel_valp)++;
        kuslck_unlock(g_kuslck);
    }

    g_kernel_racer_finished = true;

    _thread_terminate(current_thread());
}

static void death_callback(void){
    kprintf("%s: called\n", __func__);
    shmem_destroy(&g_kernel_valp_shmem);
    g_dead = true;
}

static void hookme_hook(void *arg){
    if(g_made)
        return;

    void *thread;
    kern_return_t kret = kernel_thread_start(kernel_racer, NULL, &thread);

    if(kret){
        kprintf("%s: kernel_thread_start returned %#x\n", __func__, kret);
        return;
    }

    thread_deallocate(thread);

    kret = vm_allocate_external(kernel_map, (uint64_t *)&g_kernel_valp,
            0x4000, VM_FLAGS_ANYWHERE);

    if(kret){
        kprintf("%s: mach_vm_allocate_external: %#x\n", __func__, kret);
        return;
    }

    int res = mkshmem_ktou((uint64_t)g_kernel_valp, 0x4000, VM_PROT_READ |
            VM_PROT_WRITE, &g_kernel_valp_shmem);

    if(res){
        kprintf("%s: mkshmem_ktou failed: %d\n", __func__, res);
        return;
    }

    kprintf("%s: returned shmem: %p\n", __func__,
            g_kernel_valp_shmem.shm_base);

    g_made = true;
}

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

    GET(KERNEL_THREAD_START, &kernel_thread_start);
    GET(KPRINTF, &kprintf);
    GET(THREAD_DEALLOCATE, &thread_deallocate);
    GET(THREAD_TERMINATE, &_thread_terminate);
    GET(KERNEL_SLIDE, &kernel_slide);
    GET(HOOKME, &hookme_addr);
    GET(MKSHMEM_KTOU, &mkshmem_ktou);
    GET(MKSHMEM_UTOK, &mkshmem_utok);
    GET(MKSHMEM_RAW, &mkshmem_raw);
    GET(SHMEM_DESTROY, &shmem_destroy);
    GET(KERNEL_MAP, &kernel_map);
    GET(VM_ALLOCATE_EXTERNAL, &vm_allocate_external);

    hookme_addr -= kernel_slide;

    return 0;
}

static void *userspace_racer(void *arg){
    while(!g_go){}

    uint64_t *user_valp = g_kernel_valp_shmem.shm_base;

    for(int i=0; i<500; i++){
        kuslck_lock(g_kuslck);
        (*user_valp)++;
        kuslck_unlock(g_kuslck);
    }

    return NULL;
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

    sleep(1);

    pthread_t pt;
    pthread_create(&pt, NULL, userspace_racer, NULL);

    g_go = true;

    while(!g_kernel_racer_finished){}

    sleep(2);

    uint64_t result = *(uint64_t *)g_kernel_valp_shmem.shm_base;

    if(result != 1000)
        printf("Got unexpected result %lld\n", result);
    else
        printf("Correct result! %lld\n", result);

    return 0;
}
