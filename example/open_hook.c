#include <errno.h>
#include <limits.h>
#include <mach/mach.h>
#include <mach-o/loader.h>
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
static void (*kprintf)(const char *, ...);
static void (*IOSleep)(unsigned int mills);

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
/* static int sysctl_handle_long(void){ */
    /* (*kprotect)((uint64_t)arg1, 0x4000, VM_PROT_READ | VM_PROT_WRITE); */
    /* *(long *)arg1 = 0x123456789abcdef; */

    /* long nonsense = 1122334455667788; */

    /* (*copyout)(&nonsense, req->oldptr, sizeof(nonsense)); */

    /* asm volatile("mov x19, %0" : : "r" (req)); */
    /* asm volatile("mov x20, %0" : : "r" (req->oldptr)); */
    /* asm volatile("brk 0"); */

    /* *(long *)req->oldptr = 1122334455667788; */
    /* req->oldlen = sizeof(nonsense); */
    /* req->oldidx = 8; */
    // XXX XXX XXX XXX XXX
    /* return ENOENT; */
    /* return 0; */

    uint64_t tpidr_el1;
    asm volatile("mrs %0, tpidr_el1" : "=r" (tpidr_el1));

    void *cpudata = *(void **)(tpidr_el1 + 0x478);
    uint16_t curcpu = *(uint16_t *)cpudata;

    /* asm volatile("mrs x3, ttbr0_el1"); */
    /* asm volatile("mov x4, 0x4141"); */
    /* int val = *g_num_pointer; */
    /* asm volatile("mov x5, %0" : "=r" (val)); */
    /* asm volatile("ldr x0, [x5]"); */

    /* static void (*kprintf2)(const char *, ...) = */
    /*     (void (*)(const char *, ...))(0xFFFFFFF0081D28E0 + 0xd2b4000); */

    /* asm volatile("mov x4, 0x4141"); */
    /* asm volatile("mov x5, %0" : : "r" (curcpu)); */
    /* asm volatile("mov x6, 0x7777"); */

    /* kprintf2("%s: alive and on CPU %d\n", __func__, curcpu); */

    /* return ENOENT; */

    kprintf("%s: *****We are on CPU %d, calling orig function...\n", __func__,
            curcpu);

    /* int i = 0; */
    /* for(;;){ */
    /*     uint64_t dbgbvr2_el1; */
    /*     /1* uint64_t revidr_el1; *1/ */
    /*     asm volatile("mrs %0, dbgbvr2_el1" : "=r" (dbgbvr2_el1)); */
    /*     /1* asm volatile("mrs %0, tpidr_el0" : "=r" (tpidr_el0)); *1/ */
    /*     kprintf("%s(%d): *****dbgbvr2_el1 = %#llx tpidr_el0 = %#llx\n", */
    /*             __func__, i, dbgbvr2_el1, tpidr_el0); */

    /*     IOSleep(1000); */
    /*     i++; */
    /* } */

    /* return 0; */
    /* return (int)curcpu; */

    return sysctl_handle_long_orig(oidp, arg1, arg2, req);
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

static void *(*kalloc_canblock_orig)(size_t *sizep, int canblock, void *site);

static void *kalloc_canblock(size_t *sizep, int canblock, void *site){
    return kalloc_canblock_orig(sizep, canblock, site);
}

static void DumpMemory(void *startaddr, void *data, size_t size){
    char ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    int putloc = 0;
    uint64_t curaddr = startaddr;
    for (i = 0; i < size; ++i) {
        if(!putloc){
            if(startaddr != (uint64_t)-1){
                printf("%#llx: ", curaddr);
                curaddr += 0x10;
            }

            putloc = 1;
        }

        printf("%02X ", ((unsigned char*)data)[i]);
        if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
            ascii[i % 16] = ((unsigned char*)data)[i];
        } else {
            ascii[i % 16] = '.';
        }
        if ((i+1) % 8 == 0 || i+1 == size) {
            printf(" ");
            if ((i+1) % 16 == 0) {
                printf("|  %s \n", ascii);
                putloc = 0;
            } else if (i+1 == size) {
                ascii[(i+1) % 16] = '\0';
                if ((i+1) % 16 <= 8) {
                    printf(" ");
                }
                for (j = (i+1) % 16; j < 16; ++j) {
                    printf("   ");
                }
                printf("|  %s \n", ascii);
                putloc = 0;
            }
        }
    }
}

static int KernelRead(vm_address_t kaddr, void *buffer, vm_size_t length){
    vm_address_t current_loc = kaddr;
    vm_address_t end = kaddr + length;

    vm_size_t bytes_read = 0;
    vm_size_t bytes_left = length;

    int ret = 0;

    while(current_loc < end){
        vm_size_t chunk = 0x100;

        if(chunk > bytes_left)
            chunk = bytes_left;

        /* kret = vm_read_overwrite(tfp0, current_loc, chunk, */
        /*         (vm_address_t)((uint8_t *)buffer + bytes_read), &chunk); */


        ret = syscall(SYS_xnuspy_ctl, XNUSPY_KREAD, current_loc,
                (uint8_t *)buffer + bytes_read, chunk);

        if(ret)
            return ret;

        bytes_read += chunk;
        current_loc += chunk;
        bytes_left -= chunk;
    }

    return 0;
}

static void DumpKernelMemory(vm_address_t kaddr, size_t size){
    uint8_t *data = malloc(size);

    int ret = KernelRead(kaddr, data, size);

    if(ret){
        printf("%s: KernelRead failed: %s\n", __func__, strerror(errno));
        return;
    }

    DumpMemory(kaddr, data, size);

    free(data);
}

struct ipc_space {
    struct {
        uint64_t data;
        uint32_t type;
        uint32_t pad;
    } is_lock_data;
    uint32_t is_bits;
    uint32_t is_table_size;
    uint32_t is_table_hashed;
    uint32_t is_table_free;
    uint64_t is_table;
    uint64_t is_task;
    uint64_t is_table_next;
    uint32_t is_low_mod;
    uint32_t is_high_mod;

    /* other stuff that isn't needed */
};

struct ipc_entry {
    uint64_t ie_object;
    uint32_t ie_dist : 12;
    uint32_t ie_bits : 20;
    uint32_t ie_index;
    union {
        uint32_t next;
        uint32_t request;
    } index;
};

/* found in ipc_task_init */
static const int TASK_ITK_SPACE_OFFSET = 0x320;

static uint64_t kaddr_of_port(uint64_t task, mach_port_t port){
    uint64_t ipc_space_kaddr = 0;
    int ret = KernelRead(task + TASK_ITK_SPACE_OFFSET, &ipc_space_kaddr,
            sizeof(ipc_space_kaddr));

    if(ret){
        printf("%s: couldnt get kaddr of our ipc_space: %s\n", __func__,
                strerror(ret));
        return -1;
    }

    uint64_t is_table_kaddr = 0;
    ret = KernelRead(ipc_space_kaddr + __builtin_offsetof(struct ipc_space, is_table),
            &is_table_kaddr, sizeof(is_table_kaddr));

    if(ret){
        printf("%s: couldnt get kaddr of our is_table: %s\n", __func__,
                strerror(errno));
        return -1;
    }

    uint32_t idx = (port >> 8) * sizeof(struct ipc_entry);
    uint64_t baseaddr = is_table_kaddr + idx;

    uint64_t kaddr = 0;

    ret = KernelRead(baseaddr, &kaddr, sizeof(kaddr));

    if(ret){
        printf("%s: couldnt read out ie_object ptr: %s\n", __func__,
                strerror(ret));
        return -1;
    }

    return kaddr;
}

#define EL0 0
#define EL1 1
static void sideband_buffer_shmem_tests(void){
    uint64_t current_task = 0;
    syscall(SYS_xnuspy_ctl, XNUSPY_GET_CURRENT_TASK, &current_task, 0, 0, 0);

    printf("%s: current task @ %#llx\n", __func__, current_task);

    mach_port_t p;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &p);

    uint64_t p_kaddr = kaddr_of_port(current_task, p);

    if(p_kaddr != -1)
        DumpKernelMemory(p_kaddr, 0x100);

    /* syscall(SYS_xnuspy_ctl, XNUSPY_DUMP_TTES, current_task, EL1, 0, 0); */
    /* DumpKernelMemory(current_task, 0x100); */
}

const int a = 42;

static void address_space_tests(void){
    uint64_t current_task = 0;
    syscall(SYS_xnuspy_ctl, XNUSPY_GET_CURRENT_TASK, &current_task, 0, 0, 0);

    printf("%s: current task @ %#llx\n", __func__, current_task);

    if(!current_task)
        return;


}

/* Copy the calling process' __TEXT and __DATA onto a contiguous set
 * of the pages we reserved before booting XNU. Lame, but safe. Swapping
 * out translation table base registers and changing PTE OutputAddress'es
 * was hacky and left me at the mercy of the scheduler.
 *
 * Returns the kernel virtual address of the start of the user's
 * replacement function, or 0 upon failure.
 */
static uint64_t map_user_replacement(struct mach_header_64 *umh,
        uint64_t replacement){
    uint64_t replacement_kva = 0;

    struct load_command *lc = umh + 1;
    /* DumpMemory(lc, lc, 0x500); */

    uint64_t aslr_slide = (uintptr_t)umh - 0x100000000;

    for(int i=0; i<umh->ncmds; i++){
        printf("%s: got cmd %d\n", __func__, lc->cmd);

        if(lc->cmd != LC_SEGMENT_64)
            goto next;

        struct segment_command_64 *sc64 = (struct segment_command_64 *)lc;

        if(strcmp(sc64->segname, "__TEXT") == 0){
            printf("%s: __TEXT segment start %#llx end %#llx\n", __func__,
                    sc64->vmaddr + aslr_slide,
                    sc64->vmaddr + sc64->vmsize + aslr_slide);


        }
        if(strcmp(sc64->segname, "__DATA") == 0){
            printf("%s: __DATA segment start %#llx end %#llx\n", __func__,
                    sc64->vmaddr + aslr_slide,
                    sc64->vmaddr + sc64->vmsize + aslr_slide);
        }

next:
        lc = (struct load_command *)((uintptr_t)lc + lc->cmdsize);
    }

    return replacement_kva;
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
    printf("pid == %d\n", getpid());

    /* sideband_buffer_shmem_tests(); */
    /* getchar(); */
    /* return 0; */

    ret = syscall(SYS_xnuspy_ctl, XNUSPY_GET_FUNCTION, KPROTECT, &kprotect, 0);
    printf("got kprotect @ %#llx\n", kprotect);
    ret = syscall(SYS_xnuspy_ctl, XNUSPY_GET_FUNCTION, COPYOUT, &copyout, 0);
    printf("got copyout @ %#llx\n", copyout);
    ret = syscall(SYS_xnuspy_ctl, XNUSPY_GET_FUNCTION, KPRINTF, &kprintf, 0);
    printf("got kprintf @ %#llx\n", kprintf);
    ret = syscall(SYS_xnuspy_ctl, XNUSPY_GET_FUNCTION, IOSLEEP, &IOSleep, 0);
    printf("got IOSleep @ %#llx\n", IOSleep);
    /* printf("%llx\n", *kprotect); */

    /* ret = syscall(SYS_xnuspy_ctl, XNUSPY_INSTALL_HOOK, g_num_pointer, 0, 0); */

    /* try and hook kalloc_canblock */
    /* iphone 8 13.6.1 */
    /* uint64_t kalloc_canblock = 0xFFFFFFF007C031E4; */
    /* void *(*kalloc_canblock_orig)(size_t *, void *, bool) = NULL; */
    ret = syscall(SYS_xnuspy_ctl, XNUSPY_INSTALL_HOOK, 0xFFFFFFF007C031E4,
            kalloc_canblock, &kalloc_canblock_orig);

    printf("kalloc_canblock_orig = %#llx\n", kalloc_canblock_orig);

    /* uint64_t some_fxn_with_cbz_as_first = 0xFFFFFFF007E5FFCC; */
    /* void (*dummy)(void) = NULL; */
    /* ret = syscall(SYS_xnuspy_ctl, XNUSPY_INSTALL_HOOK, some_fxn_with_cbz_as_first, code, */
    /*         &dummy); */

    /* try and hook sysctl_handle_long */
    /* iphone 8 13.6.1 */
    /* for(;;){ */
    extern struct mach_header_64 *_mh_execute_header;
    printf("%#llx\n", &_mh_execute_header);
    /* map_user_replacement(&_mh_execute_header, (uint64_t)sysctl_handle_long); */

    /* uint64_t sysctl_handle_long = 0xfffffff00800d508; */
    /* ret = syscall(SYS_xnuspy_ctl, XNUSPY_INSTALL_HOOK, 0xfffffff00800d508, */
    /*         sysctl_handle_long, &sysctl_handle_long_orig); */

    /* printf("sysctl_handle_long_orig = %#llx\n", sysctl_handle_long_orig); */

    /* if(ret){ */
    /*     printf("%s\n", strerror(errno)); */
    /* } */


    /* address_space_tests(); */
    /* sleep(2); */
    /* printf("%s: %#x\n", __func__, *(uint32_t *)sysctl_handle_long); */

    /* DumpKernelMemory(0xfffffff0ac000440, 0x10); */
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
