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

static uint64_t kernel_slide = 0;

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

    /* uint64_t tpidr_el1; */
    /* asm volatile("mrs %0, tpidr_el1" : "=r" (tpidr_el1)); */

    /* void *cpudata = *(void **)(tpidr_el1 + 0x478); */
    /* uint16_t curcpu = *(uint16_t *)cpudata; */

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

    /* kprintf("%s: *****We are on CPU %d, calling orig function...\n", __func__, */
    /*         curcpu); */

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

    /* uint64_t dbgbcr = 0x1e7; */
    /* uint64_t dbgbcr; */
    /* asm volatile("mov %0, sp" : "=r" (dbgbcr)); */
    /* uint64_t dbgbvr = 0xFFFFFFF0082044A4 + kernel_slide; */

    /* asm volatile("msr dbgbcr0_el1, %0" : : "r" (dbgbcr)); */
    /* /1* asm volatile("msr dbgbcr0_el1, fp"); *1/ */
    /* asm volatile("msr dbgbvr0_el1, %0" : : "r" (dbgbvr)); */

    /* asm volatile("mrs x8, mdscr_el1"); */
    /* asm volatile("orr x8, x8, 0x2000"); */
    /* asm volatile("orr x8, x8, 0x8000"); */
    /* asm volatile("msr mdscr_el1, x8"); */
    /* asm volatile("isb sy"); */


    /* asm volatile("" */
    /*         "mov x0, 0x4141\n" */
    /*         "msr dbgbvr0_el1, x0\n" */
    /*         /1* "mov x18, 0x4242\n" *1/ */
    /*         /1* "msr actlr_el1, x0\n" *1/ */
    /*         "isb\n" */
    /*         "dsb sy\n" */
    /*         "isb\n" */
    /*         ); */

    /* msr DBGAUTHSTATUS_EL1, fp */
    /* asm volatile(".long 0xd5107edd"); */
    /* asm volatile("msr S2_0_c7_c14_6, fp"); */

    /* asm volatile("" */
    /*         "mrs x8, cpacr_el1\n" */
    /*         "mov x9, fp\n" */
    /*         "and x9, x9, 0xffffffff\n" */
    /*         "lsl x9, x9, 31\n" */
    /*         "orr x8, x8, x9\n" */
    /*         "msr cpacr_el1, x8\n" */
    /*         "isb sy\n" */
    /*         ); */
    /* asm volatile("msr DBGAUTHSTATUS_EL1, fp"); */
    /* asm volatile("isb sy"); */

    uint64_t mpidr_el1;
    asm volatile("mrs %0, mpidr_el1" : "=r" (mpidr_el1));
    uint32_t curcpu = (uint32_t)(mpidr_el1 & 0xff);

    /* asm volatile("mov x29, %0" : : "r" (curcpu)); */

    /* asm volatile("" */
    /*         "mov x0, 0x4141\n" */
    /*         "mov x1, 0x4242\n" */
    /*         "mov x2, 0x4343\n" */
    /*         "msr afsr0_el1, x0\n" */
    /*         "msr afsr1_el1, x1\n" */
    /*         "msr amair_el1, x2\n" */
    /*         "msr esr_el1, x2\n" */
    /*         /1* "msr aidr_el1, x2\n" *1/ */
    /*         /1* : : : "memory" *1/ */
    /*         "dsb sy\n" */
    /*         /1* "tlbi vmalle1\n" *1/ */
    /*         "isb sy\n" */
    /*         ); */
    /* uint64_t afsr0_el1, afsr1_el1, amair_el1, aidr_el1, esr_el1; */
    /* asm volatile("mrs %0, afsr0_el1" : "=r" (afsr0_el1) : : "memory"); */
    /* asm volatile("mrs %0, afsr1_el1" : "=r" (afsr1_el1) : : "memory"); */
    /* asm volatile("mrs %0, amair_el1" : "=r" (amair_el1) : : "memory"); */
    /* asm volatile("mrs %0, aidr_el1" : "=r" (aidr_el1) : : "memory"); */
    /* asm volatile("mrs %0, esr_el1" : "=r" (esr_el1) : : "memory"); */
    /* asm volatile("dsb sy"); */
    /* asm volatile("isb sy"); */
    /* kprintf("%s(CPU %d): afsr0_el1 = %#llx, afsr1_el1 = %#llx" */
    /*         " amair_el1 = %#llx, aidr_el1 = %#llx, esr_el1 = %#llx\n", __func__, */
    /*         curcpu, afsr0_el1, afsr1_el1, amair_el1, aidr_el1, esr_el1); */

    /* void *ct; */
    /* asm volatile("mrs %0, tpidr_el1" : "=r" (ct)); */
    /* *(uint64_t *)((uint8_t *)ct + 0x3f8) = __builtin_frame_address(0); */

    /* int i = 0; */
    /* for(int i=0; i<10000; i++){ */
    /* for(;;){ */
        /* uint64_t dbgbcr0_el1, dbgbvr0_el1, dbgauthstatus_el1; */
        /* asm volatile("mrs %0, dbgbcr0_el1" : "=r" (dbgbcr0_el1)); */
        /* asm volatile("mrs %0, dbgbvr0_el1" : "=r" (dbgbvr0_el1)); */
        /* asm volatile("mrs %0, S2_0_c7_c14_6" : "=r" (dbgauthstatus_el1)); */
        /* uint64_t cpacr_el1; */
        /* asm volatile("mrs %0, cpacr_el1" : "=r" (cpacr_el1)); */
        /* asm volatile("isb sy"); */
        /* kprintf("%s(%d, CPU %d): dbgbcr0_el1 = %#llx, dbgbvr0_el1 = %#llx" */
        /*         " dbgauthstatus_el1 = %#llx\n", __func__, i, curcpu, dbgbcr0_el1, */
        /*         dbgbvr0_el1, dbgauthstatus_el1); */
        /* kprintf("%s(%d, CPU %d): cpacr_el1 = %#llx\n", __func__, i, curcpu, cpacr_el1); */


        /* uint64_t fp; */
        /* asm volatile("mov %0, x29" : "=r" (fp)); */

        /* kprintf("%s(%d, CPU %d): fp = %#llx\n", __func__, i, curcpu, fp); */

        /* volatile uint64_t dbgbvr0_el1; */
        /* volatile uint64_t actlr_el1; */
        /* volatile uint64_t x18; */
        /* asm volatile("" */
        /*         "mrs %0, dbgbvr0_el1\n" */
        /*         "mrs %0, actlr_el1\n" */
        /*         "isb sy\n" */
        /*         : "=r" (dbgbvr0_el1), */
        /*         "=r" (actlr_el1), */

        /*         ); */

        /* if(dbgbvr0_el1 == 0) */
        /*     break; */
        /* kprintf("%s(%d): dbgbvr0_el1 = %#llx actlr_el1 = %#llx\n", __func__, i, */
        /*         dbgbvr0_el1, actlr_el1); */

        /* uint64_t x18; */
        /* asm volatile("mov %0, x18" : "=r" (x18)); */
        /* kprintf("%s(%d, CPU %d): x18: %#llx\n", __func__, i, curcpu, x18); */

        /* uint64_t afsr0_el1, afsr1_el1, amair_el1, aidr_el1, esr_el1; */
        /* asm volatile("mrs %0, afsr0_el1" : "=r" (afsr0_el1) : : "memory"); */
        /* asm volatile("mrs %0, afsr1_el1" : "=r" (afsr1_el1) : : "memory"); */
        /* asm volatile("mrs %0, amair_el1" : "=r" (amair_el1) : : "memory"); */
        /* asm volatile("mrs %0, aidr_el1" : "=r" (aidr_el1) : : "memory"); */
        /* asm volatile("mrs %0, esr_el1" : "=r" (esr_el1) : : "memory"); */
        /* asm volatile("dsb sy"); */
        /* asm volatile("isb sy"); */
        /* kprintf("%s(%d, CPU %d): afsr0_el1 = %#llx, afsr1_el1 = %#llx" */
        /*         " amair_el1 = %#llx, aidr_el1 = %#llx, esr_el1 = %#llx\n", __func__, */
        /*         i, curcpu, afsr0_el1, afsr1_el1, amair_el1, aidr_el1, esr_el1); */

        /* void *ct; */
        /* asm volatile("mrs %0, tpidr_el1" : "=r" (ct)); */
        /* void *cpuDatap = *(void **)((uint8_t *)ct + 0x478); */

        /* if(!cpuDatap){ */
        /*     kprintf("%s(%d, CPU %d): NULL cpu data???\n", __func__, i, curcpu); */
        /* } */
        /* else{ */
        /*     uint64_t saved_fp = *(uint64_t *)((uint8_t *)cpuDatap + 0x1a8); */
        /*     kprintf("%s(%d, CPU %d): saved_fp = %#llx\n", __func__, i, curcpu, */
        /*             saved_fp); */
        /* } */

        /* IOSleep(1000); */
        /* i++; */
    /* } */

    /* kprintf("%s: took %d spins for DBGBVR0_EL1 to get zeroed\n", __func__, i); */

    kprintf("%s: on CPU %d\n", __func__, curcpu);

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
    void *mem = kalloc_canblock_orig(sizep, canblock, site);
    /* uint8_t *memp = mem; */
    /* size_t size = *sizep; */

    /* for(size_t i=0; i<size; i++){ */
    /*     memp[i] = 0x41; */
    /* } */

    /* uint64_t tpidr_el1; */
    /* asm volatile("mrs %0, tpidr_el1" : "=r" (tpidr_el1)); */

    /* void *cpudata = *(void **)(tpidr_el1 + 0x478); */
    /* uint16_t curcpu = *(uint16_t *)cpudata; */

    /* uint64_t mpidr_el1; */
    /* asm volatile("mrs %0, mpidr_el1" : "=r" (mpidr_el1)); */
    /* uint8_t curcpu = mpidr_el1 & 0xff; */

    /* uint64_t caller = (uint64_t)__builtin_return_address(0); */


    /* if(!canblock){ */
    /*     kprintf("*****kalloc_canblock hook (CPU %d, caller=%#llx): returned mem @ " */
    /*             " %#llx for size %#llx\n", curcpu, caller, mem, *sizep); */
    /* } */

    return mem;
}

static void (*zone_require_orig)(void *addr, void *expected_zone);

static void zone_require(void *addr, void *expected_zone){
    uint64_t mpidr_el1;
    asm volatile("mrs %0, mpidr_el1" : "=r" (mpidr_el1));
    uint8_t cpuid = mpidr_el1 & 0xff;

    uint64_t caller = (uint64_t)__builtin_return_address(0);

    char *zname = *(char **)((uint8_t *)expected_zone + 0x120);

    /* kprintf("CPU %d, caller %#llx: zone_require called with addr %#llx," */
    /*         " expected zone", cpuid, caller, addr); */

    /* if(zname) */
    /*     kprintf(" '%s'\n", zname); */
    /* else */
    /*     kprintf(" %#llx\n", expected_zone); */

    zone_require_orig(addr, expected_zone);
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


static void *gIOUserClientClassKey = NULL;
static void *IOService_metaClass = NULL;

static void *(*OSMetaClassBase_safeMetaCast)(void *me, void *to_type) = NULL;

static const char *(*getClassName)(const void *OSObject) = NULL;

struct IOService_vtab {
    uint8_t pad[0x138];
    /* Found in IOService::newUserClient */
    void *(*copyProperty)(void *this, void *key);
};

struct IOService {
    struct IOService_vtab *vt;
};

struct IOUserClient_vtab {
    /* uint8_t pad0[0x38]; */
    /* void *(*getMetaClass)(void *this); */

    uint8_t pad0[0x118];
    /* Found in is_io_service_open_extended */
    void *(*getProperty)(void *this, const char *key);
    uint8_t pad120[0x370 - 0x120];
    struct IOService *(*getProvider)(void *this);
};

struct IOUserClient {
    struct IOUserClient_vtab *vt;
    /* uint8_t pad8[0xd0]; */
    /* struct IOService *__provider; */
};

#define kIOUserClientClassKey       "IOUserClientClass"

static kern_return_t (*is_io_service_open_extended_orig)(void *_service,
        void *owning_task, uint32_t connect_type, NDR_record_t ndr,
        char *properties, mach_msg_type_number_t properties_cnt,
        kern_return_t *result, void *connection);

static kern_return_t is_io_service_open_extended(void *_service,
        void *owning_task, uint32_t connect_type, NDR_record_t ndr,
        char *properties, mach_msg_type_number_t properties_cnt,
        kern_return_t *result, void *connection){
    uint64_t mpidr_el1;
    asm volatile("mrs %0, mpidr_el1" : "=r" (mpidr_el1));
    uint8_t cpuid = mpidr_el1 & 0xff;
    uint64_t caller = (uint64_t)__builtin_return_address(0);

    kern_return_t kret = is_io_service_open_extended_orig(_service, owning_task,
            connect_type, ndr, properties, properties_cnt, result,
            connection);

    kprintf("(CPU %d, unslid caller %#llx): connect type %d: ", cpuid,
            caller - kernel_slide, connect_type);

    if(*result != KERN_SUCCESS){
        kprintf("failed. Returned %#x, result = %#x\n", kret, *result);
        return kret;
    }

    struct IOUserClient *client = *(struct IOUserClient **)connection;

    kprintf("opened user client = %#llx ", client);

    if(!client){
        kprintf("\n");
        return kret;
    }

    const char *class_name = getClassName(client);

    if(!class_name){
        kprintf("getClassName failed.\n");
        return kret;
    }

    kprintf("class: '%s'", class_name);

    struct IOService *provider = client->vt->getProvider(client);

    if(!provider)
        kprintf(" unknown provider");
    else{
        const char *provider_class_name = getClassName(provider);

        if(provider_class_name)
            kprintf(" provider: '%s'", provider_class_name);
    }

    /* OSString */
    void *creator_name_prop = client->vt->getProperty(client, "IOUserClientCreator");

    if(!creator_name_prop){
        kprintf(" unknown creator\n");
        return kret;
    }

    const char *creator_name = *(const char **)((uint8_t *)creator_name_prop + 0x10);

    if(!creator_name){
        kprintf(" unknown creator\n");
        return kret;
    }

    kprintf(" creator: '%s'\n", creator_name);

    return kret;
}

#define	PAD_(t)	(sizeof(uint64_t) <= sizeof(t) \
        ? 0 : sizeof(uint64_t) - sizeof(t))
#define	PADL_(t)	0
#define	PADR_(t)	PAD_(t)
#define PAD_ARG_(arg_type, arg_name) \
    char arg_name##_l_[PADL_(arg_type)]; arg_type arg_name; char arg_name##_r_[PADR_(arg_type)];

struct mach_msg_overwrite_trap_args {
    PAD_ARG_(user_addr_t, msg);
    PAD_ARG_(mach_msg_option_t, option);
    PAD_ARG_(mach_msg_size_t, send_size);
    PAD_ARG_(mach_msg_size_t, rcv_size);
    PAD_ARG_(mach_port_name_t, rcv_name);
    PAD_ARG_(mach_msg_timeout_t, timeout);
    PAD_ARG_(mach_msg_priority_t, override);
    PAD_ARG_(user_addr_t, rcv_msg);  /* Unused on mach_msg_trap */
};

kern_return_t (*mach_msg_trap_orig)(struct mach_msg_overwrite_trap_args *args);

kern_return_t mach_msg_trap_hook(struct mach_msg_overwrite_trap_args *args){
    uint64_t mpidr_el1;
    asm volatile("mrs %0, mpidr_el1" : "=r" (mpidr_el1));
    uint8_t cpuid = mpidr_el1 & 0xff;
    uint64_t caller = (uint64_t)__builtin_return_address(0);

    /* kprintf("(CPU %d, unslid caller %#llx): msg %#llx option %#x send size %#x" */
    /*         " recv size %#x recv name %#x timeout %#x override %d recv msg %#llx\n", */
    /*         cpuid, caller - kernel_slide, args->msg, args->option, args->send_size, */
    /*         args->rcv_size, args->rcv_name, args->timeout, args->override, */
    /*         args->rcv_msg); */

    kern_return_t kret = mach_msg_trap_orig(args);

    /* kprintf("(CPU %d, unslid caller %#llx): mach_msg returned %d\n", cpuid, */
    /*         caller - kernel_slide, kret); */

    return kret;
}

struct IOExternalMethod {
    void *object;
    uint64_t func;
    uint32_t flags;
    uint64_t count0;
    uint64_t count1;
};

struct IOExternalMethod *(*FairPlayIOKitUserClient_getTargetAndMethodForIndex)(void *this, void **x1, uint32_t idx);

struct IOExternalMethod *_FairPlayIOKitUserClient_getTargetAndMethodForIndex(void *this, void **x1, uint32_t idx){
    struct IOExternalMethod *res =
        FairPlayIOKitUserClient_getTargetAndMethodForIndex(this, x1, idx);

    uint64_t mpidr_el1;
    asm volatile("mrs %0, mpidr_el1" : "=r" (mpidr_el1));
    uint8_t cpuid = mpidr_el1 & 0xff;
    uint64_t caller = (uint64_t)__builtin_return_address(0);

    kprintf("%s: (CPU %d, unslid caller %#llx): called with idx %d (was corrected"
            " to %d)", __func__, cpuid, caller - kernel_slide, idx, idx - 3);

    if(res){
        kprintf(", got external method @ %#llx [unslid] back\n",
                res->func - kernel_slide);
    }
    else{
        kprintf(", got nothing back\n");
    }

    void *provider = *(void **)((uintptr_t)this + 0xd8);
    
    if(!provider)
        return res;

    void *provider_vtab = *(void **)provider;
    uintptr_t plus_0x578 = (uintptr_t)provider_vtab + 0x578;

    kprintf("%s: +0x578 == %#llx\n", __func__, plus_0x578 - kernel_slide);

    return res;
}

static struct hook {
    uint64_t kva;
    void *replacement;
    void *original;
} g_hooks[] = {
    /* iphone 8 13.6.1 */
    { 0xFFFFFFF0081994DC, is_io_service_open_extended,
        &is_io_service_open_extended_orig },
    { 0xFFFFFFF007C031E4, kalloc_canblock, &kalloc_canblock_orig },
    { 0xFFFFFFF007C4B420, zone_require, &zone_require_orig },
    { 0xFFFFFFF007BEAFD0, mach_msg_trap_hook, &mach_msg_trap_orig },
    { 0xFFFFFFF00878A31C, _FairPlayIOKitUserClient_getTargetAndMethodForIndex,
        &FairPlayIOKitUserClient_getTargetAndMethodForIndex },
};

const size_t g_nhooks = sizeof(g_hooks) / sizeof(*g_hooks);

/* static void sig(int signum){ */
/*     int ret; */

/*     for(int i=0; i<g_nhooks; i++){ */
/*         struct hook *h = &g_hooks[i]; */

/*         ret = syscall(SYS_xnuspy_ctl, XNUSPY_UNINSTALL_HOOK, h->kva); */

/*         if(ret){ */
/*             printf("%s: could not uninstall hook for %#llx: %s\n", __func__, */
/*                     h->kva, strerror(errno)); */
/*         } */
/*     } */

/*     exit(0); */
/* } */

int main(int argc, char **argv){
    /* signal(SIGINT, sig); */

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

    ret = syscall(SYS_xnuspy_ctl, XNUSPY_GET_FUNCTION, KERNEL_SLIDE, &kernel_slide, 0);
    printf("got kernel slide @ %#llx\n", kernel_slide);
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

    /* Found in IOService::newUserClient */
    gIOUserClientClassKey = (void *)(0xFFFFFFF00925B840 + kernel_slide);

    OSMetaClassBase_safeMetaCast =
        (void *(*)(void *, void *))(0xFFFFFFF0080EA930 + kernel_slide);

    /* Found in _container_init */
    IOService_metaClass = (void *)(0xFFFFFFF00793DA88 + kernel_slide);

    getClassName = (const char *(*)(const void *))(0xFFFFFFF0080EC9A8 + kernel_slide);

    for(int i=0; i<g_nhooks; i++){
        struct hook *h = &g_hooks[i];

        ret = syscall(SYS_xnuspy_ctl, XNUSPY_INSTALL_HOOK, h->kva,
                h->replacement, h->original);

        if(ret){
            printf("%s: could not uninstall hook for %#llx: %s\n", __func__,
                    h->kva, strerror(errno));
        }

        printf("orig for %#llx: %#llx\n", h->kva, *(uint64_t *)h->original);
    }

    /* iphone 8 13.6.1 */
    /* ret = syscall(SYS_xnuspy_ctl, XNUSPY_INSTALL_HOOK, 0xFFFFFFF0081994DC, */
    /*         is_io_service_open_extended, &is_io_service_open_extended_orig); */

    /* if(ret) */
    /*     printf("%s\n", strerror(errno)); */

    /* printf("is_io_service_open_extended_orig = %#llx\n", */
    /*         is_io_service_open_extended_orig); */

    /* try and hook kalloc_canblock */
    /* iphone 8 13.6.1 */
    /* uint64_t kalloc_canblock = 0xFFFFFFF007C031E4; */
    /* void *(*kalloc_canblock_orig)(size_t *, void *, bool) = NULL; */
    /* ret = syscall(SYS_xnuspy_ctl, XNUSPY_INSTALL_HOOK, 0xFFFFFFF007C031E4, */
    /*         kalloc_canblock, &kalloc_canblock_orig); */

    /* if(ret) */
    /*     printf("%s\n", strerror(errno)); */

    /* printf("kalloc_canblock_orig = %#llx\n", kalloc_canblock_orig); */

    /* uint64_t some_fxn_with_cbz_as_first = 0xFFFFFFF007E5FFCC; */
    /* void (*dummy)(void) = NULL; */
    /* ret = syscall(SYS_xnuspy_ctl, XNUSPY_INSTALL_HOOK, some_fxn_with_cbz_as_first, code, */
    /*         &dummy); */

    /* iphone 8 13.6.1 */
    /* ret = syscall(SYS_xnuspy_ctl, XNUSPY_INSTALL_HOOK, 0xFFFFFFF007C4B420, */
    /*         zone_require, &zone_require_orig); */

    /* if(ret) */
    /*     printf("%s\n", strerror(errno)); */

    /* printf("zone_require_orig = %#llx\n", zone_require_orig); */

    /* try and hook sysctl_handle_long */
    /* iphone 8 13.6.1 */
    /* for(;;){ */
    extern struct mach_header_64 *_mh_execute_header;
    printf("%#llx\n", &_mh_execute_header);
    /* map_user_replacement(&_mh_execute_header, (uint64_t)sysctl_handle_long); */

    /* uint64_t sysctl_handle_long = 0xfffffff00800d508; */
    /* ret = syscall(SYS_xnuspy_ctl, XNUSPY_INSTALL_HOOK, 0xfffffff00800d508, */
    /*         sysctl_handle_long, &sysctl_handle_long_orig); */

    /* if(ret){ */
    /*     printf("%s\n", strerror(errno)); */
    /* } */

    /* printf("sysctl_handle_long_orig = %#llx\n", sysctl_handle_long_orig); */



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

    /* for(int i=0; i<g_nhooks; i++){ */
    /*     struct hook *h = &g_hooks[i]; */

    /*     ret = syscall(SYS_xnuspy_ctl, XNUSPY_UNINSTALL_HOOK, h->kva); */

    /*     if(ret){ */
    /*         printf("%s: could not uninstall hook for %#llx: %s\n", __func__, */
    /*                 h->kva, strerror(errno)); */
    /*     } */
    /* } */

    return 0;
}
