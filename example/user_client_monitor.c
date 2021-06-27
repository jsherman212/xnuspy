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

static void *(*current_proc)(void);
static void (*kprintf)(const char *, ...);
static pid_t (*proc_pid)(void *);

static uint64_t kernel_slide;

static uint8_t curcpu(void){
    uint64_t mpidr_el1;
    asm volatile("mrs %0, mpidr_el1" : "=r" (mpidr_el1));
    return (uint8_t)(mpidr_el1 & 0xff);
}

static pid_t caller_pid(void){
    return proc_pid(current_proc());
}

static const char *(*getClassName)(const void *OSObject);

struct IOUserClient_vtab {
    uint8_t pad0[0x118];
    void *(*getProperty)(void *this, const char *key);
    uint8_t pad120[0x370 - 0x120];
    void *(*getProvider)(void *this);
};

struct IOUserClient {
    struct IOUserClient_vtab *vt;
};

static kern_return_t (*is_io_service_open_extended_orig)(void *_service,
        void *owning_task, uint32_t connect_type, NDR_record_t ndr,
        char *properties, mach_msg_type_number_t properties_cnt,
        kern_return_t *result, struct IOUserClient **connection);

static kern_return_t is_io_service_open_extended(void *_service,
        void *owning_task, uint32_t connect_type, NDR_record_t ndr,
        char *properties, mach_msg_type_number_t properties_cnt,
        kern_return_t *result, struct IOUserClient **connection){
    uint8_t cpu = curcpu();
    pid_t cpid = caller_pid();
    uint64_t caller = (uint64_t)__builtin_return_address(0);

    kern_return_t kret = is_io_service_open_extended_orig(_service, owning_task,
            connect_type, ndr, properties, properties_cnt, result,
            connection);

    kprintf("user_client_monitor: (CPU %d, unslid caller %#llx, pid %d): connect "
            "type %#x: ", cpu, caller - kernel_slide, cpid, connect_type);

    if(*result != KERN_SUCCESS){
        kprintf("failed. Returned %#x, result = %#x\n", kret, *result);
        return kret;
    }

    struct IOUserClient *client = *connection;

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

    /* IOService */
    void *provider = client->vt->getProvider(client);

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

static kern_return_t (*is_io_connect_method)(struct IOUserClient *,
        uint32_t selector, uint64_t *scalar_input,
        uint32_t scalar_input_sz, uint8_t *struct_input,
        uint32_t struct_input_sz, uint64_t ool_input, uint64_t ool_input_sz,
        uint8_t *struct_output, uint32_t *struct_output_szp,
        uint64_t *scalar_output, uint64_t *scalar_output_szp,
        uint64_t ool_output, uint64_t *ool_output_szp);

static kern_return_t _is_io_connect_method(struct IOUserClient *uc,
        uint32_t selector, uint64_t *scalar_input,
        uint32_t scalar_input_sz, uint8_t *struct_input,
        uint32_t struct_input_sz, uint64_t ool_input, uint64_t ool_input_sz,
        uint8_t *struct_output, uint32_t *struct_output_szp,
        uint64_t *scalar_output, uint64_t *scalar_output_szp,
        uint64_t ool_output, uint64_t *ool_output_szp){
    kern_return_t kret = is_io_connect_method(uc, selector, scalar_input,
            scalar_input_sz, struct_input, struct_input_sz, ool_input,
            ool_input_sz, struct_output, struct_output_szp, scalar_output,
            scalar_output_szp, ool_output, ool_output_szp);

    const char *class_name = getClassName(uc);

    if(!class_name)
        return kret;

    kprintf("user_client_monitor: '%s' invoked external method %d\n",
            class_name, selector);

    return kret;
}

static long SYS_xnuspy_ctl = 0;

static int gather_kernel_offsets(void){
    int ret;

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

    /* iPhone SE 14.5 */
    getClassName = (const char *(*)(const void *))(0xfffffff007652c80 + kernel_slide);

    printf("kernel slide: %#llx\n", kernel_slide);
    printf("current_proc @ %#llx\n", (uint64_t)current_proc);
    printf("getClassName @ %#llx\n", (uint64_t)getClassName);
    printf("kprintf @ %#llx\n", (uint64_t)kprintf);
    printf("proc_pid @ %#llx\n", (uint64_t)proc_pid);

    ret = syscall(SYS_xnuspy_ctl, XNUSPY_INSTALL_HOOK, 0xfffffff007708dac,
            is_io_service_open_extended, &is_io_service_open_extended_orig);

    if(ret){
        printf("Could not hook is_io_service_open_extended: %s\n",
                strerror(errno));
        return 1;
    }

    /* I don't remember what device/version this offset corresponds to */
    ret = syscall(SYS_xnuspy_ctl, XNUSPY_INSTALL_HOOK, 0xFFFFFFF00770A22C,
            _is_io_connect_method, &is_io_connect_method);

    if(ret){
        printf("Could not hook is_io_connect_method: %s\n",
                strerror(errno));
        return 1;
    }

    printf("Hit enter to quit\n");
    getchar();

    return 0;
}
