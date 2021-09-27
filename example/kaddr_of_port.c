#include <errno.h>
#include <mach/mach.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <xnuspy/xnuspy_ctl.h>

static long SYS_xnuspy_ctl = 0;

/* https://gist.github.com/ccbrown/9722406 */
void kdump(const void *kaddr, size_t size) {
    char *data = malloc(size);
    if(syscall(SYS_xnuspy_ctl, XNUSPY_KREAD, kaddr, data, size)){
        printf("%s: kread failed: %s\n", __func__, strerror(errno));
        return;
    }
    char ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    for (i = 0; i < size; ++i) {
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
            } else if (i+1 == size) {
                ascii[(i+1) % 16] = '\0';
                if ((i+1) % 16 <= 8) {
                    printf(" ");
                }
                for (j = (i+1) % 16; j < 16; ++j) {
                    printf("   ");
                }
                printf("|  %s \n", ascii);
            }
        }
    }
    free(data);
}

struct ipc_entry {
    uint64_t ie_object;
    uint32_t ie_bits;
    uint32_t ie_dist : 12;
    uint32_t ie_index : 20;
    union {
        uint32_t next;
        uint32_t request;
    } index;
};

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
    struct ipc_entry *is_table;
    uint64_t is_task;
    uint64_t is_table_next;
    uint32_t is_low_mod;
    uint32_t is_high_mod;

    /* other stuff that isn't needed */
};

static uint64_t kaddr_of_port(mach_port_t p){
    uint64_t tp;
    int ret = syscall(SYS_xnuspy_ctl, XNUSPY_GET_CURRENT_THREAD, &tp, 0, 0);

    if(ret){
        printf("%s: XNUSPY_GET_CURRENT_THREAD failed: %s\n", __func__,
                strerror(errno));
        return 0;
    }
    
    uint64_t offsetof_map;
    ret = syscall(SYS_xnuspy_ctl, XNUSPY_CACHE_READ, OFFSETOF_STRUCT_THREAD_MAP,
            &offsetof_map, 0);

    if(ret){
        printf("%s: getting map offset failed: %s\n", __func__,
                strerror(errno));
        return 0;
    }

    /* task pointer is conveniently right before map pointer for all
     * my phones */
    uint64_t task;
    ret = syscall(SYS_xnuspy_ctl, XNUSPY_KREAD, tp + (offsetof_map - 8), &task,
            sizeof(task));

    if(ret){
        printf("%s: kread failed for task: %s\n", __func__, strerror(errno));
        return 0;
    }

    if(!task){
        printf("%s: task NULL?\n", __func__);
        return 0;
    }

    /* Offsets:
     *  iPhone 8 13.6.1: 0x320
     *  iPhone X 13.3.1: 0x320
     *  iPhone 7 14.1:   0x330
     */
    uint64_t itk_space;
    ret = syscall(SYS_xnuspy_ctl, XNUSPY_KREAD, task + 0x320, &itk_space,
            sizeof(itk_space));

    if(ret){
        printf("%s: kread failed for itk_space: %s\n", __func__,
                strerror(errno));
        return 0;
    }

    struct ipc_entry *is_tablep = NULL;
    ret = syscall(SYS_xnuspy_ctl, XNUSPY_KREAD,
            itk_space + __builtin_offsetof(struct ipc_space, is_table),
            &is_tablep, sizeof(is_tablep));

    if(ret){
        printf("%s: kread for is_table failed: %s\n", __func__,
                strerror(errno));
        return 0;
    }

    uint64_t kaddr;
    struct ipc_entry *entryp = is_tablep + (p >> 8);

    ret = syscall(SYS_xnuspy_ctl, XNUSPY_KREAD, entryp, &kaddr, sizeof(kaddr));

    if(ret){
        printf("%s: kread for ie_object failed: %s\n", __func__,
                strerror(errno));
        return 0;
    }

    return kaddr;
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

    uint64_t taskport_kaddr = kaddr_of_port(mach_task_self());

    if(!taskport_kaddr)
        return 1;

    printf("mach_task_self() @ %#llx\n", taskport_kaddr);

    kdump((void *)taskport_kaddr, 0xa8);

    return 0;
}
