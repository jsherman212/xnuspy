#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

#include <xnuspy/xnuspy_structs.h>

#include <xnuspy/el1/externs.h>

__attribute__ ((naked)) uint64_t current_thread(void){
    asm(""
        "mrs x0, tpidr_el1\n"
        "ret\n"
       );
}

struct _vm_map *current_map(void){
    return *(struct _vm_map **)(current_thread() + offsetof_struct_thread_map);
}

void vm_map_reference(void *map){
    uint64_t off = offsetof_struct_vm_map_refcnt;
    _Atomic int *refcnt = (_Atomic int *)((uintptr_t)map + off);
    atomic_fetch_add_explicit(refcnt, 1, memory_order_relaxed);
}

bool is_14_5_and_above(void){
    if(iOS_version <= iOS_13_x)
        return false;

    if (iOS_version == iOS_14_x &&
        kern_version_minor < 4)
        return false;

    return true;
}

void ipc_port_release_send_wrapper(void *port){
    if(is_14_5_and_above()){
        if(io_lock == NULL)
            _panic("%s: io_lock is still 0 on >=14.5??", __func__);

        io_lock(port);
    }

    ipc_port_release_send(port);
}

kern_return_t vm_map_unwire_wrapper(void *map, uint64_t start, uint64_t end,
    int user)
{
    /*  iOS 15 -- vm_map_unwire_nested is used */
    if (vm_map_unwire_nested != NULL)
    {
        return vm_map_unwire_nested(map, start, end, user, 0x0, 0x0);
    }

    return vm_map_unwire(map, start, end, user);
}
