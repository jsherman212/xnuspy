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

bool is_15_x(void){
    return iOS_version == iOS_15_x;
}

bool is_14_5_and_above(void){
    if(iOS_version <= iOS_13_x)
        return false;

    if (iOS_version == iOS_14_x &&
        kern_version_minor < 4)
        return false;

    return true;
}

bool is_14_x_and_above(void){
    return iOS_version >= iOS_14_x;
}

bool is_14_x_and_below(void){
    return iOS_version <= iOS_14_x;
}

bool is_14_x(void){
    return iOS_version == iOS_14_x;
}

bool is_13_x(void){
    return iOS_version == iOS_13_x;
}

/* On 14.5+, the patchfinder for proc_list_mlock yields a pointer
 * to it, not a pointer to a pointer to it like on 13.0 - 14.4.2 */
void *get_proc_list_mlock(void){
    void *mtx = proc_list_mlockp;

    if(is_14_5_and_above())
        return mtx;

    return *(void **)mtx;
}

void proc_list_lock(void){
    lck_mtx_lock(get_proc_list_mlock());
}

/* proc_list_unlock has been inlined so aggressively on all kernels that there
 * are no xrefs to the actual function so we need to do it like this */
void proc_list_unlock(void){
    lck_mtx_unlock(get_proc_list_mlock());
}
