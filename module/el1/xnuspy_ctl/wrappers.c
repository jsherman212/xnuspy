#include <stdbool.h>
#include <stdint.h>

#include <xnuspy/el1/utils.h>
#include <xnuspy/el1/externs.h>

void ipc_port_release_send_wrapper(void *port){
    if(!is_14_5_and_above()){
        ipc_port_release_send(port);
        return;
    }

    if(is_15_x())
        ipc_object_lock(port);
    else
        io_lock(port);

    ipc_port_release_send_and_unlock(port);
}

kern_return_t vm_map_unwire_wrapper(void *map, uint64_t start, uint64_t end,
        int user){
    if(is_15_x())
        return vm_map_unwire_nested(map, start, end, user, 0, 0);

    return vm_map_unwire(map, start, end, user);
}

void *proc_ref_wrapper(void *proc, bool holding_proc_list_mlock){
    /* For 13.x and 14.x, proc_ref_locked and proc_rele_locked expect
     * the proc_list_mlock to be held before they are called. For
     * 15.x, the second parameter to proc_ref indicates whether it is
     * held or not */
    if(is_15_x())
        return proc_ref(proc, holding_proc_list_mlock);

    void *proc_list_mlock = get_proc_list_mlock();

    if(!holding_proc_list_mlock)
        lck_mtx_lock(proc_list_mlock);

    void *res = proc_ref_locked(proc);

    if(!holding_proc_list_mlock)
        lck_mtx_unlock(proc_list_mlock);

    return res;
}

int proc_rele_wrapper(void *proc, bool holding_proc_list_mlock){
    /* On 15.x the second parameter is ignored, but we need to know
     * if we're on 13.x or 14.x */
    if(is_15_x())
        return proc_rele(proc);

    void *proc_list_mlock = get_proc_list_mlock();

    if(!holding_proc_list_mlock)
        lck_mtx_lock(proc_list_mlock);

    proc_rele_locked(proc);

    if(!holding_proc_list_mlock)
        lck_mtx_unlock(proc_list_mlock);

    /* Just return 0 for 13.x and 14.x, proc_rele_locked has no
     * return value for those kernels */

    return 0;
}
