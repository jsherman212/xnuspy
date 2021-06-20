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

bool is_14_5_and_above(void){
    if(iOS_version == iOS_13_x)
        return false;

    if(kern_version_minor < 4)
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
