#ifndef WRAPPERS
#define WRAPPERS

#include <stdint.h>

void ipc_port_release_send_wrapper(void *);
kern_return_t vm_map_unwire_wrapper(void *, uint64_t, uint64_t, int);
void *proc_ref_wrapper(void *, bool);
int proc_rele_wrapper(void *, bool);

#endif
