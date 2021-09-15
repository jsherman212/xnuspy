#ifndef PF_15
#define PF_15

#include <stdbool.h>

typedef struct xnu_pf_patch xnu_pf_patch_t;

bool ipc_port_release_send_finder_15(xnu_pf_patch_t *, void *);
bool proc_name_snprintf_strlen_finder_15(xnu_pf_patch_t *, void *);
bool current_proc_finder_15(xnu_pf_patch_t *, void *);
bool vm_map_unwire_nested_finder_15(xnu_pf_patch_t *, void *);
bool kernel_map_finder_15(xnu_pf_patch_t *, void *);
bool vm_deallocate_finder_15(xnu_pf_patch_t *, void *);
bool lck_mtx_lock_unlock_finder_15(xnu_pf_patch_t *, void *);
bool proc_list_mlock_finder_15(xnu_pf_patch_t *, void *);
bool lck_grp_free_finder_15(xnu_pf_patch_t *, void *);
bool iolog_finder_15(xnu_pf_patch_t *, void *);

#endif
