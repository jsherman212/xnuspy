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

#if 0
bool kalloc_external_finder_14(xnu_pf_patch_t *, void *);
bool kfree_ext_finder_14(xnu_pf_patch_t *, void *);
bool ExceptionVectorsBase_finder_14(xnu_pf_patch_t *, void *);
bool sysctl__kern_children_and_register_oid_finder_14(xnu_pf_patch_t *, void *);
bool lck_grp_alloc_init_finder_14(xnu_pf_patch_t *, void *);
bool lck_rw_alloc_init_finder_14(xnu_pf_patch_t *, void *);
bool ktrr_lockdown_patcher_14(xnu_pf_patch_t *, void *);
bool amcc_ctrr_lockdown_patcher_14(xnu_pf_patch_t *, void *);
bool name2oid_and_its_dependencies_finder_14(xnu_pf_patch_t *, void *);
#endif 

#endif
