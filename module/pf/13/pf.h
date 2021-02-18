#ifndef PF_13
#define PF_13

#include <stdbool.h>

typedef struct xnu_pf_patch xnu_pf_patch_t;

bool sysent_finder_13(xnu_pf_patch_t *, void *);
bool kalloc_canblock_finder_13(xnu_pf_patch_t *, void *);
bool kfree_addr_finder_13(xnu_pf_patch_t *, void *);
bool ExceptionVectorsBase_finder_13(xnu_pf_patch_t *, void *);
bool sysctl__kern_children_finder_13(xnu_pf_patch_t *, void *);
bool sysctl_register_oid_finder_13(xnu_pf_patch_t *, void *);
bool sysctl_handle_long_finder_13(xnu_pf_patch_t *, void *);
bool name2oid_and_its_dependencies_finder_13(xnu_pf_patch_t *, void *);
bool hook_system_check_sysctlbyname_finder_13(xnu_pf_patch_t *, void *);
bool lck_grp_alloc_init_finder_13(xnu_pf_patch_t *, void *);
bool lck_rw_alloc_init_finder_13(xnu_pf_patch_t *, void *);
bool bcopy_phys_finder_13(xnu_pf_patch_t *, void *);
bool phystokv_finder_13(xnu_pf_patch_t *, void *);
bool ktrr_lockdown_patcher_13(xnu_pf_patch_t *, void *);
bool amcc_lockdown_patcher_13(xnu_pf_patch_t *, void *);
bool copyin_finder_13(xnu_pf_patch_t *, void *);
bool copyout_finder_13(xnu_pf_patch_t *, void *);
bool IOSleep_finder_13(xnu_pf_patch_t *, void *);
bool kprintf_finder_13(xnu_pf_patch_t *, void *);
bool kernel_map_vm_deallocate_vm_map_unwire_finder_13(xnu_pf_patch_t *, void *);
bool kernel_thread_start_thread_deallocate_finder_13(xnu_pf_patch_t *, void *);
bool mach_make_memory_entry_64_finder_13(xnu_pf_patch_t *, void *);
bool offsetof_struct_thread_map_finder_13(xnu_pf_patch_t *, void *);
bool proc_stuff0_finder_13(xnu_pf_patch_t *, void *);
bool proc_stuff1_finder_13(xnu_pf_patch_t *, void *);
bool allproc_finder_13(xnu_pf_patch_t *, void *);
bool misc_lck_stuff_finder_13(xnu_pf_patch_t *, void *);
bool vm_map_wire_external_finder_13(xnu_pf_patch_t *, void *);
bool mach_vm_map_external_finder_13(xnu_pf_patch_t *, void *);
bool ipc_port_release_send_finder_13(xnu_pf_patch_t *, void *);
bool lck_rw_free_finder_13(xnu_pf_patch_t *, void *);
bool lck_grp_free_finder_13(xnu_pf_patch_t *, void *);
bool doprnt_hide_pointers_patcher_13(xnu_pf_patch_t *, void *);
bool copyinstr_finder_13(xnu_pf_patch_t *, void *);
bool thread_terminate_finder_13(xnu_pf_patch_t *, void *);
bool pinst_set_tcr_patcher_13(xnu_pf_patch_t *, void *);
bool msr_tcr_el1_x18_patcher_13(xnu_pf_patch_t *, void *);
bool proc_name_snprintf_strlen_finder_13(xnu_pf_patch_t *, void *);
bool strncmp_finder_13(xnu_pf_patch_t *, void *);
bool memset_finder_13(xnu_pf_patch_t *, void *);
bool memmove_finder_13(xnu_pf_patch_t *, void *);
bool panic_finder_13(xnu_pf_patch_t *, void *);

#endif
