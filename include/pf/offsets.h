#ifndef OFFSETS
#define OFFSETS

#include <stdint.h>

extern uint64_t *xnuspy_cache_base;

/* This file contains offsets which will be written to the xnuspy cache
 * as well as offsets needed before XNU boots.  */

/* NOT a kernel virtual address */
extern uint64_t g_sysent_addr;

/* iOS 13.x: kalloc_canblock
 * iOS 14.x: kalloc_external */
extern uint64_t g_kalloc_canblock_addr;
extern uint64_t g_kalloc_external_addr;

/* iOS 13.x: kfree_addr
 * iOS 14.x: kfree_ext */
extern uint64_t g_kfree_addr_addr;
extern uint64_t g_kfree_ext_addr;

extern uint64_t g_sysctl__kern_children_addr;
extern uint64_t g_sysctl_register_oid_addr;
extern uint64_t g_sysctl_handle_long_addr;
extern uint64_t g_name2oid_addr;
extern uint64_t g_sysctl_geometry_lock_addr;
extern uint64_t g_lck_rw_done_addr;
extern uint64_t g_h_s_c_sbn_branch_addr;
extern uint64_t g_h_s_c_sbn_epilogue_addr;
extern uint64_t g_lck_grp_alloc_init_addr;
extern uint64_t g_lck_rw_alloc_init_addr;
extern uint64_t g_exec_scratch_space_addr;
extern uint64_t g_exec_scratch_space_size;
extern uint32_t *g_ExceptionVectorsBase_stream;
extern uint64_t g_bcopy_phys_addr;
extern uint64_t g_phystokv_addr;
extern uint64_t g_copyin_addr;
extern uint64_t g_copyout_addr;
extern uint64_t g_IOSleep_addr;
extern uint64_t g_kprintf_addr;
extern uint64_t g_vm_map_unwire_addr;
extern uint64_t g_vm_deallocate_addr;
extern uint64_t g_kernel_map_addr;
extern uint64_t g_kernel_thread_start_addr;
extern uint64_t g_thread_deallocate_addr;
extern uint64_t g_mach_make_memory_entry_64_addr;
extern uint64_t g_offsetof_struct_thread_map;
extern uint64_t g_current_proc_addr;
extern uint64_t g_proc_list_lock_addr;
extern uint64_t g_proc_ref_locked_addr;
extern uint64_t g_proc_list_mlock_addr;
extern uint64_t g_lck_mtx_unlock_addr;
extern uint64_t g_proc_rele_locked_addr;
extern uint64_t g_proc_uniqueid_addr;
extern uint64_t g_proc_pid_addr;
extern uint64_t g_allproc_addr;
extern uint64_t g_lck_rw_lock_shared_addr;
extern uint64_t g_lck_rw_lock_shared_to_exclusive_addr;
extern uint64_t g_lck_rw_lock_exclusive_addr;
extern uint64_t g_vm_map_wire_external_addr;
extern uint64_t g_mach_vm_map_external_addr;
extern uint64_t g_ipc_port_release_send_addr;
extern uint64_t g_lck_rw_free_addr;
extern uint64_t g_lck_grp_free_addr;
extern int g_patched_doprnt_hide_pointers;
extern uint64_t g_copyinstr_addr;
extern uint64_t g_thread_terminate_addr;
extern int g_patched_pinst_set_tcr;
extern int g_patched_all_msr_tcr_el1_x18;
extern uint64_t g_snprintf_addr;
extern uint64_t g_strlen_addr;
extern uint64_t g_proc_name_addr;
extern uint64_t g_strncmp_addr;
extern uint64_t g_memset_addr;
extern uint64_t g_memmove_addr;
extern uint64_t g_panic_addr;
extern uint64_t g_mach_to_bsd_errno_addr;
extern uint64_t g_xnuspy_sysctl_mib_ptr;
extern uint64_t g_xnuspy_sysctl_mib_count_ptr;
extern uint64_t g_xnuspy_ctl_callnum;
extern uint64_t g_kern_version_major;
extern uint64_t g_kern_version_minor;
extern uint64_t g_io_lock_addr;
extern uint64_t g_vm_allocate_external_addr;

#endif
