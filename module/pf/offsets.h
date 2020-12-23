#ifndef OFFSETS
#define OFFSETS

extern uint64_t *xnuspy_cache_base;

/* This file contains offsets which will be written to the xnuspy cache
 * as well as offsets needed before XNU boots.
 */

extern uint64_t g_sysent_addr;

/* iOS 13.x: kalloc_canblock
 * iOS 14.x: kalloc_external
 */
extern uint64_t g_kalloc_canblock_addr;
extern uint64_t g_kalloc_external_addr;

/* iOS 13.x: kfree_addr
 * iOS 14.x: kfree_ext
 */
extern uint64_t g_kfree_addr_addr;
extern uint64_t g_kfree_ext_addr;

extern uint64_t g_sysctl__kern_children_addr;
extern uint64_t g_sysctl_register_oid_addr;
extern uint64_t g_sysctl_handle_long_addr;
extern uint64_t g_name2oid_addr;
extern uint64_t g_sysctl_geometry_lock_addr;
extern uint64_t g_lck_rw_lock_shared_addr;
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
extern uint64_t g_xnuspy_sysctl_name_ptr;
extern uint64_t g_xnuspy_sysctl_descr_ptr;
extern uint64_t g_xnuspy_sysctl_fmt_ptr;
extern uint64_t g_xnuspy_sysctl_mib_ptr;
extern uint64_t g_xnuspy_sysctl_mib_count_ptr;
extern uint64_t g_xnuspy_ctl_callnum;
extern uint64_t g_kern_version_major;

#endif
