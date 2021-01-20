#ifndef EXTERNS
#define EXTERNS

#include <mach/mach.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/queue.h>
#include <unistd.h>

#undef PAGE_SIZE
#define PAGE_SIZE       (0x4000uLL)

#define iOS_13_x        (19)
#define iOS_14_x        (20)

#define MAP_MEM_VM_SHARE            0x400000 /* extract a VM range for remap */

typedef unsigned int lck_rw_type_t;

typedef	void (*thread_continue_t)(void *param, int wait_result);

typedef struct __lck_rw_t__ lck_rw_t;

/* Start kernel offsets */

extern void **allprocp;
extern void (*bcopy_phys)(uint64_t src, uint64_t dst,
        vm_size_t bytes);
extern int (*copyin)(const void *uaddr, void *kaddr,
        vm_size_t nbytes);
extern int (*copyinstr)(const void *uaddr, void *kaddr,
        size_t len, size_t *done);
extern int (*copyout)(const void *kaddr, uint64_t uaddr,
        vm_size_t nbytes);
extern void *(*current_proc)(void);
extern uint64_t hookme_in_range;
extern uint64_t iOS_version;
extern void (*IOSleep)(unsigned int millis);
extern void (*ipc_port_release_send)(void *port);
extern void *(*kalloc_canblock)(vm_size_t *sizep, bool canblock,
        void *site);
extern void *(*kalloc_external)(vm_size_t sz);
extern void **kernel_mapp;
extern uint64_t kernel_slide;
extern kern_return_t (*kernel_thread_start)(thread_continue_t cont,
        void *parameter, void **new_thread);
extern void (*kfree_addr)(void *addr);
extern void (*kfree_ext)(void *kheap, void *addr,
        vm_size_t sz);
extern void (*kprintf)(const char *fmt, ...);
extern void *(*lck_grp_alloc_init)(const char *grp_name,
        void *attr);
extern void (*lck_grp_free)(void *grp);
extern void (*lck_mtx_unlock)(void *lock);
extern lck_rw_t *(*lck_rw_alloc_init)(void *grp, void *attr);
extern uint32_t (*lck_rw_done)(lck_rw_t *lock);
extern void (*lck_rw_free)(lck_rw_t *lock, void *grp);
extern void (*lck_rw_lock_exclusive)(void *lock);
extern void (*lck_rw_lock_shared)(void *lock);
extern int (*lck_rw_lock_shared_to_exclusive)(lck_rw_t *lck);
/* Extra underscore so compiler stops complaining */
extern kern_return_t (*_mach_make_memory_entry_64)(void *target_map,
        uint64_t *size, uint64_t offset, vm_prot_t prot, void **object_handle,
        void *parent_handle);
extern kern_return_t (*mach_vm_map_external)(void *target_map,
        uint64_t *address, uint64_t size, uint64_t mask, int flags,
        void *memory_object, uint64_t offset, int copy,
        vm_prot_t cur_protection, vm_prot_t max_protection,
        vm_inherit_t inheritance);
extern uint64_t offsetof_struct_thread_map;
extern uint64_t (*phystokv)(uint64_t pa);
extern void (*proc_list_lock)(void);
extern void **proc_list_mlockp;
extern pid_t (*proc_pid)(void *proc);
extern void (*proc_ref_locked)(void *proc);
extern void (*proc_rele_locked)(void *proc);
extern uint64_t (*proc_uniqueid)(void *proc);
extern void (*thread_deallocate)(void *thread);
/* Extra underscore so compiler stops complaining */
extern void (*_thread_terminate)(void *thread);
/* Extra underscore so compiler stops complaining */
extern kern_return_t (*_vm_deallocate)(void *map,
        uint64_t start, uint64_t size);
extern kern_return_t (*vm_map_unwire)(void *map, uint64_t start,
        uint64_t end, int user);
extern kern_return_t (*vm_map_wire_external)(void *map,
        uint64_t start, uint64_t end, vm_prot_t prot, int user_wire);
extern struct xnuspy_tramp *xnuspy_tramp_mem;
extern struct xnuspy_tramp *xnuspy_tramp_mem_end;

/* End kernel offsets */

extern STAILQ_HEAD(, stailq_entry) freelist;
extern STAILQ_HEAD(, stailq_entry) usedlist;
extern STAILQ_HEAD(, stailq_entry) unmaplist;

extern lck_rw_t *xnuspy_rw_lck;

#endif
