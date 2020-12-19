#ifndef EXTERNS
#define EXTERNS

#undef PAGE_SIZE
#define PAGE_SIZE       (0x4000uLL)

#define iOS_13_x        (19)
#define iOS_14_x        (20)

extern uint64_t iOS_version;
extern void *(*kalloc_canblock)(vm_size_t *sizep, bool canblock,
        void *site);
extern void *(*kalloc_external)(vm_size_t sz);
extern void (*kfree_addr)(void *addr);
extern void (*kfree_ext)(void *addr, vm_size_t sz);
extern void (*lck_rw_lock_shared)(void *lock);
extern uint32_t (*lck_rw_done)(void *lock);
extern void *(*lck_grp_alloc_init)(const char *grp_name,
        void *attr);
extern void *(*lck_rw_alloc_init)(void *grp, void *attr);
extern void (*bcopy_phys)(uint64_t src, uint64_t dst,
        vm_size_t bytes);
extern uint64_t (*phystokv)(uint64_t pa);
extern int (*copyin)(const uint64_t uaddr, void *kaddr,
        vm_size_t nbytes);
extern int (*copyout)(const void *kaddr, uint64_t uaddr,
        vm_size_t nbytes);
extern int (*machine_thread_set_state)(void *thread, int flavor, void *state,
        uint32_t count);
extern uint32_t *ncpusp;
extern void *mh_execute_header;
extern uint64_t kernel_slide;
extern uint8_t *xnuspy_tramp_page;

/* XXX For debugging only */
/* extern void (*IOLog)(const char *fmt, ...); */
extern void (*kprintf)(const char *fmt, ...);
extern void (*IOSleep)(uint32_t millis);
/* extern void *___osLog; */
/* extern void *_os_log_default; */
/* extern void (*os_log_internal)(void *dso, void *log, int type, */
/*         const char *fmt, ...); */

#endif
