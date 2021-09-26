#ifndef XNUSPY_CTL
#define XNUSPY_CTL

#include <stdint.h>

/* Flavors for xnuspy_ctl */
enum {
    XNUSPY_CHECK_IF_PATCHED = 0,
    XNUSPY_INSTALL_HOOK,
    XNUSPY_REGISTER_DEATH_CALLBACK,
    XNUSPY_CALL_HOOKME,
    XNUSPY_CACHE_READ,
    XNUSPY_KREAD,
    XNUSPY_KWRITE,
    XNUSPY_GET_CURRENT_THREAD,
#ifdef XNUSPY_PRIVATE
    XNUSPY_MAX_FLAVOR = XNUSPY_GET_CURRENT_THREAD,
#endif
};

/* Values for XNUSPY_CACHE_READ - keep this alphabetical so it's
 * easier to find things */

#ifdef XNUSPY_PRIVATE
enum xnuspy_cache_id {
#else
enum {
#endif
    /* struct proclist allproc @ bsd/sys/proc_internal.h */
    ALLPROC = 0,
    BCOPY_PHYS,
    BZERO,
    COPYIN,
    COPYINSTR,
    COPYOUT,

    /* Idential to XNU's implementation */
    CURRENT_MAP,

    CURRENT_PROC,

    /* Only valid for iOS 14.5 - iOS 14.8, inclusive. EINVAL will be
     * returned otherwise. */
    IO_LOCK,

    /* Only valid for iOS 15.x. EINVAL will be returned otherwise. */
    IPC_OBJECT_LOCK,

    IOLOG,
    IOSLEEP,

    /* Only valid for < iOS 14.5. EINVAL will be returned otherwise. */
    IPC_PORT_RELEASE_SEND,
    
    /* Only valid for >= iOS 14.5. EINVAL will be returned otherwise. */
    IPC_PORT_RELEASE_SEND_AND_UNLOCK,

    /* Selects the correct way to release a send right based on the
     * kernel version. Parameters are the same as XNU's
     * ipc_port_release_send. */
    IPC_PORT_RELEASE_SEND_WRAPPER,

    /* Only valid for iOS 13.x. EINVAL will be returned otherwise. */
    KALLOC_CANBLOCK,

    /* Only valid for iOS 14.x and iOS 15.x. EINVAL will be returned
     * otherwise. */
    KALLOC_EXTERNAL,

    /* vm_map_t kernel_map @ osfmk/vm/vm_kern.h */
    KERNEL_MAP,

    KERNEL_THREAD_START,

    /* Only valid for iOS 13.x. EINVAL will be returned otherwise. */
    KFREE_ADDR,

    /* Only valid for iOS 14.x and iOS 15.x. EINVAL will be returned
     * otherwise. */
    KFREE_EXT,

    KPRINTF,
    LCK_GRP_ALLOC_INIT,
    LCK_GRP_FREE,
    LCK_MTX_LOCK,
    LCK_MTX_UNLOCK,
    LCK_RW_ALLOC_INIT,
    LCK_RW_DONE,
    LCK_RW_FREE,
    LCK_RW_LOCK_EXCLUSIVE,
    LCK_RW_LOCK_SHARED,
    LCK_RW_LOCK_SHARED_TO_EXCLUSIVE,
    MACH_MAKE_MEMORY_ENTRY_64,
    MACH_TO_BSD_ERRNO,
    MACH_VM_MAP_EXTERNAL,
    MEMCHR,
    MEMCMP,
    MEMMEM,
    MEMMOVE,
    MEMRCHR,
    MEMSET,
    PANIC,
    PHYSTOKV,

    /* Selects the correct way to take proc_list_mlock based
     * on the kernel version.
     *
     *      void proc_list_lock(void);
     *
     */
    PROC_LIST_LOCK,

    /* lck_mtx_t *proc_list_mlock @ bsd/sys/proc_internal.h */
    PROC_LIST_MLOCK,

    /* Selects the correct way to release proc_list_mlock based
     * on the kernel version.
     *
     *      void proc_list_unlock(void);
     *
     */
    PROC_LIST_UNLOCK,

    PROC_NAME,
    PROC_PID,

    /* Only valid for 15.x. EINVAL will be returned otherwise.
     * Until 15 sources come out, here's what I think the function
     * signature is:
     *
     *      proc_t proc_ref(proc_t proc, bool holding_proc_list_mlock);
     *
     * You can find a call to it in proc_exit. It looks like it is good
     * practice to make sure the returned proc pointer was the same one
     * as you passed in. Not sure what the return value being different
     * than the first parameter indicates... */
    PROC_REF,

    /* Only valid for 13.x and 14.x. EINVAL will be returned otherwise.
     * This function assumes the caller holds proc_list_mlock. */
    PROC_REF_LOCKED,

    /* Selects the correct way to take a reference on a proc structure
     * based on the kernel version.
     *
     *      void *proc_ref_wrapper(void *proc, bool holding_proc_list_mlock);
     *
     * If you are on iOS 13.x or iOS 14.x and you pass false for the
     * second parameter, this function takes proc_list_mlock before
     * calling proc_ref_locked and releases it after that returns. If
     * you are on iOS 15.x, this tail calls proc_ref. Return value
     * is either the return value of proc_ref or proc_ref_locked. */
    PROC_REF_WRAPPER,

    /* Only valid for 15.x. EINVAL will be returned otherwise.
     * This function assumes the caller DOES NOT hold proc_list_mlock,
     * though I'm not sure if it's safe to hold that mutex and call this
     * function.
     * Until 15 sources come out, here's the function signature:
     *
     *      int proc_rele(proc_t proc);
     *
     * Seems to always return 0. */
    PROC_RELE,

    /* Only valid for 13.x and 14.x. EINVAL will be returned otherwise.
     * This function assumes the caller holds proc_list_mlock. */
    PROC_RELE_LOCKED,

    /* Selects the correct way to release a reference on a proc structure
     * based on the kernel version.
     *
     *      int proc_rele_wrapper(void *proc, bool holding_proc_list_mlock);
     *
     * If you are on iOS 13.x or iOS 14.x and you pass false for the
     * second parameter, this function takes proc_list_mlock before
     * calling proc_rele_locked and releases it after that returns. If
     * you are on iOS 15.x, this tail calls proc_rele and the second
     * parameter is ignored. Return value is either the return value
     * of proc_ref (for iOS 15.x) or zero (for iOS 13.x and iOS 14.x) */
    PROC_RELE_WRAPPER,

    PROC_UNIQUEID,
    SNPRINTF,
    STRCHR,
    STRRCHR,
    STRCMP,
    STRLEN,
    STRNCMP,
    STRSTR,
    STRNSTR,
    THREAD_DEALLOCATE,
    THREAD_TERMINATE,
    VM_ALLOCATE_EXTERNAL,
    VM_DEALLOCATE,
    VM_MAP_DEALLOCATE,

    /* Identical to XNU's implementation */
    VM_MAP_REFERENCE,

    /* Only valid for 13.x and 14.x. EINVAL will be returned otherwise. */
    VM_MAP_UNWIRE,

    /* Only valid for 15.x. EINVAL will be returned otherwise. */
    VM_MAP_UNWIRE_NESTED,

    /* Selects the correct way to unwire a vm_map based on the
     * kernel version. Parameters are the same as XNU's vm_map_unwire. */
    VM_MAP_UNWIRE_WRAPPER,

    VM_MAP_WIRE_EXTERNAL,

    /*  --------------------------------------------
     * Everything above (with the exception of the small wrapper functions)
     * is from XNU, everything below are things from xnuspy you may
     * find useful
     *  ---------------------------------------------
     */

    /* uint64_t *el0_ptep(void *uaddr)
     *
     * Given a user virtual address, this function returns a pointer to its
     * page table entry.
     *
     * Parameters:
     *  uaddr: user virtual address.
     *
     * Returns:
     *  Kernel virtual address of page table entry for uaddr.
     */
    EL0_PTEP,

    /* uint64_t *el1_ptep(void *kaddr)
     *
     * Given a kernel virtual address, this function returns a pointer to its
     * page table entry.
     *
     * Parameters:
     *  kaddr: kernel virtual address.
     *
     * Returns:
     *  Kernel virtual address of page table entry for kaddr.
     */
    EL1_PTEP,

    /* void hookme(void *arg)
     *
     * This function is a stub for you to hook to easily gain kernel code
     * execution without having to hook an actual kernel function. You can
     * get xnuspy to call it by invoking xnuspy_ctl with the
     * XNUSPY_CALL_HOOKME flavor.
     */
    HOOKME,

    /* uint64_t iOS_version
     *
     * This variable contains the major from the "Darwin Kernel Version"
     * string. On iOS 13.x, this is 19, on iOS 14.x, this is 20, and
     * on iOS 15.x, this is 21. */
    IOS_VERSION,

    /* uint64_t kernel_slide
     *
     * KASLR slide */
    KERNEL_SLIDE,

    /* uint64_t kern_version_minor
     *
     * This variable contains the minor from the "Darwin Kernel Version"
     * string. */
    KERN_VERSION_MINOR,

    /* int kprotect(void *kaddr, uint64_t size, vm_prot_t prot)
     *
     * Change protections of kernel memory at the page table level.
     * You are allowed to make writable, executable memory.
     *
     * Parameters:
     *  kaddr: kernel virtual address of target.
     *  size:  the number of bytes in the target region.
     *  prot:  protections to apply. Only VM_PROT_READ, VM_PROT_WRITE, and
     *         VM_PROT_EXECUTE are respected.
     *
     * Returns:
     *  Zero if successful, non-zero otherwise.
     */
    KPROTECT,

    /* uint64_t kvtophys(uint64_t kaddr)
     *
     * Convert a kernel (EL1) virtual address to a physical address.
     *
     * Parameters:
     *  kaddr: kernel virtual address.
     *
     * Returns:
     *  Non-zero if address translation was successful, zero otherwise.
     */
    KVTOPHYS,

    /* void kwrite_instr(uint64_t addr, uint32_t instr)
     *
     * Patch a single instruction of executable kernel code. This function
     * handles permissions, data cache cleaning, and instruction cache
     * invalidation.
     *
     * Parameters:
     *  addr:  kernel virtual address.
     *  instr: new instruction for addr.
     */
    KWRITE_INSTR,

    /* void kwrite_static(void *dst, void *buf, size_t sz)
     *
     * Write to static kernel memory, using bcopy_phys.
     *
     * Parameters:
     *  dst: kernel virtual address of destination.
     *  buf: kernel virtual address of data.
     *  sz:  how many bytes 'buf' is.
     */
    KWRITE_STATIC,

    /* The next three functions deal with shared memory. KTOU ("kernel to
     * user") and UTOK ("user to kernel") specify the "direction". "a to b",
     * where <a> and <b> are both vm_map pointers, means pages from <a> will
     * be mapped into <b> as shared memory. Pages from <a> must have been
     * allocated via vm_allocate for these functions to succeed. KTOU and UTOK
     * automatically select the <a> and <b> vm_map pointers for convenience.
     * The RAW variant allows you to specify the <a> and <b> vm_map pointers.
     * You would use mkshmem_raw when you are unsure of current_task()->map
     * or the current CPU's TTBR0 inside your kernel code.
     *
     * int mkshmem_ktou(uint64_t kaddr, uint64_t sz, vm_prot_t prot,
     *         struct xnuspy_shmem *shmemp);
     * int mkshmem_utok(uint64_t uaddr, uint64_t sz, vm_prot_t prot,
     *         struct xnuspy_shmem *shmemp);
     * int mkshmem_raw(uint64_t addr, uint64_t sz, vm_prot_t prot,
     *         vm_map_t from, vm_map_t to, struct xnuspy_shmem *shmemp);
     *
     * Parameters (for all three):
     *  kaddr/uaddr/addr: virtual address somewhere inside <a>
     *  sz:               page aligned mapping size
     *  prot:             virtual protections to apply to the created
     *                    shared mapping
     *  shmemp:           returned shmem. The structure definition can
     *                    be found at the end of this file.
     *
     * Parameters specific to mkshmem_raw:
     *  from: source map, aka <a>
     *  to:   destination map, aka <b>
     *
     * Returns (for all three):
     *  Zero on success (and populated shmemp structure), non-zero BSD errno
     *  on failure.
     *
     * Other notes:
     *  These functions use kprotect to apply VM protections, so any
     *  combination of those are allowed. VM protections are only applied
     *  to the newly-created mapping, not the source pages that came
     *  from <a>.
     */
    MKSHMEM_KTOU,
    MKSHMEM_UTOK,
    MKSHMEM_RAW,

    /* offsetof(struct thread, map), vm_map_t */
    OFFSETOF_STRUCT_THREAD_MAP,

    /* offsetof(struct _vm_map, map_refcnt), int (yes, int) */
    OFFSETOF_STRUCT_VM_MAP_REFCNT,

    /* int shmem_destroy(struct xnuspy_shmem *shmemp);
     *
     * Destory shared memory returned by mkshmem_ktou, mkshmem_utok, or
     * mkshmem_raw.
     *
     * Parameters:
     *  shmemp: pointer to shmem structure
     *
     * Returns:
     *  Zero on success, non-zero BSD errno on failure.
     */
    SHMEM_DESTROY,

    /* void tlb_flush(void)
     *
     * After modifying a page table, call this function to invalidate
     * the TLB.
     */
    TLB_FLUSH,

    /* The next two functions abstract away the different kalloc/kfree pairs
     * for different iOS versions and keeps track of allocation sizes. This
     * creates an API like malloc/free. Pointers returned from unified_kalloc
     * can only be freed with unified_kfree, and pointers returned by other
     * memory allocation functions cannot be freed with unified_kfree.
     *
     *  uint8_t *buf = unified_kalloc(0x200);
     *  
     *  if(!buf)
     *     <error>
     *
     *  buf[0] = '\0';
     *
     *  unified_kfree(buf);
     *
     * -------------------------------
     *
     * void *unified_kalloc(size_t sz)
     *
     * Parameters:
     *  sz: allocation size.
     *
     * Returns:
     *  Upon success, a pointer to memory. If we are on 13.x, kalloc_canblock's
     *  canblock parameter is false. Upon failure, NULL.
     *
     * -------------------------------
     *
     * void unified_kfree(void *ptr)
     *
     * Parameters:
     *  ptr: a pointer returned from unified_kalloc.
     */
    UNIFIED_KALLOC,
    UNIFIED_KFREE,

    /* int uprotect(void *uaddr, uint64_t size, vm_prot_t prot)
     *
     * Change protections of user memory at the page table level.
     * You are allowed to make writable, executable memory.
     *
     * Parameters:
     *  uaddr: user virtual address of target.
     *  size:  the number of bytes in the target region.
     *  prot:  protections to apply. Only VM_PROT_READ, VM_PROT_WRITE, and
     *         VM_PROT_EXECUTE are respected.
     *
     * Returns:
     *  Zero if successful, non-zero otherwise.
     */
    UPROTECT,

    /* uint64_t uvtophys(uint64_t uaddr)
     *
     * Convert a user (EL0) virtual address to a physical address.
     *
     * Parameters:
     *  uaddr: user virtual address.
     *
     * Returns:
     *  Non-zero if address translation was successful, zero otherwise.
     */
    UVTOPHYS,

#ifdef XNUSPY_PRIVATE
    MAX_CACHE = UVTOPHYS,
#endif
};

#define iOS_13_x    (19)
#define iOS_14_x    (20)
#define iOS_15_x    (21)

/* Structures for locks that work in both kernelspace and userspace.
 * Any locks you declare must be declared globally so they
 * are mapped as shared memory when you install your kernel hooks */
/* kuslck_t: a simple spinlock */
typedef struct {
    uint32_t word;
} kuslck_t;

#define KUSLCK_UNLOCKED (0)
#define KUSLCK_LOCKED   (1)

/* kuslck_t lck = KUSLCK_INITIALIZER; */
#define KUSLCK_INITIALIZER { .word = KUSLCK_UNLOCKED }

#define kuslck_lock(lck) \
    do { \
        while(__atomic_exchange_n(&(lck).word, KUSLCK_LOCKED, \
                    __ATOMIC_ACQ_REL) == 0){} \
    } while (0) \

#define kuslck_unlock(lck) \
    do { \
        __atomic_store_n(&(lck).word, KUSLCK_UNLOCKED, __ATOMIC_RELEASE); \
    } while (0) \

struct xnuspy_shmem {
    /* Base of shared memory */
    void *shm_base;
    /* Size of shared memory, page multiple */
    uint64_t shm_sz;
#ifdef XNUSPY_PRIVATE
    /* Memory entry for the shared memory, ipc_port_t */
    void *shm_entry;
    /* The vm_map_t which the source pages belong to */
    void *shm_map_from;
    /* The vm_map_t which the source pages were mapped into */
    void *shm_map_to;
#else
    void *opaque[3];
#endif
};

#endif
