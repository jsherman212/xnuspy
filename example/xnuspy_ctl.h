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
};

/* Values for XNUSPY_CACHE_READ */
enum {
    KERNEL_SLIDE = 0,
    KPRINTF,

    /* Use kalloc_canblock for iOS 13.x. On iOS 14.x, EINVAL will
     * be returned. */
    KALLOC_CANBLOCK,

    /* Use kalloc_external for iOS 14.x. On iOS 13.x, EINVAL will
     * be returned. */
    KALLOC_EXTERNAL,

    /* Use kfree_addr for iOS 13.x. On iOS 14.x, EINVAL will
     * be returned. */
    KFREE_ADDR,

    /* Use kfree_ext for iOS 14.x. On iOS 13.x, EINVAL will
     * be returned. */
    KFREE_EXT,

    BCOPY_PHYS,
    PHYSTOKV,
    COPYIN,
    COPYINSTR,
    COPYOUT,
    CURRENT_PROC,
    PROC_PID,
    KERNEL_THREAD_START,
    THREAD_DEALLOCATE,
    THREAD_TERMINATE,

    /* struct proclist allproc @ bsd/sys/proc_internal.h */
    ALLPROC,

    BZERO,

    /* IMPORTANT: the ipc_port_release_send found by xnuspy's patchfinder
     * does not take the port's lock, so I wrote a tiny wrapper which does.
     * IPC_PORT_RELEASE_SEND will export that wrapper instead. */
    IPC_PORT_RELEASE_SEND,

    /* vm_map_t kernel_map @ osfmk/vm/vm_kern.h */
    KERNEL_MAP,

    LCK_GRP_ALLOC_INIT,
    LCK_GRP_FREE,
    LCK_MTX_UNLOCK,
    LCK_RW_ALLOC_INIT,
    LCK_RW_DONE,
    LCK_RW_FREE,
    LCK_RW_LOCK_EXCLUSIVE,
    LCK_RW_LOCK_SHARED,
    LCK_RW_LOCK_SHARED_TO_EXCLUSIVE,
    MACH_MAKE_MEMORY_ENTRY_64,
    MACH_VM_MAP_EXTERNAL,
    MEMCHR,
    MEMCMP,
    MEMMEM,
    MEMMOVE,
    MEMRCHR,
    MEMSET,

    /* offsetof(struct thread, map), vm_map_t */
    OFFSETOF_STRUCT_THREAD_MAP,

    PROC_LIST_LOCK,
    PROC_LIST_UNLOCK,

    /* lck_mtx_t *proc_list_mlock @ bsd/sys/proc_internal.h */
    PROC_LIST_MLOCK,

    PROC_NAME,
    PROC_REF_LOCKED,
    PROC_RELE_LOCKED,
    PROC_UNIQUEID,
    SNPRINTF,
    STRCHR,
    STRRCHR,
    STRCMP,
    STRLEN,
    STRNCMP,
    STRSTR,
    STRNSTR,
    VM_ALLOCATE_EXTERNAL,
    VM_DEALLOCATE,
    VM_MAP_UNWIRE,
    VM_MAP_WIRE_EXTERNAL,
    IOSLEEP,
    
    /* Everything below is from xnuspy, everything above is from XNU */

    /* void hookme(void *arg)
     *
     * This function is a stub for you to hook to easily gain kernel code
     * execution without having to hook an actual kernel function. You can
     * get xnuspy to call it by invoking xnuspy_ctl with the
     * XNUSPY_CALL_HOOKME flavor.
     */
    HOOKME,

    /* void *current_map(void)
     *
     * Returns the vm_map_t for the current thread. Identical to XNU's
     * implementation.
     *
     * Returns:
     *  Pointer to current thread's vm_map_t structure.
     */
    CURRENT_MAP,

    /* uint64_t iOS_version
     *
     * This variable contains the major from the "Darwin Kernel Version"
     * string. On iOS 13.x, this is 19. On iOS 14.x, this is 20.
     */
    IOS_VERSION,

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

    /* int kprotect(void *kaddr, uint64_t size, vm_prot_t prot)
     *
     * Change protections of kernel memory at the page table level.
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

    /* int uprotect(void *uaddr, uint64_t size, vm_prot_t prot)
     *
     * Change protections of user memory at the page table level.
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

    /* The next two functions deal with shared memory. One is for mapping
     * userspace memory into the kernel and the other is for mapping kernel
     * memory into userspace.
     *
     * Change VM protections of returned kernel memory with kprotect.
     * 
     * TODO XXX XXX XXX CHANGE THIS WHEN DONE
     *
     * int mkshmem_ktou(uint64_t kaddr, uint64_t sz, uint64_t *shm_uaddrp,
     *         void **shm_entryp)
     *
     * Parameters:
     *  kaddr:      kva of where to start mapping from
     *  shm_uaddrp: pointer to uva of newly-created shared mapping
     *
     * int mkshmem_utok(uint64_t uaddr, uint64_t sz, uint64_t *shm_kaddrp,
     *         void **shm_entryp)
     *
     * Parameters:
     *  uaddr:      uva of where to start mapping from
     *  shm_kaddrp: pointer to kva of newly-created shared mapping
     *
     * For both functions:
     *  sz:         desired length of shared mapping, page multiple
     *  shm_entryp: pointer to the memory object (ipc_port_t) that
     *     represents this shared mapping. 
     *
     * Returns:
     *  Zero on success, non-zero errno on failure.
     */
    MKSHMEM_KTOU,
    MKSHMEM_UTOK,
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

/* The structure which the shmem functions interact with */

struct xnuspy_shmem {
    /* Base of shared memory */
    void *shm_base;
    /* Size of shared memory, page multiple */
    uint64_t shm_sz;
    /* Memory entry for the shared memory, ipc_port_t */
    void *shm_entry;
    /* The vm_map_t to which the source pages belong to */
    void *shm_map_from;
    /* The vm_map_t to which the source pages were mapped into */
    void *shm_map_to;
};

#endif
