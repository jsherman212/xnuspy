#ifndef XNUSPY_CTL
#define XNUSPY_CTL

#define XNUSPY_INSTALL_HOOK         (0)
#define XNUSPY_CHECK_IF_PATCHED     (1)
#define XNUSPY_CACHE_READ           (2)
#define XNUSPY_MAX_FLAVOR           XNUSPY_CACHE_READ

/* values for XNUSPY_CACHE_READ */
#define KERNEL_SLIDE                (0)
#define KPRINTF                     (1)
/* use kalloc_canblock for iOS 13.x */
#define KALLOC_CANBLOCK             (2)
/* use kalloc_external for iOS 14.x */
#define KALLOC_EXTERNAL             (3)
/* use kfree_addr for iOS 13.x */
#define KFREE_ADDR                  (4)
/* use kfree_ext for iOS 14.x */
#define KFREE_EXT                   (5)
#define BCOPY_PHYS                  (6)
#define PHYSTOKV                    (7)
#define COPYIN                      (8)
#define COPYINSTR                   (9)
#define COPYOUT                     (10)
#define CURRENT_PROC                (11)
#define PROC_PID                    (12)
#define KERNEL_THREAD_START         (13)
#define THREAD_DEALLOCATE           (14)

/* The rest of these functions are from xnuspy */

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
#define KVTOPHYS                    (15)

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
#define UVTOPHYS                    (16)

/* int kprotect(uint64_t kaddr, uint64_t size, vm_prot_t prot)
 *
 * Change protections of static kernel memory at the page table level.
 *
 * Parameters:
 *  kaddr: kernel virtual address of target.
 *  size:  the number of bytes in the target region.
 *  prot:  protections to apply. Only VM_PROT_READ, VM_PROT_WRITE, and
 *         VM_PROT_EXECUTE are respected. If VM_PROT_EXECUTE is set, both
 *         the XN & PXN bits of the page table are turned off.
 *
 * Returns:
 *  Zero if successful, non-zero otherwise.
 */
#define KPROTECT                    (17)

/* int uprotect(uint64_t uaddr, uint64_t size, vm_prot_t prot)
 *
 * Change protections of user memory at the page table level.
 *
 * Parameters:
 *  uaddr: user virtual address of target.
 *  size:  the number of bytes in the target region.
 *  prot:  protections to apply. Only VM_PROT_READ, VM_PROT_WRITE, and
 *         VM_PROT_EXECUTE are respected. If VM_PROT_EXECUTE is set, both
 *         the XN & PXN bits of the page table are turned off.
 *
 * Returns:
 *  Zero if successful, non-zero otherwise.
 */
#define UPROTECT                    (18)

/* void kwrite(void *dst, void *buf, size_t sz)
 *
 * Write to kernel memory, using bcopy_phys. Useful if you want to write
 * to static kernel memory.
 *
 * Parameters:
 *  dst: kernel virtual address of destination.
 *  buf: kernel virtual address of data.
 *  sz:  how many bytes 'buf' is.
 */
#define KWRITE                      (19)

/* void kwrite_instr(uint64_t addr, uint32_t instr)
 *
 * Patch a single instruction of executable kernel code. This function handles
 * permissions, data cache cleaning, and instruction cache invalidation.
 *
 * Parameters:
 *  addr:  kernel virtual address.
 *  instr: new instruction for addr.
 */
#define KWRITE_INSTR                (20)

/* uint64_t *el0_ptep(uint64_t uaddr)
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
#define EL0_PTEP                    (21)

/* uint64_t *el1_ptep(uint64_t kaddr)
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
#define EL1_PTEP                    (22)

/* The next two functions abstract away the different kalloc/kfree pairs for
 * different iOS versions and keeps track of allocation sizes. This creates
 * an API somewhat like malloc/free. Every allocation must be a struct and
 * must start with an objhdr field followed by data. For example:
 *  
 *  struct mystruct {
 *      struct objhdr hdr;
 *      uint64_t a;
 *      float b;
 *  };
 *
 *  struct mystruct *mem = common_kalloc(sizeof(*mem));
 *
 *  if(!mem)
 *     <error>
 *
 *  mem->a = 99;
 *  mem->b = 4.0f;
 *
 *  common_kfree(mem);
 *
 * -------------------------------
 *
 * void *common_kalloc(size_t sz)
 *
 * Parameters:
 *  sz: allocation size.
 *
 * Returns:
 *  NULL if the chosen kalloc function fails, a pointer otherwise.
 *
 * -------------------------------
 *
 * void common_kfree(void *ptr)
 *
 * Parameters:
 *  ptr: a pointer to memory with an objhdr struct at the beginning.
 */
#define COMMON_KALLOC               (23)
#define COMMON_KFREE                (24)

struct objhdr {
    size_t sz;
};

#endif
