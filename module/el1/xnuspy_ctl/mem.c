#include <mach/mach.h>
#include <stdbool.h>
#include <stdint.h>

#include "externs.h"
#include "pte.h"

__attribute__ ((naked)) uint64_t kvtophys(uint64_t kaddr){
    asm volatile(""
            "mrs x1, DAIF\n"
            "msr DAIFSet, #0xf\n"
            "at s1e1r, x0\n"
            "mrs x2, par_el1\n"
            "msr DAIF, x1\n"
            "tbnz x2, 0x0, 5f\n"
            "and x2, x2, 0xfffffffff000\n"
            "and x1, x0, 0x3fff\n"
            "orr x0, x2, x1\n"
            "b 3f\n"
            "5:\n"
            "mov x0, xzr\n"
            "3:\n"
            "ret\n"
            );
}

__attribute__ ((naked)) uint64_t uvtophys(uint64_t kaddr){
    asm volatile(""
            "mrs x1, DAIF\n"
            "msr DAIFSet, #0xf\n"
            "at s1e0r, x0\n"
            "mrs x2, par_el1\n"
            "msr DAIF, x1\n"
            "tbnz x2, 0x0, 5f\n"
            "and x2, x2, 0xfffffffff000\n"
            "and x1, x0, 0x3fff\n"
            "orr x0, x2, x1\n"
            "b 3f\n"
            "5:\n"
            "mov x0, xzr\n"
            "3:\n"
            "ret\n"
            );
}

/* Write to kernel memory, using bcopy_phys.
 *
 * Parameters:
 *  dst: kernel virtual address of destination
 *  buf: kernel virtual address of data
 *  sz:  how many bytes 'buf' is
 *
 * Returns: nothing
 */
void kwrite(void *dst, void *buf, size_t sz){
    uint64_t dst_phys = kvtophys((uint64_t)dst);
    uint64_t buf_phys = kvtophys((uint64_t)buf);

    bcopy_phys(buf_phys, dst_phys, sz);
}

static int protect_common(uint64_t vaddr, uint64_t size, vm_prot_t prot,
        uint32_t el){
    /* memory must be readable */
    if(!(prot & VM_PROT_READ))
        return 1;

    /* Round size up to the nearest page if not already a multiple of PAGE_SIZE */
    if(size & 0xfff)
        size = (size + PAGE_SIZE) & ~(PAGE_SIZE - 1);

    uint64_t target_region_cur = vaddr & ~(PAGE_SIZE - 1);
    uint64_t target_region_end = (vaddr + size) & ~(PAGE_SIZE - 1);

    /* Determine the equivalent PTE protections of 'prot'. Assume caller only
     * wants read permissions. */
    uint64_t new_pte_ap;

    if(el == 0)
        new_pte_ap = ARM_PTE_AP(AP_RORO);
    else
        new_pte_ap = ARM_PTE_AP(AP_RONA);

    if(prot & VM_PROT_WRITE){
        if(el == 0)
            new_pte_ap = ARM_PTE_AP(AP_RWRW);
        else
            new_pte_ap = ARM_PTE_AP(AP_RWNA);
    }

    while(target_region_cur < target_region_end){
        pte_t *pte;

        if(el == 0)
            pte = el0_ptep(target_region_cur);
        else
            pte = el1_ptep(target_region_cur);

        pte_t new_pte = (*pte & ~ARM_PTE_APMASK) | new_pte_ap;

        if(prot & VM_PROT_EXECUTE)
            new_pte &= ~(ARM_PTE_NX | ARM_PTE_PNX);

        kwrite(pte, &new_pte, sizeof(new_pte));

        target_region_cur += PAGE_SIZE;
    }

    asm volatile("isb");
    asm volatile("dsb sy");
    asm volatile("tlbi vmalle1");
    asm volatile("dsb sy");
    asm volatile("isb");

    return 0;
}

/* Change protections of kernel memory at the page table level.
 *
 * Parameters:
 *  kaddr: kernel virtual address of target
 *  size:  the number of bytes in the target region
 *  prot:  protections to apply
 *
 * Returns:
 *  zero if successful, non-zero otherwise
 */
int kprotect(uint64_t kaddr, uint64_t size, vm_prot_t prot){
    return protect_common(kaddr, size, prot, 1);
}

/* Change protections of user memory at the page table level.
 *
 * Parameters:
 *  uaddr: EL0 virtual address of target
 *  size:  the number of bytes in the target region
 *  prot:  protections to apply
 *
 * Returns:
 *  zero if successful, non-zero otherwise
 */
int uprotect(uint64_t uaddr, uint64_t size, vm_prot_t prot){
    return protect_common(uaddr, size, prot, 0);
}

void kwrite_instr(uint64_t dst, uint32_t instr){
    kprotect(dst, sizeof(uint32_t), VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);

    *(uint32_t *)dst = instr;

    asm volatile("dc cvau, %0" : : "r" (dst));
    asm volatile("dsb ish");
    asm volatile("ic ivau, %0" : : "r" (dst));
    asm volatile("dsb ish");
    asm volatile("isb sy");

    kprotect(dst, sizeof(uint32_t), VM_PROT_READ | VM_PROT_EXECUTE);
}

struct unifiedhdr {
    size_t allocsz;
};

void *unified_kalloc(size_t sz){
    struct unifiedhdr *hdr;
    size_t allocsz = sizeof(*hdr) + sz;

    if(iOS_version == iOS_13_x)
        hdr = kalloc_canblock(&allocsz, 0, NULL);
    else
        hdr = kalloc_external(allocsz);

    if(!hdr)
        return NULL;

    hdr->allocsz = allocsz;

    /* future-proofing */
    return (void *)((uintptr_t)hdr + sizeof(*hdr));
}

void unified_kfree(void *ptr){
    if(!ptr)
        return;

    struct unifiedhdr *hdr = (struct unifiedhdr *)((uintptr_t)ptr - sizeof(*hdr));

    if(iOS_version == iOS_13_x)
        kfree_addr(hdr);
    else
        kfree_ext(NULL, hdr, hdr->allocsz);
}
