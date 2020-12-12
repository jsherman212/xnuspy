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

    /* kprintf("%s: dst %#llx dst_phys %#llx buf %#llx buf_phys %#llx\n", __func__, */
    /*         dst, dst_phys, buf, buf_phys); */

    bcopy_phys(buf_phys, dst_phys, sz);

    /* kprintf("%s: still here after bcopy_phys\n", __func__); */
}

static int protect_common(uint64_t vaddr, uint64_t size, vm_prot_t prot,
        uint32_t el){
    /* memory must be readable */
    if(!(prot & VM_PROT_READ))
        return 1;

    uint64_t target_region_cur = vaddr & ~0x3fffuLL;
    uint64_t target_region_end = (vaddr + size) & ~0x3fffuLL;

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

        /* kprintf("%s: pte %#llx new_pte %#llx\n", __func__, *pte, new_pte); */

        kwrite(pte, &new_pte, sizeof(new_pte));

        target_region_cur += 0x4000;
    }

    asm volatile("isb");
    asm volatile("dsb ish");
    asm volatile("tlbi vmalle1");
    asm volatile("dsb ish");
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
    /* kprintf("%s: called with kaddr %#llx size %#llx prot %d\n", __func__, */
    /*         kaddr, size, prot); */

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
    /* kprintf("%s: called with uaddr %#llx size %#llx prot %d\n", __func__, */
    /*         uaddr, size, prot); */

    return protect_common(uaddr, size, prot, 0);
}

struct objhdr {
    size_t sz;
};

void *common_kalloc(size_t sz){
    struct objhdr *mem;

    if(iOS_version == iOS_13_x)
        mem = kalloc_canblock(&sz, 0, NULL);
    else
        mem = kalloc_external(sz);

    if(!mem)
        return NULL;

    mem->sz = sz;

    return mem;
}

void common_kfree(struct objhdr *obj){
    if(!obj)
        return;

    if(iOS_version == iOS_13_x)
        kfree_addr(obj);
    else
        kfree_ext(obj, ((struct objhdr *)obj)->sz);
}
