#include <errno.h>
#include <mach/mach.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>

#include <xnuspy/xnuspy_structs.h>

#include <xnuspy/el1/debug.h>
#include <xnuspy/el1/externs.h>
#include <xnuspy/el1/pte.h>
#include <xnuspy/el1/utils.h>

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

void dcache_clean_PoU(void *address, size_t size){
    const size_t cache_line_size = 64;

    size = (size + cache_line_size) & ~(cache_line_size - 1);

    uint64_t start = ((uint64_t)address & ~(cache_line_size - 1));
    uint64_t end = start + size;

    asm volatile("isb sy");

    do {
        asm volatile(""
                "dc cvau, %0\n"
                "dsb ish\n"
                "isb sy\n"
                : : "r" (start));

        start += cache_line_size;
    } while (start < end);
}

void icache_invalidate_PoU(void *address, size_t size){
    const size_t cache_line_size = 64;

    size = (size + cache_line_size) & ~(cache_line_size - 1);

    uint64_t start = ((uint64_t)address & ~(cache_line_size - 1));
    uint64_t end = start + size;

    asm volatile("isb sy");

    do {
        asm volatile(""
                "ic ivau, %0\n"
                "dsb ish\n"
                "isb sy\n"
                : : "r" (start));

        start += cache_line_size;
    } while (start < end);
}

/* Write to static kernel memory, using bcopy_phys.
 *
 * Parameters:
 *  dst: kernel virtual address of destination
 *  buf: kernel virtual address of data
 *  sz:  how many bytes 'buf' is
 *
 * Returns: nothing
 */
void kwrite_static(void *dst, void *buf, size_t sz){
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
        pte_t *ptep;

        if(el == 0)
            ptep = el0_ptep((void *)target_region_cur);
        else
            ptep = el1_ptep((void *)target_region_cur);

        pte_t new_pte = (*ptep & ~ARM_PTE_APMASK) | new_pte_ap;

        new_pte &= ~(ARM_PTE_NX | ARM_PTE_PNX);

        if(prot & VM_PROT_EXECUTE){
            if(el == 0)
                new_pte |= ARM_PTE_PNX;
            else
                new_pte |= ARM_PTE_NX;
        }

        kwrite_static(ptep, &new_pte, sizeof(new_pte));

        target_region_cur += PAGE_SIZE;
    }

    tlb_flush();

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
int kprotect(void *kaddr, uint64_t size, vm_prot_t prot){
    return protect_common((uint64_t)kaddr, size, prot, 1);
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
int uprotect(void *uaddr, uint64_t size, vm_prot_t prot){
    return protect_common((uint64_t)uaddr, size, prot, 0);
}

void kwrite_instr(uint64_t dst, uint32_t instr){
    kprotect((void *)dst, sizeof(uint32_t), VM_PROT_READ | VM_PROT_WRITE |
            VM_PROT_EXECUTE);

    *(uint32_t *)dst = instr;

    dcache_clean_PoU((void *)dst, sizeof(uint32_t));
    icache_invalidate_PoU((void *)dst, sizeof(uint32_t));

    kprotect((void *)dst, sizeof(uint32_t), VM_PROT_READ | VM_PROT_EXECUTE);
}

static int mkshmem_common(uint64_t start, uint64_t sz, vm_prot_t prot,
        struct _vm_map *from, struct _vm_map *to,
        struct xnuspy_shmem *shmemp){
    int retval = 0;

    kern_return_t kret = vm_map_wire_external(from, start, sz,
            VM_PROT_READ, from != *kernel_mapp);

    if(kret){
        SPYDBG("%s: vm_map_wire_external failed when wiring down "
                "[%#llx,%#llx): %#x\n", __func__, start, start+sz, kret);
        retval = mach_to_bsd_errno(kret);
        goto failed;
    }

    vm_prot_t shm_prot = VM_PROT_READ;

    /* ipc_port_t */
    void *shm_entry = NULL;

    uint64_t sz_before = sz;

    kret = _mach_make_memory_entry_64(from, &sz, start,
            MAP_MEM_VM_SHARE | shm_prot, &shm_entry, NULL);

    if(kret){
        SPYDBG("%s: mach_make_memory_entry_64 failed: %d\n", __func__, kret);
        retval = mach_to_bsd_errno(kret);
        goto failed_unwire_orig_pages;
    }

    if(sz_before != sz){
        SPYDBG("%s: did not map the entirety of sz? got %#llx, "
                "expected %#llx\n", __func__, sz, sz_before);
        /* Probably not the best option */
        retval = EIO;
        goto failed_dealloc_shm_entry;
    }

    uint64_t shm_addr = 0;

    kret = mach_vm_map_external(to, &shm_addr, sz, 0, VM_FLAGS_ANYWHERE,
            shm_entry, 0, 0, shm_prot, shm_prot, VM_INHERIT_NONE);

    if(kret){
        SPYDBG("%s: mach_vm_map_external failed: %d\n", __func__, kret);
        retval = mach_to_bsd_errno(kret);
        goto failed_dealloc_shm_entry;
    }

    kret = vm_map_wire_external(to, shm_addr, shm_addr + sz,
            shm_prot, to != *kernel_mapp);

    if(kret){
        SPYDBG("%s: vm_map_wire_external failed: %d\n", __func__, kret);
        retval = mach_to_bsd_errno(kret);
        goto failed_dealloc_created_mapping;
    }

    shmemp->shm_base = (void *)shm_addr;
    shmemp->shm_sz = sz;
    shmemp->shm_entry = shm_entry;
    shmemp->shm_map_from = from;
    shmemp->shm_map_to = to;

    vm_map_reference(shmemp->shm_map_from);
    vm_map_reference(shmemp->shm_map_to);

    /* Set requested protections on the new mapping. We leave the
     * original pages alone. */
    if(to == *kernel_mapp)
        kprotect(shmemp->shm_base, shmemp->shm_sz, prot);
    else
        uprotect(shmemp->shm_base, shmemp->shm_sz, prot);

    return 0;

failed_dealloc_created_mapping:
    _vm_deallocate(to, shm_addr, sz);
failed_dealloc_shm_entry:
    ipc_port_release_send_wrapper(shm_entry);
failed_unwire_orig_pages:
    vm_map_unwire(from, start, start + sz, from != *kernel_mapp);
failed:
    return retval;
}

/* This maps kernel pages into userspace as shared memory.
 * On success, it returns 0 and sets the two output parameters.
 * On failure, it returns non-zero. */
int mkshmem_ktou(uint64_t kaddr, uint64_t sz, vm_prot_t prot,
        struct xnuspy_shmem *shmemp){
    return mkshmem_common(kaddr, sz, prot, *kernel_mapp,
            current_map(), shmemp);
}

/* Same as the above function, but this maps userspace pages into the
 * kernel as shared memory. */
int mkshmem_utok(uint64_t uaddr, uint64_t sz, vm_prot_t prot,
        struct xnuspy_shmem *shmemp){
    return mkshmem_common(uaddr, sz, prot, current_map(),
            *kernel_mapp, shmemp);
}

/* Allows specification of source/destination maps */
int mkshmem_raw(uint64_t addr, uint64_t sz, vm_prot_t prot,
        struct _vm_map *from, struct _vm_map *to,
        struct xnuspy_shmem *shmemp){
    return mkshmem_common(addr, sz, prot, from, to, shmemp);
}

int shmem_destroy(struct xnuspy_shmem *shmemp){
    int retval = 0;

    ipc_port_release_send_wrapper(shmemp->shm_entry);

    kern_return_t kret = vm_map_unwire(shmemp->shm_map_to,
            (uint64_t)shmemp->shm_base,
            (uint64_t)shmemp->shm_base + shmemp->shm_sz,
            shmemp->shm_map_to != *kernel_mapp);

    /* I don't know if it's safe to deallocate if we failed to unwire.
     * But if this failed because we tried to unwire some userspace
     * mapping after its task has died, then the pages of the userspace
     * shmem won't be in its vm_map anymore. That's fine, we'll just
     * release the references we hold on both maps. */
    if(kret){
        SPYDBG("%s: vm_map_unwire failed: %#x\n", __func__, kret);
        retval = mach_to_bsd_errno(kret);
        goto out;
    }

    kret = _vm_deallocate(shmemp->shm_map_to, (uint64_t)shmemp->shm_base,
            shmemp->shm_sz);

    if(kret){
        SPYDBG("%s: vm_deallocate failed: %#x\n", __func__, kret);
        retval = mach_to_bsd_errno(kret);
    }

out:;
    vm_map_deallocate(shmemp->shm_map_from);
    vm_map_deallocate(shmemp->shm_map_to);

    return retval;
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

    return hdr + 1;
}

void unified_kfree(void *ptr){
    if(!ptr)
        return;

    /* future-proofing */
    struct unifiedhdr *hdr = (struct unifiedhdr *)((uintptr_t)ptr - sizeof(*hdr));

    if(iOS_version == iOS_13_x)
        kfree_addr(hdr);
    else
        kfree_ext(NULL, hdr, hdr->allocsz);
}
