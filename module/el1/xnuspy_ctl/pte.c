#include <stdint.h>

#include "externs.h"
#include "pte.h"

static pte_t *ptep(uint64_t ttbr, uint64_t addr){
    uint64_t l1_table = phystokv(ttbr & 0xfffffffffffe);
    uint64_t l1_idx = (addr >> ARM_TT_L1_SHIFT) & 0x7;
    pte_t *l1_ttep = (uint64_t *)(l1_table + (0x8 * l1_idx));

    uint64_t l2_table = phystokv(*l1_ttep & ARM_TTE_TABLE_MASK);
    uint64_t l2_idx = (addr >> ARM_TT_L2_SHIFT) & 0x7ff;
    pte_t *l2_ttep = (uint64_t *)(l2_table + (0x8 * l2_idx));

    uint64_t l3_table = phystokv(*l2_ttep & ARM_TTE_TABLE_MASK);
    uint64_t l3_idx = (addr >> ARM_TT_L3_SHIFT) & 0x7ff;

    return (pte_t *)(l3_table + (0x8 * l3_idx));
}

pte_t *el0_ptep(void *uaddr){
    uint64_t ttbr0_el1;
    asm volatile("mrs %0, ttbr0_el1" : "=r" (ttbr0_el1));
    return ptep(ttbr0_el1, (uint64_t)uaddr);
}

pte_t *el1_ptep(void *kaddr){
    uint64_t ttbr1_el1;
    asm volatile("mrs %0, ttbr1_el1" : "=r" (ttbr1_el1));
    return ptep(ttbr1_el1, (uint64_t)kaddr);
}

__attribute__ ((naked)) void tlb_flush(void){
    asm(""
        "isb sy\n"
        "dsb sy\n"
        "tlbi vmalle1\n"
        "dsb sy\n"
        "isb sy\n"
        "ret\n"
       );
}
