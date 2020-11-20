#include <stdint.h>
#include <stdlib.h>

#include "common.h"
#include "mem.h"

#define ARM_TTE_TABLE_MASK          (0x0000ffffffffc000)

#define ARM_16K_TT_L1_SHIFT         (36)
#define ARM_16K_TT_L2_SHIFT         (25)
#define ARM_16K_TT_L3_SHIFT         (14)

#define ARM_TT_L1_SHIFT             ARM_16K_TT_L1_SHIFT
#define ARM_TT_L2_SHIFT             ARM_16K_TT_L2_SHIFT
#define ARM_TT_L3_SHIFT             ARM_16K_TT_L3_SHIFT

static uint64_t *ptep(uint64_t ttbr, uint64_t addr){
    uint64_t vbase = phystokv(ttbr & ARM_TTE_TABLE_MASK);

    /* TODO finish */

}

uint64_t *el0_ptep(uint64_t uaddr){
    uint64_t ttbr0_el1 = 0;
    asm volatile("mrs %0, ttbr0_el1" : "=r" (ttbr0_el1));
    return ptep(ttbr0_el1, uaddr);
}

uint64_t *el1_ptep(uint64_t kaddr){
    uint64_t ttbr1_el1 = 0;
    asm volatile("mrs %0, ttbr1_el1" : "=r" (ttbr1_el1));
    return ptep(ttbr1_el1, kaddr);
}
