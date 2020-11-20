#ifndef PTE
#define PTE

uint64_t *el0_ptep(uint64_t);
uint64_t *el1_ptep(uint64_t);

#define ARM_PTE_PNX                 (0x0020000000000000uLL)

#endif
