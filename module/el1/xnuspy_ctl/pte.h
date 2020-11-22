#ifndef PTE
#define PTE

typedef uint64_t pte_t;

pte_t *el0_ptep(uint64_t);
pte_t *el1_ptep(uint64_t);

#define ARM_PTE_PNX                 (0x0020000000000000uLL)

#endif
