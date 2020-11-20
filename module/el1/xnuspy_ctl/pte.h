#ifndef PTE
#define PTE

#include <stdint.h>

uint64_t *el0_pte(uint64_t);
uint64_t *el1_pte(uint64_t);

#endif
