#ifndef TRAMP
#define TRAMP

#include <stdint.h>

void generate_original_tramp(uint64_t, uint32_t *, uint32_t *);
void generate_replacement_tramp(uint32_t *);

#endif
