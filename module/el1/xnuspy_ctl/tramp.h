#ifndef TRAMP
#define TRAMP

void generate_original_tramp(uint64_t, void (*)(void), void (*)(void),
        uint32_t *, uint32_t *);
void generate_replacement_tramp(void (*)(void), void (*)(void), uint32_t *);

#endif
