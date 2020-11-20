#ifndef MEM
#define MEM

__attribute__((naked)) uint64_t kvtophys(uint64_t);

void kwrite(void *, void *, size_t);

#endif
