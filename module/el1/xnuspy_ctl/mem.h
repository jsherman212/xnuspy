#ifndef MEM
#define MEM

__attribute__((naked)) uint64_t kvtophys(uint64_t);
__attribute__((naked)) uint64_t uvtophys(uint64_t);

void dcache_clean_PoU(void *address, size_t size);
void icache_invalidate_PoU(void *address, size_t size);

int kprotect(void *, uint64_t, vm_prot_t);
int uprotect(void *, uint64_t, vm_prot_t);

void kwrite_static(void *, void *, size_t);
void kwrite_instr(uint64_t, uint32_t);

void *unified_kalloc(size_t);
void unified_kfree(void *);

#endif
