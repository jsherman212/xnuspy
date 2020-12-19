#ifndef MEM
#define MEM

__attribute__((naked)) uint64_t kvtophys(uint64_t);
__attribute__((naked)) uint64_t uvtophys(uint64_t);

int kprotect(uint64_t, uint64_t, vm_prot_t);
int uprotect(uint64_t, uint64_t, vm_prot_t);

void kwrite(void *, void *, size_t);
void kwrite_instr(uint64_t, uint32_t);

void *common_kalloc(size_t);
void common_kfree(void *);

#endif
