#ifndef MEM
#define MEM

__attribute__((naked)) uint64_t kvtophys(uint64_t);
__attribute__((naked)) uint64_t uvtophys(uint64_t);

void kwrite(void *, void *, size_t);

int kprotect(uint64_t, uint64_t, vm_prot_t);
int uprotect(uint64_t, uint64_t, vm_prot_t);

/* struct objhdr *common_kalloc(size_t); */
/* void common_kfree(struct objhdr *); */

void *common_kalloc(size_t);
void common_kfree(void *);

#endif
