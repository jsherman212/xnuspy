#ifndef ASM
#define ASM

uint32_t assemble_b(uint64_t, uint64_t);
uint32_t assemble_bl(uint64_t, uint64_t);
uint32_t assemble_mov(uint8_t, uint32_t, uint32_t);

uint32_t bits(uint64_t, uint64_t, uint64_t);

uint64_t get_add_imm(uint32_t);

uint64_t get_adr_va_target(uint32_t *);
uint64_t get_adrp_add_va_target(uint32_t *);
uint64_t get_adrp_ldr_va_target(uint32_t *);

uint64_t get_branch_dst(uint32_t, uint32_t *);

#endif
