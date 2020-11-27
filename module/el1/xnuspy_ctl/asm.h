#ifndef ASM
#define ASM

uint32_t assemble_b(uint64_t, uint64_t);
uint32_t assemble_bl(uint64_t, uint64_t);
uint32_t assemble_csel(uint8_t, uint32_t, uint32_t, uint32_t, uint32_t);
uint32_t assemble_mov(uint8_t, uint32_t, uint32_t);
uint32_t assemble_immediate_add(uint8_t, uint8_t, uint32_t, uint32_t, uint32_t);
uint32_t assemble_immediate_cmp(uint8_t, uint8_t, uint32_t, uint32_t);

uint32_t bits(uint64_t, uint64_t, uint64_t);

uint64_t get_add_imm(uint32_t);

uint64_t get_adr_va_target(uint32_t *);
uint64_t get_adrp_va_target(uint32_t *);
uint64_t get_adrp_add_va_target(uint32_t *);
uint64_t get_adrp_ldr_va_target(uint32_t *);

uint64_t get_branch_dst(uint32_t, uint32_t *);
uint64_t get_compare_and_branch_dst(uint32_t, uint32_t *);
uint64_t get_cond_branch_dst(uint32_t, uint32_t *);
uint64_t get_test_and_branch_dst(uint32_t, uint32_t *);

#endif
