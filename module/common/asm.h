#ifndef ASM
#define ASM

uint64_t sign_extend(uint64_t, uint32_t);

uint32_t assemble_b(uint64_t, uint64_t);
uint32_t assemble_bl(uint64_t, uint64_t);
uint32_t assemble_csel(uint8_t, uint32_t, uint32_t, uint32_t, uint32_t);
uint32_t assemble_mov(uint8_t, uint32_t, uint32_t);
uint32_t assemble_immediate_add(uint8_t, uint8_t, uint32_t, uint32_t, uint32_t);
uint32_t assemble_immediate_cmp(uint8_t, uint8_t, uint32_t, uint32_t);

uint32_t bits(uint64_t, uint64_t, uint64_t);

uint64_t get_add_imm(uint32_t);

uint64_t get_adr_target(uint32_t *);
uint64_t get_adrp_target(uint32_t *);
uint64_t get_adrp_add_target(uint32_t *);
uint64_t get_adrp_ldr_target(uint32_t *);
uint64_t get_pc_rel_target(uint32_t *);

uint64_t get_branch_dst(uint32_t, uint32_t *);
uint32_t *get_branch_dst_ptr(uint32_t *);
uint64_t get_compare_and_branch_dst(uint32_t, uint32_t *);
uint64_t get_cond_branch_dst(uint32_t, uint32_t *);
uint64_t get_test_and_branch_dst(uint32_t, uint32_t *);

void write_blr(uint32_t, uint32_t *, uint64_t);

#endif
