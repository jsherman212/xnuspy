#ifndef DISAS
#define DISAS

#include <stdint.h>

uint32_t assemble_b(uint64_t, uint64_t);
uint32_t assemble_bl(uint64_t, uint64_t);
uint32_t assemble_mov(uint8_t, uint32_t, uint32_t);

uint32_t bits(uint64_t, uint64_t, uint64_t);

uint64_t get_add_imm(uint32_t);

uint64_t get_adr_va_target(uint32_t *);
uint64_t get_adrp_add_va_target(uint32_t *);
uint64_t get_adrp_ldr_va_target(uint32_t *);

uint32_t *get_branch_dst_ptr(uint32_t, uint32_t *);

void write_blr(uint32_t, uint64_t, uint64_t);

#endif
