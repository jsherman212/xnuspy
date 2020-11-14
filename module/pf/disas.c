#include <stdint.h>

#include "../common/pongo.h"

static uint64_t sign_extend(uint64_t number, uint32_t numbits /* signbit */){
    if(number & ((uint64_t)1 << (numbits - 1)))
        return number | ~(((uint64_t)1 << numbits) - 1);

    return number;
}

uint64_t bits(uint64_t number, uint64_t start, uint64_t end){
    uint64_t amount = (end - start) + 1;
    uint64_t mask = (((uint64_t)1 << amount) - 1) << start;

    return (number & mask) >> start;
}

uint32_t assemble_b(uint64_t from, uint64_t to){
    uint32_t imm26 = ((to - from) >> 2) & 0x3ffffff;
    return (5 << 26) | imm26;
}

uint32_t assemble_bl(uint64_t from, uint64_t to){
    uint32_t imm26 = ((to - from) >> 2) & 0x3ffffff;
    return (37 << 26) | imm26;
}

uint32_t assemble_mov(uint8_t sf, uint32_t imm, uint32_t Rd){
    uint32_t imm16 = imm & 0xffff;
    uint16_t hw = imm & 0x30000;

    return ((sf << 31) | (0xa5 << 23) | (hw << 21) | (imm16 << 5) | Rd);
}

/* resolves shift also */
uint64_t get_add_imm(uint32_t add){
    uint64_t imm = 0;

    uint8_t sf = add & 0x80000000;
    uint8_t sh = (add & 0x200000) >> 22;
    uint32_t imm12 = (add & 0x3ffc00) >> 10;

    if(sh)
        imm = imm12 << 12;
    else
        imm = imm12;

    return imm;
}

uint64_t get_adr_va_target(uint32_t *adrp){
    uint32_t immlo = bits(*adrp, 29, 30);
    uint32_t immhi = bits(*adrp, 5, 23);

    return sign_extend((immhi << 2) | immlo, 21) + xnu_ptr_to_va(adrp);
}

uint64_t get_adrp_add_va_target(uint32_t *adrpp){
    uint32_t adrp = *adrpp;
    uint32_t add = *(adrpp + 1);

    uint32_t immlo = bits(adrp, 29, 30);
    uint32_t immhi = bits(adrp, 5, 23);

    return sign_extend(((immhi << 2) | immlo) << 12, 32) +
        (xnu_ptr_to_va(adrpp) & ~0xfffuLL) + bits(add, 10, 21);
}

uint64_t get_adrp_ldr_va_target(uint32_t *adrpp){
    uint32_t adrp = *adrpp;
    uint32_t ldr = *(adrpp + 1);

    uint32_t immlo = bits(adrp, 29, 30);
    uint32_t immhi = bits(adrp, 5, 23);

    /* takes care of ADRP */
    uint64_t addr_va = sign_extend(((immhi << 2) | immlo) << 12, 32) +
        (xnu_ptr_to_va(adrpp) & ~0xfffuLL);

    /* for LDR, assuming unsigned immediate
     *
     * no shift on LDRB variants
     */
    uint32_t shift = 0;

    uint32_t size = bits(ldr, 30, 31);
    uint32_t V = bits(ldr, 26, 26);
    uint32_t opc = bits(ldr, 22, 23);
    uint32_t imm12 = bits(ldr, 10, 21);

    uint32_t ldr_type = (size << 3) | (V << 2) | opc;

    /* floating point variant */
    if(V)
        shift = ((opc >> 1) << 2) | size;
    /* LDRH || LDRSH (64 bit) || (LDRSH (32 bit) */
    else if(ldr_type == 9 || ldr_type == 10 || ldr_type == 11)
        shift = 1;
    /* LDRSW */
    else if(ldr_type == 18)
        shift = 2;
    /* LDR (32 bit) || LDR (64 bit) */
    else if(ldr_type == 17 || ldr_type == 25)
        shift = size;

    /* takes care of LDR */
    uint64_t pimm = sign_extend(imm12, 12) << shift;

    return addr_va + pimm;
}

uint32_t *get_branch_dst_ptr(uint32_t branch, uint32_t *pc){
    intptr_t signed_pc = (intptr_t)pc;
    int32_t imm26 = sign_extend(bits(branch, 0, 25) << 2, 28);

    return (uint32_t *)(signed_pc + imm26);
}

void write_blr(uint32_t reg, uint64_t from, uint64_t to){
    uint32_t *cur = (uint32_t *)from;

    /* movz */
    *(cur++) = (uint32_t)(0xd2800000 | ((to & 0xffff) << 5) | reg);
    /* movk */
    *(cur++) = (uint32_t)(0xf2800000 | (1 << 21) | (((to >> 16) & 0xffff) << 5) | reg);
    /* movk */
    *(cur++) = (uint32_t)(0xf2800000 | (2 << 21) | (((to >> 32) & 0xffff) << 5) | reg);
    /* movk */
    *(cur++) = (uint32_t)(0xf2800000 | (3 << 21) | (((to >> 48) & 0xffff) << 5) | reg);
    /* blr */
    *(cur++) = (uint32_t)(0xd63f0000 | (reg << 5));
}
