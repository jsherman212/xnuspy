#include <stdint.h>

uint64_t sign_extend(uint64_t number, uint32_t numbits /* signbit */){
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
    return (5u << 26) | imm26;
}

uint32_t assemble_bl(uint64_t from, uint64_t to){
    uint32_t imm26 = ((to - from) >> 2) & 0x3ffffff;
    return (37u << 26) | imm26;
}

uint32_t assemble_csel(uint8_t sf, uint32_t Rm, uint32_t cond,
        uint32_t Rn, uint32_t Rd){
    return (((uint32_t)sf << 31) | (0xd4 << 21) | (Rm << 16) | (cond << 12) | (Rn << 5) | Rd);
}

uint32_t assemble_immediate_add(uint8_t sf, uint8_t sh, uint32_t imm12,
        uint32_t Rn, uint32_t Rd){
    return (((uint32_t)sf << 31) | (0x22 << 23) | ((uint32_t)sh << 22) | (imm12 << 10) | (Rn << 5) | Rd);
}

/* this is really just SUBS RZR, Rn, #imm */
uint32_t assemble_immediate_cmp(uint8_t sf, uint8_t sh, uint32_t imm12,
        uint32_t Rn){
    return (((uint32_t)sf << 31) | (0xe2 << 23) | ((uint32_t)sh << 22) | (imm12 << 10) | (Rn << 5) | 0x1f);
}

uint32_t assemble_mov(uint8_t sf, uint32_t imm, uint32_t Rd){
    uint32_t imm16 = imm & 0xffff;
    uint16_t hw = (uint16_t)(imm & 0x30000);

    return (((uint32_t)sf << 31) | (0xa5 << 23) | ((uint32_t)hw << 21) | (imm16 << 5) | Rd);
}

/* resolves shift also */
uint64_t get_add_imm(uint32_t add){
    uint64_t imm = 0;

    uint8_t sf = (uint8_t)(add & 0x80000000);
    uint8_t sh = (add & 0x200000) >> 22;
    uint32_t imm12 = (add & 0x3ffc00) >> 10;

    if(sh)
        imm = imm12 << 12;
    else
        imm = imm12;

    return imm;
}

uint64_t get_adr_target(uint32_t *adrp){
    uint32_t immlo = (uint32_t)bits(*adrp, 29, 30);
    uint32_t immhi = (uint32_t)bits(*adrp, 5, 23);

    return sign_extend((immhi << 2) | immlo, 21) + (uintptr_t)adrp;
}

uint64_t get_adrp_target(uint32_t *adrpp){
    uint32_t adrp = *adrpp;

    uint32_t immlo = (uint32_t)bits(adrp, 29, 30);
    uint32_t immhi = (uint32_t)bits(adrp, 5, 23);

    return sign_extend(((immhi << 2) | immlo) << 12, 32) +
        ((uintptr_t)adrpp & ~0xfffuLL);
}

uint64_t get_adrp_add_target(uint32_t *adrpp){
    uint32_t adrp = *adrpp;
    uint32_t add = *(adrpp + 1);

    int64_t addr = (int64_t)get_adrp_target(adrpp);

    return (uint64_t)(addr + (int64_t)bits(add, 10, 21));
}

uint64_t get_adrp_ldr_target(uint32_t *adrpp){
    uint32_t adrp = *adrpp;
    uint32_t ldr = *(adrpp + 1);

    int64_t addr = (int64_t)get_adrp_target(adrpp);

    /* for LDR, assuming unsigned immediate
     *
     * no shift on LDRB variants
     */
    uint32_t shift = 0;

    uint32_t size = (uint32_t)bits(ldr, 30, 31);
    uint32_t V = (uint32_t)bits(ldr, 26, 26);
    uint32_t opc = (uint32_t)bits(ldr, 22, 23);
    uint32_t imm12 = (uint32_t)bits(ldr, 10, 21);

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
    int64_t pimm = (int64_t)sign_extend(imm12, 12) << shift;

    return (uint64_t)(addr + pimm);
}

uint64_t get_pc_rel_target(uint32_t *adrpp){
    if(((adrpp[1] >> 25) & 5) == 4)
        /* only ldr */
        return get_adrp_ldr_target(adrpp);
    else if(*adrpp & 0x80000000)
        return get_adrp_add_target(adrpp);
    else
        return get_adr_target(adrpp);
}

uint64_t get_branch_dst(uint32_t branch, uint32_t *pc){
    intptr_t signed_pc = (intptr_t)pc;
    int32_t imm26 = (int32_t)sign_extend(bits(branch, 0, 25) << 2, 28);

    return (uint64_t)(signed_pc + imm26);
}

uint32_t *get_branch_dst_ptr(uint32_t *pc){
    uint32_t branch = *pc;
    intptr_t signed_pc = (intptr_t)pc;

    int32_t imm26 = (int32_t)sign_extend(bits(branch, 0, 25) << 2, 28);

    return (uint32_t *)(signed_pc + imm26);
}

uint64_t get_compare_and_branch_dst(uint32_t cab, uint32_t *pc){
    intptr_t signed_pc = (intptr_t)pc;
    int32_t imm19 = (int32_t)sign_extend(bits(cab, 5, 23) << 2, 21);

    return (uint64_t)(signed_pc + imm19);
}

uint64_t get_cond_branch_dst(uint32_t branch, uint32_t *pc){
    intptr_t signed_pc = (intptr_t)pc;
    int32_t imm19 = (int32_t)sign_extend(bits(branch, 5, 23) << 2, 21);

    return (uint64_t)(signed_pc + imm19);
}

uint64_t get_test_and_branch_dst(uint32_t tab, uint32_t *pc){
    intptr_t signed_pc = (intptr_t)pc;
    int32_t imm14 = (int32_t)sign_extend(bits(tab, 5, 18) << 2, 16);

    return (uint64_t)(signed_pc + imm14);
}

void write_blr(uint32_t reg, uint32_t *from, uint64_t to){
    /* movz */
    *(from++) = (uint32_t)(0xd2800000 | ((to & 0xffff) << 5) | reg);
    /* movk */
    *(from++) = (uint32_t)(0xf2800000 | (1 << 21) | (((to >> 16) & 0xffff) << 5) | reg);
    /* movk */
    *(from++) = (uint32_t)(0xf2800000 | (2 << 21) | (((to >> 32) & 0xffff) << 5) | reg);
    /* movk */
    *(from++) = (uint32_t)(0xf2800000 | (3 << 21) | (((to >> 48) & 0xffff) << 5) | reg);
    /* blr */
    *(from++) = (uint32_t)(0xd63f0000 | (reg << 5));
}
