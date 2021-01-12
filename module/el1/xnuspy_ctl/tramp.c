#include <mach/mach.h>
#include <stdbool.h>
#include <stdint.h>

#include "externs.h"

#include "../../common/asm.h"

static void generate_b_cond_equivalent(uint32_t orig_instr, uint32_t **tramp,
        uint32_t *len_out){
    /* get the condition of this branch, and we'll use that to build
     * the CSEL */
    uint32_t cond = orig_instr & 0xf;

    /* LDR X16, #0x10 */
    *(*tramp)++ = 0x58000090;
    /* LDR X17, #0x14 */
    *(*tramp)++ = 0x580000b1;
    /* CSEL X16, X16, X17, <cond> */
    *(*tramp)++ = assemble_csel(1, 17, cond, 16, 16);
    /* BR X16 */
    *(*tramp)++ = 0xd61f0200;

    *len_out += 4;
}

static void generate_cbz_or_cbnz_equivalent(uint32_t orig_instr, uint32_t **tramp,
        uint32_t *len_out){
    uint8_t sf = orig_instr >> 31;
    uint32_t Rn = orig_instr & 0x1f;

    uint32_t cond;

    if(orig_instr & (1 << 24)){
        /* ne, because original instr is CBNZ */
        cond = 1;
    }
    else{
        /* eq, because original instr is CBZ */
        cond = 0;
    }

    /* LDR X16, #0x14 */
    *(*tramp)++ = 0x580000b0;
    /* LDR X17, #0x18 */
    *(*tramp)++ = 0x580000d1;
    /* CMP Rn, #0 */
    *(*tramp)++ = assemble_immediate_cmp(sf, 0, 0, Rn);
    /* CSEL X16, X16, X17, <cond> */
    *(*tramp)++ = assemble_csel(1, 17, cond, 16, 16);
    /* BR X16 */
    *(*tramp)++ = 0xd61f0200;

    *len_out += 5;
}

static void generate_tbz_or_tbnz_equivalent(uint32_t orig_instr, uint32_t **tramp,
        uint32_t *len_out){
    /* I'm not going to even try to understand the mind boggling encoding
     * of arm64 bitmask immediates. My head exploded while reading it. So I
     * will index inside an array of TST instrs and then set the bits
     * accordingly
     *
     * For tst[n]:
     *  n < 32: tst[n] == TST W0, (1 << (n-1))
     *  n > 32: tst[n] == TST X0, (1 << (n-1))
     */
    static const uint32_t tst[] = {
        0x7200001f, 0x721f001f, 0x721e001f, 0x721d001f, 0x721c001f, 0x721b001f,
        0x721a001f, 0x7219001f, 0x7218001f, 0x7217001f, 0x7216001f, 0x7215001f,
        0x7214001f, 0x7213001f, 0x7212001f, 0x7211001f, 0x7210001f, 0x720f001f,
        0x720e001f, 0x720d001f, 0x720c001f, 0x720b001f, 0x720a001f, 0x7209001f,
        0x7208001f, 0x7207001f, 0x7206001f, 0x7205001f, 0x7204001f, 0x7203001f,
        0x7202001f, 0x7201001f, 0xf260001f, 0xf25f001f, 0xf25e001f, 0xf25d001f,
        0xf25c001f, 0xf25b001f, 0xf25a001f, 0xf259001f, 0xf258001f, 0xf257001f,
        0xf256001f, 0xf255001f, 0xf254001f, 0xf253001f, 0xf252001f, 0xf251001f,
        0xf250001f, 0xf24f001f, 0xf24e001f, 0xf24d001f, 0xf24c001f, 0xf24b001f,
        0xf24a001f, 0xf249001f, 0xf248001f, 0xf247001f, 0xf246001f, 0xf245001f,
        0xf244001f, 0xf243001f, 0xf242001f, 0xf241001f,
    };

    uint32_t b5 = orig_instr >> 31;
    uint32_t b40 = bits(orig_instr, 19, 23);
    uint32_t tested_bit = (b5 << 5) | b40;
    uint32_t Rt = orig_instr & 0x1f;

    uint32_t cond;

    if(orig_instr & (1 << 24)){
        /* ne, because original instr is TBNZ */
        cond = 1;
    }
    else{
        /* eq, because original instr is TBZ */
        cond = 0;
    }

    uint32_t tst_instr = tst[tested_bit];

    if(b5)
        tst_instr |= 0x80000000;

    tst_instr |= (Rt << 5);

    /* LDR X16, #0x14 */
    *(*tramp)++ = 0x580000b0;
    /* LDR X17, #0x18 */
    *(*tramp)++ = 0x580000d1;
    /* TST Rn, #(1 << n) */
    *(*tramp)++ = tst_instr;
    /* CSEL X16, X16, X17, <cond> */
    *(*tramp)++ = assemble_csel(1, 17, cond, 16, 16);
    /* BR X16 */
    *(*tramp)++ = 0xd61f0200;

    *len_out += 5;
}

static void generate_adr_equivalent(uint32_t orig_instr, uint32_t *orig_instr_pc,
        uint32_t **tramp, uint32_t *len_out){
    uint64_t adr_target = get_adr_target(orig_instr_pc);
    /* uint64_t dist = (adr_target & ~0xfffuLL) - ((uintptr_t)tramp & ~0xfffuLL); */
    uint32_t Rd = orig_instr & 0x1f;
    /* uint32_t adrp = (1u << 31) | (1 << 28) | ((dist & 0x3000) << 17) | */
    /*     ((dist & 0x1ffffc000uLL) >> 9) | Rd; */

    uint64_t new_pc = (uint64_t)*tramp;

    /* ADRP Rn, #n@PAGE */
    /* *(*tramp)++ = adrp; */
    *(*tramp)++ = assemble_adrp(adr_target, new_pc, Rd);
    /* ADD Rn, Rn, #n@PAGEOFF */
    *(*tramp)++ = assemble_immediate_add(1, 0, adr_target & 0xfff, Rd, Rd);
    /* LDR X16, #0x8 */
    *(*tramp)++ = 0x58000050;
    /* BR X16 */
    *(*tramp)++ = 0xd61f0200;

    *len_out += 4;
}

static void generate_load_register_literal_equivalent(uint32_t orig_instr,
        uint64_t orig_instr_pc, uint32_t **tramp, uint32_t *len_out){
    uint32_t opc = orig_instr >> 30;
    uint8_t V = (orig_instr >> 26) & 1;
    int fp = V;
    int need_64bit = opc == 1 && !fp;
    int sw = opc == 2 && !fp;
    int prfm = opc == 3 && !fp;
    int32_t offset = sign_extend(bits(orig_instr, 5, 23) << 2, 21);
    uint32_t Rt = orig_instr & 0x1f;
    uint64_t label = (uint64_t)((int64_t)orig_instr_pc + offset);

    uint64_t new_pc = (uint64_t)*tramp;

    /* ADRP X16, <label>@PAGE */
    *(*tramp)++ = assemble_adrp(label, new_pc, 16);
    /* ADD X16, X16, <label>@PAGEOFF */
    *(*tramp)++ = assemble_immediate_add(1, 0, label & 0xfff, 16, 16);

    if(fp){
        uint32_t size;

        if(opc == 0 || opc == 1){
            if(opc == 0){
                /* Sn */
                size = 2;
            }
            else{
                /* Dn */
                size = 3;
            }

            /* Must be 1 for both Sn and Dn for immediate simd&fp ldr */
            opc = 1;
        }
        else if(opc == 2){
            /* Qn */
            size = 0;
            /* Must be 3 for immediate simd&fp ldr */
            opc = 3;
        }

        /* LDR (S|D|Q)n, [X16] */
        *(*tramp)++ = assemble_simd_fp_ldr(size, opc, 16, Rt);
    }
    else if(sw){
        /* LDRSW Rn, [X16] */
        *(*tramp)++ = assemble_ldrsw(16, Rt);
    }
    else if(prfm){
        /* PRFM <prfop>, [X16], Rt == prfop */
        *(*tramp)++ = assemble_immediate_prfm(16, Rt);
    }
    else{
        /* LDR Rn, [X16] */
        *(*tramp)++ = assemble_immediate_ldr(opc + 2, 16, Rt);
    }

    /* LDR X16, 0x8 */
    *(*tramp)++ = 0x58000050;
    /* BR X16 */
    *(*tramp)++ = 0xd61f0200;

    *len_out += 5;
}

/* This function generates a trampoline that'll represent the original
 * function. 'tramp' is expected to be an array of 10 uint32_t's, and
 * the length of the trampoline is returned through 'tramp_len_out'.
 *
 * 'addrof_second_instr' is to know where to branch back to. */
void generate_original_tramp(uint64_t addrof_second_instr,
        uint32_t *tramp, uint32_t *tramp_len_out){
    uint32_t *orig_instr_pc = (uint32_t *)(addrof_second_instr - 4);
    uint32_t orig_instr = *(uint32_t *)orig_instr_pc;

    uint32_t tramp_len = 0;

    if((orig_instr & 0xff000010) == 0x54000000){
        generate_b_cond_equivalent(orig_instr, &tramp, &tramp_len);

        uint64_t dst = get_cond_branch_dst(orig_instr, orig_instr_pc);

        ((uint64_t *)tramp)[0] = dst;
        ((uint64_t *)tramp)[1] = addrof_second_instr;

        tramp_len += 4;
    }
    else if((orig_instr & 0x7e000000) == 0x34000000){
        generate_cbz_or_cbnz_equivalent(orig_instr, &tramp, &tramp_len);

        uint64_t dst = get_compare_and_branch_dst(orig_instr, orig_instr_pc);

        ((uint64_t *)tramp)[0] = dst;
        ((uint64_t *)tramp)[1] = addrof_second_instr;

        tramp_len += 4;
    }
    else if((orig_instr & 0x7e000000) == 0x36000000){
        generate_tbz_or_tbnz_equivalent(orig_instr, &tramp, &tramp_len);

        uint64_t dst = get_test_and_branch_dst(orig_instr, orig_instr_pc);

        ((uint64_t *)tramp)[0] = dst;
        ((uint64_t *)tramp)[1] = addrof_second_instr;

        tramp_len += 4;
    }
    else if((orig_instr & 0x9f000000) == 0x10000000){
        generate_adr_equivalent(orig_instr, orig_instr_pc, &tramp, &tramp_len);

        *(uint64_t *)tramp = addrof_second_instr;
        /* ((uint64_t *)tramp)[0] = addrof_second_instr; */

        tramp_len += 2;
    }
    else if((orig_instr & 0xfc000000) == 0x14000000){
        /* B */
        uint64_t dst = get_branch_dst(orig_instr, orig_instr_pc);

        /* LDR X16, #0x8 */
        *tramp++ = 0x58000050;
        /* BR X16 */
        *tramp++ = 0xd61f0200;

        *(uint64_t *)tramp = dst;
        /* ((uint64_t *)tramp)[0] = dst; */

        tramp_len += 4;
    }
    else if((orig_instr & 0xfc000000) == 0x94000000){
        /* BL */
        uint64_t dst = get_branch_dst(orig_instr, orig_instr_pc);

        /* MOV X17, X30 */
        *tramp++ = 0xaa1e03f1;
        /* LDR X16, #0x14 */
        *tramp++ = 0x580000b0;
        /* BLR X16 */
        *tramp++ = 0xd63f0200;
        /* MOV X30, X17 */
        *tramp++ = 0xaa1103fe;
        /* LDR X16, #0x10 */
        *tramp++ = 0x58000090;
        /* BR X16 */
        *tramp++ = 0xd61f0200;

        ((uint64_t *)tramp)[0] = dst;
        ((uint64_t *)tramp)[1] = addrof_second_instr;

        tramp_len += 10;
    }
    else if((orig_instr & 0x38000000) == 0x18000000){
        generate_load_register_literal_equivalent(orig_instr,
                (uint64_t)orig_instr_pc, &tramp, &tramp_len);

        *(uint64_t *)tramp = addrof_second_instr;

        tramp_len += 2;
    }
    else{
        /* We have to fix up the immediate if we have an ADRP as the
         * original instruction. Otherwise, we just write the original
         * instruction to the trampoline. */
        uint32_t fixed_instr = orig_instr;

        if((orig_instr & 0x9f000000) == 0x90000000){
            /* page */
            uint64_t adrp_target = get_adrp_target(orig_instr_pc);

            /* uint64_t dist = (adrp_target & ~0xfffuLL) - ((uintptr_t)tramp & ~0xfffuLL); */

            uint32_t Rd = orig_instr & 0x1f;
            /* uint32_t adrp = (1u << 31) | (1 << 28) | ((dist & 0x3000) << 17) | */
            /*     ((dist & 0x1ffffc000) >> 9) | Rd; */

            fixed_instr = assemble_adrp(adrp_target, (uint64_t)tramp, Rd);
        }

        *tramp++ = fixed_instr;
        /* LDR X16, #0x8 */
        *tramp++ = 0x58000050;
        /* BR X16 */
        *tramp++ = 0xd61f0200;

        ((uint64_t *)tramp)[0] = addrof_second_instr;

        tramp_len += 5;
    }

    *tramp_len_out = tramp_len;
}

/* this function generates a replacement trampoline and returns it through
 * the 'tramp' parameter. 'tramp' is expected to be an array of 2 uint32_t's */
void generate_replacement_tramp(uint32_t *tramp){
    /* LDR X16, #-0x8 */
    tramp[0] = 0x58ffffd0;
    /* BR X16 */
    tramp[1] = 0xd61f0200;
}
