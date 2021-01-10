#include <mach/mach.h>
#include <stdbool.h>
#include <stdint.h>
#include "unistd.h"

#include "asm.h"
#include "externs.h"

static void generate_b_cond_equivalent(uint32_t orig_instr, uint32_t **tramp,
        uint32_t *len_out){
    /* get the condition of this branch, and we'll use that to build
     * the CSEL */
    uint32_t cond = orig_instr & 0xf;

    /* ADR X16, #0x14 */
    *(*tramp)++ = 0x100000b0;
    /* ADR X17, #0x18 */
    *(*tramp)++ = 0x100000d1;
    /* CSEL X16, X16, X17, <cond> */
    *(*tramp)++ = assemble_csel(1, 17, cond, 16, 16);
    /* LDR X16, [X16] */
    *(*tramp)++ = 0xf9400210;
    /* BR X16 */
    *(*tramp)++ = 0xd61f0200;

    *len_out += 5;
}

static void generate_cbz_or_cbnz_equivalent(uint32_t orig_instr, uint32_t **tramp,
        uint32_t *len_out){
    uint8_t sf = orig_instr >> 31;
    uint32_t Rn = orig_instr & 0x1f;

    /* assume cond for CSEL will be eq (orig_instr == CBZ) */
    uint32_t cond;

    if(orig_instr & (1 << 24))
        /* ne, because original instr is CBNZ */
        cond = 1;
    else
        /* eq, because original instr is CBZ */
        cond = 0;

    /* ADR X16, #0x18 */
    *(*tramp)++ = 0x100000d0;
    /* ADR X17, #0x1c */
    *(*tramp)++ = 0x100000f1;
    /* CMP Rn, #0 */
    *(*tramp)++ = assemble_immediate_cmp(sf, 0, 0, Rn);
    /* CSEL X16, X16, X17, <cond> */
    *(*tramp)++ = assemble_csel(1, 17, cond, 16, 16);
    /* LDR X16, [X16] */
    *(*tramp)++ = 0xf9400210;
    /* BR X16 */
    *(*tramp)++ = 0xd61f0200;

    *len_out += 6;
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

    uint8_t b5 = orig_instr >> 31;
    uint32_t b40 = bits(orig_instr, 19, 23);
    uint32_t tested_bit = (b5 << 5) | b40;
    uint32_t Rt = orig_instr & 0x1f;

    uint32_t cond;

    if(orig_instr & (1 << 24))
        /* ne, because original instr is TBNZ */
        cond = 1;
    else
        /* eq, because original instr is TBZ */
        cond = 0;

    uint32_t tst_instr = tst[tested_bit];

    if(b5)
        tst_instr |= 0x80000000;

    tst_instr |= (Rt << 5);

    /* ADR X16, #0x18 */
    *(*tramp)++ = 0x100000d0;
    /* ADR X17, #0x1c */
    *(*tramp)++ = 0x100000f1;
    /* TST Rn, #(1 << n) */
    *(*tramp)++ = tst_instr;
    /* CSEL X16, X16, X17, <cond> */
    *(*tramp)++ = assemble_csel(1, 17, cond, 16, 16);
    /* LDR X16, [X16] */
    *(*tramp)++ = 0xf9400210;
    /* BR X16 */
    *(*tramp)++ = 0xd61f0200;

    *len_out += 6;
}

static void generate_adr_equivalent(uint32_t orig_instr, uint64_t orig_instr_pc,
        uint32_t **tramp, uint32_t *len_out){
    uint64_t adr_va_target = get_adr_va_target((uint32_t *)orig_instr_pc);
    uint64_t dist = (adr_va_target & ~0xfffLL) - ((uintptr_t)tramp & ~0xfffLL);
    uint32_t Rd = orig_instr & 0x1f;
    uint32_t adrp = (1 << 31) | (1 << 28) | ((dist & 0x3000) << 17) |
        ((dist & 0x1ffffc000) >> 9) | Rd;

    /* ADRP Rn, #n@PAGE */
    *(*tramp)++ = adrp;
    /* ADD Rn, Rn, #n@PAGEOFF */
    *(*tramp)++ = assemble_immediate_add(1, 0, adr_va_target & 0xfff, Rd, Rd);
    /* ADR X16, #0xc */
    *(*tramp)++ = 0x10000070;
    /* LDR X16, [X16] */
    *(*tramp)++ = 0xf9400210;
    /* BR X16 */
    *(*tramp)++ = 0xd61f0200;

    *len_out += 5;
}

/* This function generates a trampoline that'll represent the original
 * function. 'tramp' is expected to be an array of 12 uint32_t's, and
 * the length of the trampoline is returned through 'tramp_len_out'.
 *
 * 'addrof_second_instr' is to know where to branch back to. */
void generate_original_tramp(uint64_t addrof_second_instr,
        uint32_t *tramp, uint32_t *tramp_len_out){
    uint32_t orig_instr = *(uint32_t *)(addrof_second_instr - 4);

    uint32_t tramp_len = 0;

    if((orig_instr & 0xff000010) == 0x54000000){
        generate_b_cond_equivalent(orig_instr, &tramp, &tramp_len);

        uint64_t dst = get_cond_branch_dst(orig_instr,
                (uint32_t *)(addrof_second_instr - 4));

        ((uint64_t *)tramp)[0] = dst;
        ((uint64_t *)tramp)[1] = addrof_second_instr;

        tramp_len += 4;
    }
    else if((orig_instr & 0x7e000000) == 0x34000000){
        generate_cbz_or_cbnz_equivalent(orig_instr, &tramp, &tramp_len);

        uint64_t dst = get_compare_and_branch_dst(orig_instr,
                (uint32_t *)(addrof_second_instr - 4));

        ((uint64_t *)tramp)[0] = dst;
        ((uint64_t *)tramp)[1] = addrof_second_instr;

        tramp_len += 4;
    }
    else if((orig_instr & 0x7e000000) == 0x36000000){
        generate_tbz_or_tbnz_equivalent(orig_instr, &tramp, &tramp_len);

        uint64_t dst = get_test_and_branch_dst(orig_instr,
                (uint32_t *)(addrof_second_instr - 4));

        ((uint64_t *)tramp)[0] = dst;
        ((uint64_t *)tramp)[1] = addrof_second_instr;

        tramp_len += 4;
    }
    else if((orig_instr & 0x9f000000) == 0x10000000){
        /* turn adr into adrp/add pair */
        generate_adr_equivalent(orig_instr, addrof_second_instr - 4,
                &tramp, &tramp_len);

        ((uint64_t *)tramp)[0] = addrof_second_instr;

        tramp_len += 2;
    }
    else{
        /* Otherwise, we have to fix up an immediate if any of the
         * following were the original instruction:
         *  - ADRP
         *  - B
         *  - BL
         */
        uint32_t fixed_instr = orig_instr;

        if((orig_instr & 0x9f000000) == 0x90000000){
            uint64_t adrp_va_target =
                get_adrp_va_target((uint32_t *)(addrof_second_instr - 4));

            uint64_t dist = (adrp_va_target & ~0xfff) - ((uintptr_t)tramp & ~0xfff);

            uint32_t Rd = orig_instr & 0x1f;
            uint32_t adrp = (1 << 31) | (1 << 28) | ((dist & 0x3000) << 17) |
                ((dist & 0x1ffffc000) >> 9) | Rd;

            fixed_instr = adrp;
        }
        else if((orig_instr & 0xfc000000) == 0x14000000){
            uint64_t dst = get_branch_dst(orig_instr,
                    (uint32_t *)(addrof_second_instr - 4));

            fixed_instr = assemble_b((uint64_t)tramp, dst);
        }
        else if((orig_instr & 0xfc000000) == 0x94000000){
            uint64_t dst = get_branch_dst(orig_instr,
                    (uint32_t *)(addrof_second_instr - 4));

            fixed_instr = assemble_bl((uint64_t)tramp, dst);
        }

        *tramp++ = fixed_instr;
        /* ADR X16, #0xc */
        *tramp++ = 0x10000070;
        /* LDR X16, [X16] */
        *tramp++ = 0xf9400210;
        /* BR X16 */
        *tramp++ = 0xd61f0200;

        ((uint64_t *)tramp)[0] = addrof_second_instr;

        tramp_len += 6;
    }

    *tramp_len_out = tramp_len;
}

/* this function generates a replacement trampoline and returns it through
 * the 'tramp' parameter. 'tramp' is expected to be an array of 4 uint32_t's */
void generate_replacement_tramp(uint32_t *tramp){
    /* ADR X16, #-0x8 */
    tramp[0] = 0x10ffffd0;
    /* LDR X16, [X16] */
    tramp[1] = 0xf9400210;
    /* BR X16 */
    tramp[2] = 0xd61f0200;
}
