#include <stdio.h>
#include <stdint.h>

/* #include "kpp_patches.h" */

/* #include "../common/asm.h" */
/* #include "../common/asm_support.h" */
/* #include "../common/common.h" */
/* #include "../common/pongo.h" */

#include <pongo.h>

#include <asm/asm.h>
#include <asm/asm_support.h>
#include <common/common.h>

#include <xnuspy/el3/kpp_patches.h>

static uint64_t find_kpp(void){
    dt_node_t *cpus = dt_find(gDeviceTree, "cpus");

    if(!cpus){
        printf("xnuspy: no cpus node?\n");
        xnuspy_fatal_error();
    }

    dt_node_t *cpu0 = dt_find(cpus, "cpu0");

    if(!cpu0){
        printf("xnuspy: no cpu0 node?\n");
        xnuspy_fatal_error();
    }

    uint32_t len;
    void *reg_private = dt_prop(cpu0, "reg-private", &len);

    if(!reg_private || len != 8){
        printf("xnuspy: bad reg-private prop?\n");
        xnuspy_fatal_error();
    }
    
    uint64_t *IORVBARp = (uint64_t *)(*(uint64_t *)reg_private + 0x40000);

    if(!IORVBARp){
        printf("xnuspy: no IORVBAR?\n");
        xnuspy_fatal_error();
    }

    return *IORVBARp & 0xfffffffff;
}

static void patchfind_kpp(uint32_t *kpp_stream, uint32_t *kpp_stream_end){
    /* We're searching for KPP's handler for synchronous exceptions from EL1.
     * It'll be easy to find; it saves X0-X17, X29, and X30 to the stack
     * then calls the function that performs all the integrity checks. 
     * We'll search for stp x16, x17, [sp, -0x10]! and then shortly after that
     * will be a BL to the integrity check/"KPP syscall" function. Once we've
     * got that function, we need to find the pointer to (what I call)
     * _kernEntry. It's set via an SMC with X0 == 0x800 (MONITOR_SET_ENTRY),
     * and KPP's _start routine depends on that being set so it can ERET back
     * to EL1 upon reset. We'll search for this, starting from the start of
     * the integrity check function:
     *
     * CMP             X0, #0x802
     * B.EQ            loc_410000647C
     * CMP             X0, #0x801
     * B.EQ            loc_41000064D0
     * CMP             X0, #0x800
     * B.NE            loc_4100005F90
     *
     * And once we've found that, the first ADRP or ADR,STR pair we see going
     * forward is for _kernEntry. We save its pointer and then loop back to
     * the start of the integrity check function and replace it with the code
     * from kpp.s.
     *
     * kpp_stream points to KPP's Mach-O header, so we can do a linear search.
     */
    uint32_t stp_x16_x17_sp_pre = 0xa9bf47f0;

    while(*kpp_stream != stp_x16_x17_sp_pre){
        if(kpp_stream >= kpp_stream_end){
            printf("xnuspy: did not find\n"
                   "   stp x16, x17 in KPP?\n");
            xnuspy_fatal_error();
        }

        kpp_stream++;
    }

    kpp_stream = get_branch_dst_ptr(kpp_stream + 2);

    uint32_t *saved_prologue = kpp_stream;

    uint32_t cmp_matches[] = {
        0xf120081f,     /* cmp x0, 0x802 */
        0x54000000,     /* b.eq n */
        0xf120041f,     /* cmp x0, 0x801 */
        0x54000000,     /* b.eq n */
        0xf120001f,     /* cmp x0, 0x800 */
        0x54000001,     /* b.ne n */
    };

    uint32_t cmp_masks[] = {
        0xffffffff,     /* match exactly */
        0xff00001f,     /* ignore immediate */
        0xffffffff,     /* match exactly */
        0xff00001f,     /* ignore immediate */
        0xffffffff,     /* match exactly */
        0xff00001f,     /* ignore immediate */
    };

    for(;;){
        if(kpp_stream >= kpp_stream_end){
            printf("xnuspy: did not find\n"
                   "   X0 if statement?\n");
            xnuspy_fatal_error();
        }

        if((*kpp_stream & *cmp_masks) == *cmp_matches){
            for(int i=1; i<sizeof(cmp_matches)/sizeof(*cmp_matches); i++){
                if((kpp_stream[i] & cmp_masks[i]) != cmp_matches[i])
                    goto nope;
            }

            break;
        }

nope:
        kpp_stream++;
    }

    /* Now look for _kernEntry. Trying to match adrp/adr,str Xn, [Xn, n] */
    while((*kpp_stream & 0x1f000000) != 0x90000000 &&
            (kpp_stream[1] & 0xffc00000) != 0xf9000000){
        if(kpp_stream >= kpp_stream_end){
            printf("xnuspy: did not find\n"
                   "   _kernEntry for KPP\n");
            xnuspy_fatal_error();
        }

        kpp_stream++;
    }

    uint32_t adrp = *kpp_stream;
    uint32_t str = kpp_stream[1];

    uint32_t immlo = bits(adrp, 29, 30);
    uint32_t immhi = bits(adrp, 5, 23);
    uint32_t imm12 = bits(str, 10, 21);
    uint32_t shift = bits(str, 30, 31);

    uint64_t page = sign_extend(((immhi << 2) | immlo) << 12, 32) +
        ((uintptr_t)kpp_stream & ~0xfffuLL);
    uint64_t pageoff = sign_extend(imm12, 12) << shift;

    uint64_t mapping_kernEntryp = page + pageoff;
    uint64_t kpp_kernEntryp = 0x4100000000 + (mapping_kernEntryp - 0xc10000000);

    uint64_t kpp_patches_len = g_kpp_patches_len / sizeof(uint32_t);
    uint32_t *kpp_patches_cursor = (uint32_t *)g_kpp_patches;
    uint32_t *kpp_patches_end = kpp_patches_cursor + kpp_patches_len;

    kpp_stream = saved_prologue;

    /* Finally, replace this function */
    while(kpp_patches_cursor < kpp_patches_end){
        if(*(uint64_t *)kpp_patches_cursor == QWORD_PLACEHOLDER)
            *(uint64_t *)kpp_patches_cursor = kpp_kernEntryp;

        *kpp_stream++ = *kpp_patches_cursor++;
    }
}

void patch_kpp(void){
    uint64_t kppphys = find_kpp();

    printf("xnuspy: found KPP at %#llx\n", kppphys);

    map_range(0xc10000000, kppphys, 0xc000, 3, 0, true);

    uint32_t *kppmapping = (uint32_t *)0xc10000000;

    patchfind_kpp(kppmapping, kppmapping + 0x3000);

    puts("xnuspy: patched KPP");
}
