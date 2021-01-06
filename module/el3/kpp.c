#include <stdio.h>

#include "../common/common.h"
#include "../common/pongo.h"

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
     * Searching for this:
     *
     * STP             X0, X1, [SP,#-0x10]!
     * STP             X2, X3, [SP,#-0x10]!
     * STP             X4, X5, [SP,#-0x10]!
     * STP             X6, X7, [SP,#-0x10]!
     * STP             X8, X9, [SP,#-0x10]!
     * STP             X10, X11, [SP,#-0x10]!
     * STP             X12, X13, [SP,#-0x10]!
     * STP             X14, X15, [SP,#-0x10]!
     * STP             X16, X17, [SP,#-0x10]!
     * STP             X29, X30, [SP,#-0x10]!
     * 
     * Then right after that will be a BL to the integrity check/
     * "KPP syscall" function. Once we've got that function, we need
     * to find the pointer to (what I call) _kernEntry. It's set via an SMC 
     * with X0 == 0x800 (MONITOR_SET_ENTRY), and KPP's _start routine depends
     * on that being set so it can ERET back to EL1 upon reset. We'll search
     * for this, starting from the start of the integrity check function:
     *
     * CMP             X0, #0x802
     * B.EQ            loc_410000647C
     * CMP             X0, #0x801
     * B.EQ            loc_41000064D0
     * CMP             X0, #0x800
     * B.NE            loc_4100005F90
     *
     * And once we've found that, the first ADRP,STR pair we see going
     * forward is for _kernEntry. Finally, we loop back to the start of the
     * integrity check function and replace it with the code from kpp.s.
     */

    uint32_t sync_exc_matches[] = {
        0xa9bf07e0, 0xa9bf0fe2, 0xa9bf17e4, 0xa9bf1fe6, 0xa9bf27e8,
        0xa9bf2fea, 0xa9bf37ec, 0xa9bf3fee, 0xa9bf47f0, 0xa9bf7bfd,
    };
}

void patch_kpp(void){
    uint64_t kppphys = find_kpp();

    printf("xnuspy: found KPP at %#llx\n", kppphys);

    map_range(0xc10000000, kppphys, 0xc000, 3, 0, true);

    uint32_t *kppmapping = (uint32_t *)0xc10000000;

    patchfind_kpp(kppmapping, kppmapping + 0x3000);

    puts("xnuspy: patched KPP");
}
