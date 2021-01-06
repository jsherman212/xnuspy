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
    
    uint64_t *IORVBARp = *(uint64_t *)reg_private + 0x40000;

    if(!IORVBARp){
        printf("xnuspy: no IORVBAR?\n");
        xnuspy_fatal_error();
    }

    return *IORVBARp & 0xfffffffff;
}

static void patchfind_kpp(uint32_t *kpp_stream){
    /* We're searching for KPP's handler for synchronous exceptions from EL1.
     * It'll be easy to find; it saves X0-X17, X29, and X30 to the stack
     * then calls the function that performs all the integrity checks. We
     * are replacing that function. Searching for this:
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
     * "KPP syscall" function.
     */

    uint32_t matches[] = {
        0xa9bf07e0, 0xa9bf0fe2, 0xa9bf17e4, 0xa9bf1fe6, 0xa9bf27e8,
        0xa9bf2fea, 0xa9bf37ec, 0xa9bf3fee, 0xa9bf47f0, 0xa9bf7bfd,
    };
}

void patch_kpp(void){
    uint64_t kppphys = find_kpp();

    printf("xnuspy: found KPP at %#llx\n", kppphys);

    map_range(0xc10000000, kppphys, 0xc000, 3, 0, true);

    patchfind_kpp((uint32_t *)0xc10000000);

    puts("xnuspy: patched KPP");
}
