#include <stdint.h>

__attribute__ ((naked)) uint64_t kvtophys(uint64_t kaddr){
    __asm__(""
            "mrs x1, DAIF\n"
            "msr DAIFSet, #0xf\n"
            "at s1e1r, x0\n"
            "mrs x2, par_el1\n"
            "msr DAIF, x1\n"
            "tbnz x2, 0x0, 5f\n"
            "and x2, x2, 0xfffffffff000\n"
            "and x1, x0, 0x3fff\n"
            "orr x0, x2, x1\n"
            "b 3f\n"
            "5:\n"
            "mov x0, xzr\n"
            "3:\n"
            "ret\n"
            );
}
