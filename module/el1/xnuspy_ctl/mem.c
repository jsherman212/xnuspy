#include <mach/mach.h>
#include <stdbool.h>
#include <stdint.h>

#include "externs.h"

__attribute__ ((naked)) uint64_t kvtophys(uint64_t kaddr){
    asm volatile(""
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

/* Write to kernel memory. We use bcopy_phys here to avoid "unexpected faults
 * in kernel static region" panics.
 *
 * Parameters:
 *  dst: kernel virtual address of destination
 *  buf: kernel virtual address of data
 *  sz:  how many bytes 'buf' is
 *
 * Returns: nothing
 */
void kwrite(void *dst, void *buf, size_t sz){
    uint64_t dst_phys = kvtophys((uint64_t)dst);
    uint64_t buf_phys = kvtophys((uint64_t)buf);

    kprintf("%s: dst %#llx dst_phys %#llx buf %#llx buf_phys %#llx\n", __func__,
            dst, dst_phys, buf, buf_phys);

    bcopy_phys(buf_phys, dst_phys, sz);

    kprintf("%s: still here after bcopy_phys\n", __func__);
}
