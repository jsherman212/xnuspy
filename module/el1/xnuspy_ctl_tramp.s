#include "../common/asm_support.h"
#include "../common/xnuspy_cache.h"

#include "xnuspy_ctl_tramp.h"

.align 2
.global _xnuspy_ctl_tramp

/* This exists to mark the __TEXT_EXEC segment of the xnuspy_ctl Mach-O as
    executable before we branch to it. We need to preserve x0, x1, and x2
    since this code is what an _enosys sysent was modified to point to. */
_xnuspy_ctl_tramp:
    sub sp, sp, STACK
    stp x0, x1, [sp, #(STACK-0x10)]
    stp x2, x19, [sp, #(STACK-0x20)]
    stp x20, x21, [sp, #(STACK-0x30)]
    stp x22, x23, [sp, #(STACK-0x40)]
    stp x24, x25, [sp, #(STACK-0x50)]
    stp x26, x27, [sp, #(STACK-0x60)]
    stp x29, x30, [sp, #(STACK-0x70)]
    add x29, sp, #(STACK-0x70)

    adr x27, addrof_xnuspy_cache
    ldr x27, [x27]

    ldr x19, [x27, XNUSPY_CTL_IS_RX]
    cbnz x19, Lhandoff

    ldr x19, [x27, XNUSPY_CTL_CODESTART]
    ldr x20, [x27, XNUSPY_CTL_CODESZ]
    /* We don't need to worry about this not being page aligned. Clang always
    page-aligns __TEXT_EXEC,__text for the xnuspy_ctl Mach-O */
    add x20, x19, x20

    mrs x0, ttbr1_el1 
    and x0, x0, #0xfffffffffffe
    ldr x22, [x27, PHYSTOKV]
    blr x22
    mov x21, x0
    
    /* For pteloop:
    X19: current page of xnuspy_ctl __TEXT_EXEC segment
    X20: end of last page of xnuspy_ctl __TEXT_EXEC segment
    X21: virtual address of TTBR1_EL1 translation table base
    X22 - X26: scratch registers
    X27: xnuspy cache pointer
    */

Lpteloop:
    lsr x22, x19, ARM_TT_L1_SHIFT
    and x22, x22, #0x7
    add x22, x21, x22, lsl #0x3
    ldr x22, [x22]
    and x0, x22, ARM_TTE_TABLE_MASK
    ldr x22, [x27, PHYSTOKV]
    blr x22
    mov x22, x0
    lsr x23, x19, ARM_TT_L2_SHIFT
    and x23, x23, #0x7ff
    add x23, x22, x23, lsl #0x3
    ldr x23, [x23]
    and x0, x23, ARM_TTE_TABLE_MASK
    ldr x22, [x27, PHYSTOKV]
    blr x22
    mov x22, x0
    lsr x23, x19, ARM_TT_L3_SHIFT
    and x23, x23, #0x7ff
    add x23, x22, x23, lsl #0x3
    /* X23 == pointer to PTE for this page */
    ldr x24, [x23]
    /* ~(ARM_PTE_PNXMASK | ARM_PTE_NXMASK) */
    mov x25, #0xff9fffffffffffff
    and x24, x24, x25
    str x24, [sp, NEW_PTE_SPACE]
    mov x0, x23
    bl _kvtophys
    mov x24, x0
    add x0, sp, NEW_PTE_SPACE
    bl _kvtophys
    mov x1, x24
    mov w2, #0x8
    ldr x23, [x27, BCOPY_PHYS]
    blr x23

Lnextpage:
    mov w22, #0x1
    add x19, x19, x22, lsl #0xe
    cmp x20, x19
    b.ne Lpteloop

    isb
    dsb sy
    tlbi vmalle1
    dsb sy
    isb

    str x22, [x27, XNUSPY_CTL_IS_RX]

Lhandoff:
    mov x7, x27
    ldp x0, x1, [sp, #(STACK-0x10)]
    ldp x2, x19, [sp, #(STACK-0x20)]
    ldp x20, x21, [sp, #(STACK-0x30)]
    ldp x22, x23, [sp, #(STACK-0x40)]
    ldp x24, x25, [sp, #(STACK-0x50)]
    ldp x26, x27, [sp, #(STACK-0x60)]
    ldp x29, x30, [sp, #(STACK-0x70)]
    add sp, sp, STACK
    ldr x7, [x7, XNUSPY_CTL_ENTRYPOINT]
    br x7
    /* Not reached */

/* All kvtophys calls were inlined on 14.x kernels :( */
_kvtophys:
    mrs x1, DAIF
    msr DAIFSet, #(DAIFSC_DEBUGF | DAIFSC_ASYNCF | DAIFSC_IRQF | DAIFSC_FIQF)
    at s1e1r, x0
    mrs x2, par_el1
    msr DAIF, x1
    tbnz x2, #0x0, 2f
    and x2, x2, #0xfffffffff000
    and x1, x0, #0x3fff
    orr x0, x2, x1

    b 1f

2:
    mov x0, xzr

1:
    ret

addrof_xnuspy_cache: .dword QWORD_PLACEHOLDER
