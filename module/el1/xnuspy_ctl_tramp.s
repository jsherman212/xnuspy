    .align 4
    .globl _main

#include "../common/xnuspy_cache.h"

#include "xnuspy_ctl_tramp.h"

; This is the code an _enosys sysent was modified to point to. We mark the
; memory which holds the xnuspy_ctl image as executable and then br to it. Since
; this is the entrypoint of xnuspy_ctl, we need to preserve x0, x1, and x2.
_main:
    sub sp, sp, STACK
    stp x0, x1, [sp, STACK-0x10]
    stp x2, x19, [sp, STACK-0x20]
    stp x20, x21, [sp, STACK-0x30]
    stp x22, x23, [sp, STACK-0x40]
    stp x24, x25, [sp, STACK-0x40]
    stp x26, x27, [sp, STACK-0x50]

    adr x27, ADDRESS_OF_XNUSPY_CACHE
    ldr x27, [x27]

    ldr x19, [x27, XNUSPY_CTL_IS_RX]
    cbnz x19, handoff

    ; XXX should be the entirety of __TEXT_EXEC and its vm size
    ldr x19, [x27, XNUSPY_CTL_CODESTART]
    ldr x20, [x27, XNUSPY_CTL_CODESZ]
    ; we don't need to worry about this not being page aligned. Clang always
    ; page-aligns __TEXT_EXEC,__text for the xnuspy_ctl image
    add x20, x19, x20

    mrs x0, ttbr1_el1 
    ; mask for baddr
    and x0, x0, 0xfffffffffffe
    ldr x22, [x27, PHYSTOKV]
    blr x22
    mov x21, x0

    ; For pteloop:
    ;   X19: current page of xnuspy_ctl code
    ;   X20: end of last page of xnuspy_ctl code
    ;   X21: virtual address of TTBR1_EL1 translation table base
    ;   X22 - X26: scratch registers
    ;   X27: xnuspy cache pointer

pteloop:
    lsr x22, x19, ARM_TT_L1_SHIFT
    and x22, x22, 0x7
    add x22, x21, x22, lsl 0x3
    ldr x22, [x22]
    and x0, x22, ARM_TTE_TABLE_MASK
    ldr x22, [x27, PHYSTOKV]
    blr x22
    mov x22, x0
    lsr x23, x19, ARM_TT_L2_SHIFT
    and x23, x23, 0x7ff
    add x23, x22, x23, lsl 0x3
    ldr x23, [x23]
    and x0, x23, ARM_TTE_TABLE_MASK
    ldr x22, [x27, PHYSTOKV]
    blr x22
    mov x22, x0
    lsr x23, x19, ARM_TT_L3_SHIFT
    and x23, x23, 0x7ff
    add x23, x22, x23, lsl 0x3
    ; ldr x0, [x23]
    ; successfully gets PTE, PTE pointer is in X23
    ; XXX good up to here

    ; XXX invalidate cache?
    ; dsb ish
    ; isb

nextpage:
    mov w22, 0x1
    add x19, x19, x22, lsl 0xe
    subs xzr, x20, x19
    b.ne pteloop

    mov x19, 0x1
    str x19, [x27, XNUSPY_CTL_IS_RX]
    ; fall thru

handoff:
    mov x7, x27
    ldp x0, x1, [sp, STACK-0x10]
    ldp x2, x19, [sp, STACK-0x20]
    ldp x20, x21, [sp, STACK-0x30]
    ldp x22, x23, [sp, STACK-0x40]
    ldp x24, x25, [sp, STACK-0x40]
    ldp x26, x27, [sp, STACK-0x50]
    add sp, sp, STACK
    ldr x7, [x7, XNUSPY_CTL_ENTRYPOINT]
    br x7
    ; not reached
