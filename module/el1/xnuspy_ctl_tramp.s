    .align 4
    .globl _main

#include "../common/xnuspy_cache.h"

#include "xnuspy_ctl_tramp.h"

; This is the code an _enosys sysent was modified to point to. We mark the
; memory which holds the xnuspy_ctl image as executable and then br to it. Since
; this is the entrypoint of xnuspy_ctl, we can clobber x3, x4, x5, x6, and x7.
_main:
    sub sp, sp, STACK
    stp x0, x1, [sp]
    str x2, [sp, 0x10]

    adr x7, ADDRESS_OF_XNUSPY_CACHE
    ldr x7, [x7]
    ldr x0, [x7, XNUSPY_CTL_IS_RX]
    cbnz x0, handoff

    ldr x0, [x7, XNUSPY_CTL_ENTRYPOINT]
    str x0, [sp, VADDR_CUR]
    ; we don't need to worry about this not being page aligned. Clang always
    ; page-aligns __TEXT_EXEC,__text for the xnuspy_ctl image
    ldr x1, [x7, XNUSPY_CTL_CODESZ]
    add x0, x0, x1
    str x0, [sp, VADDR_END]

pteloop:
    mrs x0, ttbr1_el1
    ; mask for baddr
    and x0, x0, 0xfffffffffffe
    ldr x1, [x7, PHYSTOKV]
    blr x1
    mov x1, x0
    ldr x0, [sp, VADDR_CUR]
    lsr x0, x0, ARM_TT_L1_SHIFT
    and x0, x0, 0x7
    add x0, x1, x0, lsl 0x3
    ldr x0, [x0]
    ; XXX good up to here
    and x0, x0, ARM_TTE_TABLE_MASK
    ldr x1, [x7, PHYSTOKV]
    blr x1
    mov x1, x0
    ldr x0, [sp, VADDR_CUR]
    lsr x0, x0, ARM_TT_L2_SHIFT
    and x0, x0, 0x7ff
    add x0, x1, x0, lsl 0x3
    ldr x0, [x0]
    ; XXX good up to here
    and x0, x0, ARM_TTE_TABLE_MASK
    ldr x1, [x7, PHYSTOKV]
    blr x1
    mov x1, x0
    ldr x0, [sp, VADDR_CUR]
    lsr x0, x0, ARM_TT_L3_SHIFT
    and x0, x0, 0x7ff
    add x0, x1, x0, lsl 0x3
    ; mov x2, x0
    ldr x0, [x0]
    ; successfully gets PTE
    ; XXX good up to here

nextpage:
    mov w1, 0x1
    add w1, wzr, w1, lsl 0xe
    add x0, x0, x1
    str x0, [sp, VADDR_CUR]
    ldr x1, [sp, VADDR_END]
    sub x0, x0, x1
    cbnz x0, pteloop

    mov x0, 0x1
    str x0, [x7, XNUSPY_CTL_IS_RX]
    ; fall thru

handoff:
    ldp x0, x1, [sp]
    ldr x2, [sp, 0x10]
    add sp, sp, STACK
    ldr x3, [x7, XNUSPY_CTL_ENTRYPOINT]
    ; XXX invalidate cache?
    dsb ish
    isb
    br x3
    ; not reached

; Next three functions:
; X0 = kernel virtual address
; X1 = corresponding TTE pointer (virtual addr)
;
; On returning, each return a virtual pointer to the corresponding TTE/PTE
; _l1_tte_vm_pointer_for_kvaddr:
;     lsr x0, x0, ARM_TT_L1_SHIFT
;     and x0, x0, 0x7
;     add x0, x1, x0, lsl 0x3
;     ret

; _l2_tte_vm_pointer_for_kvaddr:
;     lsr x0, x0, ARM_TT_L2_SHIFT
;     and x0, x0, 0x7ff
;     add x0, x1, x0, lsl 0x3
;     ret

; _l3_pte_vm_pointer_for_kvaddr:
;     lsr x0, x0, ARM_TT_L3_SHIFT
;     and x0, x0, 0x7ff
;     add x0, x1, x0, lsl 0x3
;     ret
