.align 12
.global _xnuspy_el3_exc_vector
_xnuspy_el3_exc_vector:
/* Current EL with SP0 */
b .     /* Synchronous */
.balign 0x80
b .     /* IRQ/vIRQ */
.balign 0x80
b .     /* FIQ/vFIQ */
.balign 0x80
b .     /* SError/vSError */
.balign 0x80
/* Current EL with SPx */
b .     /* Synchronous */
.balign 0x80
b .     /* IRQ/vIRQ */
.balign 0x80
b .     /* FIQ/vFIQ */
.balign 0x80
b .     /* SError/vSError */
.balign 0x80
/* Lower EL using AArch64 */
; str x0, [sp, -0x10]!
; mrs x0, spsr_el3
; and x0, x0, ~0xf
; orr x0, x0, 0x4
; msr spsr_el3, x0
; isb sy
; ldr x0, [sp], 0x10
; mrs x9, vbar_el1
; add x9, x9, 0x180
; msr elr_el3, x9
; mov x9, 0x4141
; msr far_el1, x9
; isb sy
eret
; stp x0, x1, [sp, -0x10]!
; stp x2, x3, [sp, -0x10]!
; stp x4, x5, [sp, -0x10]!
; stp x6, x7, [sp, -0x10]!
; stp x8, x9, [sp, -0x10]!
; stp x10, x11, [sp, -0x10]!
; stp x12, x13, [sp, -0x10]!
; stp x14, x15, [sp, -0x10]!
; stp x16, x17, [sp, -0x10]!
; stp x29, x30, [sp, -0x10]!
; /* Clang will save x19-x28 as needed */
; bl _xnuspy_el3_sync_handler
; ldp x29, x30, [sp], 0x10
; ldp x16, x17, [sp], 0x10
; ldp x14, x15, [sp], 0x10
; ldp x12, x13, [sp], 0x10
; ldp x10, x11, [sp], 0x10
; ldp x8, x9, [sp], 0x10
; ldp x6, x7, [sp], 0x10
; ldp x4, x5, [sp], 0x10
; ldp x2, x3, [sp], 0x10
; ldp x0, x1, [sp], 0x10
; eret    /* Synchronous */
.balign 0x80
str x0, [sp, -0x10]!
mrs x0, spsr_el3
and x0, x0, ~0xf
orr x0, x0, 0x4
msr spsr_el3, x0
; mov x0, 0x431
; msr scr_el3, x0
; mov x0, 0x100000
; msr cpacr_el1, x0
; mov x0, 0x80000000
; msr cptr_el3, x0
isb sy
ldr x0, [sp], 0x10
eret    /* IRQ/vIRQ */
.balign 0x80
b .     /* FIQ/vFIQ */
.balign 0x80
b .     /* SError/vSError */
.balign 0x80
/* Lower EL using AArch32 (unused) */
b .     /* Synchronous */
.balign 0x80
b .     /* IRQ/vIRQ */
.balign 0x80
b .     /* FIQ/vFIQ */
.balign 0x80
b .     /* SError/vSError */
.balign 0x80
