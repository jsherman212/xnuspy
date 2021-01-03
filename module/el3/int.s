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
eret    /* Synchronous */
.balign 0x80
b .     /* IRQ/vIRQ */
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
