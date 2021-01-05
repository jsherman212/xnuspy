/* The code in this file replaces the function which is called by KPP's
    lower EL synchronous exception handler, as well as its lower EL IRQ/vIRQ
   exception handler (maybe that won't be needed?) */

#define MONITOR_SET_ENTRY 0x800

.align 4
.global _kpp0

_kpp0:
    sub sp, sp, 0x20
    stp x19, x20, [sp]
    stp x29, x30, [sp, 0x10]
    add x29, sp, 0x10

    mrs x19, esr_el3
    /* Are we here because of monitor_call? If so, the only case we have to
    handle is MONITOR_SET_ENTRY */
    mov x20, 0x11
    movk x20, 0x5e00, lsl 16
    cmp x19, x20
    b.eq 2f

    /* Otherwise, we are here because the kernel touched CPACR_EL1, so we
    need to get off that instruction before we eret */
    mov x19, 0x6b3
    msr scr_el3, x19
    mov x19, 0x0
    msr cptr_el3, x19
    mov x19, 0x300000
    msr cpacr_el1, x19
    mrs x19, elr_el3
    add x19, x19, 0x4
    msr elr_el3, x19

    b 1f

2:
    cmp x0, MONITOR_SET_ENTRY
    b.ne 1f
    mov x19, 0x3028
    movk x19, 0x0001, lsl 16
    movk x19, 0x41, lsl 32
    str x1, [x19]

1:
    ldp x19, x20, [sp]
    ldp x29, x30, [sp, 0x10]
    add sp, sp, 0x20
    ret
