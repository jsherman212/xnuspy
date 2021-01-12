/* The code in this file replaces the function which is called by KPP's
    lower EL synchronous exception handler */

#include "../common/asm_support.h"

#define MONITOR_SET_ENTRY 0x800

.align 2
.global _kpp0

_kpp0:
    stp x19, x20, [sp, #-0x10]!

    /* Are we here because of monitor_call? If so, the only case we have to
    handle is MONITOR_SET_ENTRY */
    mrs x19, esr_el3
    mov x20, #0x11
    movk x20, #0x5e00, lsl 16
    cmp x19, x20
    b.eq 2f

    /* Otherwise, we are here because the kernel touched CPACR_EL1, so we
    need to get off that instruction before we ERET */
    mov x19, #0x6b3
    msr scr_el3, x19
    msr cptr_el3, xzr
    mov x19, #0x300000
    msr cpacr_el1, x19
    mrs x19, elr_el3
    add x19, x19, #0x4
    msr elr_el3, x19

    b 1f

2:
    cmp x0, MONITOR_SET_ENTRY
    b.ne 1f
    ldr x19, kernEntry
    str x1, [x19]

1:
    ldp x19, x20, [sp], #0x10
    ret

kernEntry: .dword QWORD_PLACEHOLDER
