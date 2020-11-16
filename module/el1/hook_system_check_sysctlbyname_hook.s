    .align 4
    .globl _main

#include "../common/xnuspy_cache.h"

#include "hook_system_check_sysctlbyname_hook.h"

_main:
    sub sp, sp, STACK
    ; we branched when parameters were being copied to callee-saved registers
    stp x7, x6, [sp, STACK-0xa0]
    stp x5, x4, [sp, STACK-0x90]
    stp x3, x2, [sp, STACK-0x80]
    stp x1, x0, [sp, STACK-0x70]
    stp x28, x27, [sp, STACK-0x60]
    stp x26, x25, [sp, STACK-0x50]
    stp x24, x23, [sp, STACK-0x40]
    stp x22, x21, [sp, STACK-0x30]
    stp x20, x19, [sp, STACK-0x20]
    stp x29, x30, [sp, STACK-0x10]
    add x29, sp, STACK-0x10

    adr x19, ADDRESS_OF_XNUSPY_CACHE
    ldr x28, [x19]

    ; MIB array
    mov x19, x2
    ; length of MIB array
    mov w20, w3

    ; this function does not take sysctl_geometry_lock
    ldr x0, [x28, SYSCTL_GEOMETRY_LOCK_PTR]
    ldr x0, [x0]
    ldr x21, [x28, LCK_RW_LOCK_SHARED]
    blr x21
    ; if this sysctl hasn't been added yet, don't do anything
    ldr x21, [x28, DID_REGISTER_SYSCTL]
    cbz x21, register_xnuspy_ctl_callnum_sysctl
    ldr x21, [x28, XNUSPY_SYSCTL_MIB_COUNT_PTR]
    ldr w21, [x21]
    cmp w21, w20
    b.ne not_ours

    ; same length, so compare MIB contents
    ldr x21, [x28, XNUSPY_SYSCTL_MIB_PTR]               ; our MIB array
    mov x22, x19                                        ; passed in MIB array
    ; end of our MIB array. The MIB array param and our MIB array are
    ; guarenteed to have matching lengths, so we can pick one of them
    ; to use to check if we hit the end of both
    add x23, x21, w20, lsl 0x2

mib_check_loop:
    ldr w24, [x21], 0x4
    ldr w25, [x22], 0x4
    ; one mismatched elem and we know it isn't ours
    cmp w24, w25
    b.ne not_ours
    ; if we hit the end of our MIB array, it's ours
    subs x26, x23, x21
    cbnz x26, mib_check_loop

ours:
    ldr x0, [x28, SYSCTL_GEOMETRY_LOCK_PTR]
    ldr x0, [x0]
    ldr x19, [x28, LCK_RW_DONE]
    blr x19
    ; if it is ours, branch right to hook_system_check_sysctlbyname's
    ; epilogue, returning no error
    ldr x1, [x28, H_S_C_SBN_EPILOGUE_ADDR]
    add sp, sp, STACK
    mov x0, xzr
    br x1
    ; not reached

register_xnuspy_ctl_callnum_sysctl:
    ; this does not need to be locked
    ldr x0, [x28, SYSCTL_GEOMETRY_LOCK_PTR]
    ldr x0, [x0]
    ldr x19, [x28, LCK_RW_DONE]
    blr x19

    mov x0, SIZEOF_STRUCT_SYSCTL_OID
    ; we still hold sysctl_geometry_lock
    ldr x19, [x28, IOS_VERSION]
    cmp x19, iOS_13_x
    b.eq iOS_13_x_kalloc
    ; fall thru

    ldr x19, [x28, KALLOC_EXTERNAL]
    blr x19

    b register

iOS_13_x_kalloc:
    str x0, [sp, KALLOC_SZ]
    add x0, sp, KALLOC_SZ
    mov x1, xzr
    mov w2, wzr
    ldr x19, [x28, KALLOC_CANBLOCK]
    ; fall thru

register:
    cbz x0, not_ours

    ldr x19, [x28, SYSCTL__KERN_CHILDREN_PTR]
    str x19, [x0, OFFSETOF_OID_PARENT]
    str xzr, [x0, OFFSETOF_OID_LINK]
    mov w19, OID_AUTO
    str w19, [x0, OFFSETOF_OID_NUMBER]
    mov w19, CTLTYPE_INT
    orr w19, w19, CTLFLAG_RD
    orr w19, w19, CTLFLAG_ANYBODY
    orr w19, w19, CTLFLAG_OID2
    str w19, [x0, OFFSETOF_OID_KIND]
    add x19, x28, XNUSPY_CTL_CALLNUM
    str x19, [x0, OFFSETOF_OID_ARG1]
    str wzr, [x0, OFFSETOF_OID_ARG2]
    ; oid_name, "kern.xnuspy_ctl_callnum"
    ldr x19, [x28, XNUSPY_SYSCTL_NAME_PTR]
    ; skip "kern."
    add x19, x19, 0x5
    str x19, [x0, OFFSETOF_OID_NAME]
    ldr x19, [x28, SYSCTL_HANDLE_LONG]
    str x19, [x0, OFFSETOF_OID_HANDLER]
    ldr x19, [x28, XNUSPY_SYSCTL_FMT_PTR]
    str x19, [x0, OFFSETOF_OID_FMT]
    ldr x19, [x28, XNUSPY_SYSCTL_DESCR_PTR]
    str x19, [x0, OFFSETOF_OID_DESCR]
    mov w19, SYSCTL_OID_VERSION
    str w19, [x0, OFFSETOF_OID_VERSION]
    str wzr, [x0, OFFSETOF_OID_REFCNT]

    ; register this sysctl
    ldr x19, [x28, SYSCTL_REGISTER_OID]
    blr x19

    ; Figure out what MIB array looks like for this new sysctl.
    ; We need this so we can check if the incoming sysctl is ours.
    ; name2oid expects this lock to be held
    ldr x0, [x28, SYSCTL_GEOMETRY_LOCK_PTR]
    ldr x0, [x0]
    ldr x19, [x28, LCK_RW_LOCK_SHARED]
    blr x19

    ldr x0, [x28, XNUSPY_SYSCTL_NAME_PTR]
    ldr x1, [x28, XNUSPY_SYSCTL_MIB_PTR]
    ldr x2, [x28, XNUSPY_SYSCTL_MIB_COUNT_PTR]
    ldr x19, [x28, NAME2OID]
    blr x19

    mov x19, 0x1
    str x19, [x28, DID_REGISTER_SYSCTL]
    ; fall thru

    ; in the case our sysctl wasn't being dealt with, return back to
    ; hook_system_check_sysctlbyname to carry out its normal operation
not_ours:
    ldr x0, [x28, SYSCTL_GEOMETRY_LOCK_PTR]
    ldr x0, [x0]
    ldr x19, [x28, LCK_RW_DONE]
    blr x19
    ldp x29, x30, [sp, STACK-0x10]
    ldp x20, x19, [sp, STACK-0x20]
    ldp x22, x21, [sp, STACK-0x30]
    ldp x24, x23, [sp, STACK-0x40]
    ldp x26, x25, [sp, STACK-0x50]
    ldp x28, x27, [sp, STACK-0x60]
    ldp x1, x0, [sp, STACK-0x70]
    ldp x3, x2, [sp, STACK-0x80]
    ldp x5, x4, [sp, STACK-0x90]
    ldp x7, x6, [sp, STACK-0xa0]
    add sp, sp, STACK
    ; this is missing a RET so xnuspy can write back the instructions
    ; we overwrote to branch to this code
