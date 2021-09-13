#include <asm/asm_support.h>
#include <xnuspy/xnuspy_cache.h>

#include "hook_system_check_sysctlbyname_hook.h"

.align 2
.global _hook_system_check_sysctlbyname_hook

_hook_system_check_sysctlbyname_hook:
    sub sp, sp, STACK
    /* We branched when parameters were being copied to callee-saved
    registers */
    stp x7, x6, [sp, #(STACK-0xa0)]
    stp x5, x4, [sp, #(STACK-0x90)]
    stp x3, x2, [sp, #(STACK-0x80)]
    stp x1, x0, [sp, #(STACK-0x70)]
    stp x28, x27, [sp, #(STACK-0x60)]
    stp x26, x25, [sp, #(STACK-0x50)]
    stp x24, x23, [sp, #(STACK-0x40)]
    stp x22, x21, [sp, #(STACK-0x30)]
    stp x20, x19, [sp, #(STACK-0x20)]
    stp x29, x30, [sp, #(STACK-0x10)]
    add x29, sp, #(STACK-0x10)

    adr x19, addrof_xnuspy_cache
    ldr x28, [x19]

    /* MIB array */
    mov x19, x2
    /* Length of MIB array */
    mov w20, w3

    /* This function does not take sysctl_geometry_lock */
    mov x0, x28
    bl _get_sysctl_geo_lck
    ldr x21, [x28, LCK_RW_LOCK_SHARED]
    blr x21
    /* If this sysctl hasn't been added yet, register it */
    ldr x21, [x28, DID_REGISTER_SYSCTL]
    cbz x21, Lregister_xnuspy_ctl_callnum_sysctl
    ldr x21, [x28, XNUSPY_SYSCTL_MIB_COUNT_PTR]
    ldr w21, [x21]
    /* Not the same length? Definitely not ours */
    cmp w21, w20
    b.ne Lnot_ours

    /* Same length, so compare MIB contents. Setting up for mib_check_loop:
    X21: pointer to kern.xnuspy_ctl_callnum MIB array
    X22: pointer to passed in MIB array
    X23: pointer to the end of our MIB array. If we're here, the MIB array
         parameter is the same length of ours.
    X24-X26: scratch registers
    */
    ldr x21, [x28, XNUSPY_SYSCTL_MIB_PTR]
    mov x22, x19
    add x23, x21, x20, lsl #0x2

Lmib_check_loop:
    ldr w24, [x21], #0x4
    ldr w25, [x22], #0x4
    /* One mismatched elem and we know it isn't ours */
    cmp w24, w25
    b.ne Lnot_ours
    /* If we hit the end of our MIB array, it's ours */
    subs x26, x23, x21
    cbnz x26, Lmib_check_loop

Lours:
    mov x0, x28
    bl _get_sysctl_geo_lck
    ldr x19, [x28, LCK_RW_DONE]
    blr x19
    /* If it is ours, branch right to hook_system_check_sysctlbyname's
    epilogue, returning no error */
    ldr x1, [x28, H_S_C_SBN_EPILOGUE_ADDR]
    add sp, sp, STACK
    mov x0, xzr
    br x1
    /* Not reached */

Lregister_xnuspy_ctl_callnum_sysctl:
    mov x0, x28
    bl _get_sysctl_geo_lck
    ldr x19, [x28, LCK_RW_DONE]
    blr x19

    mov x0, SIZEOF_STRUCT_SYSCTL_OID
    ldr x19, [x28, IOS_VERSION]
    cmp x19, iOS_13_x
    b.eq LiOS_13_x_kalloc

    ldr x19, [x28, KALLOC_EXTERNAL]
    blr x19

    b Lregister

LiOS_13_x_kalloc:
    str x0, [sp, KALLOC_SZ]
    add x0, sp, KALLOC_SZ
    mov x1, xzr
    mov w2, wzr
    ldr x19, [x28, KALLOC_CANBLOCK]
    blr x19

Lregister:
    cbz x0, Lnot_ours

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
    adr x19, oid_name
    /* Skip "kern." */
    add x19, x19, #0x5
    str x19, [x0, OFFSETOF_OID_NAME]
    ldr x19, [x28, SYSCTL_HANDLE_LONG]
    str x19, [x0, OFFSETOF_OID_HANDLER]
    adr x19, oid_fmt
    str x19, [x0, OFFSETOF_OID_FMT]
    adr x19, oid_descr
    str x19, [x0, OFFSETOF_OID_DESCR]
    mov w19, SYSCTL_OID_VERSION
    str w19, [x0, OFFSETOF_OID_VERSION]
    str wzr, [x0, OFFSETOF_OID_REFCNT]

    ldr x19, [x28, SYSCTL_REGISTER_OID]
    blr x19

    /* Figure out what the MIB array looks like for this new sysctl.
    Unfortunately I can't just reserve space for this because this
    page is r-x. name2oid expects sysctl_geometry_lock to be held */
    mov x0, x28
    bl _get_sysctl_geo_lck
    ldr x19, [x28, LCK_RW_LOCK_SHARED]
    blr x19

    /* name2oid modifies the first parameter, so we need to deep copy */
    adr x0, oid_name
    add x1, sp, SYSCTL_NAME_SPACE

Lcopy_name:
    ldrb w2, [x0], #0x1
    strb w2, [x1], #0x1
    cmp w2, wzr
    b.ne Lcopy_name

    add x0, sp, SYSCTL_NAME_SPACE
    ldr x1, [x28, XNUSPY_SYSCTL_MIB_PTR]
    ldr x2, [x28, XNUSPY_SYSCTL_MIB_COUNT_PTR]
    ldr x19, [x28, NAME2OID]
    blr x19

    mov x19, #0x1
    str x19, [x28, DID_REGISTER_SYSCTL]

Lnot_ours:
    mov x0, x28
    bl _get_sysctl_geo_lck
    ldr x19, [x28, LCK_RW_DONE]
    blr x19
    ldp x29, x30, [sp, #(STACK-0x10)]
    ldp x20, x19, [sp, #(STACK-0x20)]
    ldp x22, x21, [sp, #(STACK-0x30)]
    ldp x24, x23, [sp, #(STACK-0x40)]
    ldp x26, x25, [sp, #(STACK-0x50)]
    ldp x28, x27, [sp, #(STACK-0x60)]
    ldp x1, x0, [sp, #(STACK-0x70)]
    ldp x3, x2, [sp, #(STACK-0x80)]
    ldp x5, x4, [sp, #(STACK-0x90)]
    ldp x7, x6, [sp, #(STACK-0xa0)]
    add sp, sp, STACK
    .space (5*4), OPCODE_PLACEHOLDER_BYTE
    /* xnuspy will write back the instructions we overwrote in the space
    above inside install_h_s_c_sbn_hook (preboot_hook.c) */
    ret

/* These are still in __text, so clang treats them as code. Four byte align
    them so clang doesn't complain */
addrof_xnuspy_cache: .dword QWORD_PLACEHOLDER
oid_name: .asciz "kern.xnuspy_ctl_callnum"
.align 2
oid_descr: .asciz "query for xnuspy_ctl's call number"
.align 2
oid_fmt: .asciz "L"
/* Align so we can write four bytes every time and not have to worry about
    scratch_space being unaligned when we go to write other instructions */
.align 2

/* Cursed case: are we on 14.5? If we are, we get a pointer to
sysctl_geometry_lock from *(xnuspy_cache+SYSCTL_GEOMETRY_LOCK_PTR),
as opposed to a pointer to a pointer to sysctl_geometry_lock on
13.0 - 14.4.2. This is the case for both old and new 14.5 kernels.
This is apparently also the case for 15.x.

One parameter, a pointer to the xnuspy cache. Returns a pointer to
sysctl_geometry_lock */
.align 2
_get_sysctl_geo_lck:
    stp x19, x20, [sp, #-0x10]!
    stp x29, x30, [sp, #-0x10]!

    ldr x19, [x0, SYSCTL_GEOMETRY_LOCK_PTR]
    ldr x20, [x0, IOS_VERSION]
    cmp x20, iOS_13_x
    b.eq Lout_not_14_5
    cmp x20, iOS_15_x
    b.eq Lout_14_5
    ldr x20, [x0, KERN_VERSION_MINOR]
    cmp x20, #0x4
    /* ge in case a new version of 14 is released that does the
    same thing 14.5 does */
    b.ge Lout_14_5

Lout_not_14_5:
    ldr x0, [x19]
    b Lout

Lout_14_5:
    mov x0, x19

Lout:
    ldp x29, x30, [sp], #0x10
    ldp x19, x20, [sp], #0x10
    ret
