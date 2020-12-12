#ifndef XNUSPY_STRUCTS
#define XNUSPY_STRUCTS

/* All kalloc'ed memory will have this struct as their first field */
struct objhdr {
    size_t sz;
};

struct xnuspy_usercode_page {
    struct xnuspy_usercode_page *next;
    _Atomic uint64_t refcnt;
    uint8_t *page;
};

struct xnuspy_tramp_metadata {
    struct objhdr hdr;
    /* Process which installed this hook */
    /* XXX XXX SHOULD USE PID INSTEAD */
    void *owner;
    /* Pointer to the first usercode page used for the hook */
    struct xnuspy_usercode_page *first_usercode_page;
    /* How many usercode pages were used */
    uint64_t used_usercode_pages;
    /* EL0 virtual address of Mach header of calling process which owns this hook */
    /* struct mach_header_64 *umh; */
};

/* This structure represents a function hook. Every xnuspy_tramp struct resides
 * on writeable, executable memory. */
struct xnuspy_tramp {
    /* Kernel virtual address of copied userland replacement */
    uint64_t replacement;
    /* The trampoline for a hooked function. When the user installs a hook
     * on a function, the first instruction of that function is replaced
     * with a branch to here. An xnuspy trampoline looks like this:
     *  tramp[0]    ADR X16, <replacementp>
     *  tramp[1]    LDR X16, [X16]
     *  tramp[2]    BR X16
     */
    uint32_t tramp[3];
    /* An abstraction that represents the original function. It's just another
     * trampoline, but it can take on one of five forms. The most common
     * form is this:
     *  orig[0]     <original first instruction of the hooked function>
     *  orig[1]     ADR X16, #0xc
     *  orig[2]     LDR X16, [X16]
     *  orig[3]     BR X16
     *  orig[4]     <address of second instruction of the hooked function>[31:0]
     *  orig[5]     <address of second instruction of the hooked function>[63:32]
     *
     * The above form is taken when the original first instruction of the hooked
     * function is not an immediate conditional branch (b.cond), an immediate
     * compare and branch (cbz/cbnz), an immediate test and branch (tbz/tbnz),
     * or an ADR.
     * These are special cases because the immediates do not contain enough
     * bits for me to just "fix up", so I need to emit an equivalent sequence
     * of instructions.
     *
     * If the first instruction was B.cond <label>
     *  orig[0]     ADR X16, #0x14
     *  orig[1]     ADR X17, #0x18
     *  orig[2]     CSEL X16, X16, X17, <cond>
     *  orig[3]     LDR X16, [X16]
     *  orig[4]     BR X16
     *  orig[5]     <destination if condition holds>[31:0]
     *  orig[6]     <destination if condition holds>[63:32]
     *  orig[7]     <address of second instruction of the hooked function>[31:0]
     *  orig[8]     <address of second instruction of the hooked function>[63:32]
     *
     * If the first instruction was CBZ Rn, <label> or CBNZ Rn, <label>
     *  orig[0]     ADR X16, #0x18
     *  orig[1]     ADR X17, #0x1c
     *  orig[2]     CMP Rn, #0
     *  orig[3]     CSEL X16, X16, X17, <if CBZ, eq, if CBNZ, ne>
     *  orig[4]     LDR X16, [X16]
     *  orig[5]     BR X16
     *  orig[6]     <destination if condition holds>[31:0]
     *  orig[7]     <destination if condition holds>[63:32]
     *  orig[8]     <address of second instruction of the hooked function>[31:0]
     *  orig[9]     <address of second instruction of the hooked function>[63:32]
     *
     * If the first instruction was TBZ Rn, #n, <label> or TBNZ Rn, #n, <label>
     *  orig[0]     ADR X16, #0x18
     *  orig[1]     ADR X17, #0x1c
     *  orig[2]     TST Rn, #(1 << n)
     *  orig[3]     CSEL X16, X16, X17, <if TBZ, eq, if TBNZ, ne>
     *  orig[4]     LDR X16, [X16]
     *  orig[5]     BR X16
     *  orig[6]     <destination if condition holds>[31:0]
     *  orig[7]     <destination if condition holds>[63:32]
     *  orig[8]     <address of second instruction of the hooked function>[31:0]
     *  orig[9]     <address of second instruction of the hooked function>[63:32]
     *
     * If the first instruction was ADR Rn, #n
     *  orig[0]     ADRP Rn, #n@PAGE
     *  orig[1]     ADD Rn, Rn, #n@PAGEOFF
     *  orig[2]     ADR X16, #0xc
     *  orig[3]     LDR X16, [X16]
     *  orig[4]     BR X16
     *  orig[5]     <address of second instruction of the hooked function>[31:0]
     *  orig[6]     <address of second instruction of the hooked function>[63:32]
     */
    uint32_t orig[10];
    /* Kalloc'ed pointer to metadata about this hook to save space */
    struct xnuspy_tramp_metadata *metadata;
};

#endif
