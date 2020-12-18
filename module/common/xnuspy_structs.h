#ifndef XNUSPY_STRUCTS
#define XNUSPY_STRUCTS

/* All kalloc'ed memory will have this struct as their first field */
struct objhdr {
    size_t sz;
};

struct xnuspy_reflector_page {
    struct xnuspy_reflector_page *next;
    _Atomic uint64_t refcnt;
    void *page;
};

/* This structure represents a shared __TEXT and __DATA mapping. There is
 * one xnuspy_mapping_metadata struct per-process. When an xnuspy_tramp
 * struct is freed, this structure is kept intact so the next process who
 * takes ownership of that struct can free the previous shared mapping.
 *
 * XXX: why is this being reference counted if I'm not even gonna free
 * these structs anymore? I need these to stay intact so I can unmap a
 * previously-used mapping, and at that point, why kfree/kalloc again?
 */
struct xnuspy_mapping_metadata {
    struct objhdr hdr;
    /* Reference count for metadata, NOT the xnuspy_tramp */
    /* _Atomic uint64_t refcnt; */
    /* Process which owns this mapping */
    pid_t owner;
    /* Pointer to the first reflector page used for this mapping */
    struct xnuspy_reflector_page *first_reflector_page;
    /* How many reflector pages are used ^ */
    uint64_t used_reflector_pages;
    /* Memory object for this shared mapping, ipc_port_t */
    void *memory_object;
    /* Address of the start of this mapping */
    uint64_t mapping_addr;
    /* Size of this mapping */
    uint64_t mapping_size;
};

/* This structure contains information for an xnuspy_tramp that isn't
 * necessary to keep in the struct itself. I do this to save space. These are
 * not reference counted because they're per-hook. */
struct xnuspy_tramp_metadata {
    struct objhdr hdr;
    /* Hooked kernel function */
    uint64_t hooked;
    /* Overwritten instruction */
    uint32_t orig_instr;
};

/* This structure represents a function hook. Every xnuspy_tramp struct resides
 * on writeable, executable memory. xnuspy_tramp structs are considered free
 * when their tramp_metadata is NULL. */
struct xnuspy_tramp {
    /* Kernel virtual address of reflected userland replacement */
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
    struct xnuspy_tramp_metadata *tramp_metadata;
    struct xnuspy_mapping_metadata *mapping_metadata;
};

#endif
