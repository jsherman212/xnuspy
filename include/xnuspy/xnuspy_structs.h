#ifndef XNUSPY_STRUCTS
#define XNUSPY_STRUCTS

#include <sys/queue.h>

struct stailq_entry {
    void *elem;
    STAILQ_ENTRY(stailq_entry) link;
};

struct slist_entry {
    void *elem;
    SLIST_ENTRY(slist_entry) link;
};

/* struct xnuspy_shmem { */
/*     /1* Base of shared memory *1/ */
/*     void *shm_base; */
/*     /1* Size of shared memory, page multiple *1/ */
/*     uint64_t shm_sz; */
/*     /1* Memory entry for the shared memory, ipc_port_t *1/ */
/*     void *shm_entry; */
/*     /1* The vm_map_t which the source pages belong to *1/ */
/*     void *shm_map_from; */
/*     /1* The vm_map_t which the source pages were mapped into *1/ */
/*     void *shm_map_to; */
/* }; */

#define MAX_MAPPING_REFERENCES (0x1000000)

/* This structure represents a shared __TEXT and __DATA mapping. There could
 * be a number of these structures per-process because different dynamic
 * libraries loaded into the address space of one process can install
 * hooks. */
struct xnuspy_mapping {
    /* Reference count for this mapping, NOT the mapping metadata */
    _Atomic int64_t refcnt;
    /* Pointer to caller's Mach-O header */
    uint64_t mapping_addr_uva;
    /* Death callback to invoke when refcnt hits zero */
    void (*death_callback)(void);
    /* Kernel's mapping of the shared __TEXT and __DATA. This has
     * to be a pointer so I can easily enqueue it onto the unmaplist */
    struct xnuspy_shmem *segment_shmem;
};

/* This structure maintains all shared mappings for a given process. There
 * is one of these per-process. This will be deallocated when the mappings
 * linked list is empty. */
struct xnuspy_mapping_metadata {
    /* Process which owns all of the mappings managed by this structure
     * (p_uniqueid) */
    uint64_t owner;
    /* Linked list of all shared mappings we've created for this process.
     * Protected by xnuspy_rw_lck. */
    SLIST_HEAD(, slist_entry) mappings;
};

/* This structure contains information for an xnuspy_tramp that isn't
 * necessary to keep in the struct itself. I do this to save space. These are
 * not reference counted because they're per-hook. */
struct xnuspy_tramp_metadata {
    /* Hooked kernel function */
    uint64_t hooked;
    /* Overwritten instruction */
    uint32_t orig_instr;
};

/* This structure represents a function hook. Every xnuspy_tramp struct resides
 * on writeable, executable memory. */
struct xnuspy_tramp {
    /* Kernel virtual address of userland replacement on shared mapping */
    uint64_t replacement;
    /* The trampoline for a hooked function. When the user installs a hook
     * on a function, the first instruction of that function is replaced
     * with a branch to here. An xnuspy trampoline looks like this:
     *  tramp[0]    LDR X16, #-0x8      (replacement)
     *  tramp[1]    BR X16
     */
    uint32_t tramp[2];
    /* An abstraction that represents the original function. It's just another
     * trampoline, but it can take on one of seven forms. The most common
     * form is this:
     *  orig[0]     <original first instruction of the hooked function>
     *  orig[1]     LDR X16, #0x8
     *  orig[2]     BR X16
     *  orig[3]     <address of second instruction of the hooked function>[31:0]
     *  orig[4]     <address of second instruction of the hooked function>[63:32]
     *
     * The above form is taken when the original first instruction of the hooked
     * function is not an immediate conditional branch (b.cond), an immediate
     * compare and branch (cbz/cbnz), an immediate test and branch (tbz/tbnz),
     * an immediate unconditional branch (b), an immediate unconditional
     * branch with link (bl), load register (literal), or an ADR. These are
     * special cases because the immediates do not contain enough bits for me
     * to just "fix up" or assume we'll always be in range once we do, so I
     * need to emit an equivalent sequence of instructions.
     *
     * If the first instruction was B.cond <label>
     *  orig[0]     LDR X16, #0x10
     *  orig[1]     LDR X17, #0x14
     *  orig[2]     CSEL X16, X16, X17, <cond>
     *  orig[3]     BR X16
     *  orig[4]     <destination if condition holds>[31:0]
     *  orig[5]     <destination if condition holds>[63:32]
     *  orig[6]     <address of second instruction of the hooked function>[31:0]
     *  orig[7]     <address of second instruction of the hooked function>[63:32]
     *
     * If the first instruction was CBZ Rn, <label> or CBNZ Rn, <label>
     *  orig[0]     LDR X16, #0x14
     *  orig[1]     LDR X17, #0x18
     *  orig[2]     CMP Rn, #0
     *  orig[3]     CSEL X16, X16, X17, <if CBZ, eq, if CBNZ, ne>
     *  orig[4]     BR X16
     *  orig[5]     <destination if condition holds>[31:0]
     *  orig[6]     <destination if condition holds>[63:32]
     *  orig[7]     <address of second instruction of the hooked function>[31:0]
     *  orig[8]     <address of second instruction of the hooked function>[63:32]
     *
     * If the first instruction was TBZ Rn, #n, <label> or TBNZ Rn, #n, <label>
     *  orig[0]     LDR X16, #0x14
     *  orig[1]     LDR X17, #0x18
     *  orig[2]     TST Rn, #(1 << n)
     *  orig[3]     CSEL X16, X16, X17, <if TBZ, eq, if TBNZ, ne>
     *  orig[4]     BR X16
     *  orig[5]     <destination if condition holds>[31:0]
     *  orig[6]     <destination if condition holds>[63:32]
     *  orig[7]     <address of second instruction of the hooked function>[31:0]
     *  orig[8]     <address of second instruction of the hooked function>[63:32]
     *
     * If the first instruction was ADR Rn, #n
     *  orig[0]     ADRP Rn, #n@PAGE
     *  orig[1]     ADD Rn, Rn, #n@PAGEOFF
     *  orig[2]     LDR X16, #0x8
     *  orig[3]     BR X16
     *  orig[4]     <address of second instruction of the hooked function>[31:0]
     *  orig[5]     <address of second instruction of the hooked function>[63:32]
     *
     * If the first instruction was B <label>
     *  orig[0]     LDR X16, 0x8
     *  orig[1]     BR X16
     *  orig[2]     <address of branch destination>[31:0]
     *  orig[3]     <address of branch destination>[63:32]
     *
     * If the first instruction was BL <label>
     *  orig[0]     MOV X17, X30
     *  orig[1]     LDR X16, #0x14
     *  orig[2]     BLR X16
     *  orig[3]     MOV X30, X17
     *  orig[4]     LDR X16, #0x10
     *  orig[5]     BR X16
     *  orig[6]     <address of branch destination>[31:0]
     *  orig[7]     <address of branch destination>[63:32]
     *  orig[8]     <address of second instruction of the hooked function>[31:0]
     *  orig[9]     <address of second instruction of the hooked function>[63:32]
     *
     * If the first instruction belongs to the "Load register (literal)" class
     *  orig[0]     ADRP X16, <label>@PAGE
     *  orig[1]     ADD X16, X16, <label>@PAGEOFF
     *  orig[2]     LDR{SW} Rn, [X16] or PRFM <prfop>, [X16]
     *  orig[3]     LDR X16, 0x8
     *  orig[4]     BR X16
     *  orig[5]     <address of second instruction of the hooked function>[31:0]
     *  orig[6]     <address of second instruction of the hooked function>[63:32]
     */
    uint32_t orig[10];
    struct xnuspy_tramp_metadata *tramp_metadata;
    struct xnuspy_mapping_metadata *mapping_metadata;
};

typedef struct __lck_rw_t__ {
    uint64_t word;
    void *owner;
} lck_rw_t;

#define CAST_TO_VM_MAP_ENTRY(x) ((struct vm_map_entry *)(uintptr_t)(x))
#define vm_map_to_entry(map) CAST_TO_VM_MAP_ENTRY(&(map)->hdr.links)
#define vm_map_first_entry(map) ((map)->hdr.links.next)

#define vme_prev		links.prev
#define vme_next		links.next
#define vme_start		links.start
#define vme_end			links.end

struct vm_map_links {
    struct vm_map_entry *prev;
    struct vm_map_entry *next;
    uint64_t start;
    uint64_t end;
};

struct vm_map_entry {
    struct vm_map_links links;
};

struct vm_map_header {
    struct vm_map_links links;
};

struct _vm_map {
    lck_rw_t lck;
    struct vm_map_header hdr;
};

struct sysent {
    uint64_t sy_call;
    void *sy_arg_munge32;
    int32_t sy_return_type;
    int16_t sy_narg;
    uint16_t sy_arg_bytes;
};

#endif
