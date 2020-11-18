#ifndef XNUSPY_CTL_TRAMP
#define XNUSPY_CTL_TRAMP

#define STACK                       (0x200)

#define VADDR_CUR                   (STACK-0x70)
#define VADDR_END                   (STACK-0x78)
#define L1_TTE                      (STACK-0x80)
#define L2_TTE                      (STACK-0x88)
#define L3_PTE                      (STACK-0x90)

#define NUM_INSTRS_BEFORE_CACHE     (7)
#define ADDRESS_OF_XNUSPY_CACHE     (-((4*NUM_INSTRS_BEFORE_CACHE)+8))

/* mask for extracting pointer to the next table */
#define ARM_TTE_TABLE_MASK          (0x0000ffffffffc000)

#define ARM_16K_TT_L1_SHIFT         (36)
#define ARM_16K_TT_L2_SHIFT         (25)
#define ARM_16K_TT_L3_SHIFT         (14)

#define ARM_TT_L1_SHIFT             ARM_16K_TT_L1_SHIFT
#define ARM_TT_L2_SHIFT             ARM_16K_TT_L2_SHIFT
#define ARM_TT_L3_SHIFT             ARM_16K_TT_L3_SHIFT

#define ARM_16K_TT_L1_INDEX_MASK    (0x00007ff000000000)
#define ARM_16K_TT_L2_INDEX_MASK    (0x0000000ffe000000)
#define ARM_16K_TT_L3_INDEX_MASK    (0x0000000001ffc000)

#define ARM_TT_L1_INDEX_MASK        ARM_16K_TT_L1_INDEX_MASK
#define ARM_TT_L2_INDEX_MASK        ARM_16K_TT_L2_INDEX_MASK
#define ARM_TT_L3_INDEX_MASK        ARM_16K_TT_L3_INDEX_MASK

/* #define L1_TABLE_INDEX(va) (((va) & ARM_TT_L1_INDEX_MASK) >> ARM_TT_L1_SHIFT) */
/* #define L2_TABLE_INDEX(va) (((va) & ARM_TT_L2_INDEX_MASK) >> ARM_TT_L2_SHIFT) */
/* #define L3_TABLE_INDEX(va) (((va) & ARM_TT_L3_INDEX_MASK) >> ARM_TT_L3_SHIFT) */

#define ARM_TTE_TYPE_FAULT          (0x0000000000000000)
#define ARM_TTE_EMPTY               (0x0000000000000000)
#define ARM_TTE_VALID               (0x0000000000000001)
#define ARM_TTE_TYPE_MASK           (0x0000000000000002)
#define ARM_TTE_TYPE_TABLE          (0x0000000000000002)
#define ARM_TTE_TYPE_BLOCK          (0x0000000000000000)

#define ARM_PTE_TYPE_MASK           (0x0000000000000002)
#define ARM_PTE_TYPE_VALID          (0x0000000000000003)
/* #define PTE_IS_VALID(x) (((x) & 0x3) == ARM_PTE_TYPE_VALID) */

/* #define ttenum(a)               ((a) >> ARM_TT_L1_SHIFT) */

#define ARM_PGSHIFT                 (14)
/* #define ARM_PGBYTES (1 << ARM_PGSHIFT) */

#define AP_RWNA                     (0x0) /* priv=read-write, user=no-access */
#define AP_RWRW                     (0x1) /* priv=read-write, user=read-write */
#define AP_RONA                     (0x2) /* priv=read-only, user=no-access */
#define AP_RORO                     (0x3) /* priv=read-only, user=read-only */
#define AP_MASK                     (0x3) /* mask to find ap bits */

#define ARM_TTE_BLOCK_APSHIFT       (6)
#define ARM_TTE_BLOCK_APMASK        (0xc0)
#define ARM_TTE_BLOCK_PNXMASK       (0x0020000000000000)
#define ARM_TTE_BLOCK_NXMASK        (0x0040000000000000)
#define ARM_TTE_BLOCK_WIREDMASK     (0x0400000000000000)
#define ARM_TTE_BLOCK_WIRED         (0x0400000000000000)

#define ARM_TTE_BLOCK_PNX           (0x0020000000000000)
#define ARM_TTE_BLOCK_NX            (0x0040000000000000)

#define ARM_PTE_PNX                 (0x0020000000000000)
#define ARM_PTE_NX                  (0x0040000000000000)

#define ARM_PTE_HINT_MASK           (0x0010000000000000)
#define ARM_PTE_APMASK              (0xc0)
#define ARM_PTE_NXMASK              (0x0040000000000000)
#define ARM_PTE_PNXMASK             (0x0020000000000000)
#define ARM_PTE_WIRED               (0x0400000000000000)
#define ARM_PTE_WIRED_MASK          (0x0400000000000000)

#define DAIFSC_DEBUGF               (1 << 3)
#define DAIFSC_ASYNCF               (1 << 2)
#define DAIFSC_IRQF                 (1 << 1)
#define DAIFSC_FIQF                 (1 << 0)

#endif
