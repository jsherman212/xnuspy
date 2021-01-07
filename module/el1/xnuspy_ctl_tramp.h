#ifndef XNUSPY_CTL_TRAMP
#define XNUSPY_CTL_TRAMP

#define STACK                       (0x200)

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

#define ARM_TTE_TYPE_FAULT          (0x0000000000000000)
#define ARM_TTE_EMPTY               (0x0000000000000000)
#define ARM_TTE_VALID               (0x0000000000000001)
#define ARM_TTE_TYPE_MASK           (0x0000000000000002)
#define ARM_TTE_TYPE_TABLE          (0x0000000000000002)
#define ARM_TTE_TYPE_BLOCK          (0x0000000000000000)

#define ARM_PTE_TYPE_MASK           (0x0000000000000002)
#define ARM_PTE_TYPE_VALID          (0x0000000000000003)

#define DAIFSC_DEBUGF               (1 << 3)
#define DAIFSC_ASYNCF               (1 << 2)
#define DAIFSC_IRQF                 (1 << 1)
#define DAIFSC_FIQF                 (1 << 0)

#endif
