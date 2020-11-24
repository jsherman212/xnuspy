#ifndef PTE
#define PTE

typedef uint64_t pte_t;

pte_t *el0_ptep(uint64_t);
pte_t *el1_ptep(uint64_t);

#define ARM_PTE_NX                  (0x0040000000000000uLL)
#define ARM_PTE_PNX                 (0x0020000000000000uLL)

#define ARM_PTE_NXMASK              (0x0040000000000000uLL)
#define ARM_PTE_PNXMASK             (0x0020000000000000uLL)

#define ARM_PTE_APMASK              (0xc0uLL)
#define ARM_PTE_AP(x)               ((x) << 6)

#define AP_RWNA                     (0x0) /* priv=read-write, user=no-access */
#define AP_RWRW                     (0x1) /* priv=read-write, user=read-write */
#define AP_RONA                     (0x2) /* priv=read-only, user=no-access */
#define AP_RORO                     (0x3) /* priv=read-only, user=read-only */
#define AP_MASK                     (0x3) /* mask to find ap bits */

#endif
