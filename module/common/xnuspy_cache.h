#ifndef XNUSPY_CACHE
#define XNUSPY_CACHE

#define SYSCTL__KERN_CHILDREN_PTR                       (0x0)
#define SYSCTL_REGISTER_OID                             (0x8)
#define SYSCTL_HANDLE_LONG                              (0x10)
#define NAME2OID                                        (0x18)
#define SYSCTL_GEOMETRY_LOCK_PTR                        (0x20)
#define LCK_RW_LOCK_SHARED                              (0x28)
#define LCK_RW_DONE                                     (0x30)
#define DID_REGISTER_SYSCTL                             (0x38)
#define H_S_C_SBN_EPILOGUE_ADDR                         (0x40)
#define XNUSPY_SYSCTL_MIB_PTR                           (0x48)
#define XNUSPY_SYSCTL_MIB_COUNT_PTR                     (0x50)
#define XNUSPY_CTL_CALLNUM                              (0x58)
#define IOS_VERSION                                     (0x60)
#define XNUSPY_CTL_ENTRYPOINT                           (0x68)
#define XNUSPY_CTL_CODESTART                            (0x70)
#define XNUSPY_CTL_CODESZ                               (0x78)
#define XNUSPY_CTL_IS_RX                                (0x80)
#define PHYSTOKV                                        (0x88)
#define BCOPY_PHYS                                      (0x90)

/* for kalloc/kfree, one of these will written to the cache depending
 * on iOS version
 */
#define KALLOC_CANBLOCK                                 (0x98)
#define KALLOC_EXTERNAL                                 (0x98)

#define KFREE_ADDR                                      (0xa0)
#define KFREE_EXT                                       (0xa0)

#define iOS_13_x                                        (19)
#define iOS_14_x                                        (20)

#endif
