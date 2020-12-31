#ifndef XNUSPY_CTL
#define XNUSPY_CTL

/* flavors */
#define XNUSPY_INSTALL_HOOK         (0)
#define XNUSPY_CHECK_IF_PATCHED     (1)
#define XNUSPY_GET_FUNCTION         (2)

/* values for XNUSPY_CACHE_READ */

/* values for XNUSPY_GET_FUNCTION */
#define KPROTECT                                                    (0)
#define COPYOUT                                                     (1)
#define KPRINTF                     (2)
#define IOSLEEP (3)
#define KERNEL_SLIDE (4)

#endif
