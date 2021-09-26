#ifndef DEBUG
#define DEBUG

#include <xnuspy/xnuspy_structs.h>

#if defined(XNUSPY_DEBUG)
#define DEBUG_SPEW(fmt, args...) kprintf(fmt, ##args)
#else
#define DEBUG_SPEW(fmt, args...)
#endif

#if defined(XNUSPY_SERIAL)
#define SERIAL_SPEW(fmt, args...) IOLog(fmt, ##args)
#else
#define SERIAL_SPEW(fmt, args...)
#endif

#define SPYDBG(fmt, args...) \
    do { \
        DEBUG_SPEW(fmt, ##args); \
        SERIAL_SPEW(fmt, ##args); \
    } while (0) \

void desc_freelist(void);
void desc_xnuspy_shmem(struct xnuspy_shmem *);
/* XXX ONLY meant to be called from xnuspy_gc_thread, hence the lack
 * of locking. */
void desc_unmaplist(void);
void desc_usedlist(void);

void desc_xnuspy_mapping(struct xnuspy_mapping *);
void desc_xnuspy_mapping_metadata(struct xnuspy_mapping_metadata *);
void desc_xnuspy_tramp(struct xnuspy_tramp *, uint32_t);

#endif
