#ifndef DEBUG
#define DEBUG

#include "../../common/xnuspy_structs.h"

#if defined(XNUSPY_DEBUG)
#define SPYDBG(fmt, args...) do { kprintf(fmt, ##args); } while(0)
#else
#define SPYDBG(fmt, args...)
#endif

void desc_freelist(void);
void desc_orphan_mapping(struct orphan_mapping *);
/* XXX ONLY meant to be called from xnuspy_gc_thread, hence the lack
 * of locking. */
void desc_unmaplist(void);
void desc_usedlist(void);

void desc_xnuspy_mapping(struct xnuspy_mapping *);
void desc_xnuspy_mapping_metadata(struct xnuspy_mapping_metadata *);
void desc_xnuspy_tramp(struct xnuspy_tramp *, uint32_t);

#endif
