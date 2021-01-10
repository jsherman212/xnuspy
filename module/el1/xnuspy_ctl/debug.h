#ifndef DEBUG
#define DEBUG

#if defined(XNUSPY_DEBUG)
#define SPYDBG(fmt, args...) do { kprintf(fmt, ##args); } while(0)
#else
#define SPYDBG(fmt, args...)
#endif

void desc_freelist(void);
void desc_orphan_mapping(struct orphan_mapping *);
void desc_usedlist(void);

void desc_xnuspy_mapping_metadata(struct xnuspy_mapping_metadata *);
void desc_xnuspy_reflector_page(struct xnuspy_reflector_page *);
void desc_xnuspy_tramp(struct xnuspy_tramp *, uint32_t);

#endif
