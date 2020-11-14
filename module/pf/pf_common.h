#ifndef PF_COMMON
#define PF_COMMON

#include <stdbool.h>
#include <stdint.h>

typedef struct xnu_pf_patch xnu_pf_patch_t;

struct pf {
    const char *pf_name;
    uint64_t pf_matches[8];
    uint64_t pf_masks[8];
    uint32_t pf_mmcount;
    /* XNU_PF_ACCESS_8BIT, etc */
    uint32_t pf_access_type;
    bool (*pf_callback)(xnu_pf_patch_t *, void *);
    /* If applicable, the name of the kext used with xnu_pf_get_kext_header
     * If not applicable, NULL
     */
    const char *pf_kext;
    const char *pf_segment;
    /* If applicable, the section used with xnu_pf_section
     * If not applicable, NULL
     */
    const char *pf_section;
    uint8_t pf_unused;
};

#define LISTIZE(...) __VA_ARGS__

#define PF_DECL32(name, matches, masks, mmcount, callback, seg) \
    { \
        .pf_name = name, \
        .pf_matches = matches, \
        .pf_masks = masks, \
        .pf_mmcount = mmcount, \
        .pf_access_type = XNU_PF_ACCESS_32BIT, \
        .pf_callback = callback, \
        .pf_kext = NULL, \
        .pf_segment = seg, \
        .pf_section = NULL, \
        .pf_unused = 0, \
    }

#define PF_DECL_FULL(name, matches, masks, mmcount, access, callback, kext, seg, sect) \
    { \
        .pf_name = name, \
        .pf_matches = matches, \
        .pf_masks = masks, \
        .pf_mmcount = mmcount, \
        .pf_access_type = access, \
        .pf_callback = callback, \
        .pf_kext = kext, \
        .pf_segment = seg, \
        .pf_section = sect, \
        .pf_unused = 0, \
    }

#define PF_UNUSED { .pf_unused = 1 }

#define PF_END { .pf_unused = 0x41 }

#endif
