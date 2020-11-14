#ifndef PF_14
#define PF_14

#include <stdbool.h>

typedef struct xnu_pf_patch xnu_pf_patch_t;

bool kalloc_external_finder_14(xnu_pf_patch_t *, void *);
bool kfree_ext_finder_14(xnu_pf_patch_t *, void *);
bool ExceptionVectorsBase_finder_14(xnu_pf_patch_t *, void *);
bool sysctl__kern_children_and_register_oid_finder_14(xnu_pf_patch_t *, void *);

#endif
