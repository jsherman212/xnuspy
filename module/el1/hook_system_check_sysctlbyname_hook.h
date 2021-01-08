#ifndef HOOK_SYSTEM_CHECK_SYSCTLBYNAME_HOOK
#define HOOK_SYSTEM_CHECK_SYSCTLBYNAME_HOOK

#define STACK                       (0x200)

#define KALLOC_SZ                   (STACK-0xb0)
#define SYSCTL_NAME_SPACE           (STACK-0xf0)

/* sysctl stuff */
#define CTL_MAXNAME                 (12)

#define SIZEOF_STRUCT_SYSCTL_OID    (0x50)

#define OFFSETOF_OID_PARENT         (0x0)
#define OFFSETOF_OID_LINK           (0x8)
#define OFFSETOF_OID_NUMBER         (0x10)
#define OFFSETOF_OID_KIND           (0x14)
#define OFFSETOF_OID_ARG1           (0x18)
#define OFFSETOF_OID_ARG2           (0x20)
#define OFFSETOF_OID_NAME           (0x28)
#define OFFSETOF_OID_HANDLER        (0x30)
#define OFFSETOF_OID_FMT            (0x38)
#define OFFSETOF_OID_DESCR          (0x40)
#define OFFSETOF_OID_VERSION        (0x48)
#define OFFSETOF_OID_REFCNT         (0x4c)

#define OID_AUTO                    (-1)

#define CTLTYPE_INT                 (2)
#define CTLFLAG_OID2                (0x00400000)
#define CTLFLAG_ANYBODY             (0x10000000)
#define CTLFLAG_RD                  (0x80000000)

#define SYSCTL_OID_VERSION          (1)

#endif
