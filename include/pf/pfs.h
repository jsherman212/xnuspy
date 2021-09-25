#ifndef PFS
#define PFS

#include <pf/pf_common.h>

#include <pf/13/pf.h>
#include <pf/14/pf.h>
#include <pf/15/pf.h>

#define MAXPF                       (100)
#define NUM_SUPPORTED_VERSIONS      (3)

#define PFS_END(x) (x[0].pf_unused == 0x41 && x[1].pf_unused == 0x41 \
        && x[2].pf_unused == 0x41)
#define IS_PF_UNUSED(x) (x->pf_unused == 1)

/* Format:
 *
 * { { iOS 13 patchfinder }, { iOS 14 patchfinder }, { iOS 15 patchfinder } }
 *
 * Not all patchfinders are different across versions.
 *
 * This array will end with
 * { PF_END, PF_END, PF_END }
 */
struct pf g_all_pfs[MAXPF][NUM_SUPPORTED_VERSIONS] = {
    {
        PF_DECL32("sysent finder iOS 13",
            LISTIZE({
                0x1a803000,     /* csel Wn, Wn, Wn, cc */
                0x12003c00,     /* and Wn, Wn, 0xffff */
                0x10000000,     /* adrp Xn, n or adr Xn, n */
            }),
            LISTIZE({
                0xffe0fc00,     /* ignore all but condition code */
                0xfffffc00,     /* ignore all but immediate */
                0x1f000000,     /* ignore everything */
            }),
            3, sysent_finder_13, "__TEXT_EXEC"),
        PF_DECL32("sysent finder iOS 14",
            LISTIZE({
                0x1a803000,     /* csel Wn, Wn, Wn, cc */
                0x92403c00,     /* and Xn, Xn, 0xffff */
                0x52800300,     /* mov Wn, 0x18 */
            }),
            LISTIZE({
                0xffe0fc00,     /* ignore all but condition code */
                0xfffffc00,     /* ignore all but immediate */
                0xffffffe0,     /* ignore Rd */
            }),
            3, sysent_finder_13, "__TEXT_EXEC"),
        PF_DECL32("sysent finder iOS 15",
            LISTIZE({
                0x1a803000,     /* csel Wn, Wn, Wn, cc */
                0x92403c00,     /* and Xn, Xn, 0xffff */
                0x52800300,     /* mov Wn, 0x18 */
            }),
            LISTIZE({
                0xffe0fc00,     /* ignore all but condition code */
                0xfffffc00,     /* ignore all but immediate */
                0xffffffe0,     /* ignore Rd */
            }),
            3, sysent_finder_13, "__TEXT_EXEC"),
    },
    {
        PF_DECL32("kalloc_canblock finder iOS 13",
            LISTIZE({
                0xaa0003f3,     /* mov x19, x0 */
                0xf90003ff,     /* str xzr, [sp, n] */
                0xf9400000,     /* ldr Xn, [Xn] */
                0xf11fbc1f,     /* cmp Xn, 0x7ef */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xffc003ff,     /* ignore immediate */
                0xffc00000,     /* ignore immediate, Rn, and Rt */
                0xfffffc1f,     /* ignore Rn */
            }),
            4, kalloc_canblock_finder_13, "__TEXT_EXEC"),
        PF_DECL_FULL("kalloc_external finder iOS 14",
            LISTIZE({
                0x910022f7,     /* add x23, x23, #0x8 */
                0x910043a8,     /* add x8, x29, #0x10 */
                0xf9000fe8,     /* str w8, [sp, #0x18] */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
            }),
            3, XNU_PF_ACCESS_32BIT, kalloc_external_finder_14,
            "com.apple.driver.AppleMobileFileIntegrity",
            "__TEXT_EXEC", NULL),
        PF_DECL_FULL("kalloc_external finder iOS 15",
            LISTIZE({
                0x910022f7,     /* add x23, x23, #0x8 */
                0x910043a8,     /* add x8, x29, #0x10 */
                0xf9000fe8,     /* str w8, [sp, #0x18] */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
            }),
            3, XNU_PF_ACCESS_32BIT, kalloc_external_finder_14,
            "com.apple.driver.AppleMobileFileIntegrity",
            "__TEXT_EXEC", NULL),
    },
    {
        PF_DECL32("kfree_addr finder iOS 13",
            LISTIZE({
                0x10000009,     /* adrp x9, n or adr x9, n */
                0x0,            /* ignore this instruction */
                0xfa538002,     /* ccmp Xn, x19, #2, hi */
                0x10000000,     /* adrp Xn, n or adr Xn, n */
                0x0,            /* ignore this instruction */
            }),
            LISTIZE({
                0x1f00001f,     /* ignore immediate */
                0x0,            /* ignore this instruction */
                0xfffffc1f,     /* ignore Xn */
                0x1f000000,     /* ignore everything */
                0x0,            /* ignore this instruction */
            }),
            5, kfree_addr_finder_13, "__TEXT_EXEC"),
        PF_DECL32("kfree_ext finder iOS 14",
            LISTIZE({
                0xd2800000,     /* mov x0, #0 */
                0xaa1303e1,     /* mov x1, x19 */
                0x0,            /* ignore this instruction */
                0x94000000,     /* bl n */
                0xaa1803e0,     /* mov x0, x24 */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0x0,            /* ignore this instruction */
                0xfc000000,     /* ignore immediate */
                0xffffffff,     /* match exactly */
            }),
            5, kfree_ext_finder_14, "__TEXT_EXEC"),
        PF_DECL32("kfree_ext finder iOS 15",
            LISTIZE({
                0x10000000,     /* adrp x0, n or adr x0, n */
                0x0,            /* ignore this instruction */
                0xaa1303e1,     /* mov x1, x19 */
                0x0,            /* ignore this instruction */
                0x94000000,     /* bl n */
                0xaa1803e0,     /* mov x0, x24 */
            }),
            LISTIZE({
                0x1f00001f,     /* ignore immediate */
                0x0,            /* ignore this instruction */
                0xffffffff,     /* match exactly */
                0x0,            /* ignore this instruction */
                0xfc000000,     /* ignore immediate */
                0xffffffff,     /* match exactly */
            }),
            6, kfree_ext_finder_14, "__TEXT_EXEC"),
    },
    {
        PF_DECL32("Unused executable code finder iOS 13",
            LISTIZE({
                0xd538d092,     /* mrs x18, tpidr_el1 */
                0xf9400252,     /* ldr x18, [x18, n] */
                0xf9400252,     /* ldr x18, [x18, n] */
                0xf9400252,     /* ldr x18, [x18] */
                0xd61f0240,     /* br x18 */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xffc003ff,     /* match all but immediate */
                0xffc003ff,     /* match all but immediate */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
            }),
            5, ExceptionVectorsBase_finder_13, "__TEXT_EXEC"),
        PF_DECL32("Unused executable code finder iOS 14",
            LISTIZE({
                0xd538d092,     /* mrs x18, tpidr_el1 */
                0xf9400252,     /* ldr x18, [x18, n] */
                0xf9400252,     /* ldr x18, [x18, n] */
                0xf9400252,     /* ldr x18, [x18] */
                0xd61f0240,     /* br x18 */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xffc003ff,     /* match all but immediate */
                0xffc003ff,     /* match all but immediate */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
            }),
            5, ExceptionVectorsBase_finder_14, "__TEXT_EXEC"),
        PF_DECL32("Unused executable code finder iOS 15",
            LISTIZE({
                0xd538d092,     /* mrs x18, tpidr_el1 */
                0xf9400252,     /* ldr x18, [x18, n] */
                0xf9400252,     /* ldr x18, [x18, n] */
                0xf9400252,     /* ldr x18, [x18] */
                0xd61f0240,     /* br x18 */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xffc003ff,     /* match all but immediate */
                0xffc003ff,     /* match all but immediate */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
            }),
            5, ExceptionVectorsBase_finder_14, "__TEXT_EXEC"),
    },
    {
        PF_DECL32("sysctl__kern_children finder iOS 13",
            LISTIZE({
                0x10000013,     /* ADRP X19, n or ADR X19, n */
                0x0,            /* ignore this instruction */
                0x10000014,     /* ADRP X20, n or ADR X20, n */
                0x0,            /* ignore this instruction */
                0x10000015,     /* ADRP X21, n or ADR X21, n */
                0x0,            /* ignore this instruction */
                0x10000016,     /* ADRP X22, n or ADR X22, n */
                0x0,            /* ignore this instruction */
            }),
            LISTIZE({
                0x1f00001f,     /* ignore immediate */
                0x0,            /* ignore this instruction */
                0x1f00001f,     /* ignore immediate */
                0x0,            /* ignore this instruction */
                0x1f00001f,     /* ignore immediate */
                0x0,            /* ignore this instruction */
                0x1f00001f,     /* ignore immediate */
                0x0,            /* ignore this instruction */
            }),
            8, sysctl__kern_children_finder_13, "__TEXT_EXEC"),
        PF_DECL_FULL("sysctl__kern_children & sysctl_register_oid finder iOS 14",
            LISTIZE({
                0x94000000,     /* bl n */
                0x10000008,     /* adrp x8, n or adr x8, n */
                0x0,            /* ignore this instruction */
                0xad400500,     /* ldp q0, q1, [x8] */
                0xad0087e0,     /* stp q0, q1, [sp, 0x10] */
            }),
            LISTIZE({
                0xfc000000,     /* ignore immediate */
                0x1f00001f,     /* ignore immediate */
                0x0,            /* ignore this instruction */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
            }),
            5, XNU_PF_ACCESS_32BIT, sysctl__kern_children_and_register_oid_finder_14,
            "com.apple.kec.corecrypto", "__TEXT_EXEC", NULL),
        PF_DECL_FULL("sysctl__kern_children & sysctl_register_oid finder iOS 15",
            LISTIZE({
                0x94000000,     /* bl n */
                0x10000008,     /* adrp x8, n or adr x8, n */
                0x0,            /* ignore this instruction */
                0xad400500,     /* ldp q0, q1, [x8] */
                0xad0007e0,     /* stp q0, q1, [sp, n] */
                0x3dc00100,     /* ldr q0, [x8, n] */
                0x3d8003e0,     /* str q0, [sp, n] */
            }),
            LISTIZE({
                0xfc000000,     /* ignore immediate */
                0x1f00001f,     /* ignore immediate */
                0x0,            /* ignore this instruction */
                0xffffffff,     /* match exactly */
                0xffc07fff,     /* ignore signed offset */
                0xffc003ff,     /* ignore immediate */
                0xffc003ff,     /* ignore immediate */
            }),
            7, XNU_PF_ACCESS_32BIT, sysctl__kern_children_and_register_oid_finder_14,
            "com.apple.kec.corecrypto", "__TEXT_EXEC", NULL),
    },
    {
        PF_DECL32("sysctl_register_oid finder iOS 13",
            LISTIZE({
                0xb4000013,     /* cbz x19, n */
                0xf9000013,     /* str x19, [xn, n] */
                0x91002000,     /* add xn, xn, 8 */
                0xf9000260,     /* str xn, [x19, n] */
                0xf9400000,     /* ldr x0, [xn, n] */
                0x94000000,     /* bl n (_sysctl_register_oid) */
            }),
            LISTIZE({
                0xff00001f,     /* ignore immediate */
                0xffc0001f,     /* ignore all but Rt */
                0xfffffc00,     /* only match immediate */
                0xffc003e0,     /* ignore immediate and Rt */
                0xffc0001f,     /* ignore all but Rt */
                0xfc000000,     /* ignore immediate */
            }),
            6, sysctl_register_oid_finder_13, "__TEXT_EXEC"),
        PF_UNUSED,
        PF_UNUSED,
    },
    {
        PF_DECL_FULL("hook_system_check_sysctlbyname finder iOS 13",
            LISTIZE({
                0x7100101f,     /* cmp wn, 4 */
                0x54000003,     /* b.cc n */
                0xb9400000,     /* ldr wn, [xn] */
                0x7100041f,     /* cmp wn, 1 */
                0x54000001,     /* b.ne n */
                0xb9400400,     /* ldr wn, [xn, 4] */
                0x7100381f,     /* cmp wn, 0xe */
                0x54000001,     /* b.ne n */
            }),
            LISTIZE({
                0xfffffc1f,     /* ignore Rn */
                0xff00001f,     /* ignore immediate */
                0xfffffc00,     /* ignore Rn and Rt */
                0xfffffc1f,     /* ignore Rn */
                0xff00001f,     /* ignore immediate */
                0xfffffc00,     /* ignore Rn and Rt */
                0xfffffc1f,     /* ignore Rn */
                0xff00001f,     /* ignore immediate */
            }),
            8, XNU_PF_ACCESS_32BIT, hook_system_check_sysctlbyname_finder_13,
            "com.apple.security.sandbox", "__TEXT_EXEC", NULL),
        PF_DECL_FULL("hook_system_check_sysctlbyname finder iOS 14",
            LISTIZE({
                0xf100101f,     /* cmp xn, 4 */
                0x54000003,     /* b.cc n */
                0xb9400000,     /* ldr wn, [xn] */
                0x7100041f,     /* cmp wn, 1 */
                0x54000001,     /* b.ne n */
                0xb9400400,     /* ldr wn, [xn, 4] */
                0x7100381f,     /* cmp wn, 0xe */
                0x54000001,     /* b.ne n */
            }),
            LISTIZE({
                0xfffffc1f,     /* ignore Rn */
                0xff00001f,     /* ignore immediate */
                0xfffffc00,     /* ignore Rn and Rt */
                0xfffffc1f,     /* ignore Rn */
                0xff00001f,     /* ignore immediate */
                0xfffffc00,     /* ignore Rn and Rt */
                0xfffffc1f,     /* ignore Rn */
                0xff00001f,     /* ignore immediate */
            }),
            8, XNU_PF_ACCESS_32BIT, hook_system_check_sysctlbyname_finder_13,
            "com.apple.security.sandbox", "__TEXT_EXEC", NULL),
        PF_DECL_FULL("hook_system_check_sysctlbyname finder iOS 15",
            LISTIZE({
                0xf100101f,     /* cmp xn, 4 */
                0x54000003,     /* b.cc n */
                0xb9400000,     /* ldr wn, [xn] */
                0x7100041f,     /* cmp wn, 1 */
                0x54000001,     /* b.ne n */
                0xb9400400,     /* ldr wn, [xn, 4] */
                0x7100381f,     /* cmp wn, 0xe */
                0x54000001,     /* b.ne n */
            }),
            LISTIZE({
                0xfffffc1f,     /* ignore Rn */
                0xff00001f,     /* ignore immediate */
                0xfffffc00,     /* ignore Rn and Rt */
                0xfffffc1f,     /* ignore Rn */
                0xff00001f,     /* ignore immediate */
                0xfffffc00,     /* ignore Rn and Rt */
                0xfffffc1f,     /* ignore Rn */
                0xff00001f,     /* ignore immediate */
            }),
            8, XNU_PF_ACCESS_32BIT, hook_system_check_sysctlbyname_finder_13,
            "com.apple.security.sandbox", "__TEXT_EXEC", NULL),
    },
    {
        PF_DECL32("sysctl_handle_long finder iOS 13",
            LISTIZE({
                0xb4000001,     /* cbz x1, n */
                0xd10003ff,     /* sub sp, sp, n */
                0xa9004ff4,     /* stp x20, x19, [sp, n] */
                0xa9007bfd,     /* stp x29, x30, [sp, n] */
                0x0,            /* ignore this instruction */
                0xaa0303f4,     /* mov x20, x3 */
                0xaa0103f3,     /* mov x19, x1 */
                0xf9400028,     /* ldr x8, [x1] */
            }),
            LISTIZE({
                0xff00001f,     /* ignore immediate */
                0xffc003ff,     /* ignore immediate */
                0xffc07fff,     /* ignore immediate */
                0xffc07fff,     /* ignore immediate */
                0x0,            /* ignore this instruction */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
            }),
            8, sysctl_handle_long_finder_13, "__TEXT_EXEC"),
        PF_DECL32("sysctl_handle_long finder iOS 14",
            LISTIZE({
                0xb4000001,     /* cbz x1, n */
                0xd10003ff,     /* sub sp, sp, n */
                0xa9004ff4,     /* stp x20, x19, [sp, n] */
                0xa9007bfd,     /* stp x29, x30, [sp, n] */
                0x0,            /* ignore this instruction */
                0xaa0303f4,     /* mov x20, x3 */
                0xaa0103f3,     /* mov x19, x1 */
                0xf9400028,     /* ldr x8, [x1] */
            }),
            LISTIZE({
                0xff00001f,     /* ignore immediate */
                0xffc003ff,     /* ignore immediate */
                0xffc07fff,     /* ignore immediate */
                0xffc07fff,     /* ignore immediate */
                0x0,            /* ignore this instruction */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
            }),
            8, sysctl_handle_long_finder_13, "__TEXT_EXEC"),
        PF_DECL32("sysctl_handle_long finder iOS 15",
            LISTIZE({
                0xb4000001,     /* cbz x1, n */
                0xd10003ff,     /* sub sp, sp, n */
                0xa9004ff4,     /* stp x20, x19, [sp, n] */
                0xa9007bfd,     /* stp x29, x30, [sp, n] */
                0x0,            /* ignore this instruction */
                0xaa0303f4,     /* mov x20, x3 */
                0xaa0103f3,     /* mov x19, x1 */
                0xf9400028,     /* ldr x8, [x1] */
            }),
            LISTIZE({
                0xff00001f,     /* ignore immediate */
                0xffc003ff,     /* ignore immediate */
                0xffc07fff,     /* ignore immediate */
                0xffc07fff,     /* ignore immediate */
                0x0,            /* ignore this instruction */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
            }),
            8, sysctl_handle_long_finder_13, "__TEXT_EXEC"),
    },
    {
        PF_DECL32("name2oid and its dependencies finder iOS 13",
            LISTIZE({
                0x10000000,     /* adrp xn, n or adr xn, n (n = _sysctl_geometry_lock) */
                0xf9400000,     /* ldr x0, [xn, n] */
                0x94000000,     /* bl n (_lck_rw_lock_shared) */
                0x910003e1,     /* add x1, sp, n */
                0x910003e2,     /* add x2, sp, n */
                0x0,            /* ignore this instruction */
                0x94000000,     /* bl n (_name2oid) */
                0x0,            /* ignore this instruction */
            }),
            LISTIZE({
                0x1f000000,     /* ignore everything */
                0xffc0001f,     /* ignore all but Rt */
                0xfc000000,     /* ignore immediate */
                0xffc003ff,     /* ignore immediate */
                0xffc003ff,     /* ignore immediate */
                0x0,            /* ignore this instruction */
                0xfc000000,     /* ignore immediate */
                0x0,            /* ignore this instruction */
            }),
            8, name2oid_and_its_dependencies_finder_13, "__TEXT_EXEC"),
        PF_DECL32("name2oid and its dependencies finder iOS 14",
            LISTIZE({
                0x94000000,     /* bl n (_lck_rw_lock_shared) */
                0x910043e1,     /* add x1, sp, #0x10 */
                0x910023e2,     /* add x2, sp, #0x8 */
                0x0,            /* ignore this instruction */
                0x94000000,     /* BL n (_name2oid) */
            }),
            LISTIZE({
                0xfc000000,     /* ignore immediate */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0x0,            /* ignore this instruction */
                0xfc000000,     /* ignore immediate */
            }),
            5, name2oid_and_its_dependencies_finder_14, "__TEXT_EXEC"),
        PF_DECL32("name2oid and its dependencies finder iOS 15",
            LISTIZE({
                0x94000000,     /* bl n (_lck_rw_lock_shared) */
                0x910043e1,     /* add x1, sp, #0x10 */
                0x910023e2,     /* add x2, sp, #0x8 */
                0x0,            /* ignore this instruction */
                0x94000000,     /* BL n (_name2oid) */
            }),
            LISTIZE({
                0xfc000000,     /* ignore immediate */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0x0,            /* ignore this instruction */
                0xfc000000,     /* ignore immediate */
            }),
            5, name2oid_and_its_dependencies_finder_14, "__TEXT_EXEC"),
    },
    {
        PF_DECL_FULL("lck_grp_alloc_init finder iOS 13",
            LISTIZE({
                0xf9400260,     /* ldr x0, [x19] */
                0xf9400281,     /* ldr x1, [x20, n] */
                0x94000000,     /* bl n */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xffc003ff,     /* ignore immediate */
                0xfc000000,     /* ignore immediate */
            }),
            3, XNU_PF_ACCESS_32BIT, lck_grp_alloc_init_finder_13,
            "com.apple.security.sandbox", "__TEXT_EXEC", NULL),
        PF_DECL_FULL("lck_grp_alloc_init finder iOS 14",
            LISTIZE({
                0x910003e3,     /* add x3, sp, n */
                0x910003e5,     /* add x5, sp, n */
                0xaa1303e0,     /* mov x0, x19 */
                0x52800802,     /* mov w2, 0x40 */
                0x52800104,     /* mov w4, 0x8 */
                0xd2800006,     /* mov x6, 0 */
                0xd2800007,     /* mov x7, 0 */
            }),
            LISTIZE({
                0xffc003ff,     /* ignore immediate */
                0xffc003ff,     /* ignore immediate */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
            }),
            7, XNU_PF_ACCESS_32BIT, lck_grp_alloc_init_finder_14,
            "com.apple.kec.corecrypto", "__TEXT_EXEC", NULL),
        PF_DECL_FULL("lck_grp_alloc_init finder iOS 15",
            LISTIZE({
                0x910003e3,     /* add x3, sp, n */
                0x910003e5,     /* add x5, sp, n */
                0xaa1303e0,     /* mov x0, x19 */
                0x52800802,     /* mov w2, 0x40 */
                0x52800104,     /* mov w4, 0x8 */
                0xd2800006,     /* mov x6, 0 */
                0xd2800007,     /* mov x7, 0 */
            }),
            LISTIZE({
                0xffc003ff,     /* ignore immediate */
                0xffc003ff,     /* ignore immediate */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
            }),
            7, XNU_PF_ACCESS_32BIT, lck_grp_alloc_init_finder_14,
            "com.apple.kec.corecrypto", "__TEXT_EXEC", NULL),
    },
    {
        PF_DECL32("lck_rw_alloc_init finder iOS 13",
            LISTIZE({
                0xd37ced01,     /* lsl x1, x8, #4 */
                0x94000000,     /* bl n (bzero) */
                0x10000008,     /* adrp x8, n or adr x8, n */
                0x0,            /* ignore this instruction */
                0xd2800001,     /* mov x1, 0 */
                0x94000000,     /* bl n (lck_rw_alloc_init) */
                0xf9000260,     /* str x0, [x19, n] */
                0xb5000000,     /* cbnz x0, n */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xfc000000,     /* ignore immediate */
                0x1f00001f,     /* ignore immediate */
                0x0,            /* ignore this instruction */
                0xffffffff,     /* match exactly */
                0xfc000000,     /* ignore immediate */
                0xffc003ff,     /* ignore immediate */
                0xff00001f,     /* ignore immediate */
            }),
            8, lck_rw_alloc_init_finder_13, "__TEXT_EXEC"),
        PF_DECL32("lck_rw_alloc_init finder iOS 14",
            LISTIZE({
                0x94000000,     /* bl n (lck_rw_alloc_init) */
                0xf90002a0,     /* str x0, [x21] */
                0xb4000000,     /* cbz x0, n */
                0x0,            /* ignore this instruction */
                0x0,            /* ignore this instruction */
                0x35000000,     /* cbnz w0, n */
                0x52804000,     /* mov w0, 0x200 */
            }),
            LISTIZE({
                0xfc000000,     /* ignore immediate */
                0xffffffff,     /* match exactly */
                0xff00001f,     /* ignore immediate */
                0x0,            /* ignore this instruction */
                0x0,            /* ignore this instruction */
                0xff00001f,     /* ignore immediate */
                0xffffffff,     /* match exactly */
            }),
            7, lck_rw_alloc_init_finder_14, "__TEXT_EXEC"),
        PF_DECL32("lck_rw_alloc_init finder iOS 15",
            LISTIZE({
                0x94000000,     /* bl n (lck_rw_alloc_init) */
                0xf9000000,     /* str x0, [x21, n] */
                0xb4000000,     /* cbz x0, n */
                0x52800000,     /* mov w0, #0 */
                0x94000000,     /* bl n */
                0xaa0003e0,     /* mov Xn, x0 */
                0x35000000,     /* cbnz w0, n */
                0x52800000,     /* mov wn, n */
            }),
            LISTIZE({
                0xfc000000,     /* ignore immediate */
                0xffc0001f,     /* ignore signed offset */
                0xff00001f,     /* ignore immediate */
                0xffffffff,     /* match exactly */
                0xfc000000,     /* ignore immediate */
                0xffffffe0,     /* ignore Rd */
                0xff00001f,     /* ignore immediate */
                0xff800000,     /* ignore Rd & immediate */
            }),
            8, lck_rw_alloc_init_finder_14, "__TEXT_EXEC"),
    },
    {
        PF_DECL32("bcopy_phys finder iOS 13",
            LISTIZE({
                0x52800808,     /* mov w8, 0x4<n> */
                0x0,            /* ignore this instruction */
                0x0,            /* ignore this instruction */
                0x52800808,     /* mov w8, 0x4<n> */
            }),
            LISTIZE({
                0xfffffe1f,     /* ignore the lower 4 bits of imm16 */
                0x0,            /* ignore this instruction */
                0x0,            /* ignore this instruction */
                0xfffffe1f,     /* ignore the lower 4 bits of imm16 */
            }),
            4, bcopy_phys_finder_13, "__TEXT_EXEC"),
        PF_DECL32("bcopy_phys finder iOS 14",
            LISTIZE({
                0x52800808,     /* mov w8, 0x4<n> */
                0x0,            /* ignore this instruction */
                0x0,            /* ignore this instruction */
                0x52800808,     /* mov w8, 0x4<n> */
            }),
            LISTIZE({
                0xfffffe1f,     /* ignore the lower 4 bits of imm16 */
                0x0,            /* ignore this instruction */
                0x0,            /* ignore this instruction */
                0xfffffe1f,     /* ignore the lower 4 bits of imm16 */
            }),
            4, bcopy_phys_finder_13, "__TEXT_EXEC"),
        PF_DECL32("bcopy_phys finder iOS 15",
            LISTIZE({
                0x52800808,     /* mov w8, 0x4<n> */
                0x0,            /* ignore this instruction */
                0x0,            /* ignore this instruction */
                0x52800808,     /* mov w8, 0x4<n> */
            }),
            LISTIZE({
                0xfffffe1f,     /* ignore the lower 4 bits of imm16 */
                0x0,            /* ignore this instruction */
                0x0,            /* ignore this instruction */
                0xfffffe1f,     /* ignore the lower 4 bits of imm16 */
            }),
            4, bcopy_phys_finder_13, "__TEXT_EXEC"),
    },
    {
        PF_DECL32("phystokv finder iOS 13",
            LISTIZE({
                0x92dfff29,     /* mov x9, #-0xfff900000001 */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
            }),
            1, phystokv_finder_13, "__TEXT_EXEC"),
        PF_DECL32("phystokv finder iOS 14",
            LISTIZE({
                0x92dffe49,     /* mov x9, #-0xfff200000001 */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
            }),
            1, phystokv_finder_13, "__TEXT_EXEC"),
        PF_DECL32("phystokv finder iOS 15",
            LISTIZE({
                0x92dffe49,     /* mov x9, #-0xfff200000001 */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
            }),
            1, phystokv_finder_13, "__TEXT_EXEC"),
    },
    {
        PF_DECL32("KTRR MMU lockdown patcher iOS 13",
            LISTIZE({
                0xd51cf260,     /* msr s3_4_c15_c2_3, xn */
                0x00000000,     /* ignore this instruction */
                0xd51cf280,     /* msr s3_4_c15_c2_4, xn */
                0x00000000,     /* ignore this instruction */
                0xd51cf240,     /* msr s3_4_c15_c2_2, xn */
            }),
            LISTIZE({
                0xffffffe0,     /* ignore Rt */
                0x00000000,     /* ignore this instruction */
                0xffffffe0,     /* ignore Rt */
                0x00000000,     /* ignore this instruction */
                0xffffffe0,     /* ignore Rt */
            }),
            5, ktrr_lockdown_patcher_13, "__TEXT_EXEC"),
        PF_DECL32("KTRR MMU lockdown patcher iOS 14",
            LISTIZE({
                0xd51cf260,     /* msr s3_4_c15_c2_3, xn */
                0xd51cf280,     /* msr s3_4_c15_c2_4, xn */
                0x52800020,     /* mov (x|w)n, 1 */
                0xd51cf240,     /* msr s3_4_c15_c2_2, xn */
            }),
            LISTIZE({
                0xffffffe0,     /* ignore Rt */
                0xffffffe0,     /* ignore Rt */
                0x7fffffe0,     /* ignore Rd */
                0xffffffe0,     /* ignore Rt */
            }),
            4, ktrr_lockdown_patcher_14, "__TEXT_EXEC"),
        PF_DECL32("KTRR MMU lockdown patcher iOS 15",
            LISTIZE({
                0xd51cf260,     /* msr s3_4_c15_c2_3, xn */
                0xd51cf280,     /* msr s3_4_c15_c2_4, xn */
                0x52800020,     /* mov (x|w)n, 1 */
                0xd51cf240,     /* msr s3_4_c15_c2_2, xn */
            }),
            LISTIZE({
                0xffffffe0,     /* ignore Rt */
                0xffffffe0,     /* ignore Rt */
                0x7fffffe0,     /* ignore Rd */
                0xffffffe0,     /* ignore Rt */
            }),
            4, ktrr_lockdown_patcher_14, "__TEXT_EXEC"),
    },
    {
        PF_DECL32("AMCC MMU lockdown patcher iOS 13",
            LISTIZE({
                0xb907ec00,     /* str wn, [xn, 0x7ec] */
                0xd5033fdf,     /* isb */
                0xd51cf260,     /* msr s3_4_c15_c2_3, xn */
                0xd51cf280,     /* msr s3_4_c15_c2_4, xn */
                0xd51cf240,     /* msr s3_4_c15_c2_2, xn */
            }),
            LISTIZE({
                0xfffffc00,     /* ignore Rn and Rt */
                0xffffffff,     /* match exactly */
                0xffffffe0,     /* ignore Rt */
                0xffffffe0,     /* ignore Rt */
                0xffffffe0,     /* ignore Rt */
            }),
            5, amcc_lockdown_patcher_13, "__TEXT_EXEC"),
        PF_DECL32("AMCC CTRR MMU lockdown patcher iOS 14",
            LISTIZE({
                0xb94001d1,     /* ldr w17, [x14] */
                0x1b0f7e31,     /* mul x17, w17, w15 */
                0x8b110210,     /* add x16, x16, x17 */
                0x0,            /* ignore this instruction */
                0x0,            /* ignore this instruction */
                0xb8316a00,     /* str w0, [x16, x17] */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0x0,            /* ignore this instruction */
                0x0,            /* ignore this instruction */
                0xffffffff,     /* match exactly */
            }),
            6, amcc_ctrr_lockdown_patcher_14, "__TEXT_EXEC"),
        PF_DECL32("AMCC CTRR MMU lockdown patcher iOS 15",
            LISTIZE({
                0xb94001d1,     /* ldr w17, [x14] */
                0x1b0f7e31,     /* mul x17, w17, w15 */
                0x8b110210,     /* add x16, x16, x17 */
                0x0,            /* ignore this instruction */
                0x0,            /* ignore this instruction */
                0xb8316a00,     /* str w0, [x16, x17] */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0x0,            /* ignore this instruction */
                0x0,            /* ignore this instruction */
                0xffffffff,     /* match exactly */
            }),
            6, amcc_ctrr_lockdown_patcher_14, "__TEXT_EXEC"),
    },
    {
        PF_DECL32("copyin finder iOS 13",
            LISTIZE({
                0xb4000002,     /* cbz x2, n */
                0xaa0203f3,     /* mov x19, x2 */
                0xaa0103f4,     /* mov x20, x1 */
                0xaa0003f5,     /* mov x21, x0 */
                0x528000a3,     /* mov w3, 5 */
                0x94000000,     /* bl _copy_validate */
            }),
            LISTIZE({
                0xff00001f,     /* ignore immediate */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xfc000000,     /* ignore immediate */
            }),
            6, copyin_finder_13, "__TEXT_EXEC"),
        PF_DECL32("copyin finder iOS 14",
            LISTIZE({
                0xb4000002,     /* cbz x2, n */
                0xaa0203f3,     /* mov x19, x2 */
                0xaa0103f4,     /* mov x20, x1 */
                0xaa0003f5,     /* mov x21, x0 */
                0x528000a3,     /* mov w3, 5 */
                0x94000000,     /* bl _copy_validate */
            }),
            LISTIZE({
                0xff00001f,     /* ignore immediate */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xfc000000,     /* ignore immediate */
            }),
            6, copyin_finder_13, "__TEXT_EXEC"),
        PF_DECL32("copyin finder iOS 15",
            LISTIZE({
                0xb4000002,     /* cbz x2, n */
                0xaa0203f3,     /* mov x19, x2 */
                0xaa0103f4,     /* mov x20, x1 */
                0xaa0003f5,     /* mov x21, x0 */
                0x528000a3,     /* mov w3, 5 */
                0x94000000,     /* bl _copy_validate */
            }),
            LISTIZE({
                0xff00001f,     /* ignore immediate */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xfc000000,     /* ignore immediate */
            }),
            6, copyin_finder_13, "__TEXT_EXEC"),
    },
    {
        PF_DECL32("copyout finder iOS 13",
            LISTIZE({
                0xb4000002,     /* cbz x2, n */
                0xaa0203f3,     /* mov x19, x2 */
                0xaa0103f4,     /* mov x20, x1 */
                0xaa0003f5,     /* mov x21, x0 */
                0x0,            /* ignore this instruction */
                0x0,            /* ignore this instruction */
                0x0,            /* ignore this instruction */
                0x94000000,     /* bl _copy_validate */
            }),
            LISTIZE({
                0xff00001f,     /* ignore immediate */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0x0,            /* ignore this instruction */
                0x0,            /* ignore this instruction */
                0x0,            /* ignore this instruction */
                0xfc000000,     /* ignore immediate */
            }),
            8, copyout_finder_13, "__TEXT_EXEC"),
        PF_DECL32("copyout finder iOS 14",
            LISTIZE({
                0xb4000002,     /* cbz x2, n */
                0xaa0203f3,     /* mov x19, x2 */
                0xaa0103f4,     /* mov x20, x1 */
                0xaa0003f5,     /* mov x21, x0 */
                0x0,            /* ignore this instruction */
                0x0,            /* ignore this instruction */
                0x0,            /* ignore this instruction */
                0x94000000,     /* bl _copy_validate */
            }),
            LISTIZE({
                0xff00001f,     /* ignore immediate */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0x0,            /* ignore this instruction */
                0x0,            /* ignore this instruction */
                0x0,            /* ignore this instruction */
                0xfc000000,     /* ignore immediate */
            }),
            8, copyout_finder_13, "__TEXT_EXEC"),
        PF_DECL32("copyout finder iOS 15",
            LISTIZE({
                0xb4000002,     /* cbz x2, n */
                0xaa0203f3,     /* mov x19, x2 */
                0xaa0103f4,     /* mov x20, x1 */
                0xaa0003f5,     /* mov x21, x0 */
                0x0,            /* ignore this instruction */
                0x0,            /* ignore this instruction */
                0x0,            /* ignore this instruction */
                0x94000000,     /* bl _copy_validate */
            }),
            LISTIZE({
                0xff00001f,     /* ignore immediate */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0x0,            /* ignore this instruction */
                0x0,            /* ignore this instruction */
                0x0,            /* ignore this instruction */
                0xfc000000,     /* ignore immediate */
            }),
            8, copyout_finder_13, "__TEXT_EXEC"),
    },
    {
        PF_DECL32("IOSleep finder iOS 14",
            LISTIZE({
                0x52884801,     /* mov w1, 0x4240 */
                0x72a001e1,     /* movk w1, 0xf, lsl 16 */
                0x14000000,     /* b _delay_for_interval */
                0x52884802,     /* mov w2, 0x4240 */
                0x72a001e2,     /* movk w2, 0xf, lsl 16 */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xfc000000,     /* ignore immediate */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
            }),
            5, IOSleep_finder_13, "__TEXT_EXEC"),
        PF_DECL32("IOSleep finder iOS 14",
            LISTIZE({
                0x52884801,     /* mov w1, 0x4240 */
                0x72a001e1,     /* movk w1, 0xf, lsl 16 */
                0x14000000,     /* b _delay_for_interval */
                0x52884802,     /* mov w2, 0x4240 */
                0x72a001e2,     /* movk w2, 0xf, lsl 16 */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xfc000000,     /* ignore immediate */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
            }),
            5, IOSleep_finder_13, "__TEXT_EXEC"),
        PF_DECL32("IOSleep finder iOS 15",
            LISTIZE({
                0x52884801,     /* mov w1, 0x4240 */
                0x72a001e1,     /* movk w1, 0xf, lsl 16 */
                0x14000000,     /* b _delay_for_interval */
                0x52884802,     /* mov w2, 0x4240 */
                0x72a001e2,     /* movk w2, 0xf, lsl 16 */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xfc000000,     /* ignore immediate */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
            }),
            5, IOSleep_finder_13, "__TEXT_EXEC"),
    },
    {
        PF_DECL32("kprintf finder iOS 13",
            LISTIZE({
                0x910003fd,     /* add x29, sp, #n */
                0xaa1e03f3,     /* mov x19, x30 */
                0xaa0003f4,     /* mov x20, x0 */
                0xa9007fff,     /* stp xzr, xzr, [sp] */
            }),
            LISTIZE({
                0xffc003ff,     /* ignore immediate */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
            }),
            4, kprintf_finder_13, "__TEXT_EXEC"),
        PF_DECL32("kprintf finder iOS 14",
            LISTIZE({
                0x910003fd,     /* add x29, sp, #n */
                0xaa1e03f3,     /* mov x19, x30 */
                0xaa0003f4,     /* mov x20, x0 */
                0xa9007fff,     /* stp xzr, xzr, [sp] */
            }),
            LISTIZE({
                0xffc003ff,     /* ignore immediate */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
            }),
            4, kprintf_finder_13, "__TEXT_EXEC"),
        PF_DECL32("kprintf finder iOS 15",
            LISTIZE({
                0x910003fd,     /* add x29, sp, #n */
                0xaa1e03f3,     /* mov x19, x30 */
                0xaa0003f4,     /* mov x20, x0 */
                0xa9007fff,     /* stp xzr, xzr, [sp] */
            }),
            LISTIZE({
                0xffc003ff,     /* ignore immediate */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
            }),
            4, kprintf_finder_13, "__TEXT_EXEC"),
    },
    {
        PF_DECL_FULL("kernel_map,vm_deallocate,vm_map_unwire finder iOS 13",
            LISTIZE({
                0x94000000,     /* bl _vm_map_unwire */
                0xf94002e0,     /* ldr x0, [x23] */
                0xa9400a61,     /* ldp x1, x2, [x19] */
                0x94000000,     /* bl _vm_deallocate */
                0xa9402668,     /* ldp x8, x9, [x19] */
                0x8b090114,     /* add x20, x8, x9 */
            }),
            LISTIZE({
                0xfc000000,     /* ignore immediate */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xfc000000,     /* ignore immediate */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
            }),
            6, XNU_PF_ACCESS_32BIT,
            kernel_map_vm_deallocate_vm_map_unwire_finder_13,
            "com.apple.security.sandbox", "__TEXT_EXEC", NULL),
        PF_DECL_FULL("kernel_map,vm_deallocate,vm_map_unwire finder iOS 14",
            LISTIZE({
                0x94000000,     /* bl _vm_map_unwire */
                0xf94002e0,     /* ldr x0, [x23] */
                0xa9400a61,     /* ldp x1, x2, [x19] */
                0x94000000,     /* bl _vm_deallocate */
                0xa9402668,     /* ldp x8, x9, [x19] */
                0x8b090114,     /* add x20, x8, x9 */
            }),
            LISTIZE({
                0xfc000000,     /* ignore immediate */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xfc000000,     /* ignore immediate */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
            }),
            6, XNU_PF_ACCESS_32BIT,
            kernel_map_vm_deallocate_vm_map_unwire_finder_13,
            "com.apple.security.sandbox", "__TEXT_EXEC", NULL),
        PF_UNUSED,
    },
    {
        PF_UNUSED,
        PF_UNUSED,
        PF_DECL32("vm_map_unwire_nested finder iOS 15",
            LISTIZE({
                0x94000000,     /* bl _vm_map_unwire_nested */
                0xf9400000,     /* ldr x0, [Xn, n] */
                0x910003e4,     /* add x4, sp, n */
                0xaa0003e1,     /* mov x1, Xn */
                0xaa0003e2,     /* mov x2, Xn */
                0x52800023,     /* mov w3, #1 */
                0x94000000,     /* bl n */
            }),
            LISTIZE({
                0xfc000000,     /* ignore immediate */
                0xffc0001f,     /* ignore Rn & immediate */
                0xff8003ff,     /* ignore immediate */
                0xffe0ffff,     /* ignore Xn */
                0xffe0ffff,     /* ignore Xn */
                0xffffffff,     /* match exactly */
                0xfc000000,     /* ignore immediate */
            }),
            7, vm_map_unwire_nested_finder_15, "__TEXT_EXEC"),
    },
    {
        PF_UNUSED,
        PF_UNUSED,
        PF_DECL32("kernel_map finder iOS 15",
            LISTIZE({
                0x94000000,     /* bl n */
                0xaa0003f4,     /* mov x20, x0 */
                0x0,            /* ignore this instruction */
                0x9ba87c00,     /* umull Xn, w0, w8 */
            }),
            LISTIZE({
                0xfc000000,     /* ignore immediate */
                0xffffffff,     /* match exactly */
                0x0,            /* ignore this instruction */
                0xffffffe0,     /* ignore Rd */
            }),
            4, kernel_map_finder_15, "__TEXT_EXEC"),
    },
    {
        PF_UNUSED,
        PF_UNUSED,
        PF_DECL32("vm_deallocate finder iOS 15",
            LISTIZE({
                0x94000000,     /* bl n */
                0xf900001f,     /* str xzr, [Xn, n] */
                0x3900001f,     /* strb wzr, [Xn, n] */
                0xb4000000,     /* cbz Xn, n */
                0x0,            /* ignore this instruction */
                0x0,            /* ignore this instruction */
                0xaa0003e1,     /* mov x1, Xn */
                0xaa0003e2,     /* mov x2, Xn */
            }),
            LISTIZE({
                0xfc000000,     /* ignore immediate */
                0xffc0001f,     /* ignore Rn & immediate */
                0xffc0001f,     /* ignore Rn & immediate */
                0xff000000,     /* ignore Rn & immediate */
                0x0,            /* ignore this instruction */
                0x0,            /* ignore this instruction */
                0xffe0ffff,     /* ignore Rn */
                0xffe0ffff,     /* ignore Rn */
            }),
            8, vm_deallocate_finder_15, "__TEXT_EXEC"),
    },
    {
        PF_DECL_FULL("kernel_thread_start,thread_deallocate finder iOS 13",
            LISTIZE({
                0x94000000,     /* bl _kernel_thread_start */
                0x34000000,     /* cbz w0, n */
                0xf900027f,     /* str xzr, [x19] */
                0x528000a0,     /* mov w0, 5 */
                0xa9417bfd,     /* ldp x29, x30, [sp, 0x10] */
            }),
            LISTIZE({
                0xfc000000,     /* ignore immediate */
                0xff00001f,     /* ignore immediate */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
            }),
            5, XNU_PF_ACCESS_32BIT,
            kernel_thread_start_thread_deallocate_finder_13,
            "com.apple.filesystems.apfs", "__TEXT_EXEC", NULL),
        PF_DECL_FULL("kernel_thread_start,thread_deallocate finder iOS 14",
            LISTIZE({
                0x94000000,     /* bl _kernel_thread_start */
                0x34000000,     /* cbz w0, n */
                0xf900027f,     /* str xzr, [x19] */
                0x528000a0,     /* mov w0, 5 */
                0xa9417bfd,     /* ldp x29, x30, [sp, 0x10] */
            }),
            LISTIZE({
                0xfc000000,     /* ignore immediate */
                0xff00001f,     /* ignore immediate */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
            }),
            5, XNU_PF_ACCESS_32BIT,
            kernel_thread_start_thread_deallocate_finder_13,
            "com.apple.filesystems.apfs", "__TEXT_EXEC", NULL),
        PF_DECL_FULL("kernel_thread_start,thread_deallocate finder iOS 15",
            LISTIZE({
                0x94000000,     /* bl _kernel_thread_start */
                0x34000000,     /* cbz w0, n */
                0xf900027f,     /* str xzr, [x19] */
                0x528000a0,     /* mov w0, 5 */
                0xa9417bfd,     /* ldp x29, x30, [sp, 0x10] */
            }),
            LISTIZE({
                0xfc000000,     /* ignore immediate */
                0xff00001f,     /* ignore immediate */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
            }),
            5, XNU_PF_ACCESS_32BIT,
            kernel_thread_start_thread_deallocate_finder_13,
            "com.apple.filesystems.apfs", "__TEXT_EXEC", NULL),
    },
    {
        PF_DECL32("mach_make_memory_entry_64 finder iOS 13",
            LISTIZE({
                0x7218107f,     /* tst w3, 0x1f00 */
                0x54000000,     /* b.eq n */
                0x52800240,     /* mov w0, 0x12 */
                0xd65f03c0,     /* ret */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xff00001f,     /* ignore immediate */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
            }),
            4, mach_make_memory_entry_64_finder_13, "__TEXT_EXEC"),
        PF_DECL32("mach_make_memory_entry_64 finder iOS 14",
            LISTIZE({
                0x7218107f,     /* tst w3, 0x1f00 */
                0x54000000,     /* b.eq n */
                0x52800240,     /* mov w0, 0x12 */
                0xd65f03c0,     /* ret */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xff00001f,     /* ignore immediate */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
            }),
            4, mach_make_memory_entry_64_finder_13, "__TEXT_EXEC"),
        PF_DECL32("mach_make_memory_entry_64 finder iOS 15",
            LISTIZE({
                0x7218107f,     /* tst w3, 0x1f00 */
                0x54000000,     /* b.eq n */
                0x52800240,     /* mov w0, 0x12 */
                0xd65f03c0,     /* ret */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xff00001f,     /* ignore immediate */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
            }),
            4, mach_make_memory_entry_64_finder_13, "__TEXT_EXEC"),
    },
    {
        PF_DECL32("offsetof(struct thread, map) finder iOS 13",
            LISTIZE({
                0xd538d088,     /* mrs x8, tpidr_el1 */
                0xf9400100,     /* ldr Xn, [x8, n] */
                0xf9400020,     /* ldr Xn, [x1] */
                0xa9007fe0,     /* stp Xn, xzr, [sp, n] */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xffc003e0,     /* ignore Rt and immediate */
                0xffffffe0,     /* ignore Rt */
                0xffc07fe0,     /* ignore Rt and immediate */
            }),
            4, offsetof_struct_thread_map_finder_13, "__TEXT_EXEC"),
        PF_DECL32("offsetof(struct thread, map) finder iOS 14",
            LISTIZE({
                0xd538d088,     /* mrs x8, tpidr_el1 */
                0xf9400100,     /* ldr Xn, [x8, n] */
                0xf9400020,     /* ldr Xn, [x1] */
                0xa9007fe0,     /* stp Xn, xzr, [sp, n] */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xffc003e0,     /* ignore Rt and immediate */
                0xffffffe0,     /* ignore Rt */
                0xffc07fe0,     /* ignore Rt and immediate */
            }),
            4, offsetof_struct_thread_map_finder_13, "__TEXT_EXEC"),
        PF_DECL32("offsetof(struct thread, map) finder iOS 15",
            LISTIZE({
                0xd538d088,     /* mrs x8, tpidr_el1 */
                0xf9400100,     /* ldr x0, [x8, n] */
                0xaa1503e1,     /* mov x1, x21 */
                0xaa1703e2,     /* mov x2, x23 */
                0xaa1403e3,     /* mov x3, x20 */
                0x52800004,     /* mov w4, #0 */
                0x94000000,     /* bl n */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xffc003ff,     /* ignore immediate */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xfc000000,     /* ignore immediate */
            }),
            7, offsetof_struct_thread_map_finder_13, "__TEXT_EXEC"),
    },
    {
        PF_DECL32("proc stuff finder 0 iOS 13",
            LISTIZE({
                0x910043fd,     /* add x29, sp, 0x10 */
                0x94000000,     /* bl _current_proc */
                0xaa0003f3,     /* mov x19, x0 */
                0x94000000,     /* bl _proc_list_lock */
                0xaa1303e0,     /* mov x0, x19 */
                0x94000000,     /* bl _proc_ref_locked */
                0x0,            /* ignore this instruction */
                0x9a9f0273,     /* csel x19, x19, xzr, eq */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xfc000000,     /* ignore immediate */
                0xffffffff,     /* match exactly */
                0xfc000000,     /* ignore immediate */
                0xffffffff,     /* match exactly */
                0xfc000000,     /* ignore immediate */
                0x0,            /* ignore this instruction */
                0xffffffff,     /* match exactly */
            }),
            8, proc_stuff0_finder_13, "__TEXT_EXEC"),
        PF_DECL32("proc stuff finder 0 iOS 14",
            LISTIZE({
                0x910043fd,     /* add x29, sp, 0x10 */
                0x94000000,     /* bl _current_proc */
                0xaa0003f3,     /* mov x19, x0 */
                0x94000000,     /* bl _proc_list_lock */
                0xaa1303e0,     /* mov x0, x19 */
                0x94000000,     /* bl _proc_ref_locked */
                0x0,            /* ignore this instruction */
                0x9a9f0273,     /* csel x19, x19, xzr, eq */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xfc000000,     /* ignore immediate */
                0xffffffff,     /* match exactly */
                0xfc000000,     /* ignore immediate */
                0xffffffff,     /* match exactly */
                0xfc000000,     /* ignore immediate */
                0x0,            /* ignore this instruction */
                0xffffffff,     /* match exactly */
            }),
            8, proc_stuff0_finder_13, "__TEXT_EXEC"),
        PF_UNUSED, /* _proc_self inlines almost all calls on iOS 15 */
    },
    {
        PF_UNUSED,
        PF_UNUSED,
        PF_DECL32("current_proc finder iOS 15",
            LISTIZE({
                0xd538d088,     /* mrs x8, tpidr_el1 */
                0xf9400113,     /* ldr x19, [x8, n] */
                0xf9400262,     /* ldr x2, [x19, n] */
                0xf100005f,     /* cmp x2, #0 */
                0x90000000,     /* adrp Xn, n */
                0x91000000,     /* add Xn, Xn, n */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xffc003ff,     /* ignore immediate */
                0xffc003ff,     /* ignore immediate */
                0xffffffff,     /* match exactly */
                0x9f000000,     /* ignore Rd & immediate */
                0xff800000,     /* ignore Rd & Rn & immediate */
            }),
            6, current_proc_finder_15, "__TEXT_EXEC"),
    },
    {
        PF_DECL_FULL("proc stuff finder 1 iOS 13",
            LISTIZE({
                0xf81f82a0,     /* stur x0, [x21, -0x8] */
                0xf81e82bf,     /* stur xzr, [x21, -0x18] */
                0xb81f02bf,     /* stur wzr, [x21, -0x10] */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
            }),
            3, XNU_PF_ACCESS_32BIT,
            proc_stuff1_finder_13, "com.apple.security.sandbox",
            "__TEXT_EXEC", NULL),
        PF_DECL_FULL("proc stuff finder 1 iOS 14",
            LISTIZE({
                0xf81f82a0,     /* stur x0, [x21, -0x8] */
                0xf81e82bf,     /* stur xzr, [x21, -0x18] */
                0xb81f02bf,     /* stur wzr, [x21, -0x10] */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
            }),
            3, XNU_PF_ACCESS_32BIT,
            proc_stuff1_finder_13, "com.apple.security.sandbox",
            "__TEXT_EXEC", NULL),
        PF_DECL_FULL("proc stuff finder 1 iOS 15",
            LISTIZE({
                0xf81f82a0,     /* stur x0, [x21, -0x8] */
                0xf81e82bf,     /* stur xzr, [x21, -0x18] */
                0xb81f02bf,     /* stur wzr, [x21, -0x10] */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
            }),
            3, XNU_PF_ACCESS_32BIT,
            proc_stuff1_finder_13, "com.apple.security.sandbox",
            "__TEXT_EXEC", NULL),
    },
    {
        PF_UNUSED,
        PF_UNUSED,
        PF_DECL32("proc_list_mlock finder iOS 15",
            LISTIZE({
                0x90000000,     /* adrp Xd, n */
                0x91000000,     /* add Xd, Xn, n */
                0xaa0003e0,     /* mov x0, Xn */
                0x94000000,     /* bl _lck_mtx_lock */
                0xb9400328,     /* ldr w8, [x25, n] */
                0x32150108,     /* orr w8, w8, #0x800 */
                0xb9000328,     /* str w8, [x25, n] */
                0xaa0003e0,     /* mov x0, Xn */
                /* bl n */
            }),
            LISTIZE({
                0x9f000000,     /* ignore immediate, ignore Rd */
                0xff800000,     /* ignore immediate, ignore Rd */
                0xffe0ffff,     /* ignore Rn */
                0xfc000000,     /* ignore immediate */
                0xffc003ff,     /* ignore immediate */
                0xffffffff,     /* match exactly */
                0xffc003ff,     /* ignore immediate */
                0xffe0ffff,     /* ignore Rn */
                /* ignore immediate */
            }),
            8, proc_list_mlock_finder_15, "__TEXT_EXEC"),
    },
    {
        PF_DECL32("allproc finder iOS 13",
            LISTIZE({
                0xf900427f,     /* str xzr, [x19, 0x80] */
                0xf9000293,     /* str x19, [x20] */
                0xf9004674,     /* str x20, [x19, 0x88] */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
            }),
            3, allproc_finder_13, "__TEXT_EXEC"),
        PF_DECL32("allproc finder iOS 13",
            LISTIZE({
                0xf900427f,     /* str xzr, [x19, 0x80] */
                0xf9000293,     /* str x19, [x20] */
                0xf9004674,     /* str x20, [x19, 0x88] */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
            }),
            3, allproc_finder_13, "__TEXT_EXEC"),
        PF_DECL32("allproc finder iOS 15",
            LISTIZE({
                0xf900427f,     /* str xzr, [x19, 0x80] */
                0xf9000293,     /* str x19, [x20] */
                0xf9004674,     /* str x20, [x19, 0x88] */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
            }),
            3, allproc_finder_13, "__TEXT_EXEC"),
    },
    {
        PF_DECL32("misc. lock stuff finder iOS 13",
            LISTIZE({
                0xaa0003f3,     /* mov x19, x0 */
                0xf9400c08,     /* ldr x8, [x0, #0x18] */
                0xf9400d14,     /* ldr x20, [x8, #0x18] */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
            }),
            3, misc_lck_stuff_finder_13, "__TEXT_EXEC"),
        PF_DECL32("misc. lock stuff finder iOS 14",
            LISTIZE({
                0xaa0003f3,     /* mov x19, x0 */
                0xf9400c08,     /* ldr x8, [x0, #0x18] */
                0xf9400d14,     /* ldr x20, [x8, #0x18] */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
            }),
            3, misc_lck_stuff_finder_13, "__TEXT_EXEC"),
        PF_DECL32("misc. lock stuff finder iOS 15",
            LISTIZE({
                0xf9400c08,     /* ldr x8, [x0, #0x18] */
                0xf9400909,     /* ldr x9, [x8, #0x10] */
                0xb9400129,     /* ldr w9, [x9] */
                0x7100793f,     /* cmp w9, #0x1e */
                0x7a421924,     /* ccmp w9, #2, #4, ne */
                0x0,            /* ignore this instruction */
                0xaa0003f3,     /* mov x19, x0 */
                0xf9400d14,     /* ldr x20, [x8, #0x18] */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0x0,            /* ignore this instruction */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
            }),
            8, misc_lck_stuff_finder_13, "__TEXT_EXEC"),
    },
    {
        PF_UNUSED,
        PF_UNUSED,
        PF_DECL32("lck_mtx_lock/unlock finder iOS 15",
            LISTIZE({
                0x94000000,     /* bl n */
                0xf9400000,     /* ldr x0, [Xn, n] */ 
                0x94000000,     /* bl n */
                0xaa0003e0,     /* mov Xn, x0 */
                0xaa0003e0,     /* mov x0, Xn */
                0x94000000,     /* bl n */
                0xf9000275,     /* str x21, [x19, n] */
                0xf900027f,     /* str xzr, [x19, n] */
                // 0xf900027f,     /* str xzr, [x9, n] */
            }),
            LISTIZE({
                0xfc000000,     /* ignore immediate */
                0xffc0001f,     /* ignore Rn & immediate */
                0xfc000000,     /* ignore immediate */
                0xffffffe0,     /* ignore Rd */
                0xffe0ffff,     /* ignore Rn */
                0xfc000000,     /* ignore immediate */
                0xffc003ff,     /* ignore immediate */
                0xffc003ff,     /* ignore immediate */
                // 0xffc003ff,     /* ignore immediate */
            }),
            8, lck_mtx_lock_unlock_finder_15, "__TEXT_EXEC"),
    },
    {
        PF_DECL32("vm_map_wire_external finder iOS 13",
            LISTIZE({
                0x910003fd,     /* add x29, sp, n */
                0xaa0403f3,     /* mov x19, x4 */
                0xaa0303f4,     /* mov x20, x3 */
                0xaa0203f5,     /* mov x21, x2 */
                0xaa0103f6,     /* mov x22, x1 */
                0xaa0003f7,     /* mov x23, x0 */
                0x94000000,     /* bl n */
            }),
            LISTIZE({
                0xffc003ff,     /* ignore immediate */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xfc000000,     /* ignore immediate */
            }),
            7, vm_map_wire_external_finder_13, "__TEXT_EXEC"),
        PF_DECL32("vm_map_wire_external finder iOS 14",
            LISTIZE({
                0x910003fd,     /* add x29, sp, n */
                0xaa0403f3,     /* mov x19, x4 */
                0xaa0303f4,     /* mov x20, x3 */
                0xaa0203f5,     /* mov x21, x2 */
                0xaa0103f6,     /* mov x22, x1 */
                0xaa0003f7,     /* mov x23, x0 */
                0x94000000,     /* bl n */
            }),
            LISTIZE({
                0xffc003ff,     /* ignore immediate */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xfc000000,     /* ignore immediate */
            }),
            7, vm_map_wire_external_finder_13, "__TEXT_EXEC"),
        PF_DECL32("vm_map_wire_external finder iOS 15",
            LISTIZE({
                0x910003fd,     /* add x29, sp, n */
                0xaa0403f3,     /* mov x19, x4 */
                0xaa0303f4,     /* mov x20, x3 */
                0xaa0203f5,     /* mov x21, x2 */
                0xaa0103f6,     /* mov x22, x1 */
                0xaa0003f7,     /* mov x23, x0 */
                0x94000000,     /* bl n */
            }),
            LISTIZE({
                0xffc003ff,     /* ignore immediate */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xfc000000,     /* ignore immediate */
            }),
            7, vm_map_wire_external_finder_13, "__TEXT_EXEC"),
    },
    {
        PF_DECL32("mach_vm_map_external finder iOS 13",
            LISTIZE({
                0x5297e009,     /* mov w9, 0xbf<n>0 */
                0x72a00d09,     /* movk w9, 0x68, lsl 16 */
                0x6a09009f,     /* tst w4, w9 */
            }),
            LISTIZE({
                0xffffe1ff,     /* ignore bits [7:4] of immediate */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
            }),
            3, mach_vm_map_external_finder_13, "__TEXT_EXEC"),
        PF_DECL32("mach_vm_map_external finder iOS 14",
            LISTIZE({
                0x5297e009,     /* mov w9, 0xbf<n>0 */
                0x72a00d09,     /* movk w9, 0x68, lsl 16 */
                0x6a09009f,     /* tst w4, w9 */
            }),
            LISTIZE({
                0xffffe1ff,     /* ignore bits [7:4] of immediate */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
            }),
            3, mach_vm_map_external_finder_13, "__TEXT_EXEC"),
        PF_DECL32("mach_vm_map_external finder iOS 15",
            LISTIZE({
                0x5297e009,     /* mov w9, 0xbf<n>0 */
                0x72a00d09,     /* movk w9, 0x68, lsl 16 */
                0x6a09009f,     /* tst w4, w9 */
            }),
            LISTIZE({
                0xffffe1ff,     /* ignore bits [7:4] of immediate */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
            }),
            3, mach_vm_map_external_finder_13, "__TEXT_EXEC"),
    },
    {
        PF_DECL32("ipc_port_release_send finder iOS 13",
            LISTIZE({
                0xaa1303e0,     /* mov x0, x19 */
                0x94000000,     /* bl _ipc_port_release_send */
                0x14000000,     /* b n */
                0x94000000,     /* bl ___stack_chk_fail */
                0xf90003f8,     /* str x24, [sp] */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xfc000000,     /* ignore immediate */
                0xfc000000,     /* ignore immediate */
                0xfc000000,     /* ignore immediate */
                0xffffffff,     /* match exactly */
            }),
            5, ipc_port_release_send_finder_13, "__TEXT_EXEC"),
        PF_DECL32("ipc_port_release_send finder iOS 14",
            LISTIZE({
                0xaa1303e0,     /* mov x0, x19 */
                0x94000000,     /* bl _ipc_port_release_send */
                0x14000000,     /* b n */
                0x94000000,     /* bl ___stack_chk_fail */
                0xf90003f8,     /* str x24, [sp] */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xfc000000,     /* ignore immediate */
                0xfc000000,     /* ignore immediate */
                0xfc000000,     /* ignore immediate */
                0xffffffff,     /* match exactly */
            }),
            5, ipc_port_release_send_finder_13, "__TEXT_EXEC"),
        PF_DECL32("ipc_port_release_send finder iOS 15",
            LISTIZE({
                0x910006e8,     /* add x8, x23, #1 */
                0xf100091f,     /* cmp x8, 2 */
                0x540000a3,     /* b.lo 0x1c */
                0xaa1703e0,     /* mov x0, x23 */
                0x94000000,     /* bl _ipc_object_lock */
                0xaa1703e0,     /* mov x0, x23 */
                0x94000000      /* bl _ipc_port_release_and_unlock */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xfc000000,     /* ignore immediate */
                0xffffffff,     /* match exactly */
                0xfc000000,     /* ignore immediate */
            }),
            7, ipc_port_release_send_finder_15, "__TEXT_EXEC"),
    },
    {
        PF_DECL32("lck_rw_free finder iOS 13",
            LISTIZE({
                0x10000008,     /* adrp x8, n or adr x8, n */
                0x0,            /* ignore this instruction */
                0x14000000,     /* b n */
                0xd65f03c0,     /* ret */
                0x10000008,     /* adrp x8, n or adr x8, n */
                0x0,            /* ignore this instruction */
                0xd2800001,     /* mov x1, 0 */
            }),
            LISTIZE({
                0x1f00001f,     /* ignore immediate */
                0x0,            /* ignore this instruction */
                0xfc000000,     /* ignore immediate */
                0xffffffff,     /* match exactly */
                0x1f00001f,     /* ignore immediate */
                0x0,            /* ignore this instruction */
                0xffffffff,     /* match exactly */
            }),
            7, lck_rw_free_finder_13, "__TEXT_EXEC"),
        PF_DECL32("lck_rw_free finder iOS 14",
            LISTIZE({
                0x10000008,     /* adrp x8, n or adr x8, n */
                0x0,            /* ignore this instruction */
                0x14000000,     /* b n */
                0xd65f03c0,     /* ret */
                0x10000008,     /* adrp x8, n or adr x8, n */
                0x0,            /* ignore this instruction */
                0xd2800001,     /* mov x1, 0 */
            }),
            LISTIZE({
                0x1f00001f,     /* ignore immediate */
                0x0,            /* ignore this instruction */
                0xfc000000,     /* ignore immediate */
                0xffffffff,     /* match exactly */
                0x1f00001f,     /* ignore immediate */
                0x0,            /* ignore this instruction */
                0xffffffff,     /* match exactly */
            }),
            7, lck_rw_free_finder_13, "__TEXT_EXEC"),
        PF_DECL32("lck_rw_free finder iOS 15",
            LISTIZE({
                0x10000008,     /* adrp x8, n or adr x8, n */
                0x0,            /* ignore this instruction */
                0x14000000,     /* b n */
                0xd65f03c0,     /* ret */
                0x10000008,     /* adrp x8, n or adr x8, n */
                0x0,            /* ignore this instruction */
                0xd2800001,     /* mov x1, 0 */
            }),
            LISTIZE({
                0x1f00001f,     /* ignore immediate */
                0x0,            /* ignore this instruction */
                0xfc000000,     /* ignore immediate */
                0xffffffff,     /* match exactly */
                0x1f00001f,     /* ignore immediate */
                0x0,            /* ignore this instruction */
                0xffffffff,     /* match exactly */
            }),
            7, lck_rw_free_finder_13, "__TEXT_EXEC"),
    },
    {
        PF_DECL32("lck_grp_free finder iOS 13",
            LISTIZE({
                0x94000000,     /* bl n */
                0x0,            /* ignore this instruction. It is either
                                   mov w22, 0xc or orr w22, wzr, 0xc */
                0x14000000,     /* b n */
                0x0,            /* ignore this instruction. It is either
                                   mov w22, 0xc or orr w22, wzr, 0xc */
                0xaa1403e0,     /* mov x0, x20 */
                0x94000000,     /* bl _lck_grp_free */
                0x10000014,     /* adrp x20, n or adr x20, n */
            }),
            LISTIZE({
                0xfc000000,     /* ignore immediate */
                0x0,            /* ignore this instruction */
                0xfc000000,     /* ignore immediate */
                0x0,            /* ignore this instruction */
                0xffffffff,     /* ignore immediate */
                0xfc000000,     /* ignore immediate */
                0x1f00001f,     /* ignore immediate */
            }),
            7, lck_grp_free_finder_13, "__TEXT_EXEC"),
        PF_DECL32("lck_grp_free finder iOS 14",
            LISTIZE({
                0x94000000,     /* bl n */
                0x0,            /* ignore this instruction. It is either
                                   mov w22, 0xc or orr w22, wzr, 0xc */
                0x14000000,     /* b n */
                0x0,            /* ignore this instruction. It is either
                                   mov w22, 0xc or orr w22, wzr, 0xc */
                0xaa1403e0,     /* mov x0, x20 */
                0x94000000,     /* bl _lck_grp_free */
                0xa94006e0,     /* ldp x0, x1, [x23] */
            }),
            LISTIZE({
                0xfc000000,     /* ignore immediate */
                0x0,            /* ignore this instruction */
                0xfc000000,     /* ignore immediate */
                0x0,            /* ignore this instruction */
                0xffffffff,     /* ignore immediate */
                0xfc000000,     /* ignore immediate */
                0xffffffff,     /* match exactly */
            }),
            7, lck_grp_free_finder_13, "__TEXT_EXEC"),
        PF_DECL32("lck_grp_free finder iOS 15",
            LISTIZE({
                0xa9007c1f,     /* stp xzr, xzr, [Xn, m] */
                0xf900001f,     /* str xzr, [Xn, n] */
                0xf9400000,     /* ldr x0, [Xn, n] */
                0x94000000,     /* bl n */
                0xf9400000,     /* ldr x0, [Xn, n] */
                0x94000000,     /* bl n */
                0xf9400000,     /* ldr x0, [Xn, n] */
                0x94000000      /* bl n */
            }),
            LISTIZE({
                0xffc07c1f,     /* ignore Rn & immediate */
                0xffc0001f,     /* ignore Rn & immediate */
                0xffc0001f,     /* ignore Rn & immediate */
                0xfc000000,     /* ignore immediate */
                0xffc0001f,     /* ignore Rn & immediate */
                0xfc000000,     /* ignore immediate */
                0xffc0001f,     /* ignore Rn & immediate */
                0xfc000000,     /* ignore immediate */
            }),
            8, lck_grp_free_finder_15, "__TEXT_EXEC"),
    },
    {
        PF_DECL32("doprnt_hide_pointers patcher iOS 13",
            LISTIZE({
                0x93407c00,     /* sxtw Xn, Wn */
                0x710001df,     /* cmp w14, 0 */
                0x9a800000,     /* csel Xn, Xn, Xn, eq */
            }),
            LISTIZE({
                0xfffffc00,     /* ignore Rn and Rd */
                0xffffffff,     /* match exactly */
                0xffe0fc00,     /* ignore Rm, Rn, and Rd */
            }),
            3, doprnt_hide_pointers_patcher_13, "__TEXT_EXEC"),
        PF_DECL32("doprnt_hide_pointers patcher iOS 14",
            LISTIZE({
                0x93407c00,     /* sxtw Xn, Wn */
                0x710001df,     /* cmp w14, 0 */
                0x9a800000,     /* csel Xn, Xn, Xn, eq */
            }),
            LISTIZE({
                0xfffffc00,     /* ignore Rn and Rd */
                0xffffffff,     /* match exactly */
                0xffe0fc00,     /* ignore Rm, Rn, and Rd */
            }),
            3, doprnt_hide_pointers_patcher_13, "__TEXT_EXEC"),
        PF_DECL32("doprnt_hide_pointers patcher iOS 15",
            LISTIZE({
                0x93407c00,     /* sxtw Xn, Wn */
                0x7100001f,     /* cmp Wn, 0 */
                0x9a800000,     /* csel Xn, Xn, Xn, eq */
            }),
            LISTIZE({
                0xfffffc00,     /* ignore Rn and Rd */
                0x7fbffc1f,     /* ignore Rn and sf */
                0xffe0fc00,     /* ignore Rm, Rn, and Rd */
            }),
            3, doprnt_hide_pointers_patcher_13, "__TEXT_EXEC"),
    },
    {
        PF_DECL32("copyinstr finder iOS 13",
            LISTIZE({
                0xf90007ff,     /* str xzr, [sp, 8] */
                0xf900007f,     /* str xzr, [x3] */
                0xb4000002,     /* cbz x2, n */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xff00001f,     /* ignore immediate */
            }),
            3, copyinstr_finder_13, "__TEXT_EXEC"),
        PF_DECL32("copyinstr finder iOS 14",
            LISTIZE({
                0xf90007ff,     /* str xzr, [sp, 8] */
                0xf900007f,     /* str xzr, [x3] */
                0xb4000002,     /* cbz x2, n */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xff00001f,     /* ignore immediate */
            }),
            3, copyinstr_finder_13, "__TEXT_EXEC"),
        PF_DECL32("copyinstr finder iOS 15",
            LISTIZE({
                0xf90007ff,     /* str xzr, [sp, 8] */
                0xf900007f,     /* str xzr, [x3] */
                0xb4000002,     /* cbz x2, n */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xff00001f,     /* ignore immediate */
            }),
            3, copyinstr_finder_13, "__TEXT_EXEC"),
    },
    {
        PF_DECL32("thread_terminate finder iOS 13",
            LISTIZE({
                0xaa1503e0,     /* mov x0, x21 */
                0xaa1603e1,     /* mov x1, x22 */
                0xd63f0280,     /* blr x20 */
                0xd538d080,     /* mrs x0, tpidr_el1 */
                0x14000000,     /* b n */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xfc000000,     /* ignore immediate */
            }),
            5, thread_terminate_finder_13, "__TEXT_EXEC"),
        PF_DECL32("thread_terminate finder iOS 14",
            LISTIZE({
                0xaa1503e0,     /* mov x0, x21 */
                0xaa1603e1,     /* mov x1, x22 */
                0xd63f0280,     /* blr x20 */
                0xd538d080,     /* mrs x0, tpidr_el1 */
                0x14000000,     /* b n */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xfc000000,     /* ignore immediate */
            }),
            5, thread_terminate_finder_13, "__TEXT_EXEC"),
        PF_DECL32("thread_terminate finder iOS 15",
            LISTIZE({
                0xaa1503e0,     /* mov x0, x21 */
                0xaa1603e1,     /* mov x1, x22 */
                0xd63f0280,     /* blr x20 */
                0xd538d080,     /* mrs x0, tpidr_el1 */
                0x14000000,     /* b n */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xfc000000,     /* ignore immediate */
            }),
            5, thread_terminate_finder_13, "__TEXT_EXEC"),
    },
    {
        PF_DECL32("pinst_set_tcr patcher iOS 13",
            LISTIZE({
                0xd2facbe2,     /* movz x2, 0xd65f, lsl 48 */
                0xf2c07802,     /* movk x2, 0x03c0, lsl 32 */
                0xf2baa302,     /* movk x2, 0xd518, lsl 16 */
                0xf2840802,     /* movk x2, 0x2040 */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
            }),
            4, pinst_set_tcr_patcher_13, "__TEXT_EXEC"),
        PF_DECL32("pinst_set_tcr patcher iOS 14",
            LISTIZE({
                0xd2facbe2,     /* movz x2, 0xd65f, lsl 48 */
                0xf2c07802,     /* movk x2, 0x03c0, lsl 32 */
                0xf2baa302,     /* movk x2, 0xd518, lsl 16 */
                0xf2840802,     /* movk x2, 0x2040 */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
            }),
            4, pinst_set_tcr_patcher_13, "__TEXT_EXEC"),
        PF_DECL32("pinst_set_tcr patcher iOS 15",
            LISTIZE({
                0xd2facbe2,     /* movz x2, 0xd65f, lsl 48 */
                0xf2c07802,     /* movk x2, 0x03c0, lsl 32 */
                0xf2baa302,     /* movk x2, 0xd518, lsl 16 */
                0xf2840802,     /* movk x2, 0x2040 */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
            }),
            4, pinst_set_tcr_patcher_13, "__TEXT_EXEC"),
    },
    {
        PF_DECL32("msr tcr_el1, x18 patcher iOS 13",
            LISTIZE({
                0xd5182052,     /* msr tcr_el1, x18 */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
            }),
            1, msr_tcr_el1_x18_patcher_13, "__TEXT_EXEC"),
        PF_DECL32("msr tcr_el1, x18 patcher iOS 14",
            LISTIZE({
                0xd5182052,     /* msr tcr_el1, x18 */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
            }),
            1, msr_tcr_el1_x18_patcher_13, "__TEXT_EXEC"),
        PF_DECL32("msr tcr_el1, x18 patcher iOS 15",
            LISTIZE({
                0xd5182052,     /* msr tcr_el1, x18 */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
            }),
            1, msr_tcr_el1_x18_patcher_13, "__TEXT_EXEC"),
    },
    {
        PF_DECL32("proc_name,snprintf,strlen finder iOS 13",
            LISTIZE({
                0x94000000,     /* bl n */
                0x8b000001,     /* add x1, xn, x0 */
                0x4b000002,     /* sub w2, wn, w0 */
                0x0,            /* ignore this instruction */
                0x94000000,     /* bl n */
                0x0,            /* ignore this instruction */
                0x0,            /* ignore this instruction */
                0xb4000000,     /* cbz x0, n */
            }),
            LISTIZE({
                0xfc000000,     /* ignore immediate */
                0xfffffc1f,     /* ignore Rn */
                0xfffffc1f,     /* ignore Rn */
                0x0,            /* ignore this instruction */
                0xfc000000,     /* ignore immediate */
                0x0,            /* ignore this instruction */
                0x0,            /* ignore this instruction */
                0xff00001f,     /* ignore immediate */
            }),
            8, proc_name_snprintf_strlen_finder_13, "__TEXT_EXEC"),
        PF_DECL32("proc_name,snprintf,strlen finder iOS 14",
            LISTIZE({
                0x94000000,     /* bl n */
                0x8b000001,     /* add x1, xn, x0 */
                0x4b000002,     /* sub w2, wn, w0 */
                0x0,            /* ignore this instruction */
                0x94000000,     /* bl n */
                0x10000000,     /* adrp x0, n or adr x0, n */
            }),
            LISTIZE({
                0xfc000000,     /* ignore immediate */
                0xfffffc1f,     /* ignore Rn */
                0xfffffc1f,     /* ignore Rn */
                0x0,            /* ignore this instruction */
                0xfc000000,     /* ignore immediate */
                0x1f00001f,     /* ignore immediate */
            }),
            6, proc_name_snprintf_strlen_finder_13, "__TEXT_EXEC"),
        PF_DECL32("proc_name,snprintf,strlen finder iOS 15",
            LISTIZE({
                0x910003e0,     /* add x0, sp, n */
                0x52800001,     /* mov w1, n */
                0x94000000,     /* bl n */
                0x910003e0,     /* add x0, sp, n */
                0x94000000,     /* bl n */
                0x8b000001,     /* add x1, Xn, Xn */
                0x4b000002,     /* sub w2, Wn, Wn */
                0xaa0003e0,     /* mov x0, Xn */
            }),
            LISTIZE({
                0xff8003ff,     /* ignore immediate */
                0xff80001f,     /* ignore immediate */
                0xfc000000,     /* ignore imemdiate */
                0xff8003ff,     /* ignore immediate */
                0xfc000000,     /* ignore immediate */
                0xffe0fc1f,     /* ignore Rn & Rd */
                0xffe0fc1f,     /* ignore Rn & Rd */
                0xffe0ffff,     /* ignore Rn */
            }),
            8, proc_name_snprintf_strlen_finder_15, "__TEXT_EXEC"),
    },
    {
        PF_DECL32("strcmp finder iOS 13",
            LISTIZE({
                0xa9bf7bfd,     /* stp x29, x30, [sp, -0x10]! */
                0x910003fd,     /* mov x29, sp */
                0xca030063,     /* eor x3, x3, x3 */
                0xb4000002,     /* cbz x2, n */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xff00001f,     /* ignore immediate */
            }),
            4, strncmp_finder_13, "__TEXT_EXEC"),
        PF_DECL32("strcmp finder iOS 13",
            LISTIZE({
                0xa9bf7bfd,     /* stp x29, x30, [sp, -0x10]! */
                0x910003fd,     /* mov x29, sp */
                0xca030063,     /* eor x3, x3, x3 */
                0xb4000002,     /* cbz x2, n */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xff00001f,     /* ignore immediate */
            }),
            4, strncmp_finder_13, "__TEXT_EXEC"),
        PF_DECL32("strcmp finder iOS 15",
            LISTIZE({
                0xa9bf7bfd,     /* stp x29, x30, [sp, -0x10]! */
                0x910003fd,     /* mov x29, sp */
                0xca030063,     /* eor x3, x3, x3 */
                0xb4000002,     /* cbz x2, n */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xff00001f,     /* ignore immediate */
            }),
            4, strncmp_finder_13, "__TEXT_EXEC"),
    },
    {
        PF_DECL32("memset finder iOS 13",
            LISTIZE({
                0x92401c21,     /* and x1, x1, 0xff */
                0xb200c3e3,     /* mov x3, 0x101010101010101 */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
            }),
            2, memset_finder_13, "__TEXT_EXEC"),
        PF_DECL32("memset finder iOS 14",
            LISTIZE({
                0x92401c21,     /* and x1, x1, 0xff */
                0xb200c3e3,     /* mov x3, 0x101010101010101 */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
            }),
            2, memset_finder_13, "__TEXT_EXEC"),
        PF_DECL32("memset finder iOS 15",
            LISTIZE({
                0x92401c21,     /* and x1, x1, 0xff */
                0xb200c3e3,     /* mov x3, 0x101010101010101 */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
            }),
            2, memset_finder_13, "__TEXT_EXEC"),
    },
    {
        PF_DECL32("memmove finder iOS 13",
            LISTIZE({
                0xcb010003,     /* sub x3, x0, x1 */
                0xeb02007f,     /* cmp x3, x2 */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
            }),
            2, memmove_finder_13, "__TEXT_EXEC"),
        PF_DECL32("memmove finder iOS 14",
            LISTIZE({
                0xcb010003,     /* sub x3, x0, x1 */
                0xeb02007f,     /* cmp x3, x2 */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
            }),
            2, memmove_finder_13, "__TEXT_EXEC"),
        PF_DECL32("memmove finder iOS 15",
            LISTIZE({
                0xcb010003,     /* sub x3, x0, x1 */
                0xeb02007f,     /* cmp x3, x2 */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
            }),
            2, memmove_finder_13, "__TEXT_EXEC"),
    },
    {
        PF_DECL32("panic finder iOS 13",
            LISTIZE({
                0x910023e1,     /* add x1, sp, #8 */
                0x52800002,     /* mov w2, #0 */
                0xd2800003,     /* mov x3, #0 */
                0xd2800004,     /* mov x4, #0 */
                0xd2800005,     /* mov x5, #0 */
                0xaa1e03e6      /* mov x6, x30 */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
            }),
            6, panic_finder_13, "__TEXT_EXEC"),
        PF_DECL32("panic finder iOS 14",
            LISTIZE({
                0x910023e1,     /* add x1, sp, #8 */
                0x52800002,     /* mov w2, #0 */
                0xd2800003,     /* mov x3, #0 */
                0xd2800004,     /* mov x4, #0 */
                0xd2800005,     /* mov x5, #0 */
                0xaa1e03e6      /* mov x6, x30 */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
            }),
            6, panic_finder_13, "__TEXT_EXEC"),
        PF_DECL32("panic finder iOS 15",
            LISTIZE({
                0x910023e1,     /* add x1, sp, #8 */
                0x52800002,     /* mov w2, #0 */
                0xd2800003,     /* mov x3, #0 */
                0xd2800004,     /* mov x4, #0 */
                0xd2800005,     /* mov x5, #0 */
                0xaa1e03e6      /* mov x6, x30 */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
            }),
            6, panic_finder_13, "__TEXT_EXEC"),
    },
    {
        PF_DECL32("mach_bsd_to_errno finder iOS 13",
            LISTIZE({
                0x7100cc1f,     /* cmp w0, #0x33 */
                0x54000008,     /* b.hi n */
                0x10000008,     /* adrp x8, n or adr x8, n */
                0x0,            /* ignore this instruction */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xff00001f,     /* ignore immediate */
                0x1f00001f,     /* ignore immediate */
                0x0,            /* ignore this instruction */
            }),
            4, mach_to_bsd_errno_finder_13, "__TEXT_EXEC"),
        PF_DECL32("mach_bsd_to_errno finder iOS 14",
            LISTIZE({
                0x7100cc1f,     /* cmp w0, #0x33 */
                0x54000008,     /* b.hi n */
                0x10000008,     /* adrp x8, n or adr x8, n */
                0x0,            /* ignore this instruction */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xff00001f,     /* ignore immediate */
                0x1f00001f,     /* ignore immediate */
                0x0,            /* ignore this instruction */
            }),
            4, mach_to_bsd_errno_finder_13, "__TEXT_EXEC"),
        PF_DECL32("mach_bsd_to_errno finder iOS 15",
            LISTIZE({
                0x7100e01f,     /* cmp w0, #0x38 */
                0x54000008,     /* b.hi n */
                0x10000008,     /* adrp x8, n or adr x8, n */
                0x0,            /* ignore this instruction */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xff00001f,     /* ignore immediate */
                0x1f00001f,     /* ignore immediate */
                0x0,            /* ignore this instruction */
            }),
            4, mach_to_bsd_errno_finder_13, "__TEXT_EXEC"),
    },
    {
        PF_DECL32("vm_allocate_external finder iOS 13",
            LISTIZE({
                0x53187C64,     /* lsr w4, w3, #0x18 */
                0x14000000,     /* b n */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xfc000000,     /* ignore immediate */
            }),
            2, vm_allocate_external_finder_13, "__TEXT_EXEC"),
        PF_DECL32("vm_allocate_external finder iOS 14",
            LISTIZE({
                0x53187C64,     /* lsr w4, w3, #0x18 */
                0x14000000,     /* b n */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xfc000000,     /* ignore immediate */
            }),
            2, vm_allocate_external_finder_13, "__TEXT_EXEC"),
        PF_DECL32("vm_allocate_external finder iOS 15",
            LISTIZE({
                0x53187C64,     /* lsr w4, w3, #0x18 */
                0x14000000,     /* b n */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xfc000000,     /* ignore immediate */
            }),
            2, vm_allocate_external_finder_13, "__TEXT_EXEC"),
    },
    {
        PF_DECL32("vm_map_deallocate, offsetof(vm_map_t, refcnt) finder iOS 13",
            LISTIZE({
                0xb4000000,     /* cbz x0, n */
                0x94000000,     /* bl n */
                0xf900027f,     /* str xzr, [x19, n] */
                0xf900027f,     /* str xzr, [x19, n] */
                0xf900027f,     /* str xzr, [x19, n] */
            }),
            LISTIZE({
                0xfc000000,     /* ignore immediate */
                0xfc000000,     /* ignore immediate */
                0xffc003ff,     /* ignore immediate */
                0xffc003ff,     /* ignore immediate */
                0xffc003ff,     /* ignore immediate */
            }),
            5, vm_map_deallocate_offsetof_vm_map_refcnt_finder_13,
            "__TEXT_EXEC"),
        PF_DECL32("vm_map_deallocate, offsetof(vm_map_t, refcnt) finder iOS 14",
            LISTIZE({
                0xb4000000,     /* cbz x0, n */
                0x94000000,     /* bl n */
                0xf900027f,     /* str xzr, [x19, n] */
                0xf900027f,     /* str xzr, [x19, n] */
                0xf900027f,     /* str xzr, [x19, n] */
            }),
            LISTIZE({
                0xfc000000,     /* ignore immediate */
                0xfc000000,     /* ignore immediate */
                0xffc003ff,     /* ignore immediate */
                0xffc003ff,     /* ignore immediate */
                0xffc003ff,     /* ignore immediate */
            }),
            5, vm_map_deallocate_offsetof_vm_map_refcnt_finder_13,
            "__TEXT_EXEC"),
        PF_DECL32("vm_map_deallocate, offsetof(vm_map_t, refcnt) finder iOS 15",
            LISTIZE({
                0xb4000000,     /* cbz x0, n */
                0x94000000,     /* bl n */
                0xf900027f,     /* str xzr, [x19, n] */
                0xf900027f,     /* str xzr, [x19, n] */
                0xf900027f,     /* str xzr, [x19, n] */
            }),
            LISTIZE({
                0xfc000000,     /* ignore immediate */
                0xfc000000,     /* ignore immediate */
                0xffc003ff,     /* ignore immediate */
                0xffc003ff,     /* ignore immediate */
                0xffc003ff,     /* ignore immediate */
            }),
            5, vm_map_deallocate_offsetof_vm_map_refcnt_finder_13,
            "__TEXT_EXEC"),
    },
    {
        PF_UNUSED, /* not tested for 13 */
        PF_UNUSED, /* not tested for 14 */
        PF_DECL32("IOLog finder iOS 15",
            LISTIZE({
                0xf9400008,
                0xf9400108,
                0xaa0003e0,
                0xd2800001,
                0xd63f0100,
                0xf90003e0,
                0x90000000,
                0x91000000,
            }),
            LISTIZE({
                0xfffffc1f,
                0xffc003ff,
                0xffe0ffff,
                0xffffffff,
                0xffffffff,
                0xffc003ff,
                0xff00001f,
                0xffc003ff,
            }),
            8, iolog_finder_15, "__TEXT_EXEC"),
    },
    { PF_END, PF_END, PF_END },
};

#endif
