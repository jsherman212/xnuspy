#include <errno.h>
#include <mach/mach.h>
#include <mach-o/loader.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>

#include "../../common/asm.h"
#include "../../common/xnuspy_structs.h"

#include "debug.h"
#include "libc.h"
#include "mem.h"
#include "pte.h"
#include "tramp.h"

#undef current_thread
#undef PAGE_SIZE

#define PAGE_SIZE                   (0x4000)

#define iOS_13_x                    (19)
#define iOS_14_x                    (20)

/* THIS NEEDS TO STAY IN SYNC WITH example/xnuspy_ctl.h */
enum {
    XNUSPY_CHECK_IF_PATCHED = 0,
    XNUSPY_INSTALL_HOOK,
    XNUSPY_REGISTER_DEATH_CALLBACK,
    XNUSPY_CALL_HOOKME,
    XNUSPY_CACHE_READ,
    XNUSPY_KREAD,
    XNUSPY_KWRITE,
    XNUSPY_GET_CURRENT_THREAD,
    XNUSPY_MAX_FLAVOR = XNUSPY_GET_CURRENT_THREAD,
};

/* Values for XNUSPY_CACHE_READ */
enum xnuspy_cache_id {
    KERNEL_SLIDE = 0,
    KPRINTF,
    KALLOC_CANBLOCK,
    KALLOC_EXTERNAL,
    KFREE_ADDR,
    KFREE_EXT,
    BCOPY_PHYS,
    PHYSTOKV,
    COPYIN,
    COPYINSTR,
    COPYOUT,
    CURRENT_PROC,
    PROC_PID,
    KERNEL_THREAD_START,
    THREAD_DEALLOCATE,
    THREAD_TERMINATE,
    ALLPROC,
    BZERO,
    IPC_PORT_RELEASE_SEND,
    KERNEL_MAP,
    LCK_GRP_ALLOC_INIT,
    LCK_GRP_FREE,
    LCK_MTX_UNLOCK,
    LCK_RW_ALLOC_INIT,
    LCK_RW_DONE,
    LCK_RW_FREE,
    LCK_RW_LOCK_EXCLUSIVE,
    LCK_RW_LOCK_SHARED,
    LCK_RW_LOCK_SHARED_TO_EXCLUSIVE,
    MACH_MAKE_MEMORY_ENTRY_64,
    MACH_VM_MAP_EXTERNAL,
    MEMCHR,
    MEMCMP,
    MEMMEM,
    MEMMOVE,
    MEMRCHR,
    MEMSET,
    OFFSETOF_STRUCT_THREAD_MAP,
    PROC_LIST_LOCK,
    PROC_LIST_UNLOCK,
    PROC_LIST_MLOCK,
    PROC_NAME,
    PROC_REF_LOCKED,
    PROC_RELE_LOCKED,
    PROC_UNIQUEID,
    SNPRINTF,
    STRCHR,
    STRRCHR,
    STRCMP,
    STRLEN,
    STRNCMP,
    STRSTR,
    STRNSTR,
    VM_DEALLOCATE,
    VM_MAP_UNWIRE,
    VM_MAP_WIRE_EXTERNAL,
    IOSLEEP,

    /* Everything below is from xnuspy, everything above is from XNU */

    HOOKME,
    CURRENT_MAP,
    IOS_VERSION,
    KVTOPHYS,
    UVTOPHYS,
    KPROTECT,
    UPROTECT,
    KWRITE_STATIC,
    KWRITE_INSTR,
    EL0_PTEP,
    EL1_PTEP,
    TLB_FLUSH,
    UNIFIED_KALLOC,
    UNIFIED_KFREE,
    MAX_CACHE = UNIFIED_KFREE
};

#define MAP_MEM_VM_SHARE            0x400000 /* extract a VM range for remap */

typedef unsigned int lck_rw_type_t;

typedef	void (*thread_continue_t)(void *param, int wait_result);

#define MARK_AS_KERNEL_OFFSET __attribute__ ((section("__DATA,__koff")))

MARK_AS_KERNEL_OFFSET void **allprocp;
MARK_AS_KERNEL_OFFSET void (*bcopy_phys)(uint64_t src, uint64_t dst,
        vm_size_t bytes);
MARK_AS_KERNEL_OFFSET int (*copyin)(const void *uaddr, void *kaddr,
        vm_size_t nbytes);
MARK_AS_KERNEL_OFFSET int (*copyinstr)(const void *uaddr, void *kaddr,
        size_t len, size_t *done);
MARK_AS_KERNEL_OFFSET int (*copyout)(const void *kaddr, uint64_t uaddr,
        vm_size_t nbytes);
MARK_AS_KERNEL_OFFSET void *(*current_proc)(void);
/* Keep these all aligned 8 bytes */
MARK_AS_KERNEL_OFFSET uint64_t hookme_in_range;
MARK_AS_KERNEL_OFFSET uint64_t iOS_version;
MARK_AS_KERNEL_OFFSET void (*IOSleep)(unsigned int millis);
MARK_AS_KERNEL_OFFSET void (*ipc_port_release_send)(void *port);
MARK_AS_KERNEL_OFFSET void *(*kalloc_canblock)(vm_size_t *sizep, bool canblock,
        void *site);
MARK_AS_KERNEL_OFFSET void *(*kalloc_external)(vm_size_t sz);
MARK_AS_KERNEL_OFFSET void **kernel_mapp;
MARK_AS_KERNEL_OFFSET uint64_t kernel_slide;
MARK_AS_KERNEL_OFFSET kern_return_t (*kernel_thread_start)(thread_continue_t cont,
        void *parameter, void **new_thread);
MARK_AS_KERNEL_OFFSET void (*kfree_addr)(void *addr);
MARK_AS_KERNEL_OFFSET void (*kfree_ext)(void *kheap, void *addr,
        vm_size_t sz);
MARK_AS_KERNEL_OFFSET void (*kprintf)(const char *fmt, ...);
MARK_AS_KERNEL_OFFSET void *(*lck_grp_alloc_init)(const char *grp_name,
        void *attr);
MARK_AS_KERNEL_OFFSET void (*lck_grp_free)(void *grp);
MARK_AS_KERNEL_OFFSET void (*lck_mtx_unlock)(void *lock);
MARK_AS_KERNEL_OFFSET lck_rw_t *(*lck_rw_alloc_init)(void *grp, void *attr);
MARK_AS_KERNEL_OFFSET uint32_t (*lck_rw_done)(lck_rw_t *lock);
MARK_AS_KERNEL_OFFSET void (*lck_rw_free)(lck_rw_t *lock, void *grp);
MARK_AS_KERNEL_OFFSET void (*lck_rw_lock_exclusive)(void *lock);
MARK_AS_KERNEL_OFFSET void (*lck_rw_lock_shared)(void *lock);
MARK_AS_KERNEL_OFFSET int (*lck_rw_lock_shared_to_exclusive)(lck_rw_t *lck);
MARK_AS_KERNEL_OFFSET kern_return_t (*_mach_make_memory_entry_64)(void *target_map,
        uint64_t *size, uint64_t offset, vm_prot_t prot, void **object_handle,
        void *parent_handle);
MARK_AS_KERNEL_OFFSET kern_return_t (*mach_vm_map_external)(void *target_map,
        uint64_t *address, uint64_t size, uint64_t mask, int flags,
        void *memory_object, uint64_t offset, int copy,
        vm_prot_t cur_protection, vm_prot_t max_protection,
        vm_inherit_t inheritance);
MARK_AS_KERNEL_OFFSET void *(*_memmove)(void *dest, const void *src, size_t n);
MARK_AS_KERNEL_OFFSET void *(*_memset)(void *s, int c, size_t n);
MARK_AS_KERNEL_OFFSET uint64_t offsetof_struct_thread_map;
MARK_AS_KERNEL_OFFSET __attribute__ ((noreturn)) void (*_panic)(const char *fmt, ...);
MARK_AS_KERNEL_OFFSET uint64_t (*phystokv)(uint64_t pa);
MARK_AS_KERNEL_OFFSET void (*proc_list_lock)(void);
MARK_AS_KERNEL_OFFSET void **proc_list_mlockp;
/* XNU's declaration, not mine */
MARK_AS_KERNEL_OFFSET void (*proc_name)(int pid, char *buf, int size);
MARK_AS_KERNEL_OFFSET pid_t (*proc_pid)(void *proc);
MARK_AS_KERNEL_OFFSET void (*proc_ref_locked)(void *proc);
MARK_AS_KERNEL_OFFSET void (*proc_rele_locked)(void *proc);
MARK_AS_KERNEL_OFFSET uint64_t (*proc_uniqueid)(void *proc);
MARK_AS_KERNEL_OFFSET int (*_snprintf)(char *str, size_t size, const char *fmt, ...);
MARK_AS_KERNEL_OFFSET size_t (*_strlen)(const char *s);
MARK_AS_KERNEL_OFFSET int (*_strncmp)(const char *s1, const char *s2, size_t n);
MARK_AS_KERNEL_OFFSET void (*thread_deallocate)(void *thread);
MARK_AS_KERNEL_OFFSET void (*_thread_terminate)(void *thread);
MARK_AS_KERNEL_OFFSET kern_return_t (*_vm_deallocate)(void *map,
        uint64_t start, uint64_t size);
MARK_AS_KERNEL_OFFSET kern_return_t (*vm_map_unwire)(void *map, uint64_t start,
        uint64_t end, int user);
MARK_AS_KERNEL_OFFSET kern_return_t (*vm_map_wire_external)(void *map,
        uint64_t start, uint64_t end, vm_prot_t prot, int user_wire);
MARK_AS_KERNEL_OFFSET struct xnuspy_tramp *xnuspy_tramp_mem;
MARK_AS_KERNEL_OFFSET struct xnuspy_tramp *xnuspy_tramp_mem_end;

__attribute__ ((naked)) static uint64_t current_thread(void){
    asm(""
        "mrs x0, tpidr_el1\n"
        "ret\n"
       );
}

static struct _vm_map *current_map(void){
    return *(struct _vm_map **)(current_thread() + offsetof_struct_thread_map);
}

static int kern_return_to_errno(kern_return_t kret){
    switch(kret){
        case KERN_INVALID_ADDRESS:
            return EFAULT;
        case KERN_PROTECTION_FAILURE:
        case KERN_NO_ACCESS:
            return EPERM;
        case KERN_NO_SPACE:
        case KERN_RESOURCE_SHORTAGE:
            return ENOSPC;
        case KERN_FAILURE:
        case KERN_INVALID_ARGUMENT:
            return EINVAL;      /* is this the best for KERN_FAILURE? */
        case KERN_MEMORY_PRESENT:
            return EEXIST;
    };

    SPYDBG("%s: unhandled kern_return_t %#x, returning 10000\n",
            __func__, kret);

    /* Not a valid errno */
    return 10000;
}

lck_rw_t *xnuspy_rw_lck = NULL;

/* I cannot reference count the xnuspy_tramp structs because I am unable
 * to use the stack to push a frame so the replacement function returns to
 * a routine to release a taken reference. Reference counting these structs
 * would prevent me from unmapping something that some thread is currently
 * executing on.
 *
 * Instead, I'm maximizing the time between the previous free and the next
 * allocation of a given xnuspy_tramp struct. I do this in case we uninstall
 * while some thread is currently, or will end up, executing on a trampoline.
 * When a hook is uninstalled, its shared mapping won't be unmapped immediately.
 * It may be unmapped when xnuspy_gc_thread notices that we're pushing our
 * limit in regard to the number of pages we're currently leaking. 
 *
 * Freed structs will be pushed to the end of the freelist, and we allocate
 * from the front of the freelist. The usedlist is used as a normal linked
 * list, but has to be an STAILQ so I can insert objects from the freelist
 * and into the usedlist and vice versa. The unmaplist contains shared mappings
 * from recently freed xnuspy_tramp structs. The mapping from the most
 * recently freed xnuspy_tramp struct is pushed to the end of the unmaplist,
 * and we pull from the start of the unmaplist for garbage collection.
 *
 * freelist and usedlist are protected by xnuspy_rw_lck, unmaplist isn't
 * because it's only touched by xnuspy_gc_thread.
 */
STAILQ_HEAD(, stailq_entry) freelist = STAILQ_HEAD_INITIALIZER(freelist);
STAILQ_HEAD(, stailq_entry) usedlist = STAILQ_HEAD_INITIALIZER(usedlist);
STAILQ_HEAD(, stailq_entry) unmaplist = STAILQ_HEAD_INITIALIZER(unmaplist);

static uint64_t g_num_leaked_pages = 0;

static bool xnuspy_mapping_release(struct xnuspy_mapping *m){
    int64_t prev = m->refcnt--;

    if(prev < 1)
        _panic("xnuspy_mapping(%p) over-release", m);

    bool last = (prev == 1);

    if(last){
        if(m->death_callback){
            SPYDBG("%s: invoking death callback\n", __func__);
            m->death_callback();
        }

        g_num_leaked_pages += m->mapping_size / PAGE_SIZE;

        struct orphan_mapping *om = unified_kalloc(sizeof(*om));

        /* I don't care for allocation failures here, we just won't be able to
         * ever unmap this mapping. This shouldn't happen too often? */
        if(!om){
            SPYDBG("%s: om allocation failed\n", __func__);
            return last;
        }

        struct stailq_entry *stqe = unified_kalloc(sizeof(*stqe));

        if(!stqe){
            SPYDBG("%s: stqe allocation failed\n", __func__);
            return last;
        }

        om->mapping_addr = m->mapping_addr_kva;
        om->mapping_size = m->mapping_size;
        om->memory_entry = m->memory_entry;

        stqe->elem = om;

        STAILQ_INSERT_TAIL(&unmaplist, stqe, link);

        SPYDBG("%s: added mapping @ %#llx to the unmaplist\n", __func__,
                om->mapping_addr);

        desc_orphan_mapping(om);

        unified_kfree(m);
    }

    return last;
}

static void xnuspy_mapping_reference(struct xnuspy_mapping *m){
    int64_t prev = m->refcnt++;

    if(prev < 0)
        _panic("xnuspy_mapping(%p) resurrection", m);

    if(prev >= MAX_MAPPING_REFERENCES)
        _panic("xnuspy_mapping(%p) possible memory corruption", m);
}

/* This function is expected to be called with an xnuspy_tramp that has
 * already been pulled off the usedlist, but not yet added to the freelist.
 * xnuspy_rw_lock is expected to be held exclusively if we're here. */
static void xnuspy_tramp_teardown(struct xnuspy_tramp *t){
    struct xnuspy_mapping_metadata *mm = t->mapping_metadata;
    struct xnuspy_tramp_metadata *tm = t->tramp_metadata;

    uint64_t replacement_kva = t->replacement;

    struct slist_entry *entry, *tmp;

    SLIST_FOREACH_SAFE(entry, &mm->mappings, link, tmp){
        struct xnuspy_mapping *m = entry->elem;

        uint64_t start = m->mapping_addr_kva;
        uint64_t end = start + m->mapping_size;

        if(replacement_kva >= start && replacement_kva < end){
            if(xnuspy_mapping_release(m)){
                SPYDBG("%s: last ref on mapping was released, removing from"
                        " list\n", __func__);
                SLIST_REMOVE(&mm->mappings, entry, slist_entry, link);

                if(SLIST_EMPTY(&mm->mappings)){
                    SPYDBG("%s: mappings list is empty, freeing mm\n",
                            __func__);
                    unified_kfree(mm);
                }
            }

            t->mapping_metadata = NULL;

            break;
        }
    }

    if(t->tramp_metadata){
        unified_kfree(t->tramp_metadata);
        t->tramp_metadata = NULL;
    }
}

/* Free an xnuspy_tramp struct by putting it at the end of the freelist */
static void xnuspy_tramp_free(struct stailq_entry *stqe){
    lck_rw_lock_exclusive(xnuspy_rw_lck);
    STAILQ_INSERT_TAIL(&freelist, stqe, link);
    lck_rw_done(xnuspy_rw_lck);
}

/* Pull an xnuspy_tramp struct off of the freelist, we may or may not commit
 * it to use */
static struct stailq_entry *xnuspy_tramp_alloc(void){
    lck_rw_lock_exclusive(xnuspy_rw_lck);

    if(STAILQ_EMPTY(&freelist)){
        lck_rw_done(xnuspy_rw_lck);
        return NULL;
    }

    struct stailq_entry *allocated = STAILQ_FIRST(&freelist);

    STAILQ_REMOVE_HEAD(&freelist, link);

    lck_rw_done(xnuspy_rw_lck);

    return allocated;
}

/* Commit an xnuspy_tramp struct to use by putting it on the usedlist */
static void xnuspy_tramp_commit(struct stailq_entry *stqe){
    lck_rw_lock_exclusive(xnuspy_rw_lck);
    STAILQ_INSERT_TAIL(&usedlist, stqe, link);
    lck_rw_done(xnuspy_rw_lck);
}

/* Add an xnuspy mapping to the list of the calling process's shared
 * mappings. A reference for m must have been taken before calling this
 * function. */
static int xnuspy_mapping_add(struct xnuspy_mapping_metadata *mm,
        struct xnuspy_mapping *m){
    struct slist_entry *sle = unified_kalloc(sizeof(*sle));

    if(!sle)
        return ENOMEM;

    sle->elem = m;

    lck_rw_lock_exclusive(xnuspy_rw_lck);
    SLIST_INSERT_HEAD(&mm->mappings, sle, link);
    lck_rw_done(xnuspy_rw_lck);

    return 0;
}

static struct xnuspy_mapping_metadata *find_mapping_metadata(void){
    uint64_t cuniqueid = proc_uniqueid(current_proc());
    struct stailq_entry *entry;

    lck_rw_lock_shared(xnuspy_rw_lck);

    STAILQ_FOREACH(entry, &usedlist, link){
        struct xnuspy_tramp *tramp = entry->elem;

        if(tramp->mapping_metadata->owner == cuniqueid){
            struct xnuspy_mapping_metadata *mm = tramp->mapping_metadata;
            lck_rw_done(xnuspy_rw_lck);
            return mm;
        }
    }

    lck_rw_done(xnuspy_rw_lck);

    return NULL;
}

static int hook_already_exists(uint64_t target){
    struct stailq_entry *entry;

    lck_rw_lock_shared(xnuspy_rw_lck);

    STAILQ_FOREACH(entry, &usedlist, link){
        struct xnuspy_tramp *tramp = entry->elem;

        if(tramp->tramp_metadata->hooked == target){
            lck_rw_done(xnuspy_rw_lck);
            return 1;
        }
    }

    lck_rw_done(xnuspy_rw_lck);

    return 0;
}

/* Figure out the kernel virtual address of a user address on a shared
 * mapping */
static uint64_t shared_mapping_kva(struct xnuspy_mapping *m,
        uint64_t /* __user */ uaddr){
    uint64_t dist = uaddr - m->mapping_addr_uva;

    SPYDBG("%s: dist %#llx uaddr %#llx umh %#llx kmh %#llx\n", __func__,
            dist, uaddr, m->mapping_addr_uva, m->mapping_addr_kva);

    return m->mapping_addr_kva + dist;
}

/* Create a shared mapping of __TEXT and __DATA from the Mach-O header passed
 * in.
 *
 * We share __TEXT so the user can call other functions they wrote from their
 * kernel hooks. We share __DATA so modifications to global variables are
 * visible to both EL1 and EL0. 
 *
 * On success, returns a new xnuspy_mapping struct with a reference taken.
 *
 * On failure, returns NULL and sets retval.
 */
static struct xnuspy_mapping *
map_segments(struct mach_header_64 * /* __user */ umh,
        struct _vm_map *current_map, int *retval){
    struct mach_header_64 umh_kern;

    int res = copyin(umh, &umh_kern, sizeof(umh_kern));

    if(res){
        SPYDBG("%s: copyin failed for mach-o header: %d\n", __func__, res);
        *retval = res;
        return NULL;
    }

    if(umh_kern.magic != MH_MAGIC_64){
        SPYDBG("%s: %#llx is not a Mach-O header? Found %#x\n", __func__,
                (uint64_t)umh, umh_kern.magic);
        *retval = EFAULT;
        return NULL;
    }

    uint32_t sizeofcmds = umh_kern.sizeofcmds;

    struct load_command *lc = unified_kalloc(sizeofcmds);

    if(!lc){
        SPYDBG("%s: failed allocating load command buffer\n", __func__);
        *retval = ENOMEM;
        return NULL;
    }

    struct load_command *lc_orig = lc;
    struct load_command *ulc = (struct load_command *)(umh + 1);

    res = copyin(ulc, lc, sizeofcmds);

    if(res){
        unified_kfree(lc);
        SPYDBG("%s: copyin failed for load commands: %d\n", __func__, res);
        *retval = res;
        return NULL;
    }

    uint64_t aslr_slide;

    if(umh_kern.filetype == MH_EXECUTE)
        aslr_slide = (uintptr_t)umh - 0x100000000;
    else if(umh_kern.filetype == MH_DYLIB)
        aslr_slide = (uint64_t)umh;
    else{
        unified_kfree(lc);
        SPYDBG("%s: the caller is not from a Mach-O executable or a"
                " dylib? Filetype=%#x\n", __func__, umh_kern.filetype);
        *retval = ENOTSUP;
        return NULL;
    }

    uint64_t copystart = 0, copysz = 0;
    bool seen_text = false, seen_data = false;

    uint32_t ncmds = umh_kern.ncmds;

    for(uint32_t i=0; i<ncmds; i++){
        if(lc->cmd != LC_SEGMENT_64)
            goto nextcmd;

        struct segment_command_64 *sc64 = (struct segment_command_64 *)lc;

        bool is_text = strcmp(sc64->segname, "__TEXT") == 0;
        bool is_data = strcmp(sc64->segname, "__DATA") == 0;

        /* These will always be page aligned and unslid */
        uint64_t /* __user */ start = sc64->vmaddr + aslr_slide;
        uint64_t /* __user */ end = start + sc64->vmsize;

        SPYDBG("%s: start %#llx end %#llx\n", __func__, start, end);

        /* If this segment is neither __TEXT nor __DATA, but we've already
         * seen __TEXT or __DATA, we need to make sure we account for
         * that gap. copystart being non-zero implies we've already seen
         * __TEXT or __DATA */
        if(copystart && !is_text && !is_data)
            copysz += sc64->vmsize;
        else if(is_text || is_data){
            if(copystart)
                copysz += sc64->vmsize;
            else{
                copystart = start;
                copysz = sc64->vmsize;
            }

            if(is_text)
                seen_text = true;

            if(is_data)
                seen_data = true;

            if(seen_text && seen_data){
                SPYDBG("%s: we've seen text and data, breaking\n", __func__);
                break;
            }
        }

nextcmd:
        lc = (struct load_command *)((uintptr_t)lc + lc->cmdsize);
    }

    unified_kfree(lc_orig);

    SPYDBG("%s: ended with copystart %#llx copysz %#llx\n", __func__,
            copystart, copysz);

    bool need_free_on_error = false;
    struct xnuspy_mapping *m = NULL;

    if(!copystart || !copysz){
        *retval = ENOENT;
        goto failed;
    }

    m = unified_kalloc(sizeof(*m));

    if(!m){
        SPYDBG("%s: unified_kalloc returned NULL when allocating mapping obj\n",
                __func__);
        *retval = ENOMEM;
        goto failed;
    }

    bzero(m, sizeof(*m));

    need_free_on_error = true;

    void *kernel_map = *kernel_mapp;

    /* Wire down __TEXT and __DATA of the calling process so they are not
     * swapped out. We only set VM_PROT_READ in case there were some segments
     * in between __TEXT and __DATA. Also, vm_map_wire_nested needs to be
     * patched to not bail when VM_PROT_EXECUTE is given, so that's also one
     * less patchfinder for me to write :D We also set from_user to one because
     * we're dealing with a user map. */
    kern_return_t kret = vm_map_wire_external(current_map, copystart, copysz,
            VM_PROT_READ, 1);

    if(kret){
        SPYDBG("%s: vm_map_wire_external failed when wiring down "
                "[copystart, copysz): %d\n", __func__, kret);
        *retval = kern_return_to_errno(kret);
        goto failed;
    }

    /* We create the mapping with only VM_PROT_READ because that is the
     * minimum VM protections for a segment (unless they have none, which won't
     * happen, unless the user does something weird). Additionally, we map
     * [copystart, copystart+copysz) in one shot, so it's easier to map
     * everything with the minimum permissions.
     *
     * Eventually these permissions will be changed to rwx through the PTEs
     * of this mapping. */
    vm_prot_t shm_prot = VM_PROT_READ;

    /* ipc_port_t */
    void *shm_entry = NULL;

    uint64_t copysz_before = copysz;

    kret = _mach_make_memory_entry_64(current_map, &copysz, copystart,
            MAP_MEM_VM_SHARE | shm_prot, &shm_entry, NULL);

    if(kret){
        SPYDBG("%s: mach_make_memory_entry_64 failed: %d\n", __func__, kret);
        *retval = kern_return_to_errno(kret);
        goto failed_unwire_user_segments;
    }

    if(copysz_before != copysz){
        SPYDBG("%s: did not map the entirety of copystart? got %#llx "
                "expected %#llx\n", __func__, copysz, copysz_before);
        /* Probably not the best option */
        *retval = EIO;
        goto failed_dealloc_mementry;
    }

    uint64_t shm_addr = 0;

    kret = mach_vm_map_external(kernel_map, &shm_addr, copysz, 0,
            VM_FLAGS_ANYWHERE, shm_entry, 0, 0, shm_prot, shm_prot,
            VM_INHERIT_NONE);

    if(kret){
        SPYDBG("%s: mach_vm_map_external failed: %d\n", __func__, kret);
        *retval = kern_return_to_errno(kret);
        goto failed_dealloc_mementry;
    }

    /* Wire down the shared mapping */
    kret = vm_map_wire_external(kernel_map, shm_addr, shm_addr + copysz,
            shm_prot, 0);

    if(kret){
        SPYDBG("%s: vm_map_wire_external failed: %d\n", __func__, kret);
        *retval = kern_return_to_errno(kret);
        goto failed_dealloc_kernel_mapping;
    }

    m->memory_entry = shm_entry;
    m->mapping_addr_uva = (uint64_t)umh;
    m->mapping_addr_kva = shm_addr;
    m->mapping_size = copysz;

    xnuspy_mapping_reference(m);

    *retval = 0;

    return m;

failed_unwire_kernel_mapping:
    vm_map_unwire(kernel_map, shm_addr, shm_addr + copysz, 0);
failed_dealloc_kernel_mapping:
    _vm_deallocate(kernel_map, shm_addr, copysz);
failed_dealloc_mementry:
    ipc_port_release_send(shm_entry);
failed_unwire_user_segments:
    vm_map_unwire(current_map, copystart, copystart + copysz, 1);
failed:;
   if(need_free_on_error)
       unified_kfree(m);

    return NULL;
}

static struct xnuspy_mapping *
find_mapping_for_uaddr(struct xnuspy_mapping_metadata *mm,
        uint64_t /* __user */ addr){
    struct slist_entry *entry;

    lck_rw_lock_shared(xnuspy_rw_lck);

    SLIST_FOREACH(entry, &mm->mappings, link){
        struct xnuspy_mapping *m = entry->elem;

        uint64_t /* __user */ start = m->mapping_addr_uva;
        uint64_t /* __user */ end = m->mapping_size + start;

        if(addr >= start && addr < end){
            xnuspy_mapping_reference(m);
            lck_rw_done(xnuspy_rw_lck);
            return m;
        }
    }

    lck_rw_done(xnuspy_rw_lck);

    return NULL;
}

/* Given the vm_map of the caller, figure out the Mach-O header that
 * corresponds to addr. This exists so xnuspy can be used inside dynamic
 * libraries. */
static struct mach_header_64 * /* __user */ mh_for_addr(struct _vm_map *cm,
        uint64_t /* __user */ addr){
    struct vm_map_entry *entry;

    lck_rw_lock_shared(&cm->lck);

    for(entry = vm_map_first_entry(cm);
            entry != vm_map_to_entry(cm);
            entry = entry->vme_next){
        uint64_t /* __user */ start = entry->vme_start;
        uint64_t /* __user */ end = entry->vme_end;

        if(addr >= start && addr < end){
            lck_rw_done(&cm->lck);

            SPYDBG("%s: found mach header for %#llx @ %#llx\n", __func__,
                    addr, start);

            return (struct mach_header_64 *)start;
        }
    }

    lck_rw_done(&cm->lck);

    return NULL;
}

static int xnuspy_install_hook(uint64_t target,
        uint64_t /* __user */ replacement, uint64_t /* __user */ origp){
    SPYDBG("%s: called with unslid target %#llx replacement %#llx origp %#llx\n",
            __func__, target, replacement, origp);

    int res = 0;

    /* Slide target */
    target += kernel_slide;

    if(hook_already_exists(target)){
        SPYDBG("%s: hook for %#llx already exists\n", __func__, target);
        res = EEXIST;
        goto out;
    }

    struct xnuspy_tramp_metadata *tm = unified_kalloc(sizeof(*tm));

    if(!tm){
        SPYDBG("%s: failed allocating mem for tramp metadata\n", __func__);
        res = ENOMEM;
        goto out;
    }

    tm->hooked = target;
    tm->orig_instr = *(uint32_t *)target;

    struct stailq_entry *tramp_entry = xnuspy_tramp_alloc();

    /* We don't need to keep this locked because we have not committed
     * this entry to the usedlist and it no longer exists in the freelist */

    if(!tramp_entry){
        SPYDBG("%s: no free xnuspy_tramp structs\n", __func__);
        res = ENOSPC;
        goto out_free_tramp_metadata;
    }

    uint32_t orig_tramp_len = 0;

    struct xnuspy_tramp *tramp = tramp_entry->elem;

    generate_replacement_tramp(tramp->tramp);
    generate_original_tramp(target + 4, tramp->orig, &orig_tramp_len);

    dcache_clean_PoU(tramp->tramp, sizeof(tramp->tramp));
    icache_invalidate_PoU(tramp->tramp, sizeof(tramp->tramp));

    dcache_clean_PoU(tramp->orig, sizeof(tramp->orig));
    icache_invalidate_PoU(tramp->orig, sizeof(tramp->orig));

    /* copyout the original function trampoline before the target
     * function is hooked, if necessary */
    if(origp){
        uint32_t *orig_tramp = tramp->orig;
        res = copyout(&orig_tramp, origp, sizeof(origp));

        if(res){
            SPYDBG("%s: copyout orig trampoline failed: %d\n", __func__, res);
            goto out_free_tramp_entry;
        }
    }

    /* Check if we've got mapping metadata for the calling process already.
     * If we don't, this is the first hook being installed for this process,
     * so we need to create it. */
    struct xnuspy_mapping_metadata *mm = find_mapping_metadata();

    bool need_mm_kfree_on_fail = false;

    if(!mm){
        SPYDBG("%s: no mapping metadata for this process, creating it\n",
                __func__);

        mm = unified_kalloc(sizeof(*mm));

        if(!mm){
            SPYDBG("%s: unified_kalloc failed for new metadata object\n",
                    __func__);
            res = ENOMEM;
            goto out_free_tramp_entry;
        }

        need_mm_kfree_on_fail = true;

        mm->owner = proc_uniqueid(current_proc());

        SLIST_INIT(&mm->mappings);
    }

    /* Check to see if we already have a mapping for the replacement.
     * If we don't, we need to create it now. A reference has already
     * been taken for m if it's not NULL. */
    struct xnuspy_mapping *m = find_mapping_for_uaddr(mm, replacement);
    struct _vm_map *cm = current_map();

    if(!m){
        struct mach_header_64 * /* __user */ umh = mh_for_addr(cm, replacement);

        if(!umh){
            SPYDBG("%s: could not find Mach-O header corresponding to the page"
                    " containing %#llx\n", __func__, replacement);
            res = ENOENT;
            goto out_free_mapping_metadata;
        }

        SPYDBG("%s: no shared mapping for %#llx, creating it now\n",
                __func__, replacement);

        m = map_segments(umh, cm, &res);

        if(!m){
            SPYDBG("%s: could not make mapping: %d\n", __func__, res);
            goto out_free_mapping_metadata;
        }

        res = xnuspy_mapping_add(mm, m);

        if(res){
            SPYDBG("%s: Could not add this mapping struct to mapping list"
                    " for this process: %d\n", __func__, res);
            goto out_release_mapping;
        }

        /* Easier to just grant rwx to all pages of the shared mapping */
        kprotect((void *)m->mapping_addr_kva, m->mapping_size, VM_PROT_READ |
                VM_PROT_WRITE | VM_PROT_EXECUTE);
    }

    uint32_t branch = assemble_b(target, (uint64_t)tramp->tramp);

    tramp->replacement = shared_mapping_kva(m, replacement);
    tramp->tramp_metadata = tm;
    tramp->mapping_metadata = mm;

    desc_xnuspy_tramp(tramp, orig_tramp_len);

    xnuspy_tramp_commit(tramp_entry);
    kwrite_instr(target, branch);

    return 0;

out_release_mapping:
    xnuspy_mapping_release(m);
out_free_mapping_metadata:;
    if(need_mm_kfree_on_fail)
        unified_kfree(mm);
out_free_tramp_entry:
    xnuspy_tramp_free(tramp_entry);
out_free_tramp_metadata:
    unified_kfree(tm);
out:
    return res;
}

/* proc_list_unlock has been inlined so aggressively on all kernels that there
 * are no xrefs to the actual function so we need to do it like this */
static void proc_list_unlock(void){
    lck_mtx_unlock(*proc_list_mlockp);
}

/* By default, allow around 1 mb of kernel memory to be leaked by us */
#ifndef XNUSPY_LEAKED_PAGE_LIMIT
#define XNUSPY_LEAKED_PAGE_LIMIT 64
#endif

/* We only deallocate just enough pages to get us back down around the limit. */
static void xnuspy_do_gc(void){
    SPYDBG("%s: doing gc\n", __func__);

    if(STAILQ_EMPTY(&unmaplist)){
        SPYDBG("%s: unmap list is empty\n", __func__);
        return;
    }

    int64_t dealloc_pages = (int64_t)(g_num_leaked_pages - XNUSPY_LEAKED_PAGE_LIMIT);

    SPYDBG("%s: need to deallocate %lld pages to get back around limit\n",
            __func__, dealloc_pages);

    struct stailq_entry *entry, *tmp;

    STAILQ_FOREACH_SAFE(entry, &unmaplist, link, tmp){
        if(g_num_leaked_pages <= XNUSPY_LEAKED_PAGE_LIMIT){
            SPYDBG("%s: back around limit with %lld leaked pages\n", __func__,
                    g_num_leaked_pages);
            return;
        }

        struct orphan_mapping *om = entry->elem;

        ipc_port_release_send(om->memory_entry);

        /* If we fail from this point on, make sure we don't update
         * g_num_leaked_pages */
        bool didfail = false;

        kern_return_t kret = vm_map_unwire(*kernel_mapp, om->mapping_addr,
                om->mapping_addr + om->mapping_size, 0);

        if(kret){
            SPYDBG("%s: vm_map_unwire failed: %#x\n", __func__, kret);
            didfail = true;

            /* Maybe it's unsafe to deallocate if we failed to unwire?
             * Honestly don't know */
            goto end;
        }

        kret = _vm_deallocate(*kernel_mapp, om->mapping_addr,
                om->mapping_size);

        if(kret){
            SPYDBG("%s: vm_deallocate failed: %#x\n", __func__, kret);
            didfail = true;
        }

end:;
        if(didfail){
            SPYDBG("%s: failed to gc :( those pages will be leaked forever\n",
                    __func__);
        }
        else{
            SPYDBG("%s: gc okay\n", __func__);
            g_num_leaked_pages -= om->mapping_size / PAGE_SIZE;
        }

        STAILQ_REMOVE(&unmaplist, entry, stailq_entry, link);

        unified_kfree(entry);
        unified_kfree(om);
    }
}

static void xnuspy_consider_gc(void){
    SPYDBG("%s: Currently, there are %lld leaked pages\n", __func__,
            g_num_leaked_pages);

    if(g_num_leaked_pages <= XNUSPY_LEAKED_PAGE_LIMIT)
        return;

    xnuspy_do_gc();
}

/* Every second, this thread loops through the proc list, and checks
 * if the owner of a given xnuspy_mapping_metadata struct is no longer present.
 * If so, all the hooks associated with that metadata struct are uninstalled
 * and sent back to the freelist.
 *
 * This thread also handles deallocation of shared mappings whose owners were
 * freed a long time ago so we don't end up leaking a ridiculous amount of
 * memory. */
static void xnuspy_gc_thread(void *param, int wait_result){
    for(;;){
        lck_rw_lock_shared(xnuspy_rw_lck);

        if(STAILQ_EMPTY(&usedlist))
            goto unlock_and_consider_gc;

        if(!lck_rw_lock_shared_to_exclusive(xnuspy_rw_lck))
            lck_rw_lock_exclusive(xnuspy_rw_lck);
        
        struct stailq_entry *entry, *tmp;

        STAILQ_FOREACH_SAFE(entry, &usedlist, link, tmp){
            struct xnuspy_tramp *tramp = entry->elem;
            struct xnuspy_mapping_metadata *mm = tramp->mapping_metadata;
            struct xnuspy_tramp_metadata *tm = tramp->tramp_metadata;

            proc_list_lock();

            /* Looping through allproc with LIST_FOREACH doesn't pick up the
             * last proc structure in the list for some reason */
            void *curproc = *allprocp;
            pid_t pid;

            /* For simplicity, assume owner is dead before we start the
             * search */
            bool owner_dead = true;

            do {
                proc_ref_locked(curproc);

                pid = proc_pid(curproc);
                uint64_t uniqueid = proc_uniqueid(curproc);
                void *nextproc = *(void **)curproc;

                proc_rele_locked(curproc);

                if(mm->owner == uniqueid){
                    owner_dead = false;
                    break;
                }

                curproc = nextproc;
            } while(pid != 0);

            proc_list_unlock();

            if(owner_dead){
                SPYDBG("%s: Tramp %#llx's owner (%lld) is dead, freeing it\n",
                        __func__, tramp, mm->owner);

                STAILQ_REMOVE(&usedlist, entry, stailq_entry, link);

                kwrite_instr(tm->hooked, tm->orig_instr);

                xnuspy_tramp_teardown(tramp);

                STAILQ_INSERT_TAIL(&freelist, entry, link);
            }
        }

unlock_and_consider_gc:;
        lck_rw_done(xnuspy_rw_lck);
        xnuspy_consider_gc();
        IOSleep(1000);
    }
}

static int xnuspy_init_flag = 0;

static int xnuspy_init(void){
    int res = 0;

    /* Kinda sucks I can't statically initialize the xnuspy lock, so I'll have
     * to deal with racing inside xnuspy_init. Why would anyone try to race
     * this function anyway */
    void *grp = lck_grp_alloc_init("xnuspy", NULL);
    
    if(!grp){
        SPYDBG("%s: no mem for lck grp\n", __func__);
        res = ENOMEM;
        goto out;
    }

    xnuspy_rw_lck = lck_rw_alloc_init(grp, NULL);

    if(!xnuspy_rw_lck){
        SPYDBG("%s: no mem for xnuspy rw lck\n", __func__);
        res = ENOMEM;
        goto out_dealloc_grp;
    }

    STAILQ_INIT(&freelist);
    STAILQ_INIT(&usedlist);
    STAILQ_INIT(&unmaplist);

    uint64_t nhooks = 0;

    struct xnuspy_tramp *cursor = xnuspy_tramp_mem;

    while(cursor + 1 < xnuspy_tramp_mem_end){
        struct stailq_entry *entry = unified_kalloc(sizeof(*entry));

        if(!entry){
            SPYDBG("%s: no mem for stailq_entry\n", __func__);
            res = ENOMEM;
            goto out_dealloc_xnuspy_lck;
        }

        entry->elem = cursor;
        STAILQ_INSERT_TAIL(&freelist, entry, link);
        cursor++;
        nhooks++;
    }

    SPYDBG("%s: %lld available xnuspy_tramp structs\n", __func__, nhooks);

    void *gct = NULL;
    kern_return_t kret = kernel_thread_start(xnuspy_gc_thread, NULL, &gct);

    if(kret){
        SPYDBG("%s: kernel_thread_start failed: %d\n", __func__, kret);
        res = kern_return_to_errno(kret);
        goto out_dealloc_xnuspy_lck;
    }

    thread_deallocate(gct);

    uint64_t sz = (uint64_t)xnuspy_tramp_mem_end - (uint64_t)xnuspy_tramp_mem;
    vm_prot_t prot = VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE;

    kprotect(xnuspy_tramp_mem, sz, prot);

    xnuspy_init_flag = 1;

    SPYDBG("%s: xnuspy inited\n", __func__);

    return 0;

out_dealloc_xnuspy_lck:;
    lck_rw_free(xnuspy_rw_lck, grp);
    xnuspy_rw_lck = NULL;
out_dealloc_freelist:;
    struct stailq_entry *entry, *tmp;

    STAILQ_FOREACH_SAFE(entry, &freelist, link, tmp){
        STAILQ_REMOVE(&freelist, entry, stailq_entry, link);
        unified_kfree(entry);
    }

    STAILQ_INIT(&freelist);
out_dealloc_grp:
    lck_grp_free(grp);
out:
    return res;
}

static int xnuspy_register_death_callback(uint64_t /* __user */ addr){
    SPYDBG("%s: called with user address %#llx\n", __func__, addr);

    /* Find mapping metadata for this processes, if none, no hooks are
     * installed, so it doesn't make sense to install a callback */
    struct xnuspy_mapping_metadata *mm = find_mapping_metadata();

    if(!mm){
        SPYDBG("%s: no hooks, not installing callback\n", __func__);
        return ENOENT;
    }

    struct xnuspy_mapping *m = find_mapping_for_uaddr(mm, addr);

    if(!m){
        SPYDBG("%s: no shared mapping for user addr %#llx, no hooks,"
                " not installing callback\n", __func__, addr);
        return ENOENT;
    }

    m->death_callback = (void (*)(void))shared_mapping_kva(m, addr);

    SPYDBG("%s: set death callback to %#llx for %lld\n", __func__,
            (uint64_t)m->death_callback, mm->owner);

    xnuspy_mapping_release(m);

    return 0;
}

__attribute__ ((naked)) static void _hookme(void){
    asm(""
        "nop\n"
        "ret\n"
       );
}

static int hookme(void){
    if(!hookme_in_range){
        SPYDBG("%s: _hookme is unable to be hooked, but if it was, calling"
                " it would panic, bailing.\n", __func__);
        return ENOTSUP;
    }

    _hookme();

    return 0;
}

static int xnuspy_cache_read(enum xnuspy_cache_id which,
        uint64_t /* __user */ outp){
    SPYDBG("%s: XNUSPY_CACHE_READ called with which %d origp %#llx\n",
            __func__, which, outp);

    void *what;

    switch(which){
        case KERNEL_SLIDE:
            what = (void *)kernel_slide;
            break;
        case KPRINTF:
            what = kprintf;
            break;
        case KALLOC_CANBLOCK:
            if(iOS_version == iOS_14_x)
                return EINVAL;

            what = kalloc_canblock;
            break;
        case KALLOC_EXTERNAL:
            if(iOS_version == iOS_13_x)
                return EINVAL;

            what = kalloc_external;
            break;
        case KFREE_ADDR:
            if(iOS_version == iOS_14_x)
                return EINVAL;

            what = kfree_addr;
            break;
        case KFREE_EXT:
            if(iOS_version == iOS_13_x)
                return EINVAL;

            what = kfree_ext;
            break;
        case BCOPY_PHYS:
            what = bcopy_phys;
            break;
        case PHYSTOKV:
            what = phystokv;
            break;
        case COPYIN:
            what = copyin;
            break;
        case COPYINSTR:
            what = copyinstr;
            break;
        case COPYOUT:
            what = copyout;
            break;
        case CURRENT_PROC:
            what = current_proc;
            break;
        case PROC_PID:
            what = proc_pid;
            break;
        case KERNEL_THREAD_START:
            what = kernel_thread_start;
            break;
        case THREAD_DEALLOCATE:
            what = thread_deallocate;
            break;
        case THREAD_TERMINATE:
            what = _thread_terminate;
            break;
        case ALLPROC:
            what = *allprocp;
            break;
        case BZERO:
            what = bzero;
            break;
        case IPC_PORT_RELEASE_SEND:
            what = ipc_port_release_send;
            break;
        case KERNEL_MAP:
            what = *kernel_mapp;
            break;
        case LCK_GRP_ALLOC_INIT:
            what = lck_grp_alloc_init;
            break;
        case LCK_GRP_FREE:
            what = lck_grp_free;
            break;
        case LCK_MTX_UNLOCK:
            what = lck_mtx_unlock;
            break;
        case LCK_RW_ALLOC_INIT:
            what = lck_rw_alloc_init;
            break;
        case LCK_RW_DONE:
            what = lck_rw_done;
            break;
        case LCK_RW_FREE:
            what = lck_rw_free;
            break;
        case LCK_RW_LOCK_EXCLUSIVE:
            what = lck_rw_lock_exclusive;
            break;
        case LCK_RW_LOCK_SHARED:
            what = lck_rw_lock_shared;
            break;
        case LCK_RW_LOCK_SHARED_TO_EXCLUSIVE:
            what = lck_rw_lock_shared_to_exclusive;
            break;
        case MACH_MAKE_MEMORY_ENTRY_64:
            what = _mach_make_memory_entry_64;
            break;
        case MACH_VM_MAP_EXTERNAL:
            what = mach_vm_map_external;
            break;
        case MEMCHR:
            what = memchr;
            break;
        case MEMCMP:
            what = memcmp;
            break;
        case MEMMEM:
            what = memmem;
            break;
        case MEMMOVE:
            what = _memmove;
            break;
        case MEMRCHR:
            what = memrchr;
            break;
        case MEMSET:
            what = _memset;
            break;
        case OFFSETOF_STRUCT_THREAD_MAP:
            what = (void *)offsetof_struct_thread_map;
            break;
        case PROC_NAME:
            what = proc_name;
            break;
        case PROC_LIST_LOCK:
            what = proc_list_lock;
            break;
        case PROC_LIST_UNLOCK:
            what = proc_list_unlock;
            break;
        case PROC_LIST_MLOCK:
            what = *proc_list_mlockp;
            break;
        case PROC_REF_LOCKED:
            what = proc_ref_locked;
            break;
        case PROC_RELE_LOCKED:
            what = proc_rele_locked;
            break;
        case PROC_UNIQUEID:
            what = proc_uniqueid;
            break;
        case SNPRINTF:
            what = _snprintf;
            break;
        case STRCHR:
            what = strchr;
            break;
        case STRRCHR:
            what = strrchr;
            break;
        case STRCMP:
            what = strcmp;
            break;
        case STRLEN:
            what = _strlen;
            break;
        case STRNCMP:
            what = _strncmp;
            break;
        case STRSTR:
            what = strstr;
            break;
        case STRNSTR:
            what = strnstr;
            break;
        case VM_DEALLOCATE:
            what = _vm_deallocate;
            break;
        case VM_MAP_UNWIRE:
            what = vm_map_unwire;
            break;
        case VM_MAP_WIRE_EXTERNAL:
            what = vm_map_wire_external;
            break;
        case IOSLEEP:
            what = IOSleep;
            break;
        case HOOKME:
            what = _hookme;
            break;
        case CURRENT_MAP:
            what = current_map;
            break;
        case IOS_VERSION:
            what = (void *)iOS_version;
            break;
        case KVTOPHYS:
            what = kvtophys;
            break;
        case UVTOPHYS:
            what = uvtophys;
            break;
        case KPROTECT:
            what = kprotect;
            break;
        case UPROTECT:
            what = uprotect;
            break;
        case KWRITE_STATIC:
            what = kwrite_static;
            break;
        case KWRITE_INSTR:
            what = kwrite_instr;
            break;
        case EL0_PTEP:
            what = el0_ptep;
            break;
        case EL1_PTEP:
            what = el1_ptep;
            break;
        case TLB_FLUSH:
            what = tlb_flush;
            break;
        case UNIFIED_KALLOC:
            what = unified_kalloc;
            break;
        case UNIFIED_KFREE:
            what = unified_kfree;
            break;
        default:
            return EINVAL;
    };

    return copyout(&what, outp, sizeof(outp));
}

static int xnuspy_kwhat(int what, uint64_t kva, uint64_t uva, vm_size_t sz){
    SPYDBG("%s: called with flavor %d, kva %#llx, uva %#llx, sz %#llx\n",
            __func__, what, kva, uva, sz);

    uint64_t kphys = kvtophys(kva), uphys = uvtophys(uva);

    if(!kphys || !uphys){
        SPYDBG("%s: address translation failed for kva or uva kphys=%#llx"
                " uphys=%#llx\n", __func__, kphys, uphys);
        return EFAULT;
    }

    uint64_t src, dst;

    if(what == XNUSPY_KREAD){
        src = kphys;
        dst = uphys;
    }
    else{
        src = uphys;
        dst = kphys;
    }

    bcopy_phys(src, dst, sz);

    SPYDBG("%s: wrote %#llx bytes from %#llx to %#llx\n", __func__, sz,
            src, dst);

    return 0;
}

struct xnuspy_ctl_args {
    uint64_t flavor;
    uint64_t arg1;
    uint64_t arg2;
    uint64_t arg3;
};

int xnuspy_ctl(void *p, struct xnuspy_ctl_args *uap, int *retval){
    uint64_t flavor = uap->flavor;

    if(flavor > XNUSPY_MAX_FLAVOR){
        SPYDBG("%s: bad flavor %d\n", __func__, flavor);
        *retval = -1;
        return EINVAL;
    }

    if(flavor == XNUSPY_CHECK_IF_PATCHED){
        SPYDBG("%s: we exist!\n", __func__);
        *retval = 999;
        return 0;
    }

    int res;

    if(!xnuspy_init_flag){
        res = xnuspy_init();

        if(res)
            goto out;
    }

    switch(flavor){
        case XNUSPY_INSTALL_HOOK:
            res = xnuspy_install_hook(uap->arg1, uap->arg2, uap->arg3);
            break;
        case XNUSPY_REGISTER_DEATH_CALLBACK:
            res = xnuspy_register_death_callback(uap->arg1);
            break;
        case XNUSPY_CALL_HOOKME:
            res = hookme();
            break;
        case XNUSPY_CACHE_READ:
            {
                enum xnuspy_cache_id xcid = (enum xnuspy_cache_id)uap->arg1;
                res = xnuspy_cache_read(xcid, uap->arg2);
                break;
            }
        case XNUSPY_KREAD:
        case XNUSPY_KWRITE:
            res = xnuspy_kwhat(flavor, uap->arg1, uap->arg2, uap->arg3);
            break;
        case XNUSPY_GET_CURRENT_THREAD:
            {
                uint64_t ct = current_thread();
                res = copyout(&ct, uap->arg1, sizeof(ct));
                break;
            }
        default:
            *retval = -1;
            return EINVAL;
    };

    if(res)
out:
        *retval = -1;

    return res;
}
