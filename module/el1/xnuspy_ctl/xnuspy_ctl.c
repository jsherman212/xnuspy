#include <errno.h>
#include <mach/mach.h>
#include <mach/vm_statistics.h>
#include <mach-o/loader.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/queue.h>
#include <unistd.h>

#include "asm.h"
#include "mem.h"
#include "pte.h"
/* #include "queue.h" */
#include "tramp.h"

#include "../../common/xnuspy_structs.h"

#undef current_task
#undef current_thread
#undef PAGE_SIZE

#define PAGE_SIZE                   (0x4000)

#define VM_KERN_MEMORY_NONE		0
#define VM_KERN_MEMORY_OSFMK		1
#define VM_KERN_MEMORY_BSD		2
#define VM_KERN_MEMORY_IOKIT		3
#define VM_KERN_MEMORY_LIBKERN		4
#define VM_KERN_MEMORY_OSKEXT		5
#define VM_KERN_MEMORY_KEXT		6
#define VM_KERN_MEMORY_IPC		7
#define VM_KERN_MEMORY_STACK		8
#define VM_KERN_MEMORY_CPU		9
#define VM_KERN_MEMORY_PMAP		10
#define VM_KERN_MEMORY_PTE		11
#define VM_KERN_MEMORY_ZONE		12
#define VM_KERN_MEMORY_KALLOC		13
#define VM_KERN_MEMORY_COMPRESSOR	14
#define VM_KERN_MEMORY_COMPRESSED_DATA	15
#define VM_KERN_MEMORY_PHANTOM_CACHE	16
#define VM_KERN_MEMORY_WAITQ		17
#define VM_KERN_MEMORY_DIAG		18
#define VM_KERN_MEMORY_LOG		19
#define VM_KERN_MEMORY_FILE		20
#define VM_KERN_MEMORY_MBUF		21
#define VM_KERN_MEMORY_UBC		22
#define VM_KERN_MEMORY_SECURITY		23
#define VM_KERN_MEMORY_MLOCK		24
#define VM_KERN_MEMORY_REASON		25
#define VM_KERN_MEMORY_SKYWALK		26
#define VM_KERN_MEMORY_LTABLE		27
#define VM_KERN_MEMORY_FIRST_DYNAMIC	28

static const char *tagname(int tag){
    switch(tag){
        case VM_KERN_MEMORY_NONE:
            return "none";
        case VM_KERN_MEMORY_OSFMK:
            return "osfmk";
        case VM_KERN_MEMORY_BSD:
            return "bsd";
        case VM_KERN_MEMORY_IOKIT:
            return "iokit";
        case VM_KERN_MEMORY_LIBKERN:
            return "libkern";
        case VM_KERN_MEMORY_OSKEXT:
            return "oskext";
        case VM_KERN_MEMORY_KEXT:
            return "kext";
        case VM_KERN_MEMORY_IPC:
            return "ipc";
        case VM_KERN_MEMORY_STACK:
            return "stack";
        case VM_KERN_MEMORY_CPU:
            return "cpu";
        case VM_KERN_MEMORY_PMAP:
            return "pmap";
        case VM_KERN_MEMORY_PTE:
            return "pte";
        case VM_KERN_MEMORY_ZONE:
            return "zone";
        case VM_KERN_MEMORY_KALLOC:
            return "kalloc";
        case VM_KERN_MEMORY_COMPRESSOR:
            return "compressor";
        case VM_KERN_MEMORY_COMPRESSED_DATA:
            return "compressed data";
        case VM_KERN_MEMORY_PHANTOM_CACHE:
            return "phantom cache";
        case VM_KERN_MEMORY_WAITQ:
            return "waitq";
        case VM_KERN_MEMORY_DIAG:
            return "diag";
        case VM_KERN_MEMORY_LOG:
            return "log";
        case VM_KERN_MEMORY_FILE:
            return "file";
        case VM_KERN_MEMORY_MBUF:
            return "mbuf";
        case VM_KERN_MEMORY_UBC:
            return "ubc";
        case VM_KERN_MEMORY_SECURITY:
            return "security";
        case VM_KERN_MEMORY_MLOCK:
            return "mlock";
        case VM_KERN_MEMORY_REASON:
            return "reason";
        case VM_KERN_MEMORY_SKYWALK:
            return "skywalk";
        case VM_KERN_MEMORY_LTABLE:
            return "liable";
        case VM_KERN_MEMORY_FIRST_DYNAMIC:
            return "first dynamic";
        default:
            return "unknown tag";
    };
}

#define XNUSPY_INSTALL_HOOK         (0)
#define XNUSPY_CHECK_IF_PATCHED     (1)
#define XNUSPY_GET_FUNCTION         (2)
#define XNUSPY_DUMP_TTES            (3)
#define XNUSPY_KREAD                (4)
#define XNUSPY_GET_CURRENT_TASK     (5)
#define XNUSPY_MAX_FLAVOR           XNUSPY_GET_CURRENT_TASK

/* values for XNUSPY_GET_FUNCTION */
#define KPROTECT                    (0)
#define COPYOUT                     (1)
#define KPRINTF                     (2)
#define IOSLEEP                     (3)
#define KERNEL_SLIDE                (4)
#define MAX_FUNCTION                KERNEL_SLIDE

typedef struct {
    uint64_t word;
    void *owner;
} lck_rw_t;

typedef unsigned int lck_rw_type_t;
/* read */
#define	LCK_RW_TYPE_SHARED          0x01
/* write */
#define	LCK_RW_TYPE_EXCLUSIVE       0x02

#define MARK_AS_KERNEL_OFFSET __attribute__((section("__DATA,__koff")))

/* XXX For debugging only */
MARK_AS_KERNEL_OFFSET void (*kprintf)(const char *fmt, ...);
MARK_AS_KERNEL_OFFSET void (*IOSleep)(unsigned int millis);

MARK_AS_KERNEL_OFFSET uint64_t iOS_version = 0;
MARK_AS_KERNEL_OFFSET void *(*kalloc_canblock)(vm_size_t *sizep, bool canblock,
        void *site);
MARK_AS_KERNEL_OFFSET void *(*kalloc_external)(vm_size_t sz);
MARK_AS_KERNEL_OFFSET void (*kfree_addr)(void *addr);
MARK_AS_KERNEL_OFFSET void (*kfree_ext)(void *addr, vm_size_t sz);
MARK_AS_KERNEL_OFFSET void (*lck_rw_lock_shared)(void *lock);

MARK_AS_KERNEL_OFFSET int (*lck_rw_lock_shared_to_exclusive)(lck_rw_t *lck);

/* XXX XXX these one has not had its offset found yet!! */
MARK_AS_KERNEL_OFFSET int (*lck_rw_lock_exclusive_to_shared)(lck_rw_t *lck);

MARK_AS_KERNEL_OFFSET void (*lck_rw_lock)(lck_rw_t *lock, lck_rw_type_t lck_rw_type);
MARK_AS_KERNEL_OFFSET void (*lck_rw_unlock)(lck_rw_t *lock, lck_rw_type_t lck_rw_type);

/* this will figure out how it was locked and unlock accordingly, probably
 * better to use this instead of lck_rw_unlock */
MARK_AS_KERNEL_OFFSET uint32_t (*lck_rw_done)(lck_rw_t *lock);

MARK_AS_KERNEL_OFFSET void *(*lck_grp_alloc_init)(const char *grp_name,
        void *attr);
MARK_AS_KERNEL_OFFSET lck_rw_t *(*lck_rw_alloc_init)(void *grp, void *attr);
MARK_AS_KERNEL_OFFSET void (*bcopy_phys)(uint64_t src, uint64_t dst,
        vm_size_t bytes);
MARK_AS_KERNEL_OFFSET uint64_t (*phystokv)(uint64_t pa);
MARK_AS_KERNEL_OFFSET int (*copyin)(const uint64_t uaddr, void *kaddr,
        vm_size_t nbytes);
MARK_AS_KERNEL_OFFSET int (*copyout)(const void *kaddr, uint64_t uaddr,
        vm_size_t nbytes);

MARK_AS_KERNEL_OFFSET void *(*current_proc)(void);
MARK_AS_KERNEL_OFFSET pid_t (*proc_pid)(void *proc);
MARK_AS_KERNEL_OFFSET void (*proc_list_lock)(void);
MARK_AS_KERNEL_OFFSET void (*proc_list_unlock)(void);
MARK_AS_KERNEL_OFFSET uint64_t (*proc_uniqueid)(void *proc);
MARK_AS_KERNEL_OFFSET void (*proc_ref_locked)(void *proc);
MARK_AS_KERNEL_OFFSET void (*proc_rele_locked)(void *proc);

MARK_AS_KERNEL_OFFSET uint32_t *ncpusp;
MARK_AS_KERNEL_OFFSET struct cpu_data_entry *CpuDataEntriesp;
MARK_AS_KERNEL_OFFSET vm_offset_t (*ml_io_map)(vm_offset_t phys_addr,
        vm_size_t size);
MARK_AS_KERNEL_OFFSET void *mh_execute_header;
MARK_AS_KERNEL_OFFSET uint64_t kernel_slide;

MARK_AS_KERNEL_OFFSET void (*flush_mmu_tlb_region)(uint64_t va, uint32_t len);
MARK_AS_KERNEL_OFFSET void (*flush_mmu_tlb_region_asid_async)(uint64_t va,
        uint32_t len, void *pmap);
MARK_AS_KERNEL_OFFSET void (*InvalidatePoU_IcacheRegion)(uint64_t va, uint32_t len);
MARK_AS_KERNEL_OFFSET void *(*current_task)(void);
MARK_AS_KERNEL_OFFSET uint64_t (*pmap_map)(uint64_t virt, vm_offset_t start,
        vm_offset_t end, vm_prot_t prot, unsigned int flags);
MARK_AS_KERNEL_OFFSET void *kernel_pmap;
MARK_AS_KERNEL_OFFSET int (*pmap_expand)(void *pmap, uint64_t v, unsigned int options,
        unsigned int level);
MARK_AS_KERNEL_OFFSET void (*_disable_preemption)(void);
MARK_AS_KERNEL_OFFSET void (*_enable_preemption)(void);
MARK_AS_KERNEL_OFFSET kern_return_t (*kernel_memory_allocate)(void *map,
        uint64_t *addrp, vm_size_t size, vm_offset_t mask, int flags, int tag);

MARK_AS_KERNEL_OFFSET void **kernel_mapp;

MARK_AS_KERNEL_OFFSET kern_return_t (*vm_map_wire_kernel)(void *map,
        uint64_t start, uint64_t end, vm_prot_t prot, int tag, int user_wire);

/* extra underscore so compiler stops complaining */
MARK_AS_KERNEL_OFFSET kern_return_t (*_mach_make_memory_entry_64)(void *target_map,
        uint64_t *size, uint64_t offset, vm_prot_t prot, void **object_handle,
        void *parent_handle);

typedef	void (*thread_continue_t)(void *param, int wait_result);

MARK_AS_KERNEL_OFFSET kern_return_t (*kernel_thread_start)(thread_continue_t continuation,
        void *parameter, void **new_thread);
MARK_AS_KERNEL_OFFSET void (*thread_deallocate)(void *thread);

typedef	struct {
    mach_msg_bits_t     msgh_bits;
    mach_msg_size_t     msgh_size;
    mach_port_t         msgh_remote_port;
    mach_port_t         msgh_local_port;
    mach_port_name_t    msgh_voucher_port;
    mach_msg_id_t       msgh_id;
} k_mach_msg_header_t;

/* struct proc { */
/*     LIST_ENTRY(proc) p_list; */
/* }; */

MARK_AS_KERNEL_OFFSET void **kernprocp;
/* MARK_AS_KERNEL_OFFSET LIST_HEAD(, proc) **allprocp; */
MARK_AS_KERNEL_OFFSET void **allprocp;

typedef struct {
    unsigned int
        vmkf_atomic_entry:1,
        vmkf_permanent:1,
        vmkf_guard_after:1,
        vmkf_guard_before:1,
        vmkf_submap:1,
        vmkf_already:1,
        vmkf_beyond_max:1,
        vmkf_no_pmap_check:1,
        vmkf_map_jit:1,
        vmkf_iokit_acct:1,
        vmkf_keep_map_locked:1,
        vmkf_fourk:1,
        vmkf_overwrite_immutable:1,
        vmkf_remap_prot_copy:1,
        vmkf_cs_enforcement_override:1,
        vmkf_cs_enforcement:1,
        vmkf_nested_pmap:1,
        vmkf_no_copy_on_read:1,
        __vmkf_unused:14;
} vm_map_kernel_flags_t;

MARK_AS_KERNEL_OFFSET kern_return_t (*mach_vm_map_external)(void *target_map,
        uint64_t *address, uint64_t size, uint64_t mask, int flags,
        void *memory_object, uint64_t offset, int copy,
        vm_prot_t cur_protection, vm_prot_t max_protection,
        vm_inherit_t inheritance);

MARK_AS_KERNEL_OFFSET kern_return_t (*mach_vm_map_kernel)(void *target_map,
        uint64_t *address, uint64_t size, uint64_t mask, int flags,
        vm_map_kernel_flags_t vmk_flags, int tag, void *memory_object,
        uint64_t offset, int copy, vm_prot_t cur_protection,
        vm_prot_t max_protection, vm_inherit_t inheritance);

MARK_AS_KERNEL_OFFSET kern_return_t (*ml_static_protect)(uint64_t vaddr,
        uint64_t size, vm_prot_t prot);

MARK_AS_KERNEL_OFFSET void (*pmap_protect_options)(void *pmap, uint64_t start,
        uint64_t end, vm_prot_t prot, unsigned int options, void *args);

MARK_AS_KERNEL_OFFSET kern_return_t (*vm_map_protect)(void *map, uint64_t start,
        uint64_t end, vm_prot_t new_prot, int setmax);

/* flags for mach_make_memory_entry_64 */
#define MAP_MEM_LEDGER_TAG_NETWORK 0x002000 /* charge to "network" ledger */
#define MAP_MEM_PURGABLE_KERNEL_ONLY 0x004000 /* volatility controlled by kernel */
#define MAP_MEM_GRAB_SECLUDED	0x008000 /* can grab secluded pages */
#define MAP_MEM_ONLY		0x010000 /* change processor caching  */
#define MAP_MEM_NAMED_CREATE	0x020000 /* create extant object      */
#define MAP_MEM_PURGABLE	0x040000 /* create a purgable VM object */
#define MAP_MEM_NAMED_REUSE	0x080000 /* reuse provided entry if identical */
#define MAP_MEM_USE_DATA_ADDR	0x100000 /* preserve address of data, rather than base of page */
#define MAP_MEM_VM_COPY		0x200000 /* make a copy of a VM range */
#define MAP_MEM_VM_SHARE	0x400000 /* extract a VM range for remap */
#define	MAP_MEM_4K_DATA_ADDR	0x800000 /* preserve 4K aligned address of data */

/* flags for kernel_memory_allocate */
#define KMA_HERE        0x01
#define KMA_NOPAGEWAIT  0x02
#define KMA_KOBJECT     0x04
#define KMA_LOMEM       0x08
#define KMA_GUARD_FIRST 0x10
#define KMA_GUARD_LAST  0x20
#define KMA_PERMANENT   0x40
#define KMA_NOENCRYPT   0x80
#define KMA_KSTACK      0x100
#define KMA_VAONLY      0x200
#define KMA_COMPRESSOR  0x400   /* Pages belonging to the compressor are not on the paging queues, nor are they counted as wired. */
#define KMA_ATOMIC      0x800
#define KMA_ZERO        0x1000
#define KMA_PAGEABLE    0x2000

struct pmap_statistics {
    integer_t	resident_count;	/* # of pages mapped (total)*/
    integer_t	resident_max;	/* # of pages mapped (peak) */
    integer_t	wired_count;	/* # of pages wired */
    integer_t	device;
    integer_t	device_peak;
    integer_t	internal;
    integer_t	internal_peak;
    integer_t	external;
    integer_t	external_peak;
    integer_t	reusable;
    integer_t	reusable_peak;
    uint64_t	compressed __attribute__((aligned(8)));
    uint64_t	compressed_peak __attribute__((aligned(8)));
    uint64_t	compressed_lifetime __attribute__((aligned(8)));
};

struct queue_entry {
    struct queue_entry *next;
    struct queue_entry *prev;
};

typedef struct queue_entry queue_chain_t;
typedef struct queue_entry queue_head_t;

struct pmap {
    uint64_t *tte;
    uint64_t ttep;
    uint64_t min;
    uint64_t max;
    void *ledger;
    struct {
        uint64_t lock_data;
        uint64_t type;
    } lock;
    struct pmap_statistics stats;
    queue_chain_t pmaps;
};

struct vm_map_links {
    struct vm_map_entry *prev;
    struct vm_map_entry *next;
    uint64_t start;
    uint64_t end;
};

#define vme_prev		links.prev
#define vme_next		links.next
#define vme_start		links.start
#define vme_end			links.end
struct vm_map_entry {
    struct vm_map_links links;
    struct {
        void *rbe_left;
        void *rbe_right;
        void *rbe_parent;
    } store;
    union {
        void *vmo_object;
        void *vmo_submap;
    } vme_object;
    uint64_t vme_offset;
    unsigned int
        /* boolean_t */ is_shared:1,    /* region is shared */
        /* boolean_t */ is_sub_map:1,   /* Is "object" a submap? */
        /* boolean_t */ in_transition:1, /* Entry being changed */
        /* boolean_t */ needs_wakeup:1, /* Waiters on in_transition */
        /* vm_behavior_t */ behavior:2, /* user paging behavior hint */
        /* behavior is not defined for submap type */
        /* boolean_t */ needs_copy:1,   /* object need to be copied? */

        /* Only in task maps: */
        /* vm_prot_t */ protection:3,   /* protection code */
        /* vm_prot_t */ max_protection:3, /* maximum protection */
        /* vm_inherit_t */ inheritance:2, /* inheritance */
        /* boolean_t */ use_pmap:1,     /*
         * use_pmap is overloaded:
         * if "is_sub_map":
         *      use a nested pmap?
         * else (i.e. if object):
         *      use pmap accounting
         *      for footprint?
         */
        /* boolean_t */ no_cache:1,     /* should new pages be cached? */
        /* boolean_t */ permanent:1,    /* mapping can not be removed */
        /* boolean_t */ superpage_size:1, /* use superpages of a certain size */
        /* boolean_t */ map_aligned:1,  /* align to map's page size */
        /* boolean_t */ zero_wired_pages:1, /* zero out the wired pages of
         * this entry it is being deleted
         * without unwiring them */
        /* boolean_t */ used_for_jit:1,
        /* boolean_t */ pmap_cs_associated:1, /* pmap_cs will validate */
        /* boolean_t */ from_reserved_zone:1, /* Allocated from
         * kernel reserved zone	 */

        /* iokit accounting: use the virtual size rather than resident size: */
        /* boolean_t */ iokit_acct:1,
        /* boolean_t */ vme_resilient_codesign:1,
        /* boolean_t */ vme_resilient_media:1,
        /* boolean_t */ vme_atomic:1, /* entry cannot be split/coalesced */
        /* boolean_t */ vme_no_copy_on_read:1,
        __unused:3;

    unsigned short          wired_count;    /* can be paged if = 0 */
    unsigned short          user_wired_count; /* for vm_wire */
};

struct vm_map_header {
    struct vm_map_links links;
};

struct _vm_map {
    char lck[16];
    /* struct { */
    /*     struct { */
    /*         void *prev; */
    /*         void *next; */
    /*         uint64_t start; */
    /*         uint64_t end; */
    /*     } links; */
    /* } hdr; */
    struct vm_map_header hdr;
};

MARK_AS_KERNEL_OFFSET struct pmap *(*get_task_pmap)(void *task);
MARK_AS_KERNEL_OFFSET queue_head_t *map_pmap_list;

/* shorter macros so I can stay under 80 column lines */
/* #define DIST_FROM_REFCNT_TO(x) __builtin_offsetof(struct xnuspy_tramp, x) - \ */
/*     __builtin_offsetof(struct xnuspy_tramp, refcnt) */

/* #define DIST_TO_REFCNT(x) __builtin_offsetof(struct xnuspy_tramp, x) - \ */
/*     __builtin_offsetof(struct xnuspy_tramp, refcnt) */

/* #define OFFSETOF(x) __builtin_offsetof(struct xnuspy_tramp, x) */

int strcmp(const char *s1, const char *s2){
    while(*s1 && (*s1 == *s2)){
        s1++;
        s2++;
    }

    return *(const unsigned char *)s1 - *(const unsigned char *)s2;
}

static int xnuspy_dump_ttes(uint64_t addr, uint64_t el){
    uint64_t ttbr;

    if(el == 0)
        asm volatile("mrs %0, ttbr0_el1" : "=r" (ttbr));
    else
        asm volatile("mrs %0, ttbr1_el1" : "=r" (ttbr));

    uint64_t l1_table = phystokv(ttbr & 0xfffffffffffe);
    uint64_t l1_idx = (addr >> ARM_TT_L1_SHIFT) & 0x7;
    uint64_t *l1_ttep = (uint64_t *)(l1_table + (0x8 * l1_idx));

    uint64_t l2_table = phystokv(*l1_ttep & ARM_TTE_TABLE_MASK);
    uint64_t l2_idx = (addr >> ARM_TT_L2_SHIFT) & 0x7ff;
    uint64_t *l2_ttep = (uint64_t *)(l2_table + (0x8 * l2_idx));

    uint64_t l3_table = phystokv(*l2_ttep & ARM_TTE_TABLE_MASK);
    uint64_t l3_idx = (addr >> ARM_TT_L3_SHIFT) & 0x7ff;
    uint64_t *l3_ptep = (uint64_t *)(l3_table + (0x8 * l3_idx));

    kprintf("%s: TTE dump for %#llx:\n", __func__, addr);
    kprintf("\tL1 TTE @ %#llx (phys = %#llx): %#llx\n"
            "\tL2 TTE @ %#llx (phys = %#llx): %#llx\n"
            "\tL3 PTE @ %#llx (phys = %#llx): %#llx\n",
            l1_ttep, kvtophys((uint64_t)l1_ttep), *l1_ttep,
            l2_ttep, kvtophys((uint64_t)l2_ttep), *l2_ttep,
            l3_ptep, kvtophys((uint64_t)l3_ptep), *l3_ptep);

    return 0;
}

static void desc_vm_map_entry(struct vm_map_entry *vme){
    kprintf("This map entry represents [%#llx-%#llx]\n", vme->vme_start,
            vme->vme_end);
    kprintf("\tShared:              %d\n"
            "\tSubmap?              %d\n"
            "\tIn transition?       %d\n"
            "\tNeeds wakeup?        %d\n"
            "\tBehavior:            %d\n"
            "\tNeeds copy?          %d\n"
            "\tProtection:          %#x\n"
            "\tMax Protection:      %#x\n"
            "\tInheritance:         %d\n"
            "\tUse pmap?            %d\n"
            "\tNo cache?            %d\n"
            "\tPermanent:           %d\n"
            "\tSuperpage size?      %d\n"
            "\tMap aligned?         %d\n"
            "\tZero wired pages?    %d\n"
            "\tUsed for JIT?        %d\n"
            "\tpmap_cs associated?  %d\n"
            "\tFrom reserved zone?  %d\n"
            "\tIOKit accounting?    %d\n"
            "\tResilient codesign?  %d\n"
            "\tResilient media?     %d\n"
            "\tAtomic?              %d\n"
            "\tDon't copy on read?  %d\n",
        vme->is_shared, vme->is_sub_map, vme->in_transition, vme->needs_wakeup,
        vme->behavior, vme->needs_copy, vme->protection, vme->max_protection,
        vme->inheritance, vme->use_pmap, vme->no_cache, vme->permanent,
        vme->superpage_size, vme->map_aligned, vme->zero_wired_pages,
        vme->used_for_jit, vme->pmap_cs_associated, vme->from_reserved_zone,
        vme->iokit_acct, vme->vme_resilient_codesign, vme->vme_resilient_media,
        vme->vme_atomic, vme->vme_no_copy_on_read);
}

static struct vm_map_entry *vme_for_ptr(struct _vm_map *map, uint64_t ptr){
    ptr &= ~0x3fffuLL;

    /* struct vm_map_entry *first = (struct vm_map_entry *)(&map->hdr.links); */

    /* if(ptr >= first->vme_start && ptr < first->vme_end) */
    /*     return first; */

    struct vm_map_entry *entry = map->hdr.links.next;

    int lim = 1000000, i = 0;

    while(entry && i < lim){
        if(ptr >= entry->vme_start && ptr < entry->vme_end)
            return entry;

        i++;
        entry = entry->vme_next;
    }

    return NULL;
}

static void _desc_xnuspy_reflector_page(const char *indent,
        struct xnuspy_reflector_page *p){
    kprintf("%sThis reflector page is @ %#llx. "
            "next: %#llx refcnt: %lld page %#llx\n", indent, (uint64_t)p, p->next,
            p->refcnt, p->page);
}

static void desc_xnuspy_reflector_page(struct xnuspy_reflector_page *p){
    _desc_xnuspy_reflector_page("", p);
}

static void desc_xnuspy_mapping_metadata(struct xnuspy_mapping_metadata *mm){
    kprintf("Mapping metadata refcnt: %lld\n", mm->refcnt);
    kprintf("Owner: %d\n", mm->owner);
    kprintf("# of used reflector pages: %lld\n", mm->used_reflector_pages);
    kprintf("Reflector pages:\n");

    struct xnuspy_reflector_page *cur = mm->first_reflector_page;

    for(int i=0; i<mm->used_reflector_pages; i++){
        if(!cur)
            break;

        _desc_xnuspy_reflector_page("    ", cur);
        cur = cur->next;
    }

    kprintf("Memory object: %#llx\n", mm->memory_object);
    kprintf("Shared mapping addr/size: %#llx/%#llx\n", mm->mapping_addr,
            mm->mapping_size);
}

static void desc_xnuspy_tramp(struct xnuspy_tramp *t, uint32_t orig_tramp_len){
    kprintf("This xnuspy_tramp is @ %#llx\n", (uint64_t)t);
    kprintf("Replacement: %#llx\n", t->replacement);
    
    kprintf("Replacement trampoline:\n");
    for(int i=0; i<sizeof(t->tramp)/sizeof(t->tramp[0]); i++)
        kprintf("\ttramp[%d]    %#x\n", i, t->tramp[i]);

    kprintf("Original trampoline:\n");
    for(int i=0; i<orig_tramp_len; i++)
        kprintf("\ttramp[%d]    %#x\n", i, t->orig[i]);

    if(!t->tramp_metadata)
        kprintf("NULL tramp metadata\n");
    else{
        kprintf("Hooked function: %#llx [unslid=%#llx]\n",
                t->tramp_metadata->hooked,
                t->tramp_metadata->hooked - kernel_slide);
        kprintf("Original instruction: %#x\n", t->tramp_metadata->orig_instr);
    }

    if(!t->mapping_metadata)
        kprintf("NULL mapping metadata\n");
    else
        desc_xnuspy_mapping_metadata(t->mapping_metadata);
}

__attribute__ ((naked)) static uint64_t current_thread(void){
    asm volatile(""
            "mrs x0, tpidr_el1\n"
            "ret\n"
            );
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

    /* Not a valid errno */
    return 10000;
}

static int xnuspy_reflector_page_free(struct xnuspy_reflector_page *p){
    return p->refcnt == 0;
}

static void xnuspy_reflector_page_release(struct xnuspy_reflector_page *p){
    p->refcnt--;
}

static void xnuspy_reflector_page_reference(struct xnuspy_reflector_page *p){
    p->refcnt++;
}

static void xnuspy_mapping_metadata_release(struct xnuspy_mapping_metadata *m){
    if(--m->refcnt == 0){
        m->first_reflector_page = NULL;
        m->used_reflector_pages = 0;
    }
}

static void xnuspy_mapping_metadata_reference(struct xnuspy_mapping_metadata *m){
    m->refcnt++;
}

/* void disable_preemption(void){ */
/*     _disable_preemption(); */
/* } */

/* void enable_preemption(void){ */
/*     _enable_preemption(); */
/* } */

MARK_AS_KERNEL_OFFSET struct xnuspy_tramp *xnuspy_tramp_page;
MARK_AS_KERNEL_OFFSET uint8_t *xnuspy_tramp_page_end;

MARK_AS_KERNEL_OFFSET struct xnuspy_reflector_page *first_reflector_page;

static lck_rw_t *xnuspy_rw_lck = NULL;

struct stailq_entry {
    struct objhdr hdr;
    void *elem;
    STAILQ_ENTRY(stailq_entry) link;
};

/* I cannot reference count the xnuspy_tramp structs because I am unable
 * to use the stack to push a frame so the replacement function returns to
 * a routine to release a taken reference. Reference counting these structs
 * would prevent me from unmapping something that some thread is currently
 * executing on.
 *
 * Instead, I'm maximizing the time between the previous free and the next
 * allocation of a given xnuspy_tramp struct. When a hook is uninstalled, the
 * shared mapping won't be unmapped until another process takes ownership
 * of that struct. Freed structs will be pushed to the end of the freelist,
 * and we allocate from the front of the freelist.
 *
 * The usedlist is used as a normal linked list, but has to be an STAILQ
 * so I can insert objects from the freelist and into the usedlist and vice
 * versa.
 */
static STAILQ_HEAD(, stailq_entry) freelist = STAILQ_HEAD_INITIALIZER(freelist);
static STAILQ_HEAD(, stailq_entry) usedlist = STAILQ_HEAD_INITIALIZER(usedlist);

/* This function is expected to be called with an xnuspy_tramp that has
 * already been pulled off the usedlist, but not yet added to the freelist
 * (hence lack of locking here) */
static void xnuspy_tramp_teardown(struct xnuspy_tramp *t){
    struct xnuspy_mapping_metadata *mm = t->mapping_metadata;

    if(mm){
        struct xnuspy_reflector_page *cur = mm->first_reflector_page;

        for(int i=0; i<mm->used_reflector_pages; i++){
            if(!cur)
                break;

            xnuspy_reflector_page_release(cur);

            cur = cur->next;
        }

        if(mm->refcnt > 0)
            xnuspy_mapping_metadata_release(mm);

        /* We do not NULL out the mapping metadata pointer so another process
         * can unmap this shared mapping when it takes ownership of this
         * xnuspy_tramp struct */
    }

    if(t->tramp_metadata){
        common_kfree(t->tramp_metadata);
        t->tramp_metadata = NULL;
    }
}

/* Free an xnuspy_tramp struct by putting it at the end of the freelist */
static void xnuspy_tramp_free(struct stailq_entry *stqe){
    lck_rw_lock(xnuspy_rw_lck, LCK_RW_TYPE_EXCLUSIVE);
    STAILQ_INSERT_TAIL(&freelist, stqe, link);
    lck_rw_done(xnuspy_rw_lck);
}

/* Pull an xnuspy_tramp struct off of the freelist, we may or may not commit
 * it to use */
static struct stailq_entry *xnuspy_tramp_alloc(void){
    lck_rw_lock(xnuspy_rw_lck, LCK_RW_TYPE_EXCLUSIVE);

    if(STAILQ_EMPTY(&freelist)){
        lck_rw_done(xnuspy_rw_lck);
        return NULL;
    }

    struct stailq_entry *allocated = STAILQ_FIRST(&freelist);
    STAILQ_REMOVE_HEAD(&freelist, link);

    lck_rw_done(xnuspy_rw_lck);

    return allocated;
}

/* Commit an xnuspy_tramp struct to use by putting it on the usedlist. There
 * is no locking done here because the one place this function is called
 * already holds the xnuspy lock */
static void xnuspy_tramp_commit(struct stailq_entry *stqe){
    STAILQ_INSERT_TAIL(&usedlist, stqe, link);
}

/* Pull an xnuspy_tramp off of the usedlist, according to its target */
static struct stailq_entry *xnuspy_tramp_disconnect(uint64_t target){
    lck_rw_lock(xnuspy_rw_lck, LCK_RW_TYPE_EXCLUSIVE);

    if(STAILQ_EMPTY(&usedlist)){
        lck_rw_done(xnuspy_rw_lck);
        return NULL;
    }

    struct stailq_entry *entry, *tmp;

    STAILQ_FOREACH_SAFE(entry, &usedlist, link, tmp){
        struct xnuspy_tramp *tramp = entry->elem;

        if(tramp->tramp_metadata->hooked == target){
            STAILQ_REMOVE(&usedlist, entry, stailq_entry, link);
            lck_rw_done(xnuspy_rw_lck);
            return entry;
        }
    }

    lck_rw_done(xnuspy_rw_lck);

    return NULL;
}

static struct xnuspy_mapping_metadata *find_mapping_metadata(void){
    pid_t cpid = proc_pid(current_proc());
    struct stailq_entry *entry;

    lck_rw_lock(xnuspy_rw_lck, LCK_RW_TYPE_SHARED);

    STAILQ_FOREACH(entry, &usedlist, link){
        struct xnuspy_tramp *tramp = entry->elem;

        if(tramp->mapping_metadata->owner == cpid){
            lck_rw_done(xnuspy_rw_lck);
            return tramp->mapping_metadata;
        }
    }

    lck_rw_done(xnuspy_rw_lck);

    return NULL;
}

static int hook_already_exists(uint64_t target){
    struct stailq_entry *entry;

    lck_rw_lock(xnuspy_rw_lck, LCK_RW_TYPE_SHARED);

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

static int freelist_empty(void){
    int res;
    lck_rw_lock(xnuspy_rw_lck, LCK_RW_TYPE_SHARED);
    res = STAILQ_EMPTY(&freelist);
    lck_rw_done(xnuspy_rw_lck);
    return res;
}

static int usedlist_empty(void){
    int res;
    lck_rw_lock(xnuspy_rw_lck, LCK_RW_TYPE_SHARED);
    res = STAILQ_EMPTY(&usedlist);
    lck_rw_done(xnuspy_rw_lck);
    return res;
}

/* XXX Not sure if I can kprintf while holding a rw lock in xnu so I won't */
static void desc_freelist(void){
    kprintf("[Freelist] ");

    if(STAILQ_EMPTY(&freelist)){
        kprintf("Empty\n");
        return;
    }

    kprintf("FIRST: ");

    struct stailq_entry *entry;
    STAILQ_FOREACH(entry, &freelist, link){
        kprintf("%#llx <- ", entry->elem);
    }
    kprintf("\n");
}

static void desc_usedlist(void){
    kprintf("[Usedlist] ");

    if(STAILQ_EMPTY(&usedlist)){
        kprintf("Empty\n");
        return;
    }

    struct stailq_entry *entry;

    STAILQ_FOREACH(entry, &usedlist, link){
        kprintf("%#llx -> ", entry->elem);
    }
    kprintf("\n");
}

static void desc_lists(void){
    desc_usedlist();
    desc_freelist();
}

static uint64_t find_replacement_kva(struct mach_header_64 *kmh,
        struct mach_header_64 * /* __user */ umh,
        uint64_t /* __user */ replacement){
    uint64_t dist = replacement - (uintptr_t)umh;
    kprintf("%s: dist %#llx replacement %#llx umh %#llx kmh %#llx\n", __func__,
            dist, replacement, (uint64_t)umh, (uint64_t)kmh);
    return (uint64_t)((uintptr_t)kmh + dist);
}

/* Create a shared mapping of the calling process' __TEXT and __DATA and
 * then find a contiguous set of pages we reserved before booting XNU to
 * to reflect that mapping onto. We share __TEXT so the user can call other
 * functions they wrote from their kernel hooks. We share __DATA so
 * modifications to global variables are visible to both EL1 and EL0. 
 *
 * On success, it returns metadata for every hook this process will install.
 * We also return with the xnuspy lock will be held. We only have to do this
 * once for each process since we're mapping the entirety of __TEXT and __DATA
 * and not just the one replacement function.
 *
 * On failure, returns NULL and sets retval. We do not return with the xnuspy
 * lock held.
 *
 * TODO: cleanup everything upon failures
 */
static struct xnuspy_mapping_metadata *
map_caller_segments(struct mach_header_64 * /* __user */ umh,
        struct xnuspy_tramp *alloced_tramp, void *current_map, int *retval){
    uint64_t aslr_slide = (uintptr_t)umh - 0x100000000;
    uint64_t copystart = 0, copysz = 0;
    int seen_text = 0, seen_data = 0;
    vm_prot_t text_prot = 0, data_prot = 0;

    struct segment_command_64 *text = NULL, *data = NULL;

    struct load_command *lc = (struct load_command *)(umh + 1);

    for(int i=0; i<umh->ncmds; i++){
        /* kprintf("%s: got cmd %d\n", __func__, lc->cmd); */

        if(lc->cmd != LC_SEGMENT_64)
            goto nextcmd;

        struct segment_command_64 *sc64 = (struct segment_command_64 *)lc;

        int is_text = strcmp(sc64->segname, "__TEXT") == 0;
        int is_data = strcmp(sc64->segname, "__DATA") == 0;

        /* These will always be page aligned and unslid */
        uint64_t start = sc64->vmaddr + aslr_slide;
        uint64_t end = start + sc64->vmsize;

        /* kprintf("%s: segment '%s' start %#llx end %#llx\n", __func__, */
        /*         sc64->segname, start, end); */

        /* If this segment is neither __TEXT nor __DATA, but we've already
         * seen __TEXT or __DATA, we need to make sure we account for
         * that gap. copystart being non-zero implies we've already seen
         * __TEXT or __DATA */
        if(copystart && !is_text && !is_data){
            /* kprintf("%s: got segment '%s' in between __TEXT and __DATA\n", */
            /*         __func__, sc64->segname); */
            copysz += sc64->vmsize;
        }
        else if(is_text || is_data){
            if(copystart)
                copysz += sc64->vmsize;
            else{
                copystart = start;
                copysz = sc64->vmsize;
            }

            if(is_text){
                seen_text = 1;
                text_prot = sc64->initprot;
                text = sc64;
            }

            if(is_data){
                seen_data = 1;
                data_prot = sc64->initprot;
                data = sc64;
            }

            if(seen_text && seen_data){
                kprintf("%s: we've seen text and data, breaking\n", __func__);
                break;
            }
        }

nextcmd:
        lc = (struct load_command *)((uintptr_t)lc + lc->cmdsize);
    }

    kprintf("%s: ended with copystart %#llx copysz %#llx\n", __func__,
            copystart, copysz);

    int need_free_on_error = 0;
    struct xnuspy_mapping_metadata *metadata = NULL;

    if(!copystart || !copysz){
        *retval = ENOENT;
        goto failed;
    }

    /* If some other process previously owned this hook, we may need to unmap
     * its shared mapping. However, if there's other hooks referencing this
     * mapping metadata, we don't unmap and instead create metadata from
     * scratch.
     *
     * This is not a race; alloced_tramp has been pulled from the freelist
     * but has not yet been committed to the usedlist, and once allocated,
     * mapping metadata pointers won't be freed once attached to xnuspy_tramp
     * structs.
     */
    metadata = alloced_tramp->mapping_metadata;

    if(!metadata || metadata->refcnt > 0){
        metadata = common_kalloc(sizeof(*metadata));

        if(!metadata){
            kprintf("%s: common_kalloc returned NULL when allocating metadata\n",
                    __func__);
            *retval = ENOMEM;
            goto failed;
        }

        need_free_on_error = 1;
    }
    else{
        /* Only unmap if the shared mapping is no longer being used */
        if(metadata->refcnt == 0){
            kprintf("%s: some other process previously owned this hook!! Need to"
                    " unmap the previous shared mapping and the memory object\n",
                    __func__); 

            /* TODO: unmap shared mapping and destroy the memory object.
             * XXX will the memory object still be alive here? */
        }

        /* No need to kfree this, we can just reuse the memory */
    }

    /* A reference for this will be taken if we end up hooking the target */
    metadata->refcnt = 0;
    metadata->owner = proc_uniqueid(current_proc());

    uint64_t text_start = text->vmaddr + aslr_slide;
    uint64_t text_end = text_start + text->vmsize;
    kern_return_t kret;

    /* Wire down __TEXT and __DATA of the calling process so they are not
     * swapped out. We only set VM_PROT_READ in case there were some segments
     * in between __TEXT and __DATA. Also, vm_map_wire_kernel needs to be
     * patched to not bail when VM_PROT_EXECUTE is given, so that's also one
     * less patchfinder for me to write :D We also set from_user to one because
     * we're dealing with a user map.
     *
     * TODO: wire [copystart, copystart+copysz) in one call if VM_PROT_READ
     * wiring ends up working fine
     *
     * XXX XXX Only wiring for VM_PROT_READ and not actual VM permissions
     * may screw things up?
     */

    kret = vm_map_wire_kernel(current_map, text_start, text_end, VM_PROT_READ,//text->initprot,
            VM_KERN_MEMORY_OSFMK, 1);

    if(kret){
        kprintf("%s: vm_map_wire_kernel failed when wiring down __TEXT: %d\n",
                __func__, kret);
        *retval = kern_return_to_errno(kret);
        goto failed;
    }

    uint64_t data_start = data->vmaddr + aslr_slide;
    uint64_t data_end = data_start + data->vmsize;

    kret = vm_map_wire_kernel(current_map, data_start, data_end, VM_PROT_READ,//data->initprot,
            VM_KERN_MEMORY_OSFMK, 1);

    if(kret){
        kprintf("%s: vm_map_wire_kernel failed when wiring down __DATA: %d\n",
                __func__, kret);
        *retval = kern_return_to_errno(kret);
        goto failed;
    }

    void *kernel_map = *kernel_mapp;
    
    /* We create the mapping with only VM_PROT_READ because that is the
     * minimum VM protections for a segment (unless they have none, which won't
     * happen, unless the user does something weird). Additionally, we map
     * [copystart, copystart+copysz) in one shot, so it's easier to map
     * everything with the minimum permissions.
     *
     * We are not actually interacting with this mapping directly, so the VM
     * permissions of this shared mapping do not matter. We interact with it 
     * through the static memory we reserved before XNU boot (reflector pages)
     */
    vm_prot_t shm_prot = VM_PROT_READ;

    /* ipc_port_t */
    void *shm_object = NULL;

    uint64_t copysz_before = copysz;

    kret = _mach_make_memory_entry_64(current_map, &copysz, copystart,
            MAP_MEM_VM_SHARE | shm_prot, &shm_object, NULL);

    if(kret){
        kprintf("%s: mach_make_memory_entry_64 failed: %d\n", __func__, kret);
        *retval = kern_return_to_errno(kret);
        goto failed;
    }

    if(copysz_before != copysz){
        kprintf("%s: did not map the entirety of copystart? got %#llx "
                "expected %#llx\n", __func__, copysz, copysz_before);
        /* Probably not the best option */
        *retval = EIO;
        goto failed;
    }

    /* XXX: should we take a reference on this port? */
    metadata->memory_object = shm_object;

    uint64_t shm_addr = 0;
    kret = mach_vm_map_external(kernel_map, &shm_addr, copysz, 0,
            VM_FLAGS_ANYWHERE, metadata->memory_object, 0, 0, shm_prot,
            shm_prot, VM_INHERIT_NONE);

    if(kret){
        kprintf("%s: mach_vm_map_external failed: %d\n", __func__, kret);
        *retval = kern_return_to_errno(kret);
        goto failed;
    }

    kprintf("%s: shared mapping starts @ %#llx\n", __func__, shm_addr);

    /* uint32_t *cursor = (uint32_t *)shm_addr; */
    /* for(int i=0; i<20; i++){ */
    /*     kprintf("%s: %#llx:      %#x\n", __func__, (uint64_t)(cursor+i), */
    /*             cursor[i]); */
    /* } */

    /* Wire down the shared mapping */
    kret = vm_map_wire_kernel(kernel_map, shm_addr, shm_addr + copysz,
            shm_prot, VM_KERN_MEMORY_OSFMK, 0);

    if(kret){
        kprintf("%s: vm_map_wire_kernel failed: %d\n", __func__, kret);
        *retval = kern_return_to_errno(kret);
        goto failed;
    }

    metadata->mapping_addr = shm_addr;
    metadata->mapping_size = copysz;

    uint64_t npages = metadata->mapping_size / PAGE_SIZE;

    struct xnuspy_reflector_page *found = NULL;
    struct xnuspy_reflector_page *cur = first_reflector_page;

    /* This needs to be locked because we check the reference count of more
     * than one reflector page */
    lck_rw_lock(xnuspy_rw_lck, LCK_RW_TYPE_EXCLUSIVE);

    while(cur){
        if(!xnuspy_reflector_page_free(cur))
            goto nextpage;

        /* Got one free page, check the ones after it */
        struct xnuspy_reflector_page *leftoff = cur;

        for(int i=1; i<npages; i++){
            if(!cur || !xnuspy_reflector_page_free(cur)){
                cur = leftoff;
                goto nextpage;
            }

            cur = cur->next;
        }

        /* If we're here, we found a set of free reflector pages */
        cur = leftoff;

        break;

nextpage:
        cur = cur->next;
    }

    if(!cur){
        lck_rw_done(xnuspy_rw_lck);
        kprintf("%s: no free reflector pages\n", __func__);
        *retval = ENOSPC;
        goto failed;
    }

    metadata->first_reflector_page = cur;
    metadata->used_reflector_pages = npages;

    *retval = 0;

    /* We return with the lock held because we may end up committing
     * alloced_tramp to the usedlist */

    return metadata;

failed:;
    if(need_free_on_error)
        common_kfree(metadata);

    return NULL;
}

static int xnuspy_install_hook(uint64_t target, uint64_t replacement,
        uint64_t /* __user */ origp){
    kprintf("%s: called with unslid target %#llx replacement %#llx origp %#llx\n",
            __func__, target, replacement, origp);

    int res = 0;

    /* slide target */
    target += kernel_slide;

    if(hook_already_exists(target)){
        kprintf("%s: hook for %#llx already exists\n", __func__, target);
        res = EEXIST;
        goto out;
    }

    struct xnuspy_tramp_metadata *tramp_metadata =
        common_kalloc(sizeof(*tramp_metadata));

    if(!tramp_metadata){
        kprintf("%s: failed allocating mem for tramp metadata\n", __func__);
        res = ENOMEM;
        goto out;
    }

    tramp_metadata->hooked = target;
    tramp_metadata->orig_instr = *(uint32_t *)target;

    struct stailq_entry *tramp_entry = xnuspy_tramp_alloc();

    /* We don't need to keep this locked because we have not committed
     * this entry to the usedlist and it no longer exists in the freelist */

    if(!tramp_entry){
        kprintf("%s: no free xnuspy_tramp structs\n", __func__);
        res = ENOMEM;
        goto out_free;
    }

    struct xnuspy_tramp *tramp = tramp_entry->elem;

    tramp->tramp_metadata = tramp_metadata;

    /* Build the trampoline to the replacement as well as the trampoline
     * that represents the original function */
    uint32_t orig_tramp_len = 0;

    generate_replacement_tramp(tramp->tramp);
    generate_original_tramp(target + 4, tramp->orig, &orig_tramp_len);

    /* copyout the original function trampoline before the replacement
     * is called */
    uint32_t *orig_tramp = tramp->orig;
    res = copyout(&orig_tramp, origp, sizeof(origp));

    if(res){
        kprintf("%s: copyout failed\n", __func__);
        goto out_free;
    }

    /* offset found in mmap */
    struct _vm_map *current_map = *(struct _vm_map **)(current_thread() + 0x320);

    /* User pointer to Mach header of the calling process */
    struct mach_header_64 *umh = (struct mach_header_64 *)current_map->hdr.vme_start;

    /* Check if we've got mapping metadata for the calling process already.
     * If we don't, we need to create a shared mapping out of __TEXT and
     * __DATA. */
    struct xnuspy_mapping_metadata *mm = find_mapping_metadata();

    if(mm)
        lck_rw_lock(xnuspy_rw_lck, LCK_RW_TYPE_EXCLUSIVE);
    else{
        kprintf("%s: need to map __TEXT and __DATA\n", __func__);

        mm = map_caller_segments(umh, tramp, current_map, &res);

        if(!mm){
            kprintf("%s: failed to create mapping metadata for this hook\n",
                    __func__);
            goto out_free;
        }

        /* map_caller_segments succeeded, and we returned from it with the
         * xnuspy lock held */
    }

    /* Mach header of the calling process, but the kernel's mapping of it */
    struct mach_header_64 *kmh = mm->first_reflector_page->page;

    tramp->replacement = find_replacement_kva(kmh, umh, replacement);

    struct xnuspy_reflector_page *cur = mm->first_reflector_page;

    uint64_t mapping_addr = mm->mapping_addr;

    for(int i=0; i<mm->used_reflector_pages; i++){
        if(!cur)
            break;

        void *rp = cur->page;
        pte_t *rp_ptep = el1_ptep((uint64_t)rp);

        uint64_t ma_phys = kvtophys(mapping_addr);
        uint64_t ma_physpage = ma_phys & ~0x3fffuLL;

        /* These PTEs are already marked as rwx, we just need to replace
         * the OutputAddress */
        pte_t new_rp_pte = (*rp_ptep & ~0xfffffffff000uLL) | ma_physpage;

        kwrite(rp_ptep, &new_rp_pte, sizeof(new_rp_pte));

        asm volatile("isb");
        asm volatile("dsb sy");
        asm volatile("tlbi vmalle1");
        asm volatile("dsb sy");
        asm volatile("isb");

        xnuspy_reflector_page_reference(cur);

        cur = cur->next;
        mapping_addr += PAGE_SIZE;
    }

    tramp->mapping_metadata = mm;

    xnuspy_mapping_metadata_reference(tramp->mapping_metadata);
    xnuspy_tramp_commit(tramp_entry);

    uint32_t branch = assemble_b(target, (uint64_t)tramp->tramp);

    lck_rw_done(xnuspy_rw_lck);

    kwrite_instr(target, branch);

    return 0;

out_free:;
    if(tramp){
        xnuspy_tramp_teardown(tramp);
        xnuspy_tramp_free(tramp_entry);
    }

    common_kfree(tramp_metadata);
out:
    return res;
}

/* Every second, this thread loops through the proc list, and checks
 * if the owner of a given xnuspy_mapping_metadata struct is no longer present.
 * If so, all the hooks associated with that metadata struct are uninstalled
 * and sent back to the freelist. */
static void xnuspy_gc_thread(void *param, int wait_result){
    for(;;){
        lck_rw_lock(xnuspy_rw_lck, LCK_RW_TYPE_SHARED);

        if(STAILQ_EMPTY(&usedlist))
            goto unlock_and_sleep;

        if(!lck_rw_lock_shared_to_exclusive(xnuspy_rw_lck))
            lck_rw_lock(xnuspy_rw_lck, LCK_RW_TYPE_EXCLUSIVE);
        
        struct stailq_entry *entry, *tmp;

        STAILQ_FOREACH_SAFE(entry, &usedlist, link, tmp){
            struct xnuspy_tramp *tramp = entry->elem;
            struct xnuspy_mapping_metadata *mm = tramp->mapping_metadata;
            struct xnuspy_tramp_metadata *tm = tramp->tramp_metadata;

            proc_list_lock();

            /* Looping through allproc with LIST_FOREACH doesn't pick up the last
             * proc structure in the list for some reason */
            void *curproc = *allprocp;
            pid_t pid;
            /* For simplicity, assume owner is dead before we start the
             * search */
            int owner_dead = 1;

            do {
                proc_ref_locked(curproc);

                pid = proc_pid(curproc);
                uint64_t uniqueid = proc_uniqueid(curproc);

                /* kprintf("%s: looking at %#llx with unique id %lld pid %d\n", */
                /*         __func__, curproc, uniqueid, pid); */

                void *nextproc = *(void **)curproc;

                proc_rele_locked(curproc);

                if(mm->owner == uniqueid){
                    owner_dead = 0;
                    break;
                }

                curproc = nextproc;
            } while(pid != 0);

            proc_list_unlock();

            if(owner_dead){
                kprintf("%s: Tramp %#llx's owner (%lld) is dead, freeing it\n",
                        __func__, tramp, mm->owner);

                /* desc_xnuspy_tramp(tramp, 5); */

                STAILQ_REMOVE(&usedlist, entry, stailq_entry, link);

                kwrite_instr(tm->hooked, tm->orig_instr);

                xnuspy_tramp_teardown(tramp);

                STAILQ_INSERT_TAIL(&freelist, entry, link);
            }
        }

unlock_and_sleep:;
        lck_rw_done(xnuspy_rw_lck);
        IOSleep(1000);
    }
}

static int xnuspy_init_flag = 0;

static int xnuspy_init(void){
    /* Kinda sucks I can't statically initialize the xnuspy lock, so I'll have
     * to deal with racing inside xnuspy_init. Why would anyone try to race
     * this function anyway */
    void *grp = lck_grp_alloc_init("xnuspy", NULL);
    
    if(!grp){
        kprintf("%s: no mem for lck grp\n", __func__);
        return ENOMEM;
    }

    xnuspy_rw_lck = lck_rw_alloc_init(grp, NULL);

    if(!xnuspy_rw_lck){
        kprintf("%s: no mem for xnuspy rw lck\n", __func__);
        return ENOMEM;
    }

    /* Build the initial freelist/usedlist for xnuspy_tramp structs */
    STAILQ_INIT(&freelist);
    STAILQ_INIT(&usedlist);

    struct xnuspy_tramp *cursor = (struct xnuspy_tramp *)xnuspy_tramp_page;
    
    while((uint8_t *)cursor < xnuspy_tramp_page_end){
        struct stailq_entry *entry = common_kalloc(sizeof(*entry));

        if(!entry){
            kprintf("%s: no mem for stailq_entry\n", __func__);
            /* TODO: free what was allocated before this */
            return ENOMEM;
        }

        entry->elem = cursor;
        STAILQ_INSERT_TAIL(&freelist, entry, link);
        cursor++;
    }

    void *gct = NULL;
    kern_return_t kret = kernel_thread_start(xnuspy_gc_thread, NULL, &gct);

    if(kret){
        kprintf("%s: kernel_thread_start failed: %d\n", __func__, kret);
        return kern_return_to_errno(kret);
    }

    thread_deallocate(gct);

    /* desc_lists(); */

    /* Mark the xnuspy_tramp page as writeable/executable */
    vm_prot_t prot = VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE;
    kprotect((uint64_t)xnuspy_tramp_page, PAGE_SIZE, prot);

    /* Do the same for the pages which will reflect shared mappings */
    struct xnuspy_reflector_page *cur = first_reflector_page;
    
    while(cur){
        kprotect((uint64_t)cur->page, PAGE_SIZE, prot);
        cur = cur->next;
    }

    /* Zero out PAN in case no instruction did it before us. After our kernel
     * patches, the PAN bit cannot be set to 1 again.
     *
     * msr pan, #0
     *
     * XXX XXX NEED TO CHECK IF THE HARDWARE SUPPORTS THIS BIT
     */
    asm volatile(".long 0xd500409f");
    asm volatile("isb sy");

    /* combat short read of this image */
    /* asm volatile(".align 14"); */
    /* asm volatile(".align 14"); */

    xnuspy_init_flag = 1;

    kprintf("%s: xnuspy inited\n", __func__);

    return 0;
}

/* TODO: figure out a better way to do this */
static int xnuspy_get_function(uint64_t which, uint64_t /* __user */ outp){
    kprintf("%s: XNUSPY_GET_FUNCTION called with which %lld origp %#llx\n",
            __func__, which, outp);

    if(which > MAX_FUNCTION)
        return ENOENT;

    switch(which){
        case KPROTECT:
            which = (uint64_t)kprotect;
            break;
        case COPYOUT:
            which = (uint64_t)copyout;
            break;
        case KPRINTF:
            which = (uint64_t)kprintf;
            break;
        case IOSLEEP:
            which = (uint64_t)IOSleep;
            break;
        case KERNEL_SLIDE:
            which = kernel_slide;
            break;
        default:
            break;
    };

    return copyout(&which, outp, sizeof(outp));
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
        kprintf("%s: bad flavor %d\n", __func__, flavor);
        *retval = -1;
        return EINVAL;
    }

    if(flavor == XNUSPY_CHECK_IF_PATCHED){
        *retval = 999;
        return 0;
    }

    int res;

    if(!xnuspy_init_flag){
        res = xnuspy_init();

        if(res){
            *retval = -1;
            return res;
        }
    }

    switch(flavor){
        case XNUSPY_INSTALL_HOOK:
            res = xnuspy_install_hook(uap->arg1, uap->arg2, uap->arg3);
            break;
        case XNUSPY_GET_FUNCTION:
            res = xnuspy_get_function(uap->arg1, uap->arg2);
            break;
        case XNUSPY_DUMP_TTES:
            res = xnuspy_dump_ttes(uap->arg1, uap->arg2);
            break;
        case XNUSPY_KREAD:
            res = copyout(uap->arg1, uap->arg2, uap->arg3);
            break;
        case XNUSPY_GET_CURRENT_TASK:
            {
                void *ct = current_task();
                res = copyout(&ct, uap->arg1, sizeof(void *));
                break;
            }
        default:
            *retval = -1;
            return EINVAL;
    };

    if(res)
        *retval = -1;

    return res;
}
