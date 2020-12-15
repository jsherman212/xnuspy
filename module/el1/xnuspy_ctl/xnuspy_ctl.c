#include <errno.h>
#include <mach/mach.h>
#include <mach/vm_statistics.h>
#include <mach-o/loader.h>
#include <stdbool.h>
#include <stdint.h>

#include "asm.h"
#include "mem.h"
#include "pte.h"
#include "queue.h"
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
#define XNUSPY_UNINSTALL_HOOK       (1)
#define XNUSPY_CHECK_IF_PATCHED     (2)
#define XNUSPY_GET_FUNCTION         (3)
#define XNUSPY_DUMP_TTES            (4)
#define XNUSPY_KREAD                (5)
#define XNUSPY_GET_CURRENT_TASK     (6)
#define XNUSPY_MAX_FLAVOR           XNUSPY_GET_CURRENT_TASK

/* values for XNUSPY_GET_FUNCTION */
#define KPROTECT                    (0)
#define COPYOUT                     (1)
#define KPRINTF                     (2)
#define IOSLEEP                     (3)
#define KERNEL_SLIDE                (4)
#define MAX_FUNCTION                KERNEL_SLIDE

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
MARK_AS_KERNEL_OFFSET uint32_t (*lck_rw_done)(void *lock);
MARK_AS_KERNEL_OFFSET void *(*lck_grp_alloc_init)(const char *grp_name,
        void *attr);
MARK_AS_KERNEL_OFFSET void *(*lck_rw_alloc_init)(void *grp, void *attr);
MARK_AS_KERNEL_OFFSET void (*bcopy_phys)(uint64_t src, uint64_t dst,
        vm_size_t bytes);
MARK_AS_KERNEL_OFFSET uint64_t (*phystokv)(uint64_t pa);
MARK_AS_KERNEL_OFFSET int (*copyin)(const uint64_t uaddr, void *kaddr,
        vm_size_t nbytes);
MARK_AS_KERNEL_OFFSET int (*copyout)(const void *kaddr, uint64_t uaddr,
        vm_size_t nbytes);
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
MARK_AS_KERNEL_OFFSET void *kernel_map;

MARK_AS_KERNEL_OFFSET kern_return_t (*vm_map_wire_kernel)(void *map,
        uint64_t start, uint64_t end, vm_prot_t prot, int tag, int user_wire);

/* extra underscore so compiler stops complaining */
MARK_AS_KERNEL_OFFSET kern_return_t (*_mach_make_memory_entry_64)(void *target_map,
        uint64_t *size, uint64_t offset, vm_prot_t prot, void **object_handle,
        void *parent_handle);


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

/* #define tt1_index(pmap, addr)								\ */
/* 	(((addr) & ARM_TT_L1_INDEX_MASK) >> ARM_TT_L1_SHIFT) */
/* #define tt2_index(pmap, addr)								\ */
/* 	(((addr) & ARM_TT_L2_INDEX_MASK) >> ARM_TT_L2_SHIFT) */
/* #define tt3_index(pmap, addr)								\ */
/* 	(((addr) & ARM_TT_L3_INDEX_MASK) >> ARM_TT_L3_SHIFT) */

/* shorter macros so I can stay under 80 column lines */
/* #define DIST_FROM_REFCNT_TO(x) __builtin_offsetof(struct xnuspy_tramp, x) - \ */
/*     __builtin_offsetof(struct xnuspy_tramp, refcnt) */

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

static void _desc_xnuspy_usercode_page(const char *indent,
        struct xnuspy_usercode_page *p){
    kprintf("%sThis usercode page is @ %#llx. "
            "next: %#llx refcnt: %lld page %#llx\n", indent, (uint64_t)p, p->next,
            p->refcnt, p->page);
}

static void desc_xnuspy_usercode_page(struct xnuspy_usercode_page *p){
    _desc_xnuspy_usercode_page("", p);
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

    if(!t->metadata)
        kprintf("NULL metadata\n");
    else{
        kprintf("Owner: %#llx\n", t->metadata->owner);
        kprintf("# of used usercode pages: %lld\n", t->metadata->used_usercode_pages);
        kprintf("Usercode pages:\n");

        struct xnuspy_usercode_page *cur = t->metadata->first_usercode_page;

        for(int i=0; i<t->metadata->used_usercode_pages; i++){
            if(!cur)
                break;

            _desc_xnuspy_usercode_page("    ", cur);
            cur = cur->next;
        }
    }
}

__attribute__ ((naked)) static uint64_t current_thread(void){
    asm volatile(""
            "mrs x0, tpidr_el1\n"
            "ret\n"
            );
}

static int xnuspy_usercode_page_free(struct xnuspy_usercode_page *p){
    return p->refcnt == 0;
}

static int xnuspy_tramp_free(struct xnuspy_tramp *t){
    return !t->metadata || t->metadata->owner;
}

MARK_AS_KERNEL_OFFSET struct xnuspy_tramp *xnuspy_tramp_page;
MARK_AS_KERNEL_OFFSET uint8_t *xnuspy_tramp_page_end;

MARK_AS_KERNEL_OFFSET struct xnuspy_usercode_page *first_usercode_page;

static int xnuspy_init_flag = 0;

static void xnuspy_init(void){
    /* Mark the xnuspy_tramp page as writeable/executable */
    vm_prot_t prot = VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE;
    kprotect((uint64_t)xnuspy_tramp_page, PAGE_SIZE, prot);

    /* Do the same for the pages which will hold user code */
    struct xnuspy_usercode_page *cur = first_usercode_page;
    
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
}

/* void disable_preemption(void){ */
/*     _disable_preemption(); */
/* } */

/* void enable_preemption(void){ */
/*     _enable_preemption(); */
/* } */

int strcmp(const char *s1, const char *s2){
    while(*s1 && (*s1 == *s2)){
        s1++;
        s2++;
    }

    return *(const unsigned char *)s1 - *(const unsigned char *)s2;
}

static uint64_t find_replacement_kva(struct mach_header_64 *kmh,
        struct mach_header_64 * /* __user */ umh,
        uint64_t /* __user */ replacement){
    uint64_t dist = replacement - (uintptr_t)umh;
    kprintf("%s: dist %#llx replacement %#llx umh %#llx kmh %#llx\n", __func__,
            dist, replacement, (uint64_t)umh, (uint64_t)kmh);
    return (uint64_t)((uintptr_t)kmh + dist);
}

/* Copy the calling process' __TEXT and __DATA onto a contiguous set
 * of the pages we reserved before booting XNU. This effectively creates a
 * shared mapping of __TEXT and __DATA between the kernel and the calling
 * process.
 *
 * On success, returns metadata for all hooks installed by this process.
 */
static struct xnuspy_tramp_metadata *
copy_caller_segments(struct mach_header_64 * /* __user */ umh){
    uint64_t aslr_slide = (uintptr_t)umh - 0x100000000;
    uint64_t copystart = 0, copysz = 0;
    int seen_text = 0, seen_data = 0;
    vm_prot_t text_prot = 0, data_prot = 0;

    struct segment_command_64 *text = NULL, *data = NULL;

    struct load_command *lc = (struct load_command *)(umh + 1);

    for(int i=0; i<umh->ncmds; i++){
        kprintf("%s: got cmd %d\n", __func__, lc->cmd);

        if(lc->cmd != LC_SEGMENT_64)
            goto nextcmd;

        struct segment_command_64 *sc64 = (struct segment_command_64 *)lc;

        int is_text = strcmp(sc64->segname, "__TEXT") == 0;
        int is_data = strcmp(sc64->segname, "__DATA") == 0;

        /* These will always be page aligned and unslid */
        uint64_t start = sc64->vmaddr + aslr_slide;
        uint64_t end = start + sc64->vmsize;

        kprintf("%s: segment '%s' start %#llx end %#llx\n", __func__,
                sc64->segname, start, end);

        /* If this segment is neither __TEXT nor __DATA, but we've already
         * seen __TEXT or __DATA, we need to make sure we account for
         * that gap. copystart being non-zero implies we've already seen
         * __TEXT or __DATA */
        if(copystart && (!is_text && !is_data)){
            kprintf("%s: got segment '%s' in between __TEXT and __DATA\n",
                    __func__, sc64->segname);
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

    if(!copystart || !copysz)
        return NULL;

    /* Now find a set of free, contiguous usercode pages to copy on to */
    uint64_t npages = copysz / PAGE_SIZE;

    struct xnuspy_usercode_page *found = NULL;

    /* TODO: don't start the search at the beginning every time, probably
     * would be better to pick up where we left off for another hook to make
     * this faster. Better than doing a linear search every time and I can
     * just wrap around if I hit the end of the list */
    struct xnuspy_usercode_page *cur = first_usercode_page;

    while(cur){
        if(!xnuspy_usercode_page_free(cur))
            goto nextpage;

        /* Got one free page, check the ones after it */
        struct xnuspy_usercode_page *leftoff = cur;

        for(int i=1; i<npages; i++){
            if(!cur || !xnuspy_usercode_page_free(cur)){
                cur = leftoff;
                goto nextpage;
            }

            cur = cur->next;
        }

        /* If we're here, we found a set of free usercode pages */
        cur = leftoff;

        break;

nextpage:
        cur = cur->next;
    }

    struct xnuspy_usercode_page *freeset = cur;

    kprintf("%s: free pages found:\n", __func__);

    for(int i=0; i<npages; i++){
        desc_xnuspy_usercode_page(cur);
        cur = cur->next;
    }

    /* Wire down __TEXT and __DATA of the calling process so they are not
     * swapped out */
    uint64_t thread = current_thread();
    struct _vm_map *current_map = *(struct _vm_map **)(thread + 0x320);

    asm volatile("dsb sy");
    asm volatile("isb");

    uint64_t text_start = text->vmaddr + aslr_slide;
    uint64_t text_end = text_start + text->vmsize;
    kern_return_t kret;

    /* for(int i=0; i<2; i++){ */
    kret = vm_map_wire_kernel(current_map, text_start, text_end,
            text->initprot, VM_KERN_MEMORY_OSFMK, 1);//i);//1);

    if(kret){
        kprintf("%s: vm_map_wire_kernel failed when wiring down __TEXT: %d\n",
                __func__, kret);
        return NULL;
    }
    /* } */

    uint64_t data_start = data->vmaddr + aslr_slide;
    uint64_t data_end = data_start + data->vmsize;

    /* for(int i=0; i<2; i++){ */
    kret = vm_map_wire_kernel(current_map, data_start, data_end, data->initprot,
            VM_KERN_MEMORY_OSFMK, 1);//i);//1);

    if(kret){
        kprintf("%s: vm_map_wire_kernel failed when wiring down __DATA: %d\n",
                __func__, kret);
        return NULL;
    }
    /* } */

    struct xnuspy_tramp_metadata *metadata = common_kalloc(sizeof(*metadata));

    if(!metadata)
        return NULL;

    metadata->owner = current_task();
    /* Don't take a reference yet, because failures are still possible */
    metadata->first_usercode_page = freeset;
    metadata->used_usercode_pages = npages;

    uint64_t kmap = *(uint64_t *)kernel_map;
    /* uint64_t kma_addr = 0; */
    /* uint32_t *vma_prot0 = (uint32_t *)(0xFFFFFFF007C89854 + kernel_slide); */
    /* uint32_t *vma_prot1 = (uint32_t *)(0xFFFFFFF007C89920 + kernel_slide); */

    /* kprotect((uint64_t)vma_prot0, PAGE_SIZE, VM_PROT_READ | VM_PROT_WRITE | */
    /*         VM_PROT_EXECUTE); */

    /* /1* mov w3, 1 *1/ */
    /* *vma_prot0 = 0x52800023; */
    /* asm volatile("dc cvau, %0" : : "r" (vma_prot0)); */
    /* asm volatile("dsb ish"); */
    /* asm volatile("ic ivau, %0" : : "r" (vma_prot0)); */
    /* asm volatile("dsb ish"); */
    /* asm volatile("isb sy"); */
    /* /1* mov w3, 1 *1/ */
    /* *vma_prot1 = 0x52800023; */
    /* asm volatile("dc cvau, %0" : : "r" (vma_prot1)); */
    /* asm volatile("dsb ish"); */
    /* asm volatile("ic ivau, %0" : : "r" (vma_prot1)); */
    /* asm volatile("dsb ish"); */
    /* asm volatile("isb sy"); */

    /* for(int i=0; i<1; i++){//29; i++){ */
    /*     /1* KMA_LOMEM gives back the same address as mach_vm_map_external *1/ */
    /*     kret = kernel_memory_allocate((void *)kmap, &kma_addr, copysz, PAGE_SIZE - 1, */
    /*             KMA_LOMEM, i);//VM_KERN_MEMORY_OSFMK);//0); */

    /*     const char *tn = tagname(i); */

    /*     if(kret){ */
    /*         kprintf("%s: kernel_memory_allocate failed for tag '%s': %d\n", */
    /*                 __func__, tn, kret); */
    /*         continue; */
    /*     } */
    /*     else{ */
    /*         /1* kprintf("%s: kma_addr %#llx\n", __func__, kma_addr); *1/ */
    /*         uint64_t alternate_kv = phystokv(kvtophys(kma_addr)); */

    /*         pte_t *kma_addr_ptep = el1_ptep(kma_addr); */
    /*         /1* pte_t *alternate_ptep = el1_ptep(alternate_kv); *1/ */
    /*         kprintf("%s: before: tag '%s': kma addr %#llx kma addr pte @ %#llx " */
    /*                 "pte: %#llx\n", __func__, tn, kma_addr, kma_addr_ptep, */
    /*                 *kma_addr_ptep); */

    /*         /1* kret = ml_static_protect(kma_addr, copysz, VM_PROT_READ); *1/ */

    /*         /1* pmap_protect_options(*(void **)kernel_pmap, kma_addr, kma_addr + copysz, *1/ */
    /*         /1*         VM_PROT_NONE, 0, NULL); *1/ */

    /*         /1* kprintf("%s: ml_static_protect %d\n", __func__, kret); *1/ */

    /*         kret = vm_map_protect((void *)kmap, kma_addr, kma_addr + copysz, */
    /*                 VM_PROT_READ, 1); */

    /*         kprintf("%s: vm_map_protect %d\n", __func__, kret); */

    /*         IOSleep(5000); */
    /*         *(uint32_t *)kma_addr = 0x41424344; */

    /*         kprintf("%s: %#x\n", __func__, *(uint32_t *)kma_addr); */

    /*         /1* kprintf("%s: tag '%s': kma addr %#llx kma addr pte @ %#llx pte: %#llx" *1/ */
    /*         /1*         " alternate addr %#llx alternate pte @ %#llx pte: %#llx\n", *1/ */
    /*         /1*         __func__, tn, kma_addr, kma_addr_ptep, *kma_addr_ptep, *1/ */
    /*         /1*         alternate_kv, alternate_ptep, *alternate_ptep); *1/ */

    /*         /1* kprotect(kma_addr, copysz, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE); *1/ */
    /*         /1* kprotect(kma_addr, copysz, VM_PROT_READ); *1/ */

    /*         /1* *kma_addr_ptep &= ~(ARM_PTE_PNX | ARM_PTE_NX); *1/ */
    /*         /1* *kma_addr_ptep &= ~ARM_PTE_APMASK; *1/ */
    /*         /1* *kma_addr_ptep |= ARM_PTE_AP(AP_RONA); *1/ */

    /*         /1* asm volatile("dsb sy"); *1/ */
    /*         /1* asm volatile("isb"); *1/ */

    /*         /1* IOSleep(20000); *1/ */
    /*         /1* kma_addr_ptep = el1_ptep(kma_addr); *1/ */
    /*         /1* kprintf("%s: after: tag '%s': kma addr %#llx kma addr pte @ %#llx pte: %#llx\n", *1/ */
    /*         /1*         __func__, tn, kma_addr, kma_addr_ptep, *kma_addr_ptep); *1/ */



    /*         /1* *(uint32_t *)kma_addr = 0x41424344; *1/ */

    /*         /1* kprintf("%s: %#x\n", __func__, *(uint32_t *)kma_addr); *1/ */

    /*         /1* void (*fxn)(void) = (void (*)(void))kma_addr; *1/ */
    /*         /1* fxn(); *1/ */
    /*     } */
    /* } */

    /* mov w3, 3 */
    /* *vma_prot0 = 0x52800063; */
    /* asm volatile("dc cvau, %0" : : "r" (vma_prot0)); */
    /* asm volatile("dsb ish"); */
    /* asm volatile("ic ivau, %0" : : "r" (vma_prot0)); */
    /* asm volatile("dsb ish"); */
    /* asm volatile("isb sy"); */
    /* /1* mov w3, 3 *1/ */
    /* *vma_prot1 = 0x52800063; */
    /* asm volatile("dc cvau, %0" : : "r" (vma_prot1)); */
    /* asm volatile("dsb ish"); */
    /* asm volatile("ic ivau, %0" : : "r" (vma_prot1)); */
    /* asm volatile("dsb ish"); */
    /* asm volatile("isb sy"); */

    /* return metadata; */

    /* ipc_port_t */
    /* vm_prot_t prot = VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE; */
    vm_prot_t prot = VM_PROT_READ;
    void *memory_object = NULL;
    /* MAP_MEM_NAMED_CREATE copies all 0xc000 bytes, so does MAP_MEM_VM_SHARE */
    /* kret = _mach_make_memory_entry_64(current_map, &copysz, copystart, */
    /*         MAP_MEM_NAMED_CREATE | prot, &memory_object, NULL); */

    /* describe the first entry */
    /* desc_vm_map_entry((struct vm_map_entry *)(&current_map->hdr.links)); */

    /* struct vm_map_entry *entry = current_map->hdr.links.next; */
    /* int lim = 400, i=0; */

    /* while(entry && i<lim){ */
    /*     /1* entry->max_protection = VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE; *1/ */
    /*     desc_vm_map_entry(entry); */

    /*     entry = entry->vme_next; */
    /*     i++; */
    /* } */

    /* kprintf("%s: RETURNING!\n", __func__); */
    /* return metadata; */

    /* kret = vm_map_protect(current_map, copystart, copystart + copysz, prot, 0); */

    /* kprintf("%s: vm_map_protect %d\n", __func__, kret); */

    /* kret = _mach_make_memory_entry_64(current_map, &copysz, copystart, */
    /*         MAP_MEM_VM_SHARE | prot, &memory_object, NULL); */
    kret = _mach_make_memory_entry_64(current_map, &copysz, copystart,
            prot, &memory_object, NULL);

    if(kret){
        kprintf("******%s: mach_make_memory_entry_64 failed: %d\n", __func__, kret);
        return metadata;
    }
    else{
        kprintf("%s: copysz %#llx memory object @ %#llx\n", __func__, copysz,
                memory_object);
    }

    /* kprintf("%s: kernel_map %#llx *(uint64_t*)kernel_map %#llx\n", __func__, */
    /*         kernel_map, *(uint64_t *)kernel_map); */

    /* return metadata; */

    /* kprotect((uint64_t)kernel_map, 0x4000, VM_PROT_READ | VM_PROT_WRITE); */

    uint64_t shared_address = 0;
    kret = mach_vm_map_external((void *)kmap, &shared_address, copysz, 0,
            VM_FLAGS_ANYWHERE, memory_object, 0, 0, prot, prot, VM_INHERIT_NONE);

    /* uint64_t shared_address = (uint64_t)metadata->first_usercode_page->page; */

    /* struct vm_map_entry *sa_vme = vme_for_ptr(kmap, shared_address); */

    /* if(!sa_vme){ */
    /*     kprintf("%s: no vm_map_entry for %#llx\n", shared_address); */
    /*     return metadata; */
    /* } */

    /* desc_vm_map_entry(sa_vme); */

    /* sa_vme->permanent = 0; */

    /* kprotect(el1_ptep(shared_address), PAGE_SIZE, VM_PROT_READ | VM_PROT_WRITE); */

    /* asm volatile("dsb sy"); */
    /* asm volatile("isb sy"); */

    /* kret = mach_vm_map_external((void *)kmap, &shared_address, copysz, 0, */
    /*         VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, memory_object, 0, 0, */
    /*         VM_PROT_READ | VM_PROT_EXECUTE, VM_PROT_READ | VM_PROT_EXECUTE, */
    /*         VM_INHERIT_NONE); */

    if(kret){
        kprintf("******%s: mach_vm_map_external failed: %d\n", __func__, kret);
        return metadata;
    }
    else{
        kprintf("%s: shared address %#llx\n", __func__, shared_address);

        kret = vm_map_wire_kernel((void *)kmap, shared_address,
                shared_address + copysz, VM_PROT_READ,
                VM_KERN_MEMORY_OSFMK, 0);

        kprintf("%s: vm_map_wire_kernel shared address %d\n", __func__, kret);

        if(kret)
            return metadata;

        xnuspy_dump_ttes(shared_address, 1);

        uint64_t fup = metadata->first_usercode_page->page;

        uint64_t shared_address_phys = kvtophys(shared_address);
        uint64_t shared_address_physpage = shared_address_phys & ~0x3fffuLL;

        pte_t *fup_ptep = el1_ptep(fup);
        pte_t new_fup_pte = (*fup_ptep & ~0xfffffffff000uLL) |
            shared_address_physpage;
        new_fup_pte &= ~(ARM_PTE_NX | ARM_PTE_PNX);

        kwrite(fup_ptep, &new_fup_pte, sizeof(new_fup_pte));

        asm volatile("isb");
        asm volatile("dsb sy");
        asm volatile("tlbi vmalle1");
        asm volatile("dsb sy");
        asm volatile("isb");

        uint32_t *cursor = (uint32_t *)fup;
        for(int i=0; i<20; i++){
            kprintf("%s: %#llx:      %#x\n", __func__, (uint64_t)(cursor+i),
                    cursor[i]);
        }

        void (*f4)(void) = (void (*)(void))fup;
        f4();

        return metadata;

/*         IOSleep(5000); */

        /* uprotect(copystart, copysz, VM_PROT_READ | VM_PROT_WRITE | */
        /*         VM_PROT_EXECUTE); */

        /* asm volatile("dsb sy"); */
        /* asm volatile("isb sy"); */

        /* *(uint32_t *)shared_address = 0x41424344; */

        uint64_t sctlr_el1;
        asm volatile("mrs %0, sctlr_el1" : "=r" (sctlr_el1));
        kprintf("%s: sctlr_el1 %#llx\n", __func__, sctlr_el1);
        return metadata;

        uint64_t exec_test_addr = 0;
        /* kret = mach_vm_map_external((void *)kmap, &exec_test_addr, PAGE_SIZE, */
        /*         0, VM_FLAGS_ANYWHERE, NULL, 0, 0, VM_PROT_ALL, VM_PROT_ALL, */
        /*         VM_INHERIT_NONE); */

        vm_map_kernel_flags_t vmk_flags = {0};
        vmk_flags.vmkf_permanent = 1;
        vmk_flags.vmkf_map_jit = 1;

        kret = mach_vm_map_kernel((void *)kmap, &exec_test_addr, PAGE_SIZE,
                0, VM_FLAGS_ANYWHERE, vmk_flags, VM_KERN_MEMORY_OSFMK, NULL,
                0, 0, VM_PROT_ALL, VM_PROT_ALL, VM_INHERIT_NONE);

        if(kret){
            kprintf("%s: exec_test_addr vm_map failed: %d\n", __func__, kret);
            return metadata;
        }

        uint64_t val = *(uint64_t *)exec_test_addr;
        /* asm volatile("isb"); */
        /* asm volatile("dsb sy"); */
        /* asm volatile("tlbi vmalle1"); */
        /* asm volatile("ic iallu"); */
        /* asm volatile("dsb sy"); */
        /* asm volatile("isb"); */

        /* void (*f3)(void) = (void (*)(void))exec_test_addr; */
        /* f3(); */

        kprintf("%s: did a read on exec_test_addr\n", __func__);

        /* XXX XXX This page we're wiring is not a submap */
        kret = vm_map_wire_kernel((void *)kmap, exec_test_addr,
                exec_test_addr + PAGE_SIZE, VM_PROT_READ | VM_PROT_WRITE,
                VM_KERN_MEMORY_OSFMK, 0);

        /* kprintf("%s: exec test addr @ %#llx\n", __func__, exec_test_addr); */
        /* *(uint64_t *)exec_test_addr = 31; */



        kprintf("%s: vm_map_wire_kernel kret %d\n", __func__, kret);

        asm volatile("isb");
        asm volatile("dsb sy");
        asm volatile("tlbi vmalle1");
        asm volatile("ic iallu");
        asm volatile("dsb sy");
        asm volatile("isb");

        kret = vm_map_protect((void *)kmap, exec_test_addr,
                exec_test_addr + PAGE_SIZE, VM_PROT_READ | VM_PROT_EXECUTE, 0);

        kprintf("%s: vm_map_protect exec_test_addr %d\n", __func__, kret);

        /* asm volatile("isb"); */
        /* asm volatile("dsb sy"); */
        /* asm volatile("tlbi vmalle1"); */
        /* asm volatile("dsb sy"); */
        /* asm volatile("isb"); */

        /* /1* pmap_protect_options(*(void **)kernel_pmap, exec_test_addr, *1/ */
        /* /1*         exec_test_addr + PAGE_SIZE, VM_PROT_READ | VM_PROT_EXECUTE, *1/ */
        /* /1*         0, NULL); *1/ */

        /* asm volatile("isb"); */
        /* asm volatile("dsb sy"); */
        /* asm volatile("tlbi vmalle1"); */
        /* asm volatile("dsb sy"); */
        /* asm volatile("isb"); */

        kprintf("%s: exec test addr @ %#llx\n", __func__, exec_test_addr);

        struct vm_map_entry *vme = vme_for_ptr(kmap, exec_test_addr);

        if(vme)
            desc_vm_map_entry(vme);
        else
            kprintf("%s: exec test addr has no vme?\n", __func__);

        /* IOSleep(5000); */

        /* xnuspy_dump_ttes(exec_test_addr, 1); */

        /* *(uint64_t *)exec_test_addr = 0x4142434445464748; */
        /* kprintf("%s: wrote to exec test addr: %#llx\n", __func__, */
        /*         *(uint64_t *)exec_test_addr); */

        xnuspy_dump_ttes(exec_test_addr, 1);
        IOSleep(5000);

        void (*f2)(void) = (void (*)(void))exec_test_addr;
        f2();

        return metadata;

        /* kprotect(exec_test_addr, PAGE_SIZE, VM_PROT_READ | VM_PROT_EXECUTE); */


        /* pte_t *exec_test_addr_ptep = el1_ptep(exec_test_addr); */
        /* *exec_test_addr_ptep = (*exec_test_addr_ptep & ~ARM_PTE_APMASK) | */
        /*     ARM_PTE_AP(AP_RONA); */
        /* *exec_test_addr_ptep &= ~(ARM_PTE_PNX | ARM_PTE_NX); */
        /* asm volatile("isb"); */
        /* asm volatile("dsb ish"); */
        /* asm volatile("tlbi vmalle1"); */
        /* asm volatile("dsb ish"); */
        /* asm volatile("isb"); */
        /* *(uint32_t *)exec_test_addr = 0x41424344; */

        xnuspy_dump_ttes(exec_test_addr, 1);

        IOSleep(5000);
        *(uint32_t *)exec_test_addr = 0x41424344;

        /* void (*f)(void) = (void (*)(void))exec_test_addr; */
        /* f(); */

        kprintf("%s: copystart (%#llx):\n", __func__, copystart);
        xnuspy_dump_ttes(copystart, 0);
        kprintf("%s: shared address (%#llx):\n", __func__, shared_address);
        xnuspy_dump_ttes(shared_address, 1);

        /* pte_t *shared_address_ptep = el1_ptep(shared_address); */
        /* kprintf("%s: before: shared address pte @ %#llx pte: %#llx\n", __func__, */
        /*         shared_address_ptep, *shared_address_ptep); */

        /* struct vm_map_entry *shared_address_vme = vme_for_ptr(kmap, */
        /*         shared_address); */

        /* if(shared_address_vme) */
        /*     desc_vm_map_entry(shared_address_vme); */

        /* kret = vm_map_protect((void *)kmap, shared_address, shared_address + copysz, */
        /*         VM_PROT_READ | VM_PROT_EXECUTE, 0); */

        /* kprintf("%s: vm_map_protect on shared_address = %d\n", __func__, kret); */

        /* if(shared_address_vme) */
        /*     desc_vm_map_entry(shared_address_vme); */

        /* IOSleep(10000); */

        /* *(uint32_t *)shared_address = 0x41424344; */

        /* shared_address_ptep = el1_ptep(shared_address); */
        /* kprintf("%s: after: shared address pte @ %#llx pte: %#llx\n", __func__, */
        /*         shared_address_ptep, *shared_address_ptep); */

        /* kprotect((uint64_t)shared_address, copysz, VM_PROT_READ | VM_PROT_WRITE | */
        /*         VM_PROT_EXECUTE); */

        /* uint64_t fup = metadata->first_usercode_page->page; */

        /* uint64_t shared_address_phys = kvtophys(shared_address); */
        /* uint64_t shared_address_physpage = shared_address_phys & ~0x3fffuLL; */

        /* pte_t *fup_ptep = el1_ptep(first_usercode_page); */
        /* pte_t new_fup_pte = (*fup_ptep & ~0xfffffffff000uLL) | */
        /*     shared_address_physpage; */
        /* new_fup_pte &= ~(ARM_PTE_NX | ARM_PTE_PNX); */

        /* kwrite((uint64_t)fup_ptep, &new_fup_pte, sizeof(new_fup_pte)); */

        /* asm volatile("isb"); */
        /* asm volatile("dsb sy"); */
        /* asm volatile("tlbi vmalle1"); */
        /* asm volatile("dsb sy"); */
        /* asm volatile("isb"); */


        /* kret = vm_map_wire_kernel((void *)kmap, shared_address, copysz, */
        /*         VM_PROT_READ | VM_PROT_EXECUTE, VM_KERN_MEMORY_OSFMK, 0); */

        /* kprintf("%s: vm_map_wire_kernel returned %d\n", __func__, kret); */

        /* kprotect((uint64_t)shared_address, copysz, VM_PROT_READ | VM_PROT_WRITE | */
        /*         VM_PROT_EXECUTE); */

        /* asm volatile("isb"); */
        /* asm volatile("dsb sy"); */
        /* asm volatile("tlbi vmalle1"); */
        /* asm volatile("dsb sy"); */
        /* asm volatile("isb"); */


        /* uint32_t *cursor = (uint32_t *)shared_address; */
        /* /1* uint32_t *cursor = (uint32_t *)fup; *1/ */
        /* for(int i=0; i<20; i++){ */
        /*     kprintf("%s: %#llx:      %#x\n", __func__, (uint64_t)(cursor+i), */
        /*             cursor[i]); */
        /* } */

        /* /1* IOSleep(5000); *1/ */

        /* /1* *(uint32_t *)shared_address = 0x41424344; *1/ */
        /* /1* *cursor = 0x41424344; *1/ */
        /* void (*fxn)(void) = (void (*)(void))shared_address; */
        /* fxn(); */
    }

    kprintf("%s: ********RETURNING EARLY\n", __func__);
    return metadata;

    /* Perform the reflection */
    cur = freeset;

    uint64_t end = copystart + copysz;

    while(copystart < end){
        if(!cur){
            kprintf("%s: short copy???\n", __func__);
            common_kfree(metadata);
            return NULL;
        }

        uint64_t us = copystart;
        uint64_t ks = cur->page;

        /* __uint128_t *us = (__uint128_t *)copystart; */
        /* __uint128_t *ks = (__uint128_t *)cur->page; */
        /* __uint128_t *ke = (__uint128_t *)(cur->page + PAGE_SIZE); */

        /* kprintf("%s: us %#llx ks %#llx ke %#llx\n", __func__, us, ks, ke); */
        kprintf("%s: us %#llx ks %#llx\n", __func__, us, ks);

        pte_t *us_ptep = el0_ptep(us);
        pte_t *ks_ptep = el1_ptep(ks);

        uint64_t us_phys = uvtophys(us);
        uint64_t us_physpage = us_phys & ~0x3fffuLL;

        kprintf("%s: before: us pte %#llx ks pte %#llx us phys %#llx"
                " us physpage @ %#llx\n",
                __func__, *us_ptep, *ks_ptep, us_phys, us_physpage);

        /* Replace the output address of the current reflector page with
         * the physical page of the current user address */
        pte_t new_ks_pte = (*ks_ptep & ~0xfffffffff000uLL) | us_physpage;

        /* This will mark __DATA as executable as well but I don't care */
        new_ks_pte &= ~(ARM_PTE_NX | ARM_PTE_PNX);

        kprintf("%s: new ks pte == %#llx\n", __func__, new_ks_pte);

        kwrite(ks_ptep, &new_ks_pte, sizeof(new_ks_pte));

        asm volatile("isb");
        asm volatile("dsb sy");
        asm volatile("tlbi vmalle1");
        asm volatile("dsb sy");
        asm volatile("isb");

        /* while(ks < ke) */
        /*     *ks++ = *us++; */

        /* Modify the user PTE for this page to point to the kernel mapping.
         * This will effectively share data between the two */
        /* pte_t *us_ptep = el0_ptep(us); */
        /* pte_t *ks_ptep = el1_ptep(ks); */

        /* uint64_t ks_phys = kvtophys(ks); */
        /* uint64_t ks_physpage = ks_phys & ~0x3fffuLL; */

        /* kprintf("%s: before: us pte %#llx ks pte %#llx ks phys %#llx" */
        /*         " ks physpage @ %#llx\n", */
        /*         __func__, *us_ptep, *ks_ptep, ks_phys, ks_physpage); */

        copystart += PAGE_SIZE;
        cur = cur->next;
    }

    /* Take references on the map & pmap */
    /* XXX offset found in vm_map_create */
    int current_map_refcnt = *(int *)((uint8_t *)current_map + 0x108);
    *(int *)((uint8_t *)current_map + 0x108) = current_map_refcnt + 1000;
    current_map_refcnt = *(int *)((uint8_t *)current_map + 0x108);

    uint8_t *current_pmap = get_task_pmap(current_task());
    int current_pmap_refcnt = *(int *)(current_pmap + 0xd4);
    *(int *)(current_pmap + 0xd4) = current_pmap_refcnt + 1000;

    kprintf("%s: current_map refcnt = %d\n", __func__, current_map_refcnt);


    /* Modify the PTEs of the user __DATA segment to point to our copy of
     * __DATA. This way, changes to global variables at either exception
     * level are reflected in both. We are not sharing __TEXT because it's
     * almost always unchanged (and if the user is changing their own code
     * at runtime that's on them). */
    /* uint64_t dataoff = data_start - (uintptr_t)umh; */
    /* uint64_t data_kcopy = (uint64_t)metadata->first_usercode_page->page + dataoff; */

    /* while(data_start < data_end){ */
    /*     pte_t *uv_ptep = el0_ptep(data_start); */
    /*     /1* pte_t *kv_ptep = el1_ptep(data_kcopy); *1/ */

    /*     uint64_t phys = kvtophys(data_kcopy); */
    /*     uint64_t physpage = phys & ~0x3fffuLL; */

    /*     pte_t new_uv_pte = (*uv_ptep & ~0xfffffffff000uLL) | phys; */

    /*     kwrite(uv_ptep, &new_uv_pte, sizeof(new_uv_pte)); */

    /*     asm volatile("isb"); */
    /*     asm volatile("dsb sy"); */
    /*     asm volatile("tlbi vmalle1"); */
    /*     asm volatile("dsb sy"); */
    /*     asm volatile("isb"); */

    /*     data_start += PAGE_SIZE; */
    /*     data_kcopy += PAGE_SIZE; */
    /* } */

    return metadata;
}

/* This function finds a free xnuspy_tramp struct. If the calling process
 * has already installed more than one hook, then its __TEXT and __DATA
 * segments have already been copied onto the usercode pages. */
static int find_free_xnuspy_tramp(int *copy_segments,
        struct xnuspy_usercode_page **already_copied,
        uint64_t *num_already_used,
        struct xnuspy_tramp **out){
    struct xnuspy_tramp *cursor = xnuspy_tramp_page;
    void *ct = current_task();

    while((uint8_t *)cursor < xnuspy_tramp_page_end){
        /* Won't matter if this condition evaluates to true more than once
         * because the calling process only has one __TEXT and _DATA segment */
        if(cursor->metadata && cursor->metadata->owner == ct){
            *copy_segments = 0;

            *num_already_used = cursor->metadata->used_usercode_pages;
            
            /* Reference not taken on these pages yet, as failure
             * could still occur later */
            *already_copied = cursor->metadata->first_usercode_page;
        }

        if(xnuspy_tramp_free(cursor)){
            *out = cursor;
            return 0;
        }

        cursor++;
    }

    *copy_segments = 0;
    *num_already_used = 0;
    *already_copied = NULL;
    *out = NULL;

    return ENOSPC;
}

static int xnuspy_install_hook(uint64_t target, uint64_t replacement,
        uint64_t /* __user */ origp){
    kprintf("%s: called with target %#llx replacement %#llx origp %#llx\n",
            __func__, target, replacement, origp);
    int res = 0;

    /* kprintf("%s: *******TEST\n", __func__); */




    /* return 0; */

    /* slide target */
    target += kernel_slide;

    struct xnuspy_tramp *tramp = NULL;
    /* assume we need to copy __TEXT and __DATA */
    int copy_segments = 1;
    struct xnuspy_usercode_page *already_copied = NULL;
    uint64_t num_already_used = 0;

    res = find_free_xnuspy_tramp(&copy_segments, &already_copied,
            &num_already_used, &tramp);

    if(res){
        kprintf("%s: no free xnuspy_tramp structs\n", __func__);
        return res;
    }

    kprintf("%s: got free xnuspy_ctl struct @ %#llx\n", __func__, tramp);

    /* Build the trampoline to the replacement as well as the trampoline
     * that represents the original function */
    uint32_t orig_tramp_len = 0;

    generate_replacement_tramp(tramp->tramp);
    generate_original_tramp(target + 4, tramp->orig, &orig_tramp_len);

    /* copyout the original function trampoline before the replacement
     * is called */
    uint32_t *orig_tramp = tramp->orig;
    res = copyout(&orig_tramp, origp, sizeof(origp));

    /* A failure here is fine, as this xnuspy_tramp struct hasn't been
     * assigned an owner */
    if(res){
        kprintf("%s: copyout failed, returned %d\n", __func__, res);
        return res;
    }

    uint64_t tpidr_el1;
    asm volatile("mrs %0, tpidr_el1" : "=r" (tpidr_el1));

    /* struct pmap *pmap = get_task_pmap(current_task()); */

    /* kprintf("%s: pmap min %#llx max %#llx\n", __func__, pmap->min, pmap->max); */

    /* Offset found in mmap */
    struct _vm_map *current_map = *(struct _vm_map **)(tpidr_el1 + 0x320);

    kprintf("%s: current map %#llx\n", __func__, current_map);

    /* ... probably not possble */
    if(!current_map){
        kprintf("%s: current map is NULL??\n", __func__);
        return EFAULT;
    }

    kprintf("%s: start %#llx end %#llx\n", __func__, current_map->hdr.links.start,
            current_map->hdr.links.end);

    /* Mach header of the calling process */
    struct mach_header_64 *umh = (struct mach_header_64 *)current_map->hdr.links.start;
    /* Mach header of the calling process, but the kernel's copy of it */
    struct mach_header_64 *kmh;
    struct xnuspy_tramp_metadata *metadata;

    /* If we don't need to copy segments again, figure out the kernel
     * virtual address of the user's replacement and take a reference on each
     * usercode page */
    if(!copy_segments){
        kprintf("%s: don't need to copy segments\n", __func__);

        kmh = (struct mach_header_64 *)already_copied->page;

        kprintf("%s: umh @ %#llx kmh @ %#llx\n", __func__, umh, kmh);

        /* Metadata objects aren't reference counted, so we need to deep copy */
        metadata = common_kalloc(sizeof(*metadata));

        if(!metadata){
            kprintf("%s: failed to allocate metadata for this hook\n", __func__);
            return ENOMEM;
        }

        metadata->owner = current_task();
        metadata->first_usercode_page = already_copied;
        metadata->used_usercode_pages = num_already_used;
    }
    else{
        kprintf("%s: need to copy segments\n", __func__);

        metadata = copy_caller_segments(umh);

        if(!metadata){
            kprintf("%s: failed to allocate metadata for this hook\n", __func__);
            return ENOMEM;
        }

        kmh = (struct mach_header_64 *)metadata->first_usercode_page->page;
    }

    /* No failures are possible after this point, take a reference
     * on the usercode pages and hook the target function */
    struct xnuspy_usercode_page *cur = metadata->first_usercode_page;

    for(int i=0; i<metadata->used_usercode_pages; i++){
        if(!cur)
            break;

        cur->refcnt++;
        cur = cur->next;
    }

    tramp->metadata = metadata;

    uint64_t replacement_kva = find_replacement_kva(kmh, umh, replacement);

    kprintf("%s: replacment kva @ %#llx\n", __func__, replacement_kva);

    tramp->replacement = replacement_kva;

    desc_xnuspy_tramp(tramp, orig_tramp_len);

    /* IOSleep(10000); */

    /* uint32_t *cursor = (uint32_t *)replacement_kva; */
    /* for(int i=0; i<20; i++){ */
    /*     kprintf("%s: %#llx:      %#x\n", __func__, (uint64_t)(cursor+i), */
    /*             cursor[i]); */
    /* } */

    /* All the trampolines are set up, hook the target */
    /* kprotect(target, sizeof(uint32_t), VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE); */

    /* *(uint32_t *)target = assemble_b(target, (uint64_t)tramp->tramp); */

    /* asm volatile("dc cvau, %0" : : "r" (target)); */
    /* asm volatile("dsb ish"); */
    /* asm volatile("ic ivau, %0" : : "r" (target)); */
    /* asm volatile("dsb ish"); */
    /* asm volatile("isb sy"); */

    /* kprotect(target, sizeof(uint32_t), VM_PROT_READ | VM_PROT_EXECUTE); */

    return res;
}

static int xnuspy_uninstall_hook(uint64_t target){
    kprintf("%s: XNUSPY_UNINSTALL_HOOK is not implemented yet\n", __func__);
    return ENOSYS;
}

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

    /* kprintf("%s: got flavor %d\n", __func__, flavor); */
    /* kprintf("%s: kslide %#llx\n", __func__, kernel_slide); */
    /* kprintf("%s: xnuspy_ctl @ %#llx (unslid)\n", __func__, */
    /*         (uint64_t)xnuspy_ctl - kernel_slide); */
    /* kprintf("%s: xnuspy_ctl tramp page @ [%#llx,%#llx] (unslid)\n", __func__, */
    /*         (uint64_t)xnuspy_tramp_page - kernel_slide, */
    /*         (uint64_t)xnuspy_tramp_page_end - kernel_slide); */

    if(!xnuspy_init_flag)
        xnuspy_init();

    /* kprintf("%s: ********RETURNING\n", __func__); */
    /* return 0; */

    int res;

    switch(flavor){
        case XNUSPY_CHECK_IF_PATCHED:
            *retval = 999;
            return 0;
        case XNUSPY_INSTALL_HOOK:
            res = xnuspy_install_hook(uap->arg1, uap->arg2, uap->arg3);
            break;
        case XNUSPY_UNINSTALL_HOOK:
            res = xnuspy_uninstall_hook(uap->arg1);
            break;
            /* XXX below will be replaced with XNUSPY_MAKE_CALLABLE */
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
