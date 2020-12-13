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
#undef PAGE_SIZE

#define PAGE_SIZE                   (0x4000)

#define VM_KERN_MEMORY_OSFMK        (1)

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
MARK_AS_KERNEL_OFFSET kern_return_t (*kernel_memory_allocate)(void *map, uint64_t *addrp,
        vm_size_t size, vm_offset_t mask, int flags, int tag);
MARK_AS_KERNEL_OFFSET void *kernel_map;

MARK_AS_KERNEL_OFFSET kern_return_t (*vm_map_wire_kernel)(void *map,
        uint64_t start, uint64_t end, vm_prot_t prot, int tag, int user_wire);

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

struct vm_map_entry {
    struct vm_map_links links;
#define vme_prev		links.prev
#define vme_next		links.next
#define vme_start		links.start
#define vme_end			links.end
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
 * of the pages we reserved before booting XNU. Lame, but safe. Swapping
 * translation table base registers and changing PTE OutputAddress'es
 * was hacky.
 *
 * On success, returns metadata for hooks installed by this process.
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

    struct xnuspy_tramp_metadata *metadata = common_kalloc(sizeof(*metadata));

    if(!metadata)
        return NULL;

    metadata->owner = current_task();
    /* Don't take a reference yet, because failures are still possible */
    metadata->first_usercode_page = freeset;
    metadata->used_usercode_pages = npages;
    /* Includes ASLR slide */
    /* metadata->umh = umh; */

    /* Finally, perform the copy */
    cur = freeset;

    uint64_t end = copystart + copysz;

    uint64_t tpidr_el1;
    asm volatile("mrs %0, tpidr_el1" : "=r" (tpidr_el1));
    struct _vm_map *current_map = *(struct _vm_map **)(tpidr_el1 + 0x320);

    asm volatile("dsb sy");
    asm volatile("isb");

    /* kern_return_t kret = vm_map_wire_kernel(current_map, copystart, end, */
    /*         VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE, 1, 1); */

    uint64_t text_start = text->vmaddr + aslr_slide;
    uint64_t text_end = text_start + text->vmsize;
    kern_return_t kret = vm_map_wire_kernel(current_map, text_start, text_end,
            text->initprot, VM_KERN_MEMORY_OSFMK, 1);
    kprintf("%s: vm_map_wire_kernel text kret %d\n", __func__, kret);

    uint64_t data_start = data->vmaddr + aslr_slide;
    uint64_t data_end = data_start + data->vmsize;

    kret = vm_map_wire_kernel(current_map, data_start, data_end, data->initprot,
            VM_KERN_MEMORY_OSFMK, 1);
    kprintf("%s: vm_map_wire_kernel data kret %d\n", __func__, kret);

    while(copystart < end){
        if(!cur){
            kprintf("%s: short copy???\n", __func__);
            common_kfree(metadata);
            return NULL;
        }

        __uint128_t *us = (__uint128_t *)copystart;
        __uint128_t *ks = (__uint128_t *)cur->page;
        __uint128_t *ke = (__uint128_t *)(cur->page + PAGE_SIZE);

        kprintf("%s: us %#llx ks %#llx ke %#llx\n", __func__, us, ks, ke);

        pte_t *us_ptep = el0_ptep(us);
        pte_t *ks_ptep = el1_ptep(ks);

        uint64_t us_phys = uvtophys(us);
        uint64_t us_physpage = us_phys & ~0x3fffuLL;

        kprintf("%s: before: us pte %#llx ks pte %#llx us phys %#llx"
                " us physpage @ %#llx\n",
                __func__, *us_ptep, *ks_ptep, us_phys, us_physpage);

        pte_t new_ks_pte = (*ks_ptep & ~0xfffffffff000uLL) | us_physpage;
        new_ks_pte &= ~(ARM_PTE_NX | ARM_PTE_PNX);

        kprintf("%s: new ks pte == %#llx\n", __func__, new_ks_pte);

        kwrite(ks_ptep, &new_ks_pte, sizeof(new_ks_pte));

        asm volatile("isb");
        asm volatile("dsb sy");
        asm volatile("tlbi vmalle1");
        asm volatile("dsb sy");
        asm volatile("isb");

        /* Safe, PAN is disabled */
        /* while(ks < ke) */
        /*     *ks++ = *us++; */

        copystart += PAGE_SIZE;
        cur = cur->next;
    }

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

    uint32_t *cursor = (uint32_t *)replacement_kva;
    for(int i=0; i<20; i++){
        kprintf("%s: %#llx:      %#x\n", __func__, (uint64_t)(cursor+i),
                cursor[i]);
    }

    /* All the trampolines are set up, hook the target */
    kprotect(target, sizeof(uint32_t), VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);

    *(uint32_t *)target = assemble_b(target, (uint64_t)tramp->tramp);

    asm volatile("dc cvau, %0" : : "r" (target));
    asm volatile("dsb ish");
    asm volatile("ic ivau, %0" : : "r" (target));
    asm volatile("dsb ish");
    asm volatile("isb sy");

    kprotect(target, sizeof(uint32_t), VM_PROT_READ | VM_PROT_EXECUTE);

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
