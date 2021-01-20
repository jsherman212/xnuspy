#include <mach/mach.h>
#include <stdbool.h>
#include <stdint.h>

#include "../../common/xnuspy_structs.h"

#include "debug.h"
#include "externs.h"
#include "mem.h"

static void _desc_xnuspy_reflector_page(const char *indent,
        struct xnuspy_reflector_page *p){
    SPYDBG("%sThis reflector page is @ %#llx. "
            "next: %#llx page %#llx [phys: %#llx] used: %d\n", indent,
            (uint64_t)p, p->next, p->page, kvtophys(p->page), p->used);
}

void desc_freelist(void){
    lck_rw_lock_shared(xnuspy_rw_lck);

    SPYDBG("[Freelist] ");

    if(STAILQ_EMPTY(&freelist)){
        lck_rw_done(xnuspy_rw_lck);
        SPYDBG("Empty\n");
        return;
    }

    SPYDBG("FRONT: ");

    struct stailq_entry *entry;

    STAILQ_FOREACH(entry, &freelist, link)
        SPYDBG("%#llx <- ", entry->elem);

    SPYDBG("\n");

    lck_rw_done(xnuspy_rw_lck);
}

void desc_orphan_mapping(struct orphan_mapping *om){
    if(!om){
        SPYDBG("%s: NULL\n", __func__);
        return;
    }

    SPYDBG("This orphan mapping is at %#llx\n", om);
    SPYDBG("Mapping addr: %#llx\n", om->mapping_addr);
    SPYDBG("Mapping size: %#llx\n", om->mapping_size);
    SPYDBG("Mapping memory object: %#llx\n", om->memory_object);
    SPYDBG("# of used reflector pages: %lld\n", om->used_reflector_pages);
    SPYDBG("Reflector pages:\n");

    struct xnuspy_reflector_page *cur = om->first_reflector_page;

    for(int i=0; i<om->used_reflector_pages; i++){
        if(!cur)
            break;

        _desc_xnuspy_reflector_page("    ", cur);
        cur = cur->next;
    }
}

/* XXX ONLY meant to be called from xnuspy_gc_thread, hence the lack
 * of locking. */
void desc_unmaplist(void){
    SPYDBG("[Unmaplist] ");

    if(STAILQ_EMPTY(&unmaplist)){
        SPYDBG("Empty\n");
        return;
    }

    SPYDBG("FRONT: ");

    struct stailq_entry *entry;

    STAILQ_FOREACH(entry, &unmaplist, link)
        SPYDBG("%#llx <- ", entry->elem);

    SPYDBG("\n");
}

void desc_usedlist(void){
    lck_rw_lock_shared(xnuspy_rw_lck);

    SPYDBG("[Usedlist] ");

    if(STAILQ_EMPTY(&usedlist)){
        lck_rw_done(xnuspy_rw_lck);
        SPYDBG("Empty\n");
        return;
    }

    struct stailq_entry *entry;

    STAILQ_FOREACH(entry, &usedlist, link)
        SPYDBG("%#llx -> ", entry->elem);

    SPYDBG("\n");

    lck_rw_done(xnuspy_rw_lck);
}

void desc_xnuspy_mapping_metadata(struct xnuspy_mapping_metadata *mm){
    SPYDBG("Mapping metadata refcnt: %lld\n", mm->refcnt);
    SPYDBG("Owner: %d\n", mm->owner);
    SPYDBG("# of used reflector pages: %lld\n", mm->used_reflector_pages);
    SPYDBG("Reflector pages:\n");

    struct xnuspy_reflector_page *cur = mm->first_reflector_page;

    for(int i=0; i<mm->used_reflector_pages; i++){
        if(!cur)
            break;

        _desc_xnuspy_reflector_page("    ", cur);
        cur = cur->next;
    }

    SPYDBG("Memory object: %#llx\n", mm->memory_object);
    SPYDBG("Shared mapping addr/size: %#llx/%#llx\n", mm->mapping_addr,
            mm->mapping_size);

    SPYDBG("Death callback: ");

    if(mm->death_callback)
        SPYDBG("%#llx\n", mm->death_callback);
    else
        SPYDBG("none\n");
}

void desc_xnuspy_reflector_page(struct xnuspy_reflector_page *p){
    _desc_xnuspy_reflector_page("", p);
}

void desc_xnuspy_tramp(struct xnuspy_tramp *t, uint32_t orig_tramp_len){
    SPYDBG("This xnuspy_tramp is @ %#llx\n", (uint64_t)t);
    SPYDBG("Replacement: %#llx\n", t->replacement);
    
    SPYDBG("Replacement trampoline:\n");

    for(int i=0; i<sizeof(t->tramp)/sizeof(t->tramp[0]); i++)
        SPYDBG("\ttramp[%d]    %#x\n", i, t->tramp[i]);

    SPYDBG("Original trampoline:\n");

    for(int i=0; i<orig_tramp_len; i++)
        SPYDBG("\ttramp[%d]    %#x\n", i, t->orig[i]);

    if(!t->tramp_metadata)
        SPYDBG("NULL tramp metadata\n");
    else{
        SPYDBG("Hooked function: %#llx [unslid=%#llx]\n",
                t->tramp_metadata->hooked,
                t->tramp_metadata->hooked - kernel_slide);
        SPYDBG("Original instruction: %#x\n", t->tramp_metadata->orig_instr);
    }

    if(!t->mapping_metadata)
        SPYDBG("NULL mapping metadata\n");
    else
        desc_xnuspy_mapping_metadata(t->mapping_metadata);
}
