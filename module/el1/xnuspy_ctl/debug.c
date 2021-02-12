#include <mach/mach.h>
#include <stdbool.h>
#include <stdint.h>

#include "../../common/xnuspy_structs.h"

#include "debug.h"
#include "externs.h"
#include "mem.h"

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
    SPYDBG("Mapping memory entry: %#llx\n", om->memory_entry);
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

static void _desc_xnuspy_mapping(struct xnuspy_mapping *m){
    SPYDBG("\tMapping metadata refcnt: %lld\n", m->refcnt);
    SPYDBG("\tMemory entry: %#llx\n", m->memory_entry);
    SPYDBG("\tUserspace version of this mapping: %#llx\n", m->mapping_addr_uva);
    SPYDBG("\tShared mapping addr/size: %#llx/%#llx\n", m->mapping_addr_kva,
            m->mapping_size);

    SPYDBG("\tDeath callback: ");

    if(m->death_callback)
        SPYDBG("%#llx\n", m->death_callback);
    else
        SPYDBG("none\n");
}

void desc_xnuspy_mapping(struct xnuspy_mapping *m){
    SPYDBG("Mapping metadata refcnt: %lld\n", m->refcnt);
    SPYDBG("Memory entry: %#llx\n", m->memory_entry);
    SPYDBG("Userspace version of this mapping: %#llx\n", m->mapping_addr_uva);
    SPYDBG("Shared mapping addr/size: %#llx/%#llx\n", m->mapping_addr_kva,
            m->mapping_size);

    SPYDBG("Death callback: ");

    if(m->death_callback)
        SPYDBG("%#llx\n", m->death_callback);
    else
        SPYDBG("none\n");
}

void desc_xnuspy_mapping_metadata(struct xnuspy_mapping_metadata *mm){
    SPYDBG("Owner: %d\n", mm->owner);
    SPYDBG("Mappings:\n");

    if(SLIST_EMPTY(&mm->mappings)){
        SPYDBG("none\n");
        return;
    }

    struct slist_entry *entry;

    SLIST_FOREACH(entry, &mm->mappings, link){
        struct xnuspy_mapping *m = entry->elem;
        _desc_xnuspy_mapping(m);
        SPYDBG("\n");
    }
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
