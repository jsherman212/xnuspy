#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#include "common/common.h"
#include "common/pongo.h"

#include "el3/kpp.h"

#include "pf/offsets.h"
#include "pf/pfs.h"

#include "preboot_hook.h"

static void DumpMemory(void *startaddr, void *data, size_t size){
    char ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    int putloc = 0;
    void *curaddr = startaddr;
    for (i = 0; i < size; ++i) {
        if(!putloc){
            if(startaddr != (void *)-1){
                printf("%#llx: ", (uint64_t)curaddr);
                curaddr += 0x10;
            }

            putloc = 1;
        }

        printf("%02X ", ((unsigned char*)data)[i]);
        if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
            ascii[i % 16] = ((unsigned char*)data)[i];
        } else {
            ascii[i % 16] = '.';
        }
        if ((i+1) % 8 == 0 || i+1 == size) {
            printf(" ");
            if ((i+1) % 16 == 0) {
                printf("| %s \n", ascii);
                putloc = 0;
            } else if (i+1 == size) {
                ascii[(i+1) % 16] = '\0';
                if ((i+1) % 16 <= 8) {
                    printf(" ");
                }
                for (j = (i+1) % 16; j < 16; ++j) {
                    printf("  ");
                }
                printf("| %s \n", ascii);
                putloc = 0;
            }
        }
    }
}

uint64_t g_kern_version_major = 0;

static uint32_t g_kern_version_minor = 0;
static uint32_t g_kern_version_revision = 0;

static bool getkernelv_callback(xnu_pf_patch_t *patch, void *cacheable_stream){
    xnu_pf_disable_patch(patch);

    char *version = cacheable_stream;

    /* on all kernels, major, minor, and version are no larger than 2 chars */
    char major_s[3] = {0};
    char minor_s[3] = {0};
    char revision_s[3] = {0};

    /* skip ahead until we get a digit */
    while(!isdigit(*version))
        version++;
    
    for(int i=0; *version != '.'; i++, version++)
        major_s[i] = *version;

    version++;

    for(int i=0; *version != '.'; i++, version++)
        minor_s[i] = *version;

    version++;

    for(int i=0; *version != ':'; i++, version++)
        revision_s[i] = *version;

    /* currently, I only use major, but I get the rest in case I need
     * them in the future */
    g_kern_version_major = atoi(major_s);
    g_kern_version_minor = atoi(minor_s);
    g_kern_version_revision = atoi(revision_s);

    bool pwn_seprom = (g_kern_version_major == iOS_14_x) &&
        (socnum == 0x8010 || socnum == 0x8011 || socnum == 0x8015);

    if(g_kern_version_major == iOS_13_x)
        printf("xnuspy: iOS 13.x detected\n");
    else if(g_kern_version_major == iOS_14_x)
        printf("xnuspy: iOS 14.x detected\n");
    else{
        printf("xnuspy: error: unknown\n"
                "  major %lld\n",
                g_kern_version_major);

        xnuspy_fatal_error();
    }

    /* No need to exploit SEPROM on 14.x A9(x) and below, which conveniently
     * is the only KPP chip that xnuspy supports */
    if(pwn_seprom)
        queue_rx_string("sep auto\n");
    else if(socnum == 0x8000 || socnum == 0x8001 || socnum == 0x8003){
        patch_kpp();
        /* XXX REMOVE WHEN DONE */
        /* queue_rx_string("xfb\n"); */
    }

    return true;
}

static void xnuspy_getkernelv(const char *cmd, char *args){
    xnu_pf_patchset_t *patchset = xnu_pf_patchset_create(XNU_PF_ACCESS_8BIT);

    xnu_pf_range_t *__TEXT___const = xnu_pf_section(mh_execute_header, "__TEXT",
            "__const");

    if(!__TEXT___const){
        puts("xnuspy: xnu_pf_section");
        puts("   returned NULL for");
        puts("   __TEXT:__const?");

        xnuspy_fatal_error();
    }

    const char *vers = "Darwin Kernel Version ";

    /* hardcoded so clang does not generate ___chkstk_darwin calls */
    uint64_t ver[21];
    uint64_t masks[21];

    for(int i=0; i<21; i++){
        ver[i] = vers[i];
        masks[i] = 0xff;
    }

    uint64_t count = sizeof(ver) / sizeof(*ver);

    xnu_pf_maskmatch(patchset, "kernel version finder", ver, masks, count,
            false, getkernelv_callback);
    xnu_pf_emit(patchset);
    xnu_pf_apply(__TEXT___const, patchset);
    xnu_pf_patchset_destroy(patchset);
}

#define MAXKEXTRANGE MAXPF

struct kextrange {
    xnu_pf_range_t *range;
    char *kext;
    char *seg;
    char *sect;
};

/* purpose of this function is to add patchfinder ranges for kexts in such
 * a way that there are no duplicates in `*ranges` */
static void add_kext_range(struct kextrange **ranges, const char *kext,
        const char *seg, const char *sect, size_t *nkextranges_out){
    size_t nkextranges = *nkextranges_out;

    if(nkextranges == MAXKEXTRANGE)
        return;

    /* first, check if this kext is already present */
    for(size_t i=0; i<nkextranges; i++){
        struct kextrange *kr = ranges[i];

        /* kext will never be NULL, otherwise, this function would have
         * no point */
        if(strcmp(kr->kext, kext) == 0){
            /* same segment? It will be the same range even if the section differs */
            if(seg && strcmp(kr->seg, seg) == 0)
                return;

            if(sect && strcmp(kr->sect, sect) == 0)
                return;
        }
    }

    /* new kext, make its range */
    struct mach_header_64 *mh = xnu_pf_get_kext_header(mh_execute_header, kext);

    if(!mh){
        printf( "xnuspy: could not\n"
                "   get Mach header for\n"
                "   %s\n", kext);

        xnuspy_fatal_error();
    }

    struct kextrange *kr = malloc(sizeof(struct kextrange));
    memset(kr, 0, sizeof(*kr));

    if(sect)
        kr->range = xnu_pf_section(mh, (void *)seg, (char *)sect);
    else
        kr->range = xnu_pf_segment(mh, (void *)seg);

    size_t kextl = 0, segl = 0, sectl = 0;
    
    kextl = strlen(kext);

    char *kn = malloc(kextl + 1);
    strcpy(kn, kext);
    kn[kextl] = '\0';
    kr->kext = kn;

    if(seg){
        segl = strlen(seg);
        char *segn = malloc(segl + 1);
        strcpy(segn, seg);
        segn[segl] = '\0';
        kr->seg = segn;
    }

    if(sect){
        sectl = strlen(sect);
        char *sectn = malloc(sectl + 1);
        strcpy(sectn, sect);
        sectn[sectl] = '\0';
        kr->sect = sectn;
    }

    ranges[nkextranges] = kr;
    *nkextranges_out = nkextranges + 1;
}

static void xnuspy_prep(const char *cmd, char *args){
    /* all the patchfinders in pf/pfs.h currently do 32 bit */
    xnu_pf_patchset_t *patchset = xnu_pf_patchset_create(XNU_PF_ACCESS_32BIT);

    size_t nkextranges = 0;
    struct kextrange **kextranges = malloc(sizeof(struct kextrange *) * MAXKEXTRANGE);

    for(int i=0; !PFS_END(g_all_pfs[i]); i++){
        struct pf *pf = &g_all_pfs[i][g_kern_version_major - VERSION_BIAS];

        if(IS_PF_UNUSED(pf))
            continue;

        const char *pf_kext = pf->pf_kext;
        const char *pf_segment = pf->pf_segment;
        const char *pf_section = pf->pf_section;

        if(pf_kext){
            add_kext_range(kextranges, pf_kext, pf_segment, pf_section,
                    &nkextranges);
        }

        xnu_pf_maskmatch(patchset, (char *)pf->pf_name, pf->pf_matches,
                pf->pf_masks, pf->pf_mmcount, false, pf->pf_callback);
    }

    xnu_pf_emit(patchset);

    xnu_pf_range_t *__TEXT_EXEC = xnu_pf_segment(mh_execute_header, "__TEXT_EXEC");
    xnu_pf_apply(__TEXT_EXEC, patchset);

    for(size_t i=0; i<nkextranges; i++){
        xnu_pf_range_t *range = kextranges[i]->range;
        xnu_pf_apply(range, patchset);
    }

    xnu_pf_patchset_destroy(patchset);
}

void module_entry(void){
    puts("xnuspy: loaded!");

    mh_execute_header = xnu_header();
    kernel_slide = xnu_slide_value(mh_execute_header);

    next_preboot_hook = preboot_hook;
    preboot_hook = xnuspy_preboot_hook;

    command_register("xnuspy-getkernelv", "get kernel version", xnuspy_getkernelv);
    command_register("xnuspy-prep", "get all offsets", xnuspy_prep);
}

const char *module_name = "xnuspy";

struct pongo_exports exported_symbols[] = {
    { .name = 0, .value = 0 }
};
