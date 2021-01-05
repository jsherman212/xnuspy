#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#include "common/common.h"
#include "common/pongo.h"

/* XXX after done move this logic to el3's pf directory */
#include "el3/kpp_patches.h"

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
     * them in the future
     */
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

    if(pwn_seprom){
        /* printf("%s: NOT PWNING SEPROM FOR TESTING PURPOSES\n", __func__); */
        queue_rx_string("sep auto\n");
    }
    else{
        /* Non-KTRR hardware, take this time to patch KPP. We've already
         * uploaded the patches */

        volatile uint64_t *iorvbar = (volatile uint64_t *)0x202050000;
        uint64_t kppphys = *iorvbar & 0xfffffffff;
        printf("%s: kpp is @ %#llx (phys)\n", __func__, kppphys);

        map_range(0xc10000000, kppphys, 0xc000, 3, 0, true);

        uint8_t *kppbase = (uint8_t *)0xc10000000;
        uint32_t *kpppatch0 = (uint32_t *)(kppbase + 0x5954);

        for(int i=0; i<kpp_patches_num_patches; i++){
            *kpppatch0++ = kpp_patches[i];
        }

        kpppatch0 = (uint32_t *)(kppbase + 0x5954);
        DumpMemory(kpppatch0, kpppatch0, kpp_patches_num_patches * sizeof(uint32_t));

        /* uint64_t *kppKernEntry = (uint64_t *)(kppbase + 0x */

        /* kpppatch0 = (uint32_t *)(kppbase + 0x6460); */
        /* *kpppatch0 = 0xd503201f; */

        queue_rx_string("xfb\n");

        /* DumpMemory(loader_xfer_recv_data, loader_xfer_recv_data, */
        /*         loader_xfer_recv_size); */
        /* printf("%s: recv size %#x\n", __func__, loader_xfer_recv_size); */
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

/* Because there is no way of initializing the ramdisk KPF makes besides
 * with bootx. Only used on <=A9 */
static void xnuspy_loadrd(const char *cmd, char *args){
    // XXX
    /* return; */
    if(!ramdisk_size){
        printf("xnuspy: ramdisk hasn't\n"
                "  been initialized yet?\n");

        xnuspy_fatal_error();
    }

    printf("%s: entrypoint %p\n", __func__, gEntryPoint);

    dt_node_t *memory_map = dt_find(gDeviceTree, "memory-map");

    if(!memory_map){
        printf("xnuspy: no memory map?\n");
        xnuspy_fatal_error();
    }

    struct memmap *map = dt_alloc_memmap(memory_map, "RAMDisk");

    if(!map){
        printf("xnuspy: dt_alloc_memmap failed\n");
        xnuspy_fatal_error();
    }

    void *rd_static_buf = alloc_static(ramdisk_size);

    if(!rd_static_buf){
        printf("xnuspy: alloc_static for\n"
                "  ramdisk buf failed\n");
        xnuspy_fatal_error();
    }

    printf("allocated static region for rdsk: %p, sz: %#x\n", rd_static_buf,
            ramdisk_size);

    memcpy(rd_static_buf, ramdisk_buf, ramdisk_size);

    struct memmap md0map;
    md0map.addr = ((uint64_t)rd_static_buf) + 0x800000000 - kCacheableView;
    md0map.size = ramdisk_size;

    memcpy(map, &md0map, sizeof(md0map));

    /* printf("%#x\n", socnum); */

    /* dt_node_t *sep = dt_find(gDeviceTree, "sep"); */
    /* uint32_t *xnu_wants_booted = dt_prop(sep, "sepfw-booted", NULL); */
    /* volatile uint32_t *tz_regbase = (volatile uint32_t *)0x200000480; */

    /* printf("%s: sep %p xnu_wants_booted %p\n", __func__, sep, xnu_wants_booted); */

    /* if(xnu_wants_booted){ */
    /*     printf("%s: xnu wants booted? %d\n", __func__, *xnu_wants_booted); */
    /* } */

    /* printf("%s: tz0 locked? %d\n", __func__, tz_regbase[4]); */

    /* uint64_t addr = socnum == 0x8960 ? 0x200000910 : 0x200000490; */

    /* printf("%d\n", *(volatile uint32_t *)addr); */

    /* if(tz_regbase[0]) */
    /*     tz_regbase[4] = 1; */

    /* if(tz_regbase[2]) */
    /*     tz_regbase[5] = 1; */

    /* printf("%d\n", *(volatile uint32_t *)addr); */

    printf("%s: loader_xfer_recv_count %#x data %p\n", __func__,
            loader_xfer_recv_count, loader_xfer_recv_data);

    void *el3_imgdata = alloc_static(loader_xfer_recv_count);

    printf("%s: el3_imgdata %p\n", __func__, el3_imgdata);
    
    if(!el3_imgdata){
        printf("xnuspy: failed allocing\n"
                "  static region for EL3\n");

        xnuspy_fatal_error();
    }

    volatile uint64_t *CPU0_IORVBar = (volatile uint64_t *)0x202050000;
    uint64_t kppphys = *CPU0_IORVBar & 0xfffffffff;
    printf("%s: kpp is @ %#llx (phys)\n", __func__, kppphys);

    map_range(0xc10000000, kppphys, 0xc000, 3, 0, true);

    uint8_t *kpp = (uint8_t *)0xc10000000;

    for(int i=0; i<loader_xfer_recv_count; i++){
        kpp[i] = loader_xfer_recv_data[i];
    }

    printf("%s: overwrote kpp\n", __func__);

    /* memcpy(el3_imgdata, loader_xfer_recv_data, loader_xfer_recv_count); */
    /* loader_xfer_recv_data = el3_imgdata; */
    /* /1* XXX For iPhone SE 2016 14.3 kpp *1/ */
    /* /1* loader_xfer_recv_data = (uint8_t *)((uintptr_t)el3_imgdata + 0x2804); *1/ */
    /* DumpMemory(loader_xfer_recv_data, loader_xfer_recv_data, 0x100); */


    /* volatile uint64_t *IORVBar = (volatile uint64_t *)(0x200000000uLL + 0x205000); */
    /* printf("%s: IORVBar: %#llx %#llx\n", __func__, IORVBar, *IORVBar); */

    /* for(;;); */

    /* _bsd_init, doesn't seem to be getting called */
    /* uint32_t *p = xnu_va_to_ptr(0xFFFFFFF0074F467C + kernel_slide); */
    /* *p = 0xd4200000; */

    /* monitor_call smc */
    /* BRK 0 phone just doesn't do anything */
    /* NOP: ? */
    /* p = xnu_va_to_ptr(0xFFFFFFF00710BD10 + kernel_slide); */
    /* *p = 0xd4200000; */

    /* ramdisk_size = 0; */

    queue_rx_string("xfb\n");
    /* queue_rx_string("bootux\n"); */
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
    command_register("xnuspy-loadrd", "load the ramdisk KPF initializes",
            xnuspy_loadrd);
    command_register("xnuspy-prep", "get all offsets", xnuspy_prep);
}

const char *module_name = "xnuspy";

struct pongo_exports exported_symbols[] = {
    { .name = 0, .value = 0 }
};
