#include <mach-o/loader.h>
#include <stdint.h>

#include "../common/common.h"
#include "../common/pongo.h"

static uint64_t decode_uleb128(uint8_t **p, uint64_t *len){
    uint64_t val = 0;
    uint32_t shift = 0;

    const uint8_t *orig_p = *p;

    for(;;){
        uint8_t byte = *(*p)++;

        val |= ((byte & 0x7f) << shift);
        shift += 7;

        if(byte < 0x80)
            break;
    }

    *len = (uint64_t)(*p - orig_p);

    return val;
}

static uint8_t *get_lc_fxn_starts_table(uint64_t *size_out,
        uint64_t *first_fxn_out){
    struct segment_command_64 *__TEXT_EXEC =
        macho_get_segment(mh_execute_header, "__TEXT_EXEC");

    if(!__TEXT_EXEC)
        return NULL;

    struct segment_command_64 *__LINKEDIT =
        macho_get_segment(mh_execute_header, "__LINKEDIT");

    if(!__LINKEDIT)
        return NULL;

    struct linkedit_data_command *fxn_starts = NULL;
    struct load_command *lc = (struct load_command *)(mh_execute_header + 1);

    for(int i=0; i<mh_execute_header->ncmds; i++){
        if(lc->cmd == LC_FUNCTION_STARTS){
            fxn_starts = (struct linkedit_data_command *)lc;
            break;
        }

        lc = (struct load_command *)((uint8_t *)lc + lc->cmdsize);
    }

    if(!fxn_starts)
        return NULL;

    /* figure out offset into __LINKEDIT for function starts table */
    uint64_t table_fileoff = fxn_starts->dataoff;
    uint64_t linkedit_fileoff = __LINKEDIT->fileoff;
    uint64_t lc_fxn_starts_off = table_fileoff - linkedit_fileoff;

    *size_out = fxn_starts->datasize;
    *first_fxn_out = __TEXT_EXEC->vmaddr;

    return xnu_va_to_ptr(__LINKEDIT->vmaddr + lc_fxn_starts_off);;
}

uint64_t get_function_len(uint64_t fxn){
    uint64_t fxn_starts_table_size = 0;
    uint64_t first_fxn = 0;

    uint8_t *cursor = get_lc_fxn_starts_table(&fxn_starts_table_size, &first_fxn);

    if(!cursor)
        return 0;

    const uint8_t *end = cursor + fxn_starts_table_size;

    uint64_t cur_fxn_addr = first_fxn;

    for(int i=0; cursor < end; i++){
        /* unused */
        uint64_t len = 0;
        uint64_t prev_fxn_len = decode_uleb128(&cursor, &len);

        /* first function? its value is offset from __TEXT, ignore it */
        if(i == 0)
            continue;

        if(cur_fxn_addr == fxn)
            return prev_fxn_len;

        cur_fxn_addr += prev_fxn_len;
    }

    return 0;
}
