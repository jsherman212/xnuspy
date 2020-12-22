#include <errno.h>
#include <fcntl.h>
#include <mach-o/loader.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char **argv){
    if(argc < 2){
        printf("Expected input file name\n");
        return 1;
    }

    if(argc < 3){
        printf("Expected output file name\n");
        return 1;
    }

    char *input = argv[1];

    int fd = open(input, O_RDONLY);

    if(fd == -1){
        printf("open: %s\n", strerror(errno));
        return 1;
    }

    struct stat st;

    if(stat(input, &st)){
        printf("stat: %s\n", strerror(errno));
        close(fd);
        return 1;
    }

    size_t fsz = st.st_size;

    void *fdata = mmap(NULL, fsz, PROT_READ, MAP_PRIVATE, fd, 0);

    close(fd);

    if(fdata == MAP_FAILED){
        printf("mmap: %s\n", strerror(errno));
        return 1;
    }

    struct mach_header_64 *mh = fdata;

    if(mh->magic != MH_MAGIC_64){
        printf("'%s' is not a mach-o file?\n", input);
        munmap(fdata, fsz);
        return 1;
    }

    struct load_command *lc = (struct load_command *)(mh + 1);

    uint32_t *text_cursor = NULL, *text_end = NULL;

    for(int i=0; i<mh->ncmds; i++){
        if(lc->cmd != LC_SEGMENT_64)
            goto nextcmd;

        struct segment_command_64 *sc64 = (struct segment_command_64 *)lc;

        if(strcmp(sc64->segname, "__TEXT") == 0){
            struct section_64 *sec64 = (struct section_64 *)(sc64 + 1);

            for(int k=0; k<sc64->nsects; k++){
                if(strcmp(sec64->sectname, "__text") == 0){
                    text_cursor = (uint32_t *)((uintptr_t)fdata + sec64->offset);
                    text_end = (uint32_t *)((uintptr_t)text_cursor + sec64->size);

                    break;
                }

                sec64++;
            }

            break;
        }

nextcmd:
        lc = (struct load_command *)((uintptr_t)lc + lc->cmdsize);
    }

    if(!text_cursor || !text_end){
        printf("Did not find __text section?\n");
        munmap(fdata, fsz);
        return 1;
    }

    char *output = argv[2];

    FILE *outp = fopen(output, "wb");

    if(!outp){
        printf("fopen: %s\n", strerror(errno));
        munmap(fdata, fsz);
        return 1;
    }

    while(text_cursor < text_end){
        uint8_t *op = (uint8_t *)text_cursor;
        fprintf(outp, "%02x%02x%02x%02x\n", op[3], op[2], op[1], *op);
        text_cursor++;
    }

    fflush(outp);
    fclose(outp);

    munmap(fdata, fsz);

    return 0;
}
