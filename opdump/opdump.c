#include <errno.h>
#include <fcntl.h>
#include <mach-o/loader.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

static void usage(void){
    printf("Usage:\n"
           "    -i              Input Mach-O file name\n"
           "    -o              Output file name\n"
           "    -r              Create a raw image (dump __TEXT and __DATA)\n"
           "    -t              Dump opcodes from __text, separated by newlines\n"
          );

    exit(1);
}

int main(int argc, char **argv){
    char *input = NULL, *output = NULL;
    int raw_image = 0;
    int opcode_dump = 0;

    int c;

    opterr = 0;

    while((c = getopt(argc, argv, "i:o:rt")) != -1){
        switch(c){
            case 'i':
                input = optarg;
                break;
            case 'o':
                output = optarg;
                break;
            case 'r':
                raw_image = 1;
                break;
            case 't':
                opcode_dump = 1;
                break;
            default:
                usage();
        };
    }

    if(!input){
        printf("Expected input file name\n");
        return 1;
    }

    if(!output){
        printf("Expected output file name\n");
        return 1;
    }

    if(!raw_image && !opcode_dump){
        printf("Need either -r or -t\n");
        return 1;
    }

    if(raw_image && opcode_dump){
        printf("Cannot have both -r and -t\n");
        return 1;
    }

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

    /* For opcode dump */
    uint32_t *text_cursor = NULL, *text_end = NULL;

    /* For raw image, __TEXT and __DATA are adjacent. But in case __DATA is
     * not present, we go until we hit the end of __TEXT */
    uint64_t *raw_cursor = NULL, *raw_end = NULL;

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

                    /* Make sure we start at the first function of __text and
                     * not the Mach-O header */
                    raw_cursor = (uint64_t *)text_cursor;
                    raw_end = (uint64_t *)text_end;

                    break;
                }

                sec64++;
            }
        }
        else if(strcmp(sc64->segname, "__DATA") == 0){
            uint8_t *DATA_start = (uint8_t *)((uintptr_t)fdata + sc64->fileoff);
            raw_end = (uint64_t *)(DATA_start + sc64->filesize);
        }

nextcmd:
        lc = (struct load_command *)((uintptr_t)lc + lc->cmdsize);
    }

    /* One of these being NULL implies raw_cursor is also NULL */
    if(!text_cursor || !text_end){
        printf("Did not find __text section?\n");
        munmap(fdata, fsz);
        return 1;
    }

    FILE *outp = fopen(output, "wb");

    if(!outp){
        printf("fopen: %s\n", strerror(errno));
        munmap(fdata, fsz);
        return 1;
    }

    if(opcode_dump){
        while(text_cursor < text_end){
            uint8_t *op = (uint8_t *)text_cursor;
            fprintf(outp, "%02x%02x%02x%02x\n", op[3], op[2], op[1], *op);
            text_cursor++;
        }
    }
    else{
        while(raw_cursor < raw_end){
            fwrite(raw_cursor, sizeof(uint64_t), 1, outp);
            raw_cursor++;
        }
    }

    fflush(outp);
    fclose(outp);

    munmap(fdata, fsz);

    return 0;
}
