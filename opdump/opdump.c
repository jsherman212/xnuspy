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
           "    -a <name>       Create a C uint8_t array out of what's dumped.\n"
           "    -d              Dump __DATA\n"
           "    -i <name>       Input Mach-O file name\n"
           "    -o <name>       Output file name\n"
           "    -t              Dump __TEXT\n"
          );

    exit(1);
}

int main(int argc, char **argv){
    char *input = NULL, *output = NULL;
    int c_array = 0;
    char *c_array_name = NULL;
    int dump_text = 0;
    int dump_data = 0;

    int c;

    opterr = 0;

    while((c = getopt(argc, argv, "a:di:o:t")) != -1){
        switch(c){
            case 'a':
                c_array = 1;
                c_array_name = optarg;
                break;
            case 'd':
                dump_data = 1;
                break;
            case 'i':
                input = optarg;
                break;
            case 'o':
                output = optarg;
                break;
            case 't':
                dump_text = 1;
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

    if(c_array && !c_array_name){
        printf("Need name for C array\n");
        return 1;
    }

    if(!dump_data && !dump_text){
        printf("Need either -d or -t\n");
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

    /* __TEXT and __DATA are adjacent. But in case __DATA is
     * not present, we go until we hit the end of __TEXT */
    uint8_t *raw_cursor = NULL, *raw_end = NULL;

    for(int i=0; i<mh->ncmds; i++){
        if(lc->cmd != LC_SEGMENT_64)
            goto nextcmd;

        struct segment_command_64 *sc64 = (struct segment_command_64 *)lc;

        if(strcmp(sc64->segname, "__TEXT") == 0){
            struct section_64 *sec64 = (struct section_64 *)(sc64 + 1);

            for(int k=0; k<sc64->nsects; k++){
                if(dump_text && strcmp(sec64->sectname, "__text") == 0){
                    /* Make sure we start at the first function of __text and
                     * not the Mach-O header */
                    raw_cursor = (uint8_t *)((uintptr_t)fdata + sec64->offset);
                    raw_end = (uint8_t *)((uintptr_t)raw_cursor + sec64->size);

                    break;
                }

                sec64++;
            }
        }
        else if(dump_data && strcmp(sc64->segname, "__DATA") == 0){
            uint8_t *DATA_start = (uint8_t *)((uintptr_t)fdata + sc64->fileoff);

            if(!dump_text)
                raw_cursor = DATA_start;

            raw_end = (uint8_t *)(DATA_start + sc64->filesize);
        }

nextcmd:
        lc = (struct load_command *)((uintptr_t)lc + lc->cmdsize);
    }

    if(!raw_cursor){
        printf("Did not find start section\n");
        munmap(fdata, fsz);
        return 1;
    }

    FILE *outp = fopen(output, "wb");

    if(!outp){
        printf("fopen: %s\n", strerror(errno));
        munmap(fdata, fsz);
        return 1;
    }

    /* TODO: handle function starts */
    uint64_t nbytes = 0;

    if(c_array){
        fprintf(outp,
                "#ifndef %s_h\n"
                "#define %s_h\n"
                "static uint8_t g_%s[] = {\n",
                c_array_name, c_array_name, c_array_name);
    }

    while(raw_cursor < raw_end){
        if(!c_array){
            fwrite(raw_cursor, sizeof(uint8_t), 1, outp);
        }
        else{
            fprintf(outp, "\t0x%02x,\n", *raw_cursor);
            nbytes++;
        }

        raw_cursor++;
    }

    if(c_array){
        fprintf(outp, "};\n"
                "static const uint64_t g_%s_len = %lld;\n"
                "#endif", c_array_name, nbytes);
    }

    fflush(outp);
    fclose(outp);

    munmap(fdata, fsz);

    return 0;
}
