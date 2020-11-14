#ifndef COMMON
#define COMMON

#include <mach-o/loader.h>

int atoi(const char *);
int isdigit(int);

char *strcpy(char *, const char *);

__attribute__ ((noreturn)) void xnuspy_fatal_error(void);

extern struct mach_header_64 *mh_execute_header;
extern uint64_t kernel_slide;

extern void (*next_preboot_hook)(void);

#define PAGE_SIZE                   (0x4000)

#define iOS_13_x                    (19)
#define iOS_14_x                    (20)

#define VERSION_BIAS                iOS_13_x

#endif
