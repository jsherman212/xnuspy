#ifndef COMMON
#define COMMON

#include <mach-o/loader.h>
#include <stdbool.h>

bool is_14_5_and_above__pongo(void);

int atoi(const char *);
int isdigit(int);

char *strcpy(char *, const char *);
char *strstr(const char *, const char *);

__attribute__ ((noreturn)) void xnuspy_fatal_error(void);

extern struct mach_header_64 *mh_execute_header;
extern uint64_t kernel_slide;

extern void (*next_preboot_hook)(void);

#define iOS_13_x                    (19)
#define iOS_14_x                    (20)
#define iOS_15_x                    (21)

#define VERSION_BIAS                iOS_13_x

#endif
