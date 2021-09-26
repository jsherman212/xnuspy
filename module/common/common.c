#include <mach-o/loader.h>
#include <stdbool.h>
#include <stdio.h>

#include <common/common.h>
#include <pf/offsets.h>

bool is_15_x__pongo(void){
    return g_kern_version_major == iOS_15_x;
}

bool is_14_5_and_above__pongo(void){
    if(g_kern_version_major <= iOS_13_x)
        return false;

    if (g_kern_version_major == iOS_14_x &&
        g_kern_version_minor < 4)
        return false;

    return true;
}

bool is_14_x_and_above__pongo(void){
    return g_kern_version_major >= iOS_14_x;
}

bool is_14_x_and_below__pongo(void){
    return g_kern_version_major <= iOS_14_x;
}

bool is_14_x__pongo(void){
    return g_kern_version_major == iOS_14_x;
}

bool is_13_x__pongo(void){
    return g_kern_version_major == iOS_13_x;
}

/* no sign support */
int atoi(const char *s){
    int res = 0;

    while(*s){
        res = res * 10 + (*s - '0');
        s++;
    }

    return res;
}

int isdigit(int c){
    return c >= '0' && c <= '9';
}

char *strcpy(char *dest, const char *src){
    char *src0 = (char *)src;
    while((*dest++ = *src0++));
    *dest = '\0';
    /* who cares about strcpy return value */
    return dest;
}

char *strstr(const char *haystack, const char *needle){
    if(!*needle)
        return (char *)haystack;

    char *hay = (char *)haystack;
    char *n = (char *)needle;

    for(; *hay; hay++){
        if(*hay != *n)
            continue;

        char *h = hay;

        for(;;){
            if(!*n)
                return hay;

            if(*h++ != *n++)
                break;
        }

        n = (char *)needle;
    }

    return NULL;
}

struct mach_header_64 *mh_execute_header = NULL;
uint64_t kernel_slide = 0;

/* XXX do not panic so user can see what screen says */
__attribute__ ((noreturn)) void xnuspy_fatal_error(void){
    puts("xnuspy: fatal error.");
    puts("     Please file an issue");
    puts("     on Github. Include");
    puts("     output up to this");
    puts("     point and device/iOS");
    puts("     version.");
    puts("Spinning forever.");

    for(;;);
}
