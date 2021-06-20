/* libc functions that aren't hyper-optimized inside the kernel that I can
 * just reimplement here. This saves me the trouble of writing a ton of
 * patchfinders */

#include <stddef.h>
#include <stdint.h>

#include <xnuspy/el1/externs.h>

void bzero(void *p, size_t n){
    uint8_t *p0 = p;
    uint8_t *p_end = p0 + n;

    while(p0 < p_end)
        *p0++ = '\0';
}

void *memchr(const void *s, int c, size_t n){
    if(!n)
        return NULL;

    uint8_t *sp = (uint8_t *)s;

    for(size_t i=0; i<n; i++){
        if(sp[i] == c)
            return &sp[i];
    }

    return NULL;
}

int memcmp(const void *s1, const void *s2, size_t n){
    if(!n)
        return 0;

    uint8_t *s1p = (uint8_t *)s1, *s2p = (uint8_t *)s2;

    do {
        if(*s1p++ != *s2p++)
            return *--s1p - *--s2p;

    } while (--n);

    return 0;
}

void *memmem(const void *big, size_t blen, const void *little, size_t llen){
    if(!blen || !llen)
        return NULL;

    if(llen > blen)
        return NULL;

    const char *bs = (const char *)big;
    const char *ls = (const char *)little;

    if(llen == 1)
        return memchr(big, (int)*ls, blen);

    char *limit = (char *)bs + (blen - llen);
    char *cursor;

    for(cursor = (char *)bs; cursor <= limit; cursor++){
        if(*cursor != *ls)
            continue;

        if(memcmp(cursor, ls, llen) == 0)
            return cursor;
    }

    return NULL;
}

void *memrchr(const void *s, int c, size_t n){
    if(!n)
        return NULL;

    uint8_t *sp = (uint8_t *)s + n;

    do {
        if(*(--sp) == (uint8_t)c)
            return sp;
    } while (--n != 0);

    return NULL;
}

char *strchr(const char *s, int c){
    char *sp = (char *)s;

    for(; *sp != (char)c; ++sp){
        if(!*sp)
            return NULL;
    }

    return sp;
}

char *strrchr(const char *s, int c){
    char *lastp = NULL;
    char *sp = (char *)s;

    do {
        if(*sp == (char)c)
            lastp = sp;
    } while (*sp++);

    return lastp;
}

int strcmp(const char *s1, const char *s2){
    while(*s1 && (*s1 == *s2)){
        s1++;
        s2++;
    }

    return *(const unsigned char *)s1 - *(const unsigned char *)s2;
}

char *strstr(const char *big, const char *little){
    size_t blen = _strlen(big);
    size_t llen = _strlen(little);

    if(!llen)
        return (char *)big;

    if(llen > blen)
        return NULL;

    char *limit = (char *)big + (blen - llen);
    char *cursor;

    for(cursor = (char *)big; cursor <= limit; cursor++){
        if(memcmp(cursor, little, llen) == 0)
            return cursor;
    }

    return NULL;
}

char *strnstr(const char *big, const char *little, size_t n){
    size_t llen = _strlen(little);

    if(!llen)
        return (char *)big;

    if(llen > n)
        return NULL;

    char *limit = (char *)big + (n - llen);
    char *cursor;

    for(cursor = (char *)big; cursor <= limit; cursor++){
        if(memcmp(cursor, little, llen) == 0)
            return cursor;
    }

    return NULL;
}
