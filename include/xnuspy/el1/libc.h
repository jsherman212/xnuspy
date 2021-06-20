#ifndef LIBC
#define LIBC

#include <stddef.h>

void bzero(void *p, size_t n);
void *memchr(const void *s, int c, size_t n);
int memcmp(const void *s1, const void *s2, size_t n);
void *memmem(const void *big, size_t blen, const void *little, size_t llen);
void *memrchr(const void *s, int c, size_t n);
char *strchr(const char *s, int c);
char *strrchr(const char *s, int c);
int strcmp(const char *s1, const char *s2);
char *strstr(const char *big, const char *little);
char *strnstr(const char *big, const char *little, size_t len);

#endif
