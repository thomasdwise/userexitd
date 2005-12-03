#ifndef UTILS_H 
#define UTILS_H
void log(int level,char *fmt,...);
void err_exit(char *msg);
size_t strlncat(char *dst,const char *src, size_t siz,size_t siz2);
void *xmalloc(size_t size);
void *xrealloc(void *ptr, size_t size);
void xfree(void *ptr);
char *xstrdup(const char *str);
#endif
