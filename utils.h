#ifndef UTILS_H 
#define UTILS_H
void logmsg(int level,char *fmt,...);
void err_exit(char *msg);
size_t strlncat(char *dst,const char *src, size_t siz,size_t siz2);
void *xmalloc(size_t size);
void *xrealloc(void *ptr, size_t size);
void xfree(void *ptr);
char *xstrdup(const char *str);
int open_max(void);
int get_value(char *str,int defcode,CODE dict[]);
char *get_name(int value,char *defstr,CODE dict[]);
char *get_attr(char *attrname,const char **attr);
#endif
