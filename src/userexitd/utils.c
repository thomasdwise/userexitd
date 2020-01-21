/*
 * Copyright (c) 1998 Todd C. Miller <Todd.Miller@courtesan.com> All rights reserved.
 * Copyright (c) 2005 Eugene A. Doudine <dudinea@gmail.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL
 * THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdarg.h>
#include <stdio.h>
#include <sys/types.h>
#include <string.h>

#ifdef HAVE_SYSLOG_NAMES
#define SYSLOG_NAMES
#endif
#include <syslog.h>
#ifndef HAVE_SYSLOG_NAMES
#include "syslog_names.h"
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <ctype.h>
#include <regex.h>

#include "userExitSample.h"
#include "utils.h"
#include "userexitd.h"

extern elEventRecvData ebuf;
extern config_t config;
extern int foreground;



int get_value(char *str,int defcode,CODE dict[]) {
  int i;
  if (NULL==str) {
    return defcode;
  }
  for (i=0;dict[i].c_name;i++) {
    if (!strcasecmp(dict[i].c_name,str)) {
      return dict[i].c_val;
    }
  }
  logmsg(LOG_ERR,"cannot find key '%s' in dictionary!",str);
  err_exit("dictionary lookup failed");
  return(0);
}

char* get_name(int value,char *defstr,CODE dict[]) {
  int i;
  for (i=0;dict[i].c_name;i++) {
    if (dict[i].c_val==value) {
      return dict[i].c_name;
    }
  }
  return(defstr);
}


char *get_attr(char *attrname,const char **attr) {
  int i;
  for(i=0;attr[i];i+=2) {
    if (!strcasecmp(attrname,attr[i])) {
      return (char*)attr[i+1];
    }
  } 
  return NULL; 
}



void logmsg(int level,char *fmt,...) {
  char lb[BUFSIZ];
  int len;
  va_list ap;
  va_start(ap, fmt);
  if ((level&LOG_PRIMASK)<=config.ll) {
    if (config.foreground) {
      len=snprintf(lb,sizeof(lb),"[%d] %s: ",getpid(),get_name(level & LOG_PRIMASK,"INFO",prioritynames));
      vsnprintf(lb+len,sizeof(lb)-len,fmt,ap);
      fprintf(stderr,"%s\n",lb);
    } else {
      vsnprintf(lb, sizeof(lb), fmt, ap);
      syslog(level | config.faccode,"%s",lb);
    }
  }
  va_end(ap);
}

void err_exit(char *msg) {
  logmsg(LOG_ERR,"FATAL: %s",msg);
  cleanup(0);
  exit(2);
}


size_t strlncat(char *dst,const char *src, size_t siz,size_t siz2)
{
	register char *d = dst;
	register const char *s = src;
	register size_t n = siz;
	register int i;
	size_t dlen;

	/* Find the end of dst and adjust bytes left but don't go past end */
	while (n-- != 0 && *d != '\0')
		d++;
	dlen = d - dst;
	n = siz - dlen;

	if (n == 0)
		return(dlen + strlen(s));
	i=0;
	while ((s[i] != '\0') && (i<siz2)) {
		if (n != 1) {
			*d++ = s[i];
			n--;
		}
		i++;
	}
	*d = '\0';

	return(dlen + (s - src));	/* count does not include NUL */
}

void *xmalloc(size_t size)
{
        void    *ptr;
        if (!(ptr = malloc(size))) err_exit("malloc: out of memory");
        return ptr;
}

void *xrealloc(void *ptr, size_t size)
{
        if (!(ptr = realloc(ptr, size)))  err_exit("realloc: out of memory");
        return ptr;
}

void xfree(void *ptr)
{
        free(ptr);
}

char *xstrdup(const char *str)
{
        char    *ret;
        if (!(ret = strdup(str)))  err_exit("strdup: out of memory");
        return ret;
}

#ifndef OPEN_MAX
#define OPEN_MAX 1024
#endif

int open_max(void) {
  int i=sysconf(_SC_OPEN_MAX);
  if (-1==i) return OPEN_MAX;
  return i;
}
