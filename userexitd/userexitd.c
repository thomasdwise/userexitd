/**********************************************************************
Copyright (c) 2005, Eugene A. Doudine All rights reserved.

Redistribution and use in source and binary forms, with or without 
modification, are permitted provided that the following conditions 
are met:

    * Redistributions of source code must retain the above 
      copyright notice, this list of conditions and the following 
      disclaimer.
    * Redistributions in binary form must reproduce the above 
      copyright notice, this list of conditions and the 
      following disclaimer in the documentation and/or 
      other materials provided with the distribution.
    * Neither the name of the author nor the names of 
      contributors may be used to endorse or promote products 
      derived from this software without specific prior 
      written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS 
FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT 
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED 
TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, 
OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY 
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE 
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

***********************************************************************/

#include <errno.h>
#include <signal.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>
#include <fcntl.h>
#include <getopt.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>

#include <syslog.h>

#include <regex.h>

#include <expat.h>
#include "userExitSample.h"
#include "utils.h"
#include "userexitd.h"



/*from syslog.h*/
typedef struct _code {
     char    *c_name;
     int     c_val;
} CODE;

extern CODE prioritynames[];
extern CODE facilitynames[];



elEventRecvData ebuf;
config_t config;
int debug=0;

CODE sevcodes[] ={
  {"ADSM_SEV_INFO",         ADSM_SEV_INFO},       /* Informational message.        */
  {"ADSM_SEV_WARNING",      ADSM_SEV_WARNING},    /* Warning message.              */
  {"ADSM_SEV_ERROR",        ADSM_SEV_ERROR},      /* Error message.                */
  {"ADSM_SEV_SEVERE",       ADSM_SEV_SEVERE},     /* Severe error message.         */
  {"ADSM_SEV_DIAGNOSTIC",   ADSM_SEV_DIAGNOSTIC}, /* Diagnostic message.           */
  {"ADSM_SEV_TEXT",         ADSM_SEV_TEXT},       /* Text message.                 */
  {NULL,-1}
};

CODE appltypes[] ={
  {"ADSM_APPL_BACKARCH",ADSM_APPL_BACKARCH},
  {"ADSM_APPL_HSM",     ADSM_APPL_HSM},
  {"ADSM_APPL_API",     ADSM_APPL_API},
  {"ADSM_APPL_SERVER",  ADSM_APPL_SERVER},
  {NULL,-1}
};

CODE eventtypes[]= {
  {"ADSM_SERVER_EVENT",ADSM_SERVER_EVENT},
  {"ADSM_CLIENT_EVENT",ADSM_CLIENT_EVENT},
  {NULL,-1}
};


struct Pattern_Type patterntypes[]= {
  {"eventNum",   INT32_T, &ebuf.eventNum   , 1, NULL},
  {"sevCode",    INT16_T, &ebuf.sevCode    , 1, sevcodes},
  {"applType",   INT16_T, &ebuf.applType   , 1, appltypes},
  {"sessId",     INT32_T, &ebuf.sessId     , 1, NULL},
  {"version",    INT32_T, &ebuf.version    , 1, NULL},
  {"eventType",  INT32_T, &ebuf.eventType  , 1, eventtypes},
  {"timeStamp",  TS_T,    &ebuf.timeStamp  , 1, NULL},
  {"serverName", UCHAR_T, &ebuf.serverName , sizeof(ebuf.serverName),NULL},
  {"nodeName",   UCHAR_T, &ebuf.nodeName   , sizeof(ebuf.nodeName),NULL},
  {"commMethod", UCHAR_T, &ebuf.commMethod , sizeof(ebuf.commMethod),NULL},
  {"ownerName",  UCHAR_T, &ebuf.ownerName   , sizeof(ebuf.ownerName),NULL},
  {"hlAddress",  UCHAR_T, &ebuf.hlAddress  , sizeof(ebuf.hlAddress),NULL},
  {"llAddress",  UCHAR_T, &ebuf.llAddress  , sizeof(ebuf.llAddress),NULL},
  {"schedName",  UCHAR_T, &ebuf.schedName  , sizeof(ebuf.schedName),NULL},
  {"domainName", UCHAR_T, &ebuf.domainName , sizeof(ebuf.domainName),NULL},
  {"event",      UCHAR_T, &ebuf.event      , sizeof(ebuf.event),NULL},
  {NULL,         0,       NULL             , 0,                 NULL}
};


struct Iof *ciof; 
struct Rule *crule;
struct Pattern *cpattern;
union Action *caction;
struct Counter *ccounter;
char *cdata=NULL;
size_t scdata=0;

int unix_socket=0;
regmatch_t matches[MAXMATCH];


int Depth;


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
  log(LOG_ERR,"cannot find key '%s' in dictionary!",str);
  err_exit("dictionary lookup failed");
}

int get_name(int value,char *defstr,CODE dict[]) {
  int i;
  for (i=0;dict[i].c_name;i++) {
    if (dict[i].c_val==value) {
      return dict[i].c_name;
    }
  }
  return(defstr);

}


char *get_attr(char *attrname,char **attr) {
  int i;
  for(i=0;attr[i];i+=2) {
    if (!strcasecmp(attrname,attr[i])) {
      return xstrdup((attr[i+1]));
    }
  } 
  return NULL; 
}




void addArg(char *arg) {
  int i;
  char **p=caction->ex.args;
  for (i=0;p[i]!=NULL;i++); 
  p[i]=xstrdup(arg);
  i++;
  p=xrealloc(p,sizeof(char**)*(i+1));
  p[i]=NULL;
  caction->ex.args=p;
  log(LOG_DEBUG,"added argument '%s'",arg);
}

void addCounter (char **attr) {
  struct Counter **cp;
  char *tmp;
  if (NULL==crule) {
    err_exit("cannot add counter to a non-existant rule");
  }
  cdata[0]=0;
  cp=&crule->counters;
  while (NULL!=*cp) {
    log(LOG_DEBUG,"passing counter '%s'",(*cp)->name);
    cp=&((*cp)->next);
  } 
  (*cp)=xmalloc(sizeof(struct Counter));
  (*cp)->next=NULL;
  tmp=get_attr("name",attr);
  if (NULL==tmp) {
    err_exit("counter must have a name attribute defined!");
  }
  (*cp)->name=tmp;    
  tmp=get_attr("number",attr);
  if (NULL==tmp) {
    (*cp)->number=1;    
  } else {
    (*cp)->number=atoi(tmp);
  }
  (*cp)->counts=NULL;
  (*cp)->str=NULL;
  log(LOG_DEBUG,"added counter '%s'",(*cp)->name);
  ccounter=*cp;
}

int getfdnum(char *str) {
  if (!strcasecmp(str,"stdin")) {
    return 0;
  } else if (!strcasecmp(str,"stdout")) {
    return 1;
  } else if (!strcasecmp(str,"stderr")) {
    return 2;
  } else if (!isdigit(str[0])) {
    err_exit("incorrect value for attribute, must be stdin or stdout or stderr or positive  numeric value");
  }
  return atoi(str);
}


void addFile(char ** attr) {
  struct Iof **fp;
  char *tmp;
  if ((NULL==caction) || (caction->ca.a_type!=A_EXEC)) {
    err_exit("cannot add file to a non-exec statement");
  }
  cdata[0]=0;
  fp=&caction->ex.iofiles;
  while (NULL!=*fp) {
    log(LOG_DEBUG,"passing fd %d '%s' (%s)",(*fp)->fd,(*fp)->filename,(*fp)->mode);
    fp=&((*fp)->next);
  }
  (*fp)=xmalloc(sizeof(struct Iof));
  bzero(*fp,sizeof(struct Iof));
  tmp=get_attr("fd",attr);
  if (NULL==tmp) {
    err_exit("file must have a fd attribute defined!");
  }
  (*fp)->fd=getfdnum(tmp);

  tmp=get_attr("mode",attr);
  if (NULL==tmp) {
    err_exit("file must have a mode attribute defined!");
  }

  (*fp)->mode=tmp;
  
  (*fp)->filename=get_attr("filename",attr);
  (*fp)->fdup=-1;
  if (NULL!=get_attr("dup",attr)) {
    (*fp)->fdup=getfdnum(get_attr("dup",attr));
  }
  log(LOG_DEBUG,"Added file fd=%d mode='%s' dup=%d filename='%s'",(*fp)->fd,(*fp)->mode,(*fp)->fdup,((*fp)->filename)?((*fp)->filename):"nul");
  ciof=*fp;
}



void addAction(enum A_TYPE a_type,char **attr) {
  union Action **ap;
  char *tmp;
  if (NULL==crule) {
    err_exit("cannot add action to a non-existant rule");
  }
  cdata[0]=0;
  ap=&crule->actions;
  while (NULL!=*ap) {
    log(LOG_DEBUG,"passing action type '%s'",((*ap)->ca.a_type==A_EXEC)?"exec":"syslog");
    ap=&((*ap)->ca.next);
  } 
  (*ap)=xmalloc(sizeof(union Action));
  (*ap)->ca.next=NULL;
  (*ap)->ca.a_type=a_type;
  if (a_type==A_EXEC) {
    tmp=get_attr("image",attr);
    if (NULL==tmp) {
      err_exit("exec must have an image attribute defined!");
    }
    (*ap)->ex.image=tmp;
    (*ap)->ex.args=(char**)xmalloc(sizeof(char*)*2);
    ((*ap)->ex.args)[0]=tmp;
    ((*ap)->ex.args)[1]=0;
    (*ap)->ex.iofiles=NULL;
  } else if (a_type==A_SYSLOG) {
    (*ap)->log.facility=get_value(get_attr("facility",attr),config.faccode,facilitynames);
    (*ap)->log.priority=get_value(get_attr("priority",attr),config.priocode,prioritynames);
    (*ap)->log.message=NULL;
  } else if (a_type==A_SYSTEM) {
    (*ap)->sys.text=NULL;
    (*ap)->sys.cmdline=NULL;
  }
  log(LOG_DEBUG,"added action type '%s'",(a_type==A_EXEC)?"exec":(a_type==A_SYSLOG?"syslog":"system"));
  caction=*ap;
}

void addPattern(char **attr) {
  struct Pattern **pp;
  char *ptypename;
  struct Pattern_Type *ptype;
  int i;
  
  ptype=NULL;
  if (NULL==crule) {
    err_exit("cannot add pattern to a non-existant rule");
  }
  ptypename=get_attr("type",attr);
  if (!ptypename) {
    err_exit("pattern must have a type attribute defined!");
  }
  log(LOG_DEBUG,"adding pattern type '%s'",ptypename);
  cdata[0]=0;
  for (i=0;patterntypes[i].name;i++) {
    if (!strcasecmp(patterntypes[i].name,ptypename)) {
      ptype=&patterntypes[i];
      break;
    }
  }
  if (!ptype) {
    log(LOG_ERR,"wrong pattern type '%s'!",ptypename);
    err_exit("wrong pattern type!");
  }
  pp=&crule->patterns;
  while (NULL!=*pp) {
    log(LOG_DEBUG,"passing pattern type '%s'",(*pp)->ptype->name);
    pp=&((*pp)->next);
  } 
  (*pp)=xmalloc(sizeof(struct Pattern));
  (*pp)->next=NULL;
  (*pp)->ptype=ptype;
  (*pp)->pflags=REG_EXTENDED|REG_ICASE;
  bzero(&((*pp)->preg),sizeof(regex_t));
  log(LOG_DEBUG,"added pattern type '%s'",ptypename);
  cpattern=*pp;
}

void addRule(char **attr) {
  struct Rule **rp=&config.rules;
  if (get_attr("disabled",attr) && (!strcasecmp(get_attr("disabled",attr),"yes"))) {
    return;
  }
  if (!get_attr("name",attr)) {
    err_exit("rule must have a name attribute defined!");
  } 
  log(LOG_DEBUG,"adding rule %s",get_attr("name",attr));
  while (NULL!=*rp) {
    log(LOG_DEBUG,"passing rule '%s'",(*rp)->name);
    if (!strcasecmp((*rp)->name,get_attr("name",attr))) {
      log(LOG_ERR,"rule '%s' is already defined!",get_attr("name",attr));
      err_exit("rule name must be unique!");
    }
    rp=&((*rp)->next);
  } 
  (*rp)=xmalloc(sizeof(struct Rule));
  
  log(LOG_DEBUG,"added rule %s",get_attr("name",attr));
  (*rp)->name=get_attr("name",attr);
  (*rp)->next=NULL;
  (*rp)->patterns=NULL;
  (*rp)->actions=NULL;
  (*rp)->counters=NULL;
  if (get_attr("final",attr) && (!strcasecmp(get_attr("final",attr),"yes"))) {
    (*rp)->final=1;
  }
  crule=*rp;
}


void XMLCALL
start(void *data, const char *el, const char **attr) {
  if (!strcasecmp(el,"syslog")) {
    if (crule) {
      addAction(A_SYSLOG,attr);
    } else {
      config.faccode=get_value(get_attr("facility",attr),LOG_LOCAL0,facilitynames);
      config.priocode=get_value(get_attr("priority",attr),LOG_INFO,prioritynames);
      config.ident=get_attr("ident",attr);
      if (NULL==config.ident) {
	config.ident=DEFIDENT;
      }
    }
  } else if (!strcasecmp(el,"listen")) {
    config.address=get_attr("address",attr);
  } else if (!strcasecmp(el,"pid")) {
    config.pidfile=get_attr("path",attr);
  } else if (!strcasecmp(el,"logging")) {
    if (!debug) {
      config.ll=get_value(get_attr("level",attr),LOG_WARNING,prioritynames);
    } else {
      config.ll=LOG_DEBUG;
    }
  } else if (!strcasecmp(el,"foreground")) {
    config.foreground=1;
  } else if (!strcasecmp(el,"background")) {
    if (!debug) {
      config.foreground=0;
    }
  } else if (!strcasecmp(el,"rule")) {
    addRule(attr);
  } else if (!strcasecmp(el,"pattern")) {
    addPattern(attr);
  } else if (!strcasecmp(el,"logging")) {
  } else if (!strcasecmp(el,"exec")) {
    addAction(A_EXEC,attr);
  } else if (!strcasecmp(el,"system")) {
    addAction(A_SYSTEM,attr);
  } else if (!strcasecmp(el,"arg")) {
    cdata[0]=0;
  } else if (!strcasecmp(el,"counter")) {
    cdata[0]=0;
    addCounter(attr);
  } else if (!strcasecmp(el,"file")) {
    cdata[0]=0;
    addFile(attr);
  } else if (!strcasecmp(el,"command")) {
    cdata[0]=0;
  } else if (!strcasecmp(el,"input")) {
    cdata[0]=0;
  }
}  /* End of start handler */


void XMLCALL
end(void *data, const char *el) {
  int rc;
  size_t l;
  /*  Depth--;*/
  
  if (!strcasecmp(el,"listen")) {
  } else if (!strcasecmp(el,"pattern")) {
    if (cpattern) {
      if (rc=regcomp(&(cpattern->preg),cdata,cpattern->pflags)) {
	log(LOG_ERR,"cannot compile pattern '%s'",cdata);
	regerror(rc,&(cpattern->preg),cdata,sizeof(cdata));
	err_exit(cdata);
      }
    }
    cpattern=NULL;
  } else if (!strcasecmp(el,"rule")) {
    crule=NULL;
    cpattern=NULL;
  } else if (!strcasecmp(el,"syslog")) {
    if (caction) {
      caction->log.message=xstrdup(cdata);
      caction=NULL;
    }
  } else if (!strcasecmp(el,"arg")) {
    if (caction && caction->ca.a_type==A_EXEC) {
      addArg(cdata);
    }
    //carg=0;
  } else if (!strcasecmp(el,"counter")) {
    if (ccounter) {
      ccounter->str=xstrdup(cdata);
      ccounter=NULL;
    }

  } else if (!strcasecmp(el,"file")) {
    if (ciof) {
      ciof->text=xstrdup(cdata);
      log(LOG_DEBUG,"added text input '%s'",ciof->text);
      ciof=NULL;
    }
  } else if (!strcasecmp(el,"command")) {
    if (caction) {
      caction->sys.cmdline=xstrdup(cdata);
    }
  } else if (!strcasecmp(el,"system")) {
    caction=NULL;
  } else if (!strcasecmp(el,"input")) {
    if (caction) {
      caction->sys.text=xstrdup(cdata);
    }
  }
}  /* End of end handler */

void XMLCALL charhndl(void *userData, const XML_Char *s,int len) {
  if (cpattern || caction ) {
    if (scdata<(1+strlen(cdata)+len)) {
      cdata=xrealloc(cdata,1+strlen(cdata)+len+BUFSIZ);
      scdata=1+strlen(cdata)+len+BUFSIZ;
    }
    strlncat(cdata,s,scdata,len);
  }
}

config_t *read_config(char *filename) {
  XML_Parser XMLCALL parser=NULL;
  char *cfdata;
  FILE *cfd;
  struct stat cfstat;
  bzero(&config,sizeof(config));

  if (debug) {
    config.foreground=1;
    config.ll=LOG_DEBUG;
  } else {
    config.ll=LOG_WARNING;
  }
  crule=caction=cpattern=NULL;
  
  log(LOG_DEBUG,"reading coinfiguration from '%s'",filename);
  if (NULL==(cfd=fopen(filename,"r"))) {
    log(LOG_ERR,"%s: %s",filename,strerror(errno));
    err_exit("cannot open configuration!");
  }
  if (fstat(fileno(cfd),&cfstat)) {
    log(LOG_ERR,"%s: %s",filename,strerror(errno));
    err_exit("cannot stat configuration file!");
  }
  cfdata=xmalloc(cfstat.st_size);
  
  if (1!=fread(cfdata,cfstat.st_size,1,cfd)) {
    log(LOG_ERR,"%s: %s",filename,strerror(errno));
    err_exit("error reading configuration!");
  }
  
  if (NULL==(parser=XML_ParserCreate(NULL))) {
    err_exit("cannot create configuration parser!");
  }

  XML_SetElementHandler(parser, start, end);
  XML_SetCharacterDataHandler(parser,charhndl);

  if (XML_STATUS_OK!=XML_Parse(parser,cfdata,cfstat.st_size,1)) {
    log(LOG_ERR,"expat error at (%d,%d): %s",
	    XML_GetCurrentLineNumber(parser),
	    XML_GetCurrentColumnNumber(parser),
	    XML_ErrorString(XML_GetErrorCode(parser)));
    err_exit("error parsing configuration file!");
  }
  if (!config.address) {
    config.address=DEFSOCKET;
  }
  if (!config.ident) {
    config.ident=DEFIDENT;
  }
  if (!config.pidfile) {
    config.pidfile=DEFPIDFILE;
  }
  if (!config.rules) {
    err_exit("No rules defined, please define some!");
  }
  return &config;
}


void reap(int a) {
	int status;
	do {
	} while( waitpid(-1,&status,WNOHANG)>0);
}

void cleanup(int a) {
  if (config.pidfile && strlen(config.pidfile)) {
    unlink(config.pidfile);
  }
  if (unix_socket) {
    close(unix_socket);
  }
  if (config.sockpath) {
    unlink(config.sockpath);
  }
  exit(0);
}

void usage() {
	fprintf(stderr,"Usage: userexitd [-v] [-h] [-f] [-c file] [-d] \n");
	fprintf(stderr,"\t-c file\t\tconfiguration file\n");
	fprintf(stderr,"\t-d\t\tdebug mode\n");
	fprintf(stderr,"\t-f\t\tcheck configuration\n");
	fprintf(stderr,"\t-h\t\tprint help\n");
	fprintf(stderr,"\t-v\t\tprint version\n");
}

int main(int argc,char **argv) {
  int rc;
  char c;
  char *opts="vhc:fd";
  struct Config *cfg;
  int checkconf=0;
  
  struct sockaddr_un my_addr;
  struct sockaddr *my_addr_p=(struct sockaddr*)&my_addr;
  char *configfile=DEFCFG;

  FILE *fd=0;
  char pbuf[40];
  int pd;
  bzero(pbuf,sizeof(pbuf));
  
  while(1) {
    c=getopt(argc,argv,opts);
    if (-1==c)  break;
    switch(c) {
    case 'f':
      checkconf=1;
      break;
    case 'd':
      debug=1;
      break;
    case 'h':
      usage();
      exit(0);
      break;
    case 'c':
      configfile=optarg;
      break;
    case 'v':
      fprintf(stderr,"userexitd -- %s\n",USEREXITD_VERSION);
      exit(1);
    default:
      usage();
      exit(1);
    }
  }

  cdata=xmalloc(BUFSIZ);
  scdata=BUFSIZ;

  if (NULL==(cfg=read_config(configfile))) {
    err_exit("cannot read configuration!");
  }
  
  if (debug) {
    cfg->ll=LOG_DEBUG;
    cfg->foreground=1;
  } 
  
  if (strncasecmp("unix:",cfg->address,5)) {
    err_exit("unsupported protocol in address, only local unix sockets implemented!");
  }
  my_addr.sun_family=AF_UNIX;

  cfg->sockpath=cfg->address+5;
  strcpy(my_addr.sun_path,cfg->sockpath);
  if (debug) {
    log(LOG_DEBUG,"debug='%d'",debug);
    log(LOG_DEBUG,"address='%s'",cfg->address);
    log(LOG_DEBUG,"pidfile='%s'",cfg->pidfile);
    log(LOG_DEBUG,"sockpath='%s'",cfg->sockpath);
  }
  if (checkconf) {
    fprintf(stderr,"configuration seems to be OK!\n");
    exit(0);
  }
  
  openlog(cfg->ident,LOG_NDELAY,cfg->faccode);
  
  
  if (config.pidfile && strlen(config.pidfile)) {
    if (!access(cfg->pidfile,F_OK))  {
      log(LOG_WARNING,"pid file %s exists",cfg->pidfile);
      if (NULL==(fd=fopen(cfg->pidfile,"r"))) {
        log(LOG_ERR,"%s: %s",cfg->pidfile,strerror(errno));
        err_exit("cannot open pid file for reading");
      }
      if (fread(pbuf,1,sizeof(pbuf)-1,fd)<=0) {
	log(LOG_ERR,"%s: %s",cfg->pidfile,strerror(errno));
	err_exit("cannot read contents of pid file");
      }
      fclose(fd);
      pd=atoi(pbuf);
      snprintf(pbuf,sizeof(pbuf),"/proc/%d",pd);
      if (!access(pbuf,X_OK)) {
    	err_exit("another copy of daemon is probably running!");
      } {
	log(LOG_WARNING,"deleting stale pid file",cfg->pidfile);
	if (unlink(cfg->pidfile)) {
	  err_exit("cannot unlink stale pid file!");
	}
      }

    }
    if (NULL==(fd=fopen(cfg->pidfile,"w"))) {
      log(LOG_ERR,"%s: %s",cfg->pidfile,strerror(errno));
      err_exit("cannot open pid file for writing");
    }
  }
  if (!access(my_addr.sun_path,F_OK))  {
    log(LOG_DEBUG,"unlinking stale socket file %s",my_addr.sun_path);
    if (unlink(cfg->sockpath)) {
      log(LOG_ERR,"%s: %s",cfg->sockpath,strerror(errno));
      err_exit("cannot unlink stale socket file!");
    }
  }

  if (SIG_ERR==signal(SIGTERM,&cleanup)) {
    log(LOG_ERR,"%s: %s","signal",strerror(errno));
    err_exit("cannot install SIGTERM signal handler");
  }
  if (SIG_ERR==signal(SIGINT,&cleanup)) {
    log(LOG_ERR,"%s: %s","signal",strerror(errno));
    err_exit("cannot install SIGINT signal handler");
  }

  unix_socket = socket(PF_UNIX, SOCK_DGRAM, 0); 
  if (unix_socket==-1) {
    log(LOG_ERR,"%s: %s","socket",strerror(errno));
    err_exit("cannot create socket!");
  }
  if (0>bind(unix_socket,my_addr_p, sizeof(my_addr))) {
    log(LOG_ERR,"%s: %s","bind",strerror(errno));
    err_exit("cannot bind to socket!");
  }

  if (!cfg->foreground) {
    if (-1==daemon(0,0)) {
      log(LOG_ERR,"%s: %s","daemon",strerror(errno));
      err_exit("cannot daemonize myself!");
    }
  }
	
  if (fd) {
    fprintf(fd,"%d\n",getpid());
    fclose (fd);
  }
  
  if (SIG_ERR==signal(SIGCHLD,&reap)) {
    log(LOG_ERR,"%s: %s","signal",strerror(errno));
    err_exit("cannot install SIGCHLD handler!");
  }
	
  while (1) {
    rc=recv(unix_socket,(void*)&ebuf, sizeof(ebuf), 0);
    log(LOG_DEBUG,"\ngot %d bytes!",rc);
    if (-1==rc) {
      if (EAGAIN==errno) {
	continue;
      } else if (EINTR==errno) {
	log(LOG_DEBUG,"%s: %s","recv",strerror(errno));
	continue;
      } else {
	log(LOG_ERR,"%s: %s","recv",strerror(errno));
	exit(3);
      }
    }
    if (0==fork())  {
      handle_packet(&ebuf);
      exit(0);
    }
  }
  exit(0);
}


char cbuf[40];

char* test_pattern (struct Rule *rp,struct Pattern *pp,elEventRecvData *buf) {
  char *tmp;
  int rc;
  if (NULL==pp) {
    return 1;
  }
  log(LOG_DEBUG,"testing pattern '%s' in rule '%s'",pp->ptype->name,rp->name);
  if (pp->ptype->datatype==UCHAR_T) {
    if (0==(rc=regexec(&(pp->preg),pp->ptype->ptr,MAXMATCH,&matches,0))) {
      log(LOG_DEBUG,"UCHAR_T value '%s' matches",pp->ptype->ptr);
      return pp->ptype->ptr;
    } else {
      log(LOG_DEBUG,"UCHAR_T value '%s' does not match",pp->ptype->ptr);
      return 0;
    }
  }
 
  if (pp->ptype->datatype==INT32_T) {
    if (pp->ptype->dictionary) {
      tmp=get_name(*((int32*)pp->ptype->ptr),"UNKNOWN",pp->ptype->dictionary);
      strncpy(cbuf,tmp,sizeof(cbuf));
    } else {
      snprintf(cbuf,sizeof(cbuf),"%d",*((int32*)pp->ptype->ptr));
    }
  }
  if (pp->ptype->datatype==INT16_T) {
    if (pp->ptype->dictionary) {
      tmp=get_name((int32)(*((int16*)pp->ptype->ptr)),"UNKNOWN",pp->ptype->dictionary);
      strncpy(cbuf,tmp,sizeof(cbuf));
    } else {
      snprintf(cbuf,sizeof(cbuf),"%d",*((int16*)pp->ptype->ptr));
    }
  }
  log(LOG_DEBUG,"cbuf='%s'",cbuf);
  if (0==(rc=regexec(&(pp->preg),cbuf,MAXMATCH,&matches,0))) {
    log(LOG_DEBUG,"INTEGER value '%s' matches",cbuf);
    return &cbuf;
  } else {
    log(LOG_DEBUG,"INTEGER value '%s' does not match",cbuf);
    return NULL;
  }
  return NULL;
}


char* test_rule(struct Rule *rp,elEventRecvData *buf) {
  struct Pattern *pp;
  char *matched="??????";
  log(LOG_DEBUG,"testing rule '%s'",rp->name);
  pp=rp->patterns;
  if (NULL==pp) {
    bzero(&matches[0],sizeof(regmatch_t));
    return matched;
  }
  do {
    bzero(&matches[0],sizeof(regmatch_t));
    if (NULL==(matched=test_pattern(rp,pp,buf))) {
      return NULL;
    }
  } while (NULL!=(pp=pp->next));
  return matched;
}


char *do_subst_var(char *str,int spos,int epos,int *len,char *matched,char *out) {
  int p=0,i;
  char *tmp;
  DateTime *ts=NULL;
  struct tm ct;
  if (isdigit(str[spos])) {
    p=atoi(str+spos);
    if ((p>=MAXMATCH) || matches[p].rm_so==-1) {
      *len=3;
      return "???";
    }
    *len=matches[p].rm_eo-matches[p].rm_so;
    return matched+matches[p].rm_so;
  } else {
    for (i=0;NULL!=patterntypes[i].name;i++) {
      if (!strncasecmp(patterntypes[i].name,str+spos,1+epos-spos) &&
	  ((1+epos-spos)==strlen(patterntypes[i].name))) {
	if (patterntypes[i].datatype==UCHAR_T) {
	  *len=strlen(patterntypes[i].ptr);
	  return patterntypes[i].ptr;
	} else if (patterntypes[i].datatype==INT32_T) {
	  if (NULL!=patterntypes[i].dictionary) {
	    tmp=get_name(*((int32*)patterntypes[i].ptr),"UNKNOWN",patterntypes[i].dictionary);
	    *len=strlen(tmp);
	    return tmp;
	  } else {
	    sprintf(out,"%d",*((int32*)patterntypes[i].ptr));
	    *len=strlen(out);
	    return out;
	  }
	}  else if (patterntypes[i].datatype==INT16_T) {
	  if (NULL!=patterntypes[i].dictionary) {
	    tmp=get_name(*((int16*)patterntypes[i].ptr),"UNKNOWN",patterntypes[i].dictionary);
	    *len=strlen(tmp);
	    return tmp;
	  } else {
	    sprintf(out,"%d",*((int16*)patterntypes[i].ptr));
	    *len=strlen(out);
	    return out;
	  }
	} else if (patterntypes[i].datatype==TS_T) {
	  ts=(DateTime*)patterntypes[i].ptr;
	  ct.tm_sec=ts->sec;
	  ct.tm_min=ts->min;
	  ct.tm_hour=ts->hour;
	  ct.tm_mday=ts->day;
	  ct.tm_mon=ts->mon;
	  ct.tm_year=ts->year;        
	  ct.tm_wday=ct.tm_yday=0;
	  ct.tm_isdst=-1;
	  strftime(out,BUFSIZ,"%c",&ct);
	  *len=strlen(out);
	  return(out);
	}
      }
    }
  }
  *len=3;
  return "???";
}



char *addchar(char* sbuf,int *pos,size_t *ssize,char chr) {
  char *nbuf;
  sbuf[*pos]=chr;
  (*pos)++;
  if ((*pos)>=(*ssize)) {
    *ssize=BUFSIZ+*ssize;
    log(LOG_DEBUG,"addchar: allocated extra space\n");
    return(xrealloc(sbuf,*ssize));
  }
  return sbuf;
}

char* do_subst(char *str,char *matched) {
  int i,j=0,k,n,l;
  char *sval;
  char *sbuf=xmalloc(BUFSIZ);
  size_t ssize=BUFSIZ;

  char out[BUFSIZ];
  n=strlen(str);
  for (i=0;i<=n;i++) {
    if (str[i]!='%') {
      sbuf=addchar(sbuf,&j,&ssize,str[i]);
      continue;
    }
    if (str[i]=='%' && str[i+1]=='%') {
      sbuf=addchar(sbuf,&j,&ssize,str[i]);
      i++;
      continue;
    }
    for (k=i+1;k<n && str[k]!='%';k++);
    if (k==n) {
      sbuf=addchar(sbuf,&j,&ssize,'%');
      continue;
    }
    sval=do_subst_var(str,i+1,k-1,&l,matched,out);
    i=k;
    for(k=0;k<l;k++) {
      sbuf=addchar(sbuf,&j,&ssize,sval[k]);
    }
  }
  sbuf=addchar(sbuf,&j,&ssize,0);
  return sbuf;
}


void do_exec(union Action *ap,struct Rule *rp,elEventRecvData *buf,char *matched) {
  char *args[MAXARGS];

  char *sbuf;
  int i,pip[2],om=open_max();
  struct Iof *fp;
  FILE *tfd;
  if (0==fork())  {  
    log(LOG_DEBUG,"running exec action '%s'",ap->ex.image);
    for (i=3;i<om;i++) {
      fcntl(i,F_SETFD,FD_CLOEXEC);
    }
    bzero(args,sizeof(args));
    for(i=0;(i<(MAXARGS-1)) && ap->ex.args[i];i++) {

      sbuf=do_subst(ap->ex.args[i],matched);
      args[i]=xstrdup(sbuf);
      xfree(sbuf);
    }
    for (i=0;args[i];i++) {
      log(LOG_DEBUG," arg%d=%s",i,args[i]);
    } 
    fp=ap->ex.iofiles;
    if (NULL==fp) {
      log(LOG_DEBUG,"no descriptors redirected");
    }
    while (fp!=NULL) {
      log(LOG_DEBUG,"redirecting descriptor %d",fp->fd,fp->fdup);
      if (fp->filename) {
	log(LOG_DEBUG,"to file '%s' mode='%s'",fp->filename,fp->mode);
	if (tfd=fopen(fp->filename,fp->mode)) {
	  close(fp->fd);
	  if (-1==dup2(fileno(tfd),fp->fd)){
	    log(LOG_ERR,"cannot dup '%d': %s",fileno(tfd),strerror(errno));
	  }
	  fclose(tfd);
	  fcntl(fp->fd,F_SETFD,0);
	} else {
	  log(LOG_ERR,"cannot open '%s': %s",fp->filename,strerror(errno));
	}
      } else if (((int)(fp->fdup))>=0) {
	log(LOG_DEBUG,"to descriptor %d",fp->fdup);
	close(fp->fd);
	if (-1==dup2(fp->fdup,fp->fd)) {
	  log(LOG_ERR,"dup2: %s",strerror(errno));
	}
	fcntl(fp->fd,F_SETFD,0);
      } else if ((!strcmp(fp->mode,"r")) && fp->text) {
	log(LOG_DEBUG,"to text '%s'",fp->text);

	sbuf=do_subst(fp->text,matched);
	log(LOG_DEBUG,"substituted text '%s'",sbuf);
	if (!pipe(&pip)) {
	  close(fp->fd);
	  if (-1==dup2(pip[0],fp->fd)) {
	    log(LOG_ERR,"dup2: %s",strerror(errno));
	  } else {
	    close(pip[0]);
	    if (0==fork()) {
	      for (i=0;i<om;i++) {
		if (i!=pip[1]) close(i);
	      }
	      write(pip[1],sbuf,strlen(sbuf));
	      close(pip[1]);
	      exit(0);
	    }
	    close(pip[1]);
	    fcntl(fp->fd,F_SETFD,0);
	  }
	} else {
	  log(LOG_ERR,"pipe: %s",strerror(errno));
	}
	xfree(sbuf);
      } else {
	log(LOG_ERR,"invalid redirection!");
      }
      fp=fp->next;
    }
    log(LOG_INFO,"doing exec '%s'",ap->ex.image);
    execv(ap->ex.image,args);
    log(LOG_ERR,"%s: %s","execv",strerror(errno));
    exit(0);
  }
}

void do_syslog(union Action *ap,struct Rule *rp,elEventRecvData *buf,char *matched) {
  char *sbuf;
  log(LOG_DEBUG,"doing syslog '%s'",ap->log.message);
  sbuf=do_subst(ap->log.message,matched);
  log(LOG_DEBUG,"syslog: '%s'",sbuf);
  syslog(ap->log.facility|ap->log.priority,"%s",sbuf);
  xfree(sbuf);
}

void do_system(union Action *ap,struct Rule *rp,elEventRecvData *buf,char *matched) {
  char *sbuf;
  int rc;
  FILE *wfd;
  log(LOG_DEBUG,"doing system '%s'",ap->sys.cmdline);
  if (fork()) {
    return;
  }

  sbuf=do_subst(ap->sys.cmdline,matched);
  log(LOG_DEBUG,"substituted cmdline: '%s'",sbuf);
  if (NULL!=ap->sys.text) {
    log(LOG_DEBUG,"input: '%s'",ap->sys.text);
    wfd=popen(sbuf,"w");
    if (NULL==wfd) {
      log(LOG_ERR,"popen: %s",strerror(errno));
      exit(0);
    }
    sbuf=do_subst(ap->sys.text,matched);
    log(LOG_DEBUG,"substituted input: '%s'",sbuf);
    fwrite(sbuf,strlen(sbuf),1,wfd);
    rc=pclose(wfd);
  } else {
    rc=system(sbuf);
  }
  if (-1==rc) {
    log(LOG_ERR,"system: %s",strerror(errno));
  } else if (WEXITSTATUS(rc)) {
    log(LOG_WARNING,"non zero exit status: %d",WEXITSTATUS(rc));
  } else {
    log(LOG_INFO,"system: success");
  }
  exit(0);
}


void do_actions (struct Rule *rp,elEventRecvData *buf,char *matched) {
  union Action *ap;
  ap=rp->actions;
  while (ap!=NULL) {
    if (ap->ca.a_type==A_SYSLOG) {
      do_syslog(ap,rp,buf,matched);
    } else if (ap->ca.a_type==A_EXEC) {
      do_exec(ap,rp,buf,matched);
    } else if (ap->ca.a_type==A_SYSTEM) {
      do_system(ap,rp,buf,matched);
    }
    ap=ap->ca.next;
  }
}

void handle_packet(elEventRecvData *buf) {
  int i;
  struct Rule *rp;
  log(LOG_DEBUG,"packet version: %d",buf->version);
  log(LOG_DEBUG,"eventNum: %d",buf->eventNum);
  log(LOG_DEBUG,"timestamp: %d/%d/%d %d:%d:%d",
	  buf->timeStamp.day,buf->timeStamp.mon,buf->timeStamp.year,
	  buf->timeStamp.hour,buf->timeStamp.min,buf->timeStamp.sec);
  log(LOG_DEBUG,"server: %s",buf->serverName);
  log(LOG_DEBUG,"commMethod: %s",buf->commMethod);
  log(LOG_DEBUG,"ownerName: %s",buf->ownerName);
  log(LOG_DEBUG,"address: %s:%s",buf->hlAddress,buf->llAddress);
  log(LOG_DEBUG,"domainName: %s",buf->domainName);
  log(LOG_DEBUG,"schedName: %s",buf->schedName);
  log(LOG_DEBUG,"applType=%d sevCode=%d eventType=%d",
	  buf->applType,buf->sevCode,buf->eventType);

  /* get rid of misterious trailing ~ */
  if ((strlen(buf->event)>0) && ('~'==*((buf->event)+strlen(buf->event)-1))) {
	*(buf->event+strlen(buf->event)-1)=0;
  }
  log(LOG_DEBUG,"%s",buf->event);
  
  rp=config.rules;
  do {
    char *matched;
    if (matched=test_rule(rp,buf)) {
      log(LOG_INFO,"rule '%s' matches",rp->name);
      do_actions(rp,buf,matched);
      if (rp->final) {
        log(LOG_DEBUG,"rule is final");
        break;
      }
    }
  } while (NULL!=(rp=rp->next));
  log(LOG_DEBUG,"end of matching");
  exit(0);
}


