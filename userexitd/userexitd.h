#ifndef USEREXITD_H 
#define USEREXITD_H

#ifndef DEFSOCKET
#define DEFSOCKET "unix:/var/run/userexitd.sock"
#endif

#ifndef DEFPIDFILE
#define DEFPIDFILE "/var/run/userexitd.pid"
#endif

#ifndef DEFIDENT
#define DEFIDENT "TSM"
#endif 

#ifndef DEFCFG
#define DEFCFG "/opt/tivoli/tsm/server/bin/userexitd.conf"
#endif

/*
  TODO: get rid of fixed limits
*/
#define MAXMATCH 20
#define MAXARGS 100

typedef struct Config {
  char *address;
  char *pidfile;
  char *sockpath;
  int faccode;
  int priocode;
  char *ident;
  int ll;
  int foreground;
  struct Rule *rules ;
} config_t;

enum DATATYPE {
  INT16_T,
  INT32_T,
  TS_T,
  UCHAR_T
};

typedef  struct Pattern_Type {
  char *name;
  enum DATATYPE datatype;
  void *ptr;
  int length;
  struct _code *dictionary;
} pattern_type_t;



typedef struct Pattern {
  struct Pattern *next;
  struct Pattern_Type *ptype;
  regex_t preg;
  int pflags;
} pattern_t;

enum A_TYPE {
  A_EXEC,A_SYSLOG,A_SYSTEM
};

typedef struct Ca {
  enum A_TYPE a_type;
  union Action *next;
} ca_t;

typedef struct Iof {
  struct Iof *next;
  int fd;
  char *mode;
  char *filename;
  char *text;
  signed int *fdup;
} iof_t;


typedef struct Exec {
  enum A_TYPE a_type;
  union Action *next;
  char *image;
  char **args;
  iof_t  *iofiles;
} exec_t;

typedef struct System {
  enum A_TYPE a_type;
  union Action *next;
  char *cmdline;
  char *text;
} system_t;

typedef struct Syslog {
  enum A_TYPE a_type;
  union Action *next;
  int priority;
  int facility;
  char *message;
} syslog_t;

typedef union Action {
  struct Ca ca;
  struct Exec ex;
  struct Syslog log;
  struct System sys;
} action_t;

typedef struct Counter {
  struct Counter *next;
  char *name;
  int number;
  char *str;
  struct count *counts;
} counter_t;


struct count {
  struct Count *next;
  int cnt;
  char *str;
};

typedef struct Rule {
  char *name;
  struct Rule *next;
  struct Pattern *patterns;
  union Action *actions;
  struct Counter *counters;
  int final;
  int disabled;

} rule_t;

#endif
