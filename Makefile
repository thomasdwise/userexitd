#
# global options
# TSM installation directory
TSMDIR=/opt/tivoli/tsm/server/bin
VERSION=0.5
BUILDDIR=./userexitd-$(VERSION)
#
SYSTEM=$(shell uname -s|tr '[A-Z]' '[a-z]')

ifeq ($(SYSTEM),linux)
MACHINE=$(shell uname -m|tr '[A-Z]' '[a-z]')
else
MACHINE=$(shell uname -p|tr '[A-Z]' '[a-z]')
endif

# LINUX options
ifeq ($(SYSTEM),linux)
CC=gcc
CFLAGS= -g -D_REENTRANT -D__linux -O0 -Wall -DHAVE_DAEMON -DHAVE_SYSLOG_NAMES -DHAVE_GETOPT_H -D_GNU_SOURCE
LD=ld
SOLDFLAGS= -shared -E
LDFLAGS= 
LIBEXPAT=/usr/lib/libexpat.a
INSTALL=install
SONAME=userexit.so
SONAMES=$(SONAME)
CC_INCLUDES=
PATCH=patch
DIFF=diff -u
endif

# SOLARIS options
ifeq ($(SYSTEM),sunos)
CC=gcc
CFLAGS=-g -D_REENTRANT -DSOLARIS -O0 -Wall 
LD=/usr/ccs/bin/ld
LDFLAGS=-lsocket -lnsl -lresolv
SOLDFLAGS=-dy -G -lc -lsocket -lnsl -lresolv
LIBEXPAT=/opt/sfw/lib/libexpat.a
INSTALL=install
SONAME=userexit.so
SONAMES=$(SONAME)
CC_INCLUDES=
PATCH=patch
DIFF=diff -u
endif

# AIX options
ifeq ($(SYSTEM),aix)
#TSMDIR=/usr/tivoli/tsm/server/bin
CC=gcc
CFLAGS=-g -D_THREAD_SAFE -DAIX -O0 -Wall 
CFLAGS64=$(CFLAGS) -maix64
LD=/usr/ccs/bin/ld
LDFLAGS=
SOLDFLAGS= -bnoentry -brtl -bnosymbolic -bnortllib -bnoautoexp -bM:SRE -bE:userexit.exp -binitfini:_init:_fini -lc
SOLDFLAGS64= -b64 $(SOLDFLAGS)
LIBEXPAT=../expat-2.0.0/.libs/libexpat.a
INSTALL=installbsd
SONAME=userexit.so
SONAME64=userexit64.so
# You may want to build only one module
SONAMES=$(SONAME) $(SONAME64)
CC_INCLUDES= -I../expat-2.0.0/lib
PATCH=patch
# aix diff/patch does not know unified format
DIFF=diff
endif

# probably you do not want to change anything below this line
#
# need userExitSample.h 
CC_INCLUDES+=-I$(TSMDIR)
BINDIR=$(TSMDIR)
USEREXITDIR=$(TSMDIR)
CONFDIR=$(TSMDIR)
PATCHNAME=userexit.$(SYSTEM).patch

# default unix socket path
DEFSOCKET=\"unix:/var/run/userexitd.sock\"
DEFPIDFILE=\"/var/run/userexitd.pid\"
DEFIDENT=\"TSM\"
DEFCFG=\"$(TSMDIR)/userexitd.conf\"

DEFINES=-DUSEREXITD_VERSION=\"$(VERSION)\" -DDEFAULTSOCKET=$(DEFSOCKET) -DDEFAULTPIDFILE=$(DEFPIDFILE) -DDEFINDENT=$(DEFIDENT) -DDEFCFG=$(DEFCFG) 

all:	$(SONAMES) userexitd 

install: userexitd $(SONAMES)
	$(INSTALL) -m 755 userexitd $(BINDIR)
	$(INSTALL) -m 755 userexitd.conf.sam $(CONFDIR)
	for SO in $(SONAMES); do $(INSTALL) -m 755 $$SO $(TSMDIR); done

$(PATCHNAME): userexit.c
	$(DIFF) $(TSMDIR)/userExitSample.c userexit.c >$(PATCHNAME) || [ $$? -eq 1 ]

clean:
	rm -f *.o $(SONAMES) userexitd *~ core .*.swp $(PATCHNAME)

# cannot redistribute userexit.c
src-release: clean $(PATCHNAME)
	echo ./userexitd-$(VERSION)/userexit.c >excluded.files
	echo ./userexitd-$(VERSION)/excluded.files >>excluded.files
	echo ./userexitd-$(VERSION)/CVS >>excluded.files
ifeq ($(SYSTEM),linux)
	cd .. && tar -hcvf userexitd-$(VERSION)-src.tar -X ./userexitd-$(VERSION)/excluded.files ./userexitd-$(VERSION)/
else
	cd .. && tar -cvXf ./userexitd-$(VERSION)/excluded.files userexitd-$(VERSION)-src.tar  ./userexitd-$(VERSION)/
endif
	rm -f excluded.files
	gzip -fv ../userexitd-$(VERSION)-src.tar

bin-release: $(SONAMES) userexitd 
	cd .. && tar -cvf userexitd-$(VERSION)-$(SYSTEM)-$(MACHINE).tar $(BUILDDIR)/userexitd $(BUILDDIR)/*.so $(BUILDDIR)/[A-Z]*.userexitd $(BUILDDIR)/*.conf.sam $(BUILDDIR)/Makefile $(BUILDDIR)/*.mak $(BUILDDIR)/[A-Z]*.init.*
	cd .. && gzip -fv userexitd-$(VERSION)-$(SYSTEM)-$(MACHINE).tar

utils.o: utils.c utils.h userexitd.h
	$(CC) $(CFLAGS) $(DEFINES) $(CC_INCLUDES) -c -o $@  $< 

userexitd.o: userexitd.c utils.h userexitd.h
	$(CC) $(CFLAGS) $(DEFINES) $(CC_INCLUDES) -c -o $@  $< 


userexitd: userexitd.o utils.o 
	$(CC) $(CFLAGS) $(LDFLAGS)  -o $@ $^ $(LIBEXPAT)

$(SONAME): userexit.o 
	$(LD) -o $@ $(SOLDFLAGS) userexit.o

ifeq ($(SYSTEM),aix)

userexit64.o: userexit.c
	$(CC) $(CFLAGS64) -DDEFSOCKET=$(DEFSOCKET) $(CC_INCLUDES) -c -o $@ $<

$(SONAME64): userexit64.o 
	$(LD) -o $@ $(SOLDFLAGS64) userexit64.o

endif


userexit.o: userexit.c
	$(CC) $(CFLAGS) -DDEFSOCKET=$(DEFSOCKET) $(CC_INCLUDES) -c -o $@ $<

userexit.c: 
	[ -f userexit.c ] || (cp $(TSMDIR)/userExitSample.c . && $(PATCH) -i $(PATCHNAME) -o userexit.c userExitSample.c  && rm userExitSample.c )

