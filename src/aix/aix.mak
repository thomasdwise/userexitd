#
# TSM installation directory
TSMDIR=/usr/tivoli/tsm/server/bin
VERSION=0.5
BUILDDIR=./userexitd-$(VERSION)

SYSTEM=aix
MACHINE=powerpc
CC=gcc

CFLAGS=-g -D_THREAD_SAFE -DAIX -O0 -Wall 
SOCFLAGS=-g -D_THREAD_SAFE -DAIX -O0 -Wall
SO64CFLAGS=$(SOFLAGS) -maix64
LD=/usr/ccs/bin/ld
LDFLAGS= 
SOLDFLAGS= -bnoentry -brtl -bnosymbolic -bnortllib -bnoautoexp -bM:SRE -bE:userexit.exp -binitfini:_init:_fini -lc
SO64LDFLAGS= -b64 $(SOLDFLAGS)
# expat library location
LIBEXPAT=../expat-2.0.0/.libs/libexpat.a
INSTALL=installbsd -c

# userexit shared objects:
SONAME=userexit.so
SO64NAME=userexit64.so
# comment out 64 or 32-bit module if you do not need it
SOFILES=$(SONAME) $(SO64NAME)

#PATCH=/opt/freeware/bin/patch
PATCH=patch

# need userExitSample.h and libexpat headers
CC_INCLUDES=-I$(TSMDIR) -I../expat-2.0.0/lib
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

all:	$(SOFILES) userexitd 

install: userexitd $(SONAMES)
	$(INSTALL) -m 755 userexitd $(BINDIR)
	$(INSTALL) -m 755 userexitd.conf.sam $(CONFDIR)
	$(INSTALL) -m 755 $(SONAME) $(TSMDIR) || true
	$(INSTALL) -m 755 $(SO64NAME) $(TSMDIR) || true

$(PATCHNAME): userexit.c
	diff $(TSMDIR)/userExitSample.c userexit.c >$(PATCHNAME) || [ $$? -eq 1 ]

clean:
	rm -f *.o $(SOFILES) userexitd *~ core .*.swp $(PATCHNAME)

# cannot redistribute userexit.c
src-release: clean $(PATCHNAME)
	echo ./userexitd-$(VERSION)/userexit.c >excluded.files
	echo ./userexitd-$(VERSION)/excluded.files >>excluded.files
	echo ./userexitd-$(VERSION)/CVS >>excluded.files
	cd .. && tar -cvXf ./userexitd-$(VERSION)/excluded.files userexitd-$(VERSION)-src.tar  ./userexitd-$(VERSION)
	rm -f excluded.files
	gzip -fv ../userexitd-$(VERSION)-src.tar

bin-release: $(SOFILES) userexitd 
	cd .. && tar -cvf userexitd-$(VERSION)-$(SYSTEM)-$(MACHINE).tar $(BUILDDIR)/userexitd $(BUILDDIR)/*.so $(BUILDDIR)/[A-Z]*.userexitd $(BUILDDIR)/*.conf.sam $(BUILDDIR)/Makefile $(BUILDDIR)/*.mak
	cd .. && gzip -fv userexitd-$(VERSION)-$(SYSTEM)-$(MACHINE).tar

utils.o: utils.c utils.h userexitd.h
	$(CC) $(CFLAGS) $(DEFINES) $(CC_INCLUDES) -c -o $@  $< 

userexitd.o: userexitd.c utils.h userexitd.h
	$(CC) $(CFLAGS) $(DEFINES) $(CC_INCLUDES) -c -o $@  $< 


userexitd: userexitd.o utils.o 
	$(CC) $(CFLAGS) $(LDFLAGS)  -o $@ userexitd.o utils.o $(LIBEXPAT)

$(SONAME): userexit.o 
	$(LD) -o $@ $(SOLDFLAGS) userexit.o

$(SO64NAME): userexit64.o 
	$(LD) -o $@ $(SO64LDFLAGS) userexit64.o

userexit.o: userexit.c
	$(CC) $(SOCFLAGS) -DDEFSOCKET=$(DEFSOCKET) $(CC_INCLUDES) -c -o $@ userexit.c

userexit64.o: userexit.c
	$(CC) $(SO64CFLAGS) -DDEFSOCKET=$(DEFSOCKET) $(CC_INCLUDES) -c -o $@ userexit.c

userexit.c: 
	[ -f userexit.c ] || $(PATCH) -o userexit.c $(TSMDIR)/userExitSample.c < $(PATCHNAME)

