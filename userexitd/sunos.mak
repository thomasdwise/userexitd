#
# TSM installation directory
TSMDIR=/opt/tivoli/tsm/server/bin
VERSION=0.5
BUILDDIR=./userexitd-$(VERSION)
#
SYSTEM:sh=uname -s|tr '[A-Z]' '[a-z]'

MACHINE:sh=uname -p|tr '[A-Z]' '[a-z]'

#

CC=gcc
CFLAGS=-g -D_REENTRANT -DSOLARIS -O0 -Wall 
# use the following to compile 64 bit binaries with the Sun's compiler
# (hint by Uday Bidikar)
#CFLAGS=-m64 -xcode=abs64
LD=/usr/ccs/bin/ld
LDFLAGS=-lsocket -lnsl -lresolv
SOLDFLAGS=-dy -G  -lc -lsocket -lnsl -lresolv
LIBEXPAT=/opt/sfw/lib/libexpat.a
INSTALL=install
SONAME=userexit.so

# need userExitSample.h 
CC_INCLUDES=-I$(TSMDIR)
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

all:	$(SONAME) userexitd 

install: userexitd $(SONAME)
	$(INSTALL) -m 755 userexitd $(BINDIR)
	$(INSTALL) -m 755 $(SONAME) $(TSMDIR)
	$(INSTALL) -m 755 userexitd.conf.sam $(CONFDIR)

$(PATCHNAME): userexit.c
	diff -u $(TSMDIR)/userExitSample.c userexit.c >$(PATCHNAME) || [ $$? -eq 1 ]

clean:
	rm -f *.o $(SONAME) userexitd *~ core .*.swp $(PATCHNAME)

# cannot redistribute userexit.c
src-release: clean $(PATCHNAME)
	echo ./userexitd-$(VERSION)/userexit.c >excluded.files
	echo ./userexitd-$(VERSION)/excluded.files >>excluded.files
	echo ./userexitd-$(VERSION)/CVS >>excluded.files
	cd .. && tar -cvXf ./userexitd-$(VERSION)/excluded.files userexitd-$(VERSION)-src.tar  ./userexitd-$(VERSION)
	rm -f excluded.files
	gzip -fv ../userexitd-$(VERSION)-src.tar

bin-release: $(SONAME) userexitd 
	cd .. && tar -cvf userexitd-$(VERSION)-$(SYSTEM)-$(MACHINE).tar $(BUILDDIR)/userexitd $(BUILDDIR)/$(SONAME) $(BUILDDIR)/[A-Z]*.userexitd $(BUILDDIR)/*.conf.sam $(BUILDDIR)/Makefile $(BUILDDIR)/*.mak
	cd .. && gzip -fv userexitd-$(VERSION)-$(SYSTEM)-$(MACHINE).tar

utils.o: utils.c utils.h userexitd.h
	$(CC) $(CFLAGS) $(DEFINES) $(CC_INCLUDES) -c -o $@  $< 

userexitd.o: userexitd.c utils.h userexitd.h
	$(CC) $(CFLAGS) $(DEFINES) $(CC_INCLUDES) -c -o $@  $< 


userexitd: userexitd.o utils.o 
	$(CC) $(CFLAGS) $(LDFLAGS)  -o $@ $^ $(LIBEXPAT)

$(SONAME): userexit.o 
	$(LD) -o $@ $(SOLDFLAGS) userexit.o

userexit.o: userexit.c
	$(CC) $(CFLAGS) -DDEFSOCKET=$(DEFSOCKET) $(CC_INCLUDES) -c -o $@ $<

userexit.c: 
	[ -f userexit.c ] || patch -o userexit.c $(TSMDIR)/userExitSample.c < $(PATCHNAME) 

