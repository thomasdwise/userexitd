#
# TSM installation directory
TSMDIR=/opt/tivoli/tsm/server/bin
#
CC = gcc
#
CFLAGS = -g -D_REENTRANT -D__linux -w -O0 -Wall
SOLDFLAGS= -shared -E
LDFLAGS= 
VERSION=0.2
# 

# need userExitSample.h 
CC_INCLUDES=-I$(TSMDIR)
BINDIR=$(TSMDIR)
USEREXITDIR=$(TSMDIR)
CONFDIR=$(TSMDIR)

# default unix socket path
DEFSOCKET=\"unix:/var/run/userexitd.sock\"
DEFPIDFILE=\"/var/run/userexitd.pid\"
DEFIDENT=\"TSM\"
DEFCFG=\"$(TSMDIR)/userexitd.conf\"

DEFINES=-DUSEREXITD_VERSION=\"$(VERSION)\" -D_POSIX_SOURCE -DDEFAULTSOCKET=$(DEFSOCKET) -DDEFAULTPIDFILE=$(DEFPIDFILE) -DDEFINDENT=$(DEFIDENT) -DDEFCFG=$(DEFCFG) 

all:	userexit.so userexitd 

install: userexitd userexit.so
	install -m 700 userexitd $(BINDIR)
	install -m 700 userexit.so $(TSMDIR)
	install -m 700 userexitd.conf.sam $(CONFDIR)

userexit.patch: userexit.c
	diff -u $(TSMDIR)/userExitSample.c userexit.c >userexit.patch || [ $$? == 1 ]

clean:
	rm -f *.o *.so userexitd *~ core .*.swp userexit.patch

# cannot redistribute userexit.c
src-release: clean userexit.patch 
	cd .. && tar -cvzf userexitd-$(VERSION)-src.tar.gz --exclude ./userexitd-$(VERSION)/userexit.c ./userexitd-$(VERSION)/

bin-release: userexit.so userexitd 
	cd .. && tar -czvf userexitd-$(VERSION)-`uname -s|tr A-Z a-z`-`uname -m|tr A-Z a-z`.tar.gz ./userexitd-$(VERSION)/userexitd ./userexitd-$(VERSION)/userexit.so ./userexitd-$(VERSION)/INSTALL.* ./userexitd-$(VERSION)/README.* ./userexitd-$(VERSION)/Makefile ./userexitd-$(VERSION)/TODO.* ./userexitd-$(VERSION)/*.conf.sam

utils.o: utils.c utils.h userexitd.h
	$(CC) $(CFLAGS) $(DEFINES) -DSYSLOG_NAMES $(CC_INCLUDES) -c -o $@  $< 

userexitd.o: userexitd.c utils.h userexitd.h
	$(CC) $(CFLAGS) $(DEFINES) $(CC_INCLUDES) -c -o $@  $< 


userexitd: userexitd.o utils.o 
	$(CC) $(CFLAGS) $(LDFLAGS)  -o $@ $^ /usr/lib/libexpat.a

userexit.so: userexit.o 
	$(LD) -o $@ $(SOLDFLAGS) $<

userexit.o: userexit.c
	$(CC) $(CFLAGS) -DDEFSOCKET=$(DEFSOCKET) $(CC_INCLUDES) -c -o $@ $<

userexit.c: 
	[ -f userexit.c ] || patch  -o userexit.c $(TSMDIR)/userExitSample.c userexit.patch 
