KRB5DIR=/usr/local

ifeq ($(wildcard /System/Library/Frameworks/GSS.framework),)
KRB5CFLAGS=$(shell $(KRB5DIR)/bin/krb5-config gssapi --cflags)
KRB5LIBS=$(shell $(KRB5DIR)/bin/krb5-config gssapi --libs)
else
KRB5CFLAGS=
KRB5LIBS=-framework GSS -F/System/Library/PrivateFrameworks -framework Heimdal -framework CoreFoundation
endif

CFLAGS=-Wall -g $(KRB5CFLAGS)
LDFLAGS=$(KRB5LIBS) -lpam

# detect whether we're on Linux and on a 64-bit platform
IS_LINUX_64 := $(shell uname -s)_$(shell uname -p)
ifeq ($(IS_LINUX_64),Linux_x86_64)
CFLAGS += -fPIC
endif
INSTDIR := $(R)/usr/lib/pam

all: pam_gss.so pamtest

pam_gss.so: pam_gss.o
	cc -g -shared -o $@ $? $(LDFLAGS)

pamtest: pamtest.o
	cc -o $@ $? $(LDFLAGS)

clean:
	rm -f pam_gss.so pamtest *.o

install: | $(INSTDIR)
	cp pam_gss.so $(INSTDIR)

$(INSTDIR):
	mkdir -p $(INSTDIR)
