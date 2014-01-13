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

all: pam_gss.so pamtest

pam_gss.so: pam_gss.o
	cc -g -shared -o $@ $? $(LDFLAGS)

pamtest: pamtest.o
	cc -o $@ $? $(LDFLAGS)

clean:
	rm -f pam_gss.so pamtest *.o

install:
	cp pam_gss.so /usr/lib/pam

