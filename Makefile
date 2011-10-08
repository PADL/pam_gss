KRB5DIR=/usr/local
KRB5CFLAGS=$(shell $(KRB5DIR)/bin/krb5-config gssapi --cflags)
KRB5LIBS=$(shell $(KRB5DIR)/bin/krb5-config gssapi --libs)

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

