uname_S := $(shell sh -c 'uname -s 2>/dev/null || echo not')

CC=gcc
CFLAGS=-m64 -g -O2 -Wall

ifeq ($(uname_S),Linux)
		CFLAGS+=-DHAVE_THREAD_TLS
endif
#CFLAGS+=-DWITH_DICTIONARY_WARNINGS
CFLAGS+=-DHAVE_STRUCT_SOCKADDR_IN6

all:libmyradclient.a 
test:libmyradclient.a example.o

OBJS=radclient.o dict.o md5.o misc.o \
	 	packet.o radius.o rbtree.o valuepair.o log.o \
			print.o hash.o mschap.o smbdes.o token.o hmac.o \
				sha1.o isaac.o md4.o radeap.o
#eap library
OBJS+=eapcommon.o eapcrypto.o eapsimlib.o hmacsha1.o \
	  	 fips186prf.o

libmyradclient.a:$(OBJS)
	ar -rv libmyradclient.a $(OBJS)
radclient.o:radclient.c
	$(CC) $(CFLAGS) -c radclient.c
radeap.o:radeap.c
	$(CC) $(CFLAGS) -c radeap.c
dict.o:dict.c
	$(CC) $(CFLAGS) -c dict.c
md5.o:md5.c
	$(CC) $(CFLAGS) -c md5.c
misc.o:misc.c
	$(CC) $(CFLAGS) -c misc.c
packet.o:packet.c
	$(CC) $(CFLAGS) -c packet.c
radius.o:radius.c
	$(CC) $(CFLAGS) -c radius.c
rbtree.o:rbtree.c
	$(CC) $(CFLAGS) -c rbtree.c
valuepair.o:valuepair.c
	$(CC) $(CFLAGS) -c valuepair.c
print.o:print.c
	$(CC) $(CFLAGS) -c print.c
hash.o:hash.c
	$(CC) $(CFLAGS) -c hash.c
mschap.o:mschap.c
	$(CC) $(CFLAGS) -c mschap.c
smbdes.o:smbdes.c
	$(CC) $(CFLAGS) -c smbdes.c
token.o:token.c
	$(CC) $(CFLAGS) -c token.c
hmac.o:hmac.c
	$(CC) $(CFLAGS) -c hmac.c
sha1.o:sha1.c
	$(CC) $(CFLAGS) -c sha1.c
isaac.o:isaac.c
	$(CC) $(CFLAGS) -c isaac.c
md4.o:md4.c
	$(CC) $(CFLAGS) -c md4.c
log.o:log.c
	$(CC) $(CFLAGS) -c log.c
eapcommon.o:eapcommon.c
	$(CC) $(CFLAGS) -c eapcommon.c
eapcrypto.o:eapcrypto.c
	$(CC) $(CFLAGS) -c eapcrypto.c
fips186prf.o:fips186prf.c
	$(CC) $(CFLAGS) -c fips186prf.c
hmacsha1.o:hmacsha1.c
	$(CC) $(CFLAGS) -c hmacsha1.c
eapsimlib.o:eapsimlib.c
	$(CC) $(CFLAGS) -c eapsimlib.c
example.o:example.c
	$(CC) $(CFLAGS) -c example.c

example:example.o libmyradclient.a
	$(CC) $(CFLAGS) -o example example.o libmyradclient.a

.PHONY:clean
clean:
	rm -rf *.o libmyradclient.a example

	
