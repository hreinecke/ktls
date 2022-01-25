
KTLSD = ktlsd
TLSKEY = tls_key
PROGRAMS = $(KTLSD) $(TLSKEY)
KTLSD_OBJS = main.o log.o handshake.o
TLSKEY_OBJS = tls_key.o
CFLAGS = -Wall -g -D_GNU_SOURCE

all: $(PROGRAMS)

$(KTLSD): $(KTLSD_OBJS)
	$(CC) $(CFLAGS) -o $@ $(KTLSD_OBJS) -lssl -lcrypto -lkeyutils

$(TLSKEY): $(TLSKEY_OBJS)
	$(CC) $(CFLAGS) -o $@ $(TLSKEY_OBJS) -lssl -lcrypto -lz -lkeyutils

%.o: %.c tlshd.h
	$(CC) $(CFLAGS) -c -o $@ $<
