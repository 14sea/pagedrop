CC ?= gcc
CFLAGS ?= -O0 -Wall
LDFLAGS ?= -pthread

.PHONY: all clean

all: capture sigsegv.out simple upxtest extra

capture: capture.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

sigsegv.out: sigsegv.c
	$(CC) $(CFLAGS) -o $@ $<

simple: simple.c
	$(CC) $(CFLAGS) -o $@ $<

upxtest: upxtest.c
	$(CC) $(CFLAGS) -static -no-pie -o $@ $<

extra: extra.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f capture sigsegv.out simple upxtest upxtest.orig extra
