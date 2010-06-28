CFLAGS=-Wall -pedantic --std=c99 -g
CXXFLAGS = ${CFLAGS}

LDFLAGS =

all:default

default: test

test: test.o tun.o packet.o debug.o pretty-print.o

clean:
	rm -f *.o
	rm -f test
