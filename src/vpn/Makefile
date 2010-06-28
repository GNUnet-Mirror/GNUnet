CFLAGS=-Wall -pedantic --std=c99 -g
CXXFLAGS = ${CFLAGS}

LDFLAGS =

.PHONY: .dependencies

all: default

default: .dependencies test

test: test.o tun.o packet.o debug.o pretty-print.o tcp.o

.dependencies:
	echo > .dependencies
	gcc -M *.c >> .dependencies

-include .dependencies

clean:
	rm -f *.o
	rm -f test
