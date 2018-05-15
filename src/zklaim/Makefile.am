# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

if MINGW
  WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

bin_PROGRAMS = \
 gnunet-zklaim

gnunet_zklaim_SOURCES = \
 main.c
gnunet_zklaim_LDFLAGS = -rdynamic
gnunet_zklaim_LDADD = \
 -lzklaim \
 -lgcrypt \
 -lsnark \
 -lff \
 -lgmp \
 -lgmpxx \
 -lcrypto \
 -lprocps \
 -lzm \
 -lstdc++ \
 -lm

