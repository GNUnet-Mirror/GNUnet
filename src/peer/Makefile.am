INCLUDES = -I$(top_srcdir)/src/include

if MINGW
  WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

lib_LTLIBRARIES = libgnunetpeer.la

libgnunetpeer_la_SOURCES = \
  peer.c 
libgnunetpeer_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la $(XLIB)

#check_PROGRAMS = \
# test_peer
#
#TESTS = $(check_PROGRAMS)
#
#test_peer_SOURCES = \
# test_peer.c
#test_peer_LDADD = \
# $(top_builddir)/src/peer/libgnunetpeer.la \
# $(top_builddir)/src/util/libgnunetutil.la  

