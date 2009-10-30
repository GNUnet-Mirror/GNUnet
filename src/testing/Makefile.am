INCLUDES = -I$(top_srcdir)/src/include

if MINGW
  WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

lib_LTLIBRARIES = libgnunettesting.la

libgnunettesting_la_SOURCES = \
  testing.c  \
  testing_group.c \
  testing_testbed.c 
libgnunettesting_la_LIBADD = $(XLIB) \
 $(top_builddir)/src/core/libgnunetcore.la \
 $(top_builddir)/src/transport/libgnunettransport.la \
 $(top_builddir)/src/util/libgnunetutil.la 

check_PROGRAMS = \
 test_testing \
 test_testing_connect

TESTS = test_testing
# $(check_PROGRAMS)

test_testing_SOURCES = \
 test_testing.c
test_testing_LDADD = \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/util/libgnunetutil.la  

test_testing_connect_SOURCES = \
 test_testing_connect.c
test_testing_connect_LDADD = \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/util/libgnunetutil.la  

EXTRA_DIST = \
 test_testing_data.conf \
 test_testing_connect_peer1.conf \
 test_testing_connect_peer2.conf 
