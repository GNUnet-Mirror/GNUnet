INCLUDES = -I$(top_srcdir)/src/include

if MINGW
  WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

lib_LTLIBRARIES = libgnunethello.la

libgnunethello_la_SOURCES = \
  hello.c address.c
libgnunethello_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la $(XLIB)
libgnunethello_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS) \
  -version-info 0:0:0

noinst_PROGRAMS = \
 gnunet-hello

check_PROGRAMS = \
 test_hello

if ENABLE_TEST_RUN
TESTS = $(check_PROGRAMS)
endif

test_hello_SOURCES = \
 test_hello.c
test_hello_LDADD = \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la  


gnunet_hello_SOURCES = \
 gnunet-hello.c
gnunet_hello_LDADD = \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la  
gnunet_hello_DEPENDENCIES = \
 libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la

