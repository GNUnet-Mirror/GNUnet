INCLUDES = -I$(top_srcdir)/src/include

if MINGW
  WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

lib_LTLIBRARIES = libgnunetstream.la

libgnunetstream_la_SOURCES = \
  stream_api.c stream_protocol.h
libgnunetstream_la_LIBADD = \
 $(top_builddir)/src/mesh/libgnunetmesh.la \
 $(top_builddir)/src/util/libgnunetutil.la $(XLIB)
libgnunetstream_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)

check_PROGRAMS = \
 test_stream_local 
# test_stream_halfclose

EXTRA_DIST = test_stream_local.conf

if ENABLE_TEST_RUN
TESTS = $(check_PROGRAMS)
endif

test_stream_local_SOURCES = \
 test_stream_local.c
test_stream_local_LDADD = \
 $(top_builddir)/src/stream/libgnunetstream.la \
 $(top_builddir)/src/util/libgnunetutil.la  

#test_stream_halfclose_SOURCES = \
# test_stream_halfclose.c
#test_stream_halfclose_LDADD = \
# $(top_builddir)/src/stream/libgnunetstream.la \
# $(top_builddir)/src/util/libgnunetutil.la  

