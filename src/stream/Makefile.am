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
  stream_api.c stream.h
libgnunetstream_la_LIBADD = \
 $(top_builddir)/src/mesh/libgnunetmesh.la \
 $(top_builddir)/src/lockmanager/libgnunetlockmanager.la \
 $(top_builddir)/src/statistics/libgnunetstatistics.la \
 $(top_builddir)/src/util/libgnunetutil.la $(XLIB)
libgnunetstream_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS) \
  -version-info 1:0:0

if HAVE_BENCHMARKS
 STREAM_BENCHMARKS = \
 perf_stream_api
endif

check_PROGRAMS = \
 test_stream_2peers \
 test_stream_2peers_halfclose \
 test_stream_local \
 test_stream_big \
 test_stream_sequence_wraparound \
 $(STREAM_BENCHMARKS)

EXTRA_DIST = test_stream_local.conf

if ENABLE_TEST_RUN
TESTS = \
 test_stream_2peers \
 test_stream_2peers_halfclose \
 test_stream_local \
 test_stream_big \
 test_stream_sequence_wraparound \
 $(STREAM_BENCHMARKS)
endif

test_stream_2peers_SOURCES = \
 test_stream_2peers.c
test_stream_2peers_LDADD = \
 $(top_builddir)/src/stream/libgnunetstream.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/testbed/libgnunettestbed.la


test_stream_2peers_halfclose_SOURCES = \
 test_stream_2peers_halfclose.c
test_stream_2peers_halfclose_LDADD = \
 $(top_builddir)/src/stream/libgnunetstream.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/testbed/libgnunettestbed.la

test_stream_local_SOURCES = \
 test_stream_local.c
test_stream_local_LDADD = \
 $(top_builddir)/src/stream/libgnunetstream.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/testing/libgnunettesting.la

test_stream_big_SOURCES = \
 test_stream_big.c
test_stream_big_LDADD = \
 $(top_builddir)/src/stream/libgnunetstream.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/testing/libgnunettesting.la

test_stream_sequence_wraparound_SOURCES = \
 test_stream_sequence_wraparound.c
test_stream_sequence_wraparound_LDADD = \
 $(top_builddir)/src/stream/libgnunetstream.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/testing/libgnunettesting.la

perf_stream_api_SOURCES = \
 perf_stream_api.c
perf_stream_api_LDADD = \
 $(top_builddir)/src/stream/libgnunetstream.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/testbed/libgnunettestbed.la