INCLUDES = -I$(top_srcdir)/src/include

if MINGW
 WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols 
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

pkgcfgdir= $(pkgdatadir)/config.d/

pkgcfg_DATA = \
  nse.conf


lib_LTLIBRARIES = libgnunetnse.la

libgnunetnse_la_SOURCES = \
  nse_api.c nse.h
libgnunetnse_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL) $(XLIB)
libgnunetnse_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)  $(WINFLAGS) \
  -version-info 0:0:0


bin_PROGRAMS = \
 gnunet-service-nse 

noinst_PROGRAMS = \
 gnunet-nse-profiler

gnunet_nse_profiler_SOURCES = \
 gnunet-nse-profiler.c         
gnunet_nse_profiler_LDADD = -lm \
  $(top_builddir)/src/nse/libgnunetnse.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(GN_LIBINTL)
gnunet_nse_profiler_DEPENDENCIES = \
  libgnunetnse.la				 

gnunet_service_nse_SOURCES = \
 gnunet-service-nse.c         
gnunet_service_nse_LDADD = \
  $(top_builddir)/src/nse/libgnunetnse.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/core/libgnunetcore.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  -lm \
  $(GN_LIBINTL)
gnunet_service_nse_DEPENDENCIES = \
  libgnunetnse.la				 

if HAVE_BENCHMARKS
  MULTIPEER_TEST = test_nse_multipeer
endif

check_PROGRAMS = \
 test_nse_api \
 $(MULTIPEER_TEST)


if ENABLE_TEST_RUN
TESTS = $(check_PROGRAMS) 
endif

test_nse_api_SOURCES = \
 test_nse_api.c
test_nse_api_LDADD = \
  $(top_builddir)/src/nse/libgnunetnse.la \
  $(top_builddir)/src/util/libgnunetutil.la 

test_nse_multipeer_SOURCES = \
 test_nse_multipeer.c
test_nse_multipeer_LDADD = \
  $(top_builddir)/src/nse/libgnunetnse.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  -lm

EXTRA_DIST = \
  test_nse.conf \
  nse_profiler_test.conf


