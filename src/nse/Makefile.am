# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

if MINGW
 WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

pkgcfg_DATA = \
  nse.conf

bin_PROGRAMS = gnunet-nse

gnunet_nse_SOURCES = gnunet-nse.c
gnunet_nse_LDADD = \
  libgnunetnse.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(XLIB) $(GN_LIBINTL)

lib_LTLIBRARIES = libgnunetnse.la

libgnunetnse_la_SOURCES = \
  nse_api.c nse.h
libgnunetnse_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL) $(XLIB)
libgnunetnse_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)  $(WINFLAGS) \
  -version-info 0:0:0


libexec_PROGRAMS = \
 gnunet-service-nse

if HAVE_TESTING
noinst_PROGRAMS = \
 gnunet-nse-profiler
endif

gnunet_nse_profiler_SOURCES = \
 gnunet-nse-profiler.c
gnunet_nse_profiler_LDADD = -lm \
  libgnunetnse.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/testbed/libgnunettestbed.la \
  $(GN_LIBINTL)

gnunet_service_nse_SOURCES = \
 gnunet-service-nse.c
gnunet_service_nse_LDADD = \
  libgnunetnse.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/core/libgnunetcore.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(LIBGCRYPT_LIBS) \
  -lm -lgcrypt \
  $(GN_LIBINTL)
if ENABLE_NSE_HISTOGRAM
  gnunet_service_nse_LDADD += \
    $(top_builddir)/src/testbed/libgnunettestbedlogger.la
endif


if HAVE_BENCHMARKS
  MULTIPEER_TEST = test_nse_multipeer
endif

if HAVE_TESTING
check_PROGRAMS = \
 test_nse_api \
 perf_kdf \
 $(MULTIPEER_TEST)
endif

if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;
TESTS = $(check_PROGRAMS)
endif

test_nse_api_SOURCES = \
 test_nse_api.c
test_nse_api_LDADD = \
  libgnunetnse.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la

test_nse_multipeer_SOURCES = \
 test_nse_multipeer.c
test_nse_multipeer_LDADD = \
  libgnunetnse.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testbed/libgnunettestbed.la \
  -lm

perf_kdf_SOURCES = \
 perf_kdf.c
perf_kdf_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(LIBGCRYPT_LIBS) \
  -lgcrypt

EXTRA_DIST = \
  test_nse.conf \
  nse_profiler_test.conf


