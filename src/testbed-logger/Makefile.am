# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

if MINGW
  WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

libexecdir= $(pkglibdir)/libexec/

pkgcfgdir= $(pkgdatadir)/config.d/

pkgcfg_DATA = \
  testbed-logger.conf

libexec_PROGRAMS = \
  gnunet-service-testbed-logger

gnunet_service_testbed_logger_SOURCES = \
  gnunet-service-testbed-logger.c
gnunet_service_testbed_logger_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la

lib_LTLIBRARIES = \
  libgnunettestbedlogger.la

libgnunettestbedlogger_la_SOURCES = \
  testbed_logger_api.c
libgnunettestbedlogger_la_LIBADD = $(XLIB) \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(LTLIBINTL)
libgnunettestbedlogger_la_LDFLAGS = \
 $(GN_LIB_LDFLAGS) \
 -version-info 0:0:0

check_PROGRAMS = \
  test_testbed_logger_api

if ENABLE_TEST_RUN
 AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;
 TESTS = \
  test_testbed_logger_api
endif

test_testbed_logger_api_SOURCES = \
 test_testbed_logger_api.c
test_testbed_logger_api_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/testing/libgnunettesting.la \
 libgnunettestbedlogger.la

EXTRA_DIST = \
  test_testbed_logger_api.conf
