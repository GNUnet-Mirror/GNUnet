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
  testbed.conf

bin_PROGRAMS = \
  gnunet-service-testbed \
  gnunet-testbed-helper

gnunet_service_testbed_SOURCES = \
  gnunet-service-testbed.c
gnunet_service_testbed_LDADD = $(XLIB) \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/testbed/libgnunettestbed.la \
 $(LTLIBINTL) -lz
gnunet_service_testbed_DEPENDENCIES = \
  libgnunettestbed.la

gnunet_testbed_helper_SOURCES = \
  gnunet-testbed-helper.c
gnunet_testbed_helper_LDADD = $(XLIB) \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(LTLIBINTL) -lz
gnunet_testbed_helper_DEPENDENCIES = \
  gnunet-service-testbed.$(OBJEXT)

lib_LTLIBRARIES = \
  libgnunettestbed.la

libgnunettestbed_la_SOURCES = \
  testbed_api.c testbed_api.h testbed.h \
  testbed_api_hosts.c testbed_api_hosts.h testbed_helper.h \
  testbed_api_operations.c testbed_api_operations.h \
  testbed_api_peers.c testbed_api_peers.h \
  testbed_api_services.c \
  testbed_api_testbed.c \
  testbed_api_test.c \
  testbed_api_topology.c
libgnunettestbed_la_LIBADD = $(XLIB) \
 $(top_builddir)/src/core/libgnunetcore.la \
 $(top_builddir)/src/statistics/libgnunetstatistics.la \
 $(top_builddir)/src/transport/libgnunettransport.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 -lm \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(LTLIBINTL)
libgnunettestbed_la_LDFLAGS = \
 $(GN_LIB_LDFLAGS) \
 -version-info 0:0:0

check_PROGRAMS = \
 test_testbed_api_hosts \
 test_testbed_api \
 test_gnunet_testbed_helper

if ENABLE_TEST_RUN
 TESTS = \
   test_testbed_api_hosts \
   test_testbed_api \
   test_gnunet_testbed_helper
endif

test_testbed_api_hosts_SOURCES = \
 test_testbed_api_hosts.c
test_testbed_api_hosts_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettestbed.la

test_testbed_api_SOURCES = \
 test_testbed_api.c
test_testbed_api_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/testing/libgnunettesting.la \
 libgnunettestbed.la

test_gnunet_testbed_helper_SOURCES = \
 test_gnunet_testbed_helper.c
test_gnunet_testbed_helper_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettestbed.la
