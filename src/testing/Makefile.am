INCLUDES = -I$(top_srcdir)/src/include

if MINGW
  WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

pkgcfgdir= $(pkgdatadir)/config.d/

dist_pkgcfg_DATA = \
  testing.conf

lib_LTLIBRARIES = \
  libgnunettesting.la 

libgnunettesting_la_SOURCES = \
  testing.c  
libgnunettesting_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/arm/libgnunetarm.la \
 $(LTLIBINTL)
libgnunettesting_la_LDFLAGS = \
 $(GN_LIB_LDFLAGS) \
 -version-info 2:0:1

bin_PROGRAMS = \
 gnunet-testing-run-service \
 gnunet-testing


gnunet_testing_run_service_SOURCES = \
 gnunet-testing-run-service.c

gnunet_testing_run_service_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(GN_LIBINTL)
gnunet_testing_run_service_DEPENDENCIES = \
  libgnunettesting.la

gnunet_testing_SOURCES = \
 gnunet-testing.c         
gnunet_testing_LDADD = \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(GN_LIBINTL)
gnunet_testing_DEPENDENCIES = \
 libgnunettesting.la


check_PROGRAMS = \
 test_testing_portreservation \
 test_testing_servicestartup \
 test_testing_peerstartup \
 test_testing_peerstartup2 \
 test_testing_sharedservices

if ENABLE_TEST_RUN 
TESTS = \
 test_testing_portreservation \
 test_testing_peerstartup \
 test_testing_peerstartup2 \
 test_testing_servicestartup
endif

test_testing_portreservation_SOURCES = \
 test_testing_portreservation.c
test_testing_portreservation_LDADD = \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/util/libgnunetutil.la

test_testing_peerstartup_SOURCES = \
 test_testing_peerstartup.c
test_testing_peerstartup_LDADD = \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/util/libgnunetutil.la

test_testing_peerstartup2_SOURCES = \
 test_testing_peerstartup2.c
test_testing_peerstartup2_LDADD = \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/util/libgnunetutil.la

test_testing_servicestartup_SOURCES = \
 test_testing_servicestartup.c
test_testing_servicestartup_LDADD = \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/util/libgnunetutil.la

test_testing_sharedservices_SOURCES = \
 test_testing_sharedservices.c
test_testing_sharedservices_LDADD = \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/util/libgnunetutil.la

EXTRA_DIST = \
  test_testing_defaults.conf

