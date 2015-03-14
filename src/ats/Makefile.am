# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

plugindir = $(libdir)/gnunet

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

pkgcfg_DATA = \
  ats.conf

if MINGW
 WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols
endif

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif

lib_LTLIBRARIES = libgnunetats.la

plugin_LTLIBRARIES = \
  libgnunet_plugin_ats_proportional.la \
  $(GN_MLP_LIB) \
  libgnunet_plugin_ats_ril.la

if HAVE_LIBGLPK
plugin_LTLIBRARIES += \
  libgnunet_plugin_ats_mlp.la
endif

libgnunetats_la_SOURCES = \
  ats_api_connectivity.c \
  ats_api_scanner.c \
  ats_api_scheduling.c \
  ats_api_performance.c
libgnunetats_la_LIBADD = \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(LTLIBINTL)
libgnunetats_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)  $(WINFLAGS) \
  -version-info 4:0:0

libgnunet_plugin_ats_proportional_la_SOURCES = \
  plugin_ats_proportional.c
libgnunet_plugin_ats_proportional_la_LIBADD = \
  libgnunetats.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(LTLIBINTL)
libgnunet_plugin_ats_proportional_la_LDFLAGS = \
  $(GN_PLUGIN_LDFLAGS)


if HAVE_LIBGLPK
libgnunet_plugin_ats_mlp_la_SOURCES = \
  plugin_ats_mlp.c
libgnunet_plugin_ats_mlp_la_LIBADD = \
  libgnunetats.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la
libgnunet_plugin_ats_mlp_la_LDFLAGS = \
  $(GN_PLUGIN_LDFLAGS) \
  -lglpk
endif

libgnunet_plugin_ats_ril_la_SOURCES = \
  plugin_ats_ril.c
libgnunet_plugin_ats_ril_la_LIBADD = \
  libgnunetats.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(LTLIBINTL)
libgnunet_plugin_ats_ril_la_LDFLAGS = \
  $(GN_PLUGIN_LDFLAGS)

libexec_PROGRAMS = \
 gnunet-service-ats

gnunet_service_ats_SOURCES = \
 gnunet-service-ats.c gnunet-service-ats.h \
 gnunet-service-ats_addresses.c gnunet-service-ats_addresses.h \
 gnunet-service-ats_connectivity.c gnunet-service-ats_connectivity.h \
 gnunet-service-ats_feedback.c gnunet-service-ats_feedback.h \
 gnunet-service-ats_normalization.c gnunet-service-ats_normalization.h \
 gnunet-service-ats_performance.c gnunet-service-ats_performance.h \
 gnunet-service-ats_plugins.c gnunet-service-ats_plugins.h \
 gnunet-service-ats_preferences.c gnunet-service-ats_preferences.h \
 gnunet-service-ats_scheduling.c gnunet-service-ats_scheduling.h \
 gnunet-service-ats_reservations.c gnunet-service-ats_reservations.h
gnunet_service_ats_LDADD = \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  libgnunetats.la \
  $(GN_LIBINTL)

if HAVE_TESTING
TESTING_TESTS = \
 test_ats_api_proportional \
 test_ats_reservation_api_proportional
if HAVE_WACHS
TESTING_TESTS += \
 test_ats_api_ril
if HAVE_LIBGLPK
TESTING_TESTS += \
 test_ats_api_mlp
endif
endif
endif

check_PROGRAMS = \
 $(TESTING_TESTS)

if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;
TESTS = $(check_PROGRAMS)
endif

test_ats_api_proportional_SOURCES = \
 test_ats_api.c \
 test_ats_lib.c test_ats_lib.h
test_ats_api_proportional_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/hello/libgnunethello.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  libgnunetats.la

test_ats_reservation_api_proportional_SOURCES = \
 test_ats_reservation_api.c \
 test_ats_lib.c test_ats_lib.h
test_ats_reservation_api_proportional_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/hello/libgnunethello.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  libgnunetats.la

test_ats_api_ril_SOURCES = \
 test_ats_api.c \
 test_ats_lib.c test_ats_lib.h
test_ats_api_ril_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/hello/libgnunethello.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  libgnunetats.la

test_ats_api_mlp_SOURCES = \
 test_ats_api.c \
 test_ats_lib.c test_ats_lib.h
test_ats_api_mlp_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/hello/libgnunethello.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  libgnunetats.la

EXTRA_DIST = \
  ats.h \
  test_delay \
  test_ats_api_mlp.conf \
  test_ats_api_ril.conf \
  test_ats_api_proportional.conf
