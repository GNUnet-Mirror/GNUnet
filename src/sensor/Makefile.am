# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

plugindir = $(libdir)/gnunet

dist_pkgcfg_DATA = \
  sensor.conf

if MINGW
 WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols 
endif

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif

bin_PROGRAMS = \
 gnunet-sensor 

noinst_PROGRAMS = \
 gnunet-sensor-profiler \
 perf-pow-sign

libexec_PROGRAMS = \
 gnunet-service-sensor

lib_LTLIBRARIES = \
 libgnunetsensor.la \
 libgnunetsensorutil.la

gnunet_sensor_SOURCES = \
 gnunet-sensor.c         
gnunet_sensor_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  libgnunetsensor.la \
  $(GN_LIBINTL)

gnunet_service_sensor_SOURCES = \
 gnunet-service-sensor.c \
 gnunet-service-sensor_monitoring.c \
 gnunet-service-sensor_analysis.c \
 gnunet-service-sensor_reporting.c \
 gnunet-service-sensor_update.c
gnunet_service_sensor_LDADD = \
  libgnunetsensorutil.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/peerstore/libgnunetpeerstore.la \
  $(top_builddir)/src/cadet/libgnunetcadet.la \
  $(top_builddir)/src/core/libgnunetcore.la \
  $(GN_LIBINTL)

libgnunetsensor_la_SOURCES = \
  sensor_api.c 
libgnunetsensor_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la
libgnunetsensor_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)

libgnunetsensorutil_la_SOURCES = \
  sensor_util_lib.c \
  sensor_util_lib_crypto.c
libgnunetsensorutil_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la
libgnunetsensorutil_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)

plugin_LTLIBRARIES = \
  libgnunet_plugin_sensor_model_gaussian.la

libgnunet_plugin_sensor_model_gaussian_la_SOURCES = \
  plugin_sensor_model_gaussian.c
libgnunet_plugin_sensor_model_gaussian_la_LIBADD = \
  libgnunetsensor.la  \
  $(top_builddir)/src/util/libgnunetutil.la $(XLIBS) \
  $(LTLIBINTL)
libgnunet_plugin_sensor_model_gaussian_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)

check_PROGRAMS = \
 test_sensor_api \
 test_gnunet-service-sensor_reporting \
 test_pow_sign

if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;
TESTS = $(check_PROGRAMS)
endif

test_sensor_api_SOURCES = \
  test_sensor_api.c
test_sensor_api_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la

test_gnunet_service_sensor_reporting_SOURCES = \
  test_gnunet-service-sensor_reporting.c
test_gnunet_service_sensor_reporting_LDADD = \
  libgnunetsensor.la \
  libgnunetsensorutil.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testbed/libgnunettestbed.la \
  $(top_builddir)/src/peerstore/libgnunetpeerstore.la

test_pow_sign_SOURCES = \
  test_pow_sign.c
test_pow_sign_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testbed/libgnunettestbed.la \
  libgnunetsensorutil.la

gnunet_sensor_profiler_SOURCES = \
  gnunet-sensor-profiler.c
gnunet_sensor_profiler_LDADD = \
  libgnunetsensor.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testbed/libgnunettestbed.la \
  $(top_builddir)/src/peerstore/libgnunetpeerstore.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la

perf_pow_sign_SOURCES = \
  perf_pow_sign.c
perf_pow_sign_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testbed/libgnunettestbed.la \
  libgnunetsensorutil.la

EXTRA_DIST = sensors
pkgsensordir = sensors

install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(datadir)/$(PACKAGE)/$(pkgsensordir)
	@$(NORMAL_INSTALL)
	for sensor in $(pkgsensordir)/*; do \
	  cp -a $$sensor $(DESTDIR)$(datadir)/$(PACKAGE)/$(pkgsensordir)/ ; \
	done
