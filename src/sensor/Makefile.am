AM_CPPFLAGS = -I$(top_srcdir)/src/include

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

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

libexec_PROGRAMS = \
 gnunet-service-sensor

lib_LTLIBRARIES = \
 libgnunetsensor.la

gnunet_sensor_SOURCES = \
 gnunet-sensor.c         
gnunet_sensor_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  libgnunetsensor.la \
  $(GN_LIBINTL)

gnunet_service_sensor_SOURCES = \
 gnunet-service-sensor.c \
 gnunet-service-sensor-analysis.c
gnunet_service_sensor_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/peerstore/libgnunetpeerstore.la \
  $(GN_LIBINTL)

libgnunetsensor_la_SOURCES = \
  sensor_api.c 
libgnunetsensor_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la
libgnunetsensor_la_LDFLAGS = \
  $(GNUNET_LDFLAGS)

check_PROGRAMS = \
 test_sensor_api

if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;
TESTS = $(check_PROGRAMS)
endif

test_sensor_api_SOURCES = \
 test_sensor_api.c
test_sensor_api_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la  

pkgsensordir = sensors

install-data-local:
	$(mkinstalldirs) $(datadir)/$(PACKAGE)/$(pkgsensordir)
	@$(NORMAL_INSTALL)
	for sensor in $(pkgsensordir)/*; do \
	  cp -a $$sensor $(datadir)/$(PACKAGE)/$(pkgsensordir)/ ; \
	done
