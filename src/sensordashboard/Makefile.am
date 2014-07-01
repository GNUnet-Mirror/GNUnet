AM_CPPFLAGS = -I$(top_srcdir)/src/include

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

dist_pkgcfg_DATA = \
  sensordashboard.conf

if MINGW
 WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols 
endif

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif

bin_PROGRAMS = \
 gnunet-sensordashboard 

libexec_PROGRAMS = \
 gnunet-service-sensordashboard

gnunet_sensordashboard_SOURCES = \
 gnunet-sensordashboard.c         
gnunet_sensordashboard_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)

gnunet_service_sensordashboard_SOURCES = \
 gnunet-service-sensordashboard.c         
gnunet_service_sensordashboard_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/cadet/libgnunetcadet.la \
  $(GN_LIBINTL)


check_PROGRAMS = \
 test_sensordashboard_api

if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;
TESTS = $(check_PROGRAMS)
endif

test_sensordashboard_api_SOURCES = \
 test_sensordashboard_api.c
test_sensordashboard_api_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la  

