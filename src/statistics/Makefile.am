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
  statistics.conf

lib_LTLIBRARIES = libgnunetstatistics.la

libgnunetstatistics_la_SOURCES = \
  statistics_api.c statistics.h
libgnunetstatistics_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL) $(XLIB)
libgnunetstatistics_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)  $(WINFLAGS) \
  -version-info 1:0:1


bin_PROGRAMS = \
 gnunet-statistics \
 gnunet-service-statistics

gnunet_statistics_SOURCES = \
 gnunet-statistics.c         
gnunet_statistics_LDADD = \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)
gnunet_statistics_DEPENDENCIES = \
  libgnunetstatistics.la				 

gnunet_service_statistics_SOURCES = \
 gnunet-service-statistics.c         
gnunet_service_statistics_LDADD = \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)
gnunet_service_statistics_DEPENDENCIES = \
  libgnunetstatistics.la				 

check_PROGRAMS = \
 test_statistics_api \
 test_statistics_api_loop \
 test_statistics_api_watch 

if ENABLE_TEST_RUN
TESTS = $(check_PROGRAMS) $(check_SCRIPTS)
endif

test_statistics_api_SOURCES = \
 test_statistics_api.c
test_statistics_api_LDADD = \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la  

test_statistics_api_loop_SOURCES = \
 test_statistics_api_loop.c
test_statistics_api_loop_LDADD = \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la  

test_statistics_api_watch_SOURCES = \
 test_statistics_api_watch.c
test_statistics_api_watch_LDADD = \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la  

check_SCRIPTS = \
  test_gnunet_statistics.sh

EXTRA_DIST = \
  test_statistics_api_data.conf \
  $(check_SCRIPTS) 


