INCLUDES = -I$(top_srcdir)/src/include

if MINGW
 WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols 
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

plugindir = $(libdir)/gnunet

pkgcfgdir= $(pkgdatadir)/config.d/

pkgcfg_DATA = \
  dv.conf

lib_LTLIBRARIES = libgnunetdv.la

plugin_LTLIBRARIES = libgnunet_plugin_transport_dv.la

libgnunetdv_la_SOURCES = \
  dv_api.c dv.h
libgnunetdv_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/core/libgnunetcore.la \
  $(GN_LIBINTL) $(XLIB)
libgnunetdv_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)  $(WINFLAGS) \
  -version-info 0:0:0


bin_PROGRAMS = \
 gnunet-service-dv

gnunet_service_dv_SOURCES = \
 gnunet-service-dv.c         
gnunet_service_dv_LDADD = \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/dv/libgnunetdv.la \
  $(top_builddir)/src/core/libgnunetcore.la \
  $(top_builddir)/src/hello/libgnunethello.la \
  $(top_builddir)/src/peerinfo/libgnunetpeerinfo.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)
gnunet_service_dv_DEPENDENCIES = \
  libgnunetdv.la				 

libgnunet_plugin_transport_dv_la_SOURCES = \
  plugin_transport_dv.c
libgnunet_plugin_transport_dv_la_LIBADD = \
  $(top_builddir)/src/hello/libgnunethello.la \
  $(top_builddir)/src/dv/libgnunetdv.la \
  $(top_builddir)/src/peerinfo/libgnunetpeerinfo.la \
  $(top_builddir)/src/util/libgnunetutil.la 
libgnunet_plugin_transport_dv_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)
libgnunet_plugin_transport_dv_la_DEPENDENCIES = \
  libgnunetdv.la						

check_PROGRAMS = \
 test_transport_api_dv
# test_dv_topology

if ENABLE_TEST_RUN
TESTS = $(check_PROGRAMS) $(check_SCRIPTS)
endif

test_transport_api_dv_SOURCES = \
 test_transport_api_dv.c
test_transport_api_dv_LDADD = \
 $(top_builddir)/src/core/libgnunetcore.la \
 $(top_builddir)/src/transport/libgnunettransport.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/testing/libgnunettesting.la

EXTRA_DIST = \
  test_transport_dv_data.conf
