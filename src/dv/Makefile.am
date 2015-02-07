# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

if MINGW
 WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols 
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

plugindir = $(libdir)/gnunet

libexecdir= $(pkglibdir)/libexec/

pkgcfgdir= $(pkgdatadir)/config.d/

pkgcfg_DATA = \
  dv.conf

lib_LTLIBRARIES = libgnunetdv.la

plugin_LTLIBRARIES = libgnunet_plugin_transport_dv.la

libgnunetdv_la_SOURCES = \
  dv_api.c dv.h 
libgnunetdv_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL) $(XLIB)
libgnunetdv_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)  $(WINFLAGS) \
  -version-info 0:0:0


noinst_PROGRAMS = \
 gnunet-dv

libexec_PROGRAMS = \
 gnunet-service-dv

gnunet_service_dv_SOURCES = \
 gnunet-service-dv.c dv.h
gnunet_service_dv_LDADD = \
  $(top_builddir)/src/ats/libgnunetats.la \
  $(top_builddir)/src/set/libgnunetset.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/core/libgnunetcore.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)

gnunet_dv_SOURCES = \
 gnunet-dv.c dv.h
gnunet_dv_LDADD = \
  libgnunetdv.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)

libgnunet_plugin_transport_dv_la_SOURCES = \
  plugin_transport_dv.c
libgnunet_plugin_transport_dv_la_LIBADD = \
  libgnunetdv.la \
  $(top_builddir)/src/ats/libgnunetats.la \
  $(top_builddir)/src/hello/libgnunethello.la \
  $(top_builddir)/src/util/libgnunetutil.la 
libgnunet_plugin_transport_dv_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)

if HAVE_TESTING
check_PROGRAMS = \
 test_transport_blacklist \
 test_transport_dv
endif

if ENABLE_TEST_RUN
 AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;
 TESTS = $(check_PROGRAMS) 
endif

test_transport_dv_SOURCES = \
 test_transport_dv.c
test_transport_dv_LDADD = \
 $(top_builddir)/src/testbed/libgnunettestbed.la \
 $(top_builddir)/src/core/libgnunetcore.la \
 $(top_builddir)/src/transport/libgnunettransport.la \
 $(top_builddir)/src/util/libgnunetutil.la 

test_transport_blacklist_SOURCES = \
 test_transport_blacklist.c
test_transport_blacklist_LDADD = \
 $(top_builddir)/src/testbed/libgnunettestbed.la \
 $(top_builddir)/src/core/libgnunetcore.la \
 $(top_builddir)/src/transport/libgnunettransport.la \
 $(top_builddir)/src/util/libgnunetutil.la 

EXTRA_DIST = \
  test_transport_dv_data.conf \
  test_transport_blacklist_data.conf \
  template_dv.conf

