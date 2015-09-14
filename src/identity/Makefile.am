# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

plugindir = $(libdir)/gnunet

if MINGW
 WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols 
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

pkgcfg_DATA = \
  identity.conf

lib_LTLIBRARIES = \
	libgnunetidentity.la

libgnunetidentity_la_SOURCES = \
  identity_api.c \
  identity_api_lookup.c \
  identity.h
libgnunetidentity_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL) $(XLIB)
libgnunetidentity_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)  $(WINFLAGS) \
  -version-info 0:0:0

bin_PROGRAMS = \
 gnunet-identity

libexec_PROGRAMS = \
 gnunet-service-identity 

if HAVE_REST
plugin_LTLIBRARIES = \
  libgnunet_plugin_rest_identity.la \
	libgnunet_plugin_gnsrecord_identity.la
endif


gnunet_service_identity_SOURCES = \
 gnunet-service-identity.c         
gnunet_service_identity_LDADD = \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)

libgnunet_plugin_gnsrecord_identity_la_SOURCES = \
  plugin_gnsrecord_identity.c
libgnunet_plugin_gnsrecord_identity_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(LTLIBINTL)
libgnunet_plugin_gnsrecord_identity_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)


libgnunet_plugin_rest_identity_la_SOURCES = \
  plugin_rest_identity.c
libgnunet_plugin_rest_identity_la_LIBADD = \
	libgnunetidentity.la \
  $(top_builddir)/src/rest/libgnunetrest.la \
  $(top_builddir)/src/util/libgnunetutil.la $(XLIBS) \
  $(LTLIBINTL) -ljansson -lmicrohttpd
libgnunet_plugin_rest_identity_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)


gnunet_identity_SOURCES = \
 gnunet-identity.c         
gnunet_identity_LDADD = \
  libgnunetidentity.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)

if HAVE_TESTING
check_PROGRAMS = \
 test_identity \
 test_identity_defaults 
endif

if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;
TESTS = $(check_PROGRAMS) 
endif


test_identity_SOURCES = \
 test_identity.c
test_identity_LDADD = \
  libgnunetidentity.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la 

test_identity_defaults_SOURCES = \
 test_identity_defaults.c
test_identity_defaults_LDADD = \
  libgnunetidentity.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la 

EXTRA_DIST = \
  test_identity.conf 


