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

if HAVE_SQLITE
SQLITE_PLUGIN = libgnunet_plugin_reclaim_sqlite.la
endif

if HAVE_MHD
if HAVE_JSON
REST_PLUGIN = \
  libgnunet_plugin_rest_openid_connect.la \
  libgnunet_plugin_rest_reclaim.la
endif
endif

EXTRA_DIST = \
  reclaim.conf \
  test_reclaim_defaults.conf \
  test_reclaim.conf \
  $(check_SCRIPTS)

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

pkgcfg_DATA = \
  reclaim.conf

lib_LTLIBRARIES = \
  libgnunetreclaim.la
plugin_LTLIBRARIES = \
  libgnunet_plugin_gnsrecord_reclaim.la \
  $(SQLITE_PLUGIN) \
  $(REST_PLUGIN)

bin_PROGRAMS = \
 gnunet-reclaim

libexec_PROGRAMS = \
 gnunet-service-reclaim

libgnunet_plugin_rest_reclaim_la_SOURCES = \
  plugin_rest_reclaim.c \
  json_reclaim.h \
  json_reclaim.c
libgnunet_plugin_rest_reclaim_la_LIBADD = \
  $(top_builddir)/src/identity/libgnunetidentity.la \
  libgnunetreclaim.la \
  $(top_builddir)/src/json/libgnunetjson.la \
  $(top_builddir)/src/rest/libgnunetrest.la \
  $(top_builddir)/src/reclaim-attribute/libgnunetreclaimattribute.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  $(top_builddir)/src/util/libgnunetutil.la $(XLIBS) \
  $(LTLIBINTL) -ljansson -lmicrohttpd
libgnunet_plugin_rest_reclaim_la_LDFLAGS = \
  $(GN_PLUGIN_LDFLAGS)


libgnunet_plugin_rest_openid_connect_la_SOURCES = \
  plugin_rest_openid_connect.c \
  oidc_helper.h \
  oidc_helper.c
libgnunet_plugin_rest_openid_connect_la_LIBADD = \
  $(top_builddir)/src/identity/libgnunetidentity.la \
  libgnunetreclaim.la \
  $(top_builddir)/src/rest/libgnunetrest.la \
  $(top_builddir)/src/reclaim-attribute/libgnunetreclaimattribute.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
$(top_builddir)/src/gns/libgnunetgns.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/util/libgnunetutil.la $(XLIBS) \
  $(LTLIBINTL) -ljansson -lmicrohttpd
libgnunet_plugin_rest_openid_connect_la_LDFLAGS = \
  $(GN_PLUGIN_LDFLAGS)


libgnunet_plugin_gnsrecord_reclaim_la_SOURCES = \
  plugin_gnsrecord_reclaim.c
libgnunet_plugin_gnsrecord_reclaim_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(LTLIBINTL)
libgnunet_plugin_gnsrecord_reclaim_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)

libgnunet_plugin_reclaim_sqlite_la_SOURCES = \
  plugin_reclaim_sqlite.c
libgnunet_plugin_reclaim_sqlite_la_LIBADD = \
  libgnunetreclaim.la  \
  $(top_builddir)/src/sq/libgnunetsq.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la $(XLIBS) -lsqlite3 \
  $(LTLIBINTL)
libgnunet_plugin_reclaim_sqlite_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)



gnunet_service_reclaim_SOURCES = \
 gnunet-service-reclaim.c
gnunet_service_reclaim_LDADD = \
 $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/namestore/libgnunetnamestore.la \
 $(top_builddir)/src/identity/libgnunetidentity.la \
 $(top_builddir)/src/statistics/libgnunetstatistics.la \
 $(top_builddir)/src/abe/libgnunetabe.la \
 $(top_builddir)/src/credential/libgnunetcredential.la \
 $(top_builddir)/src/reclaim-attribute/libgnunetreclaimattribute.la \
 libgnunetreclaim.la \
 $(top_builddir)/src/gns/libgnunetgns.la \
 $(GN_LIBINTL)

libgnunetreclaim_la_SOURCES = \
 reclaim_api.c \
 reclaim.h
libgnunetreclaim_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
	$(GN_LIBINTL) $(XLIB)
libgnunetreclaim_la_LDFLAGS = \
	$(GN_LIB_LDFLAGS)  $(WINFLAGS) \
	-version-info 0:0:0

gnunet_reclaim_SOURCES = \
 gnunet-reclaim.c
gnunet_reclaim_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
	$(top_builddir)/src/namestore/libgnunetnamestore.la \
	libgnunetreclaim.la \
	$(top_builddir)/src/identity/libgnunetidentity.la \
	$(top_builddir)/src/reclaim-attribute/libgnunetreclaimattribute.la \
  $(GN_LIBINTL)

check_SCRIPTS = \
	test_reclaim_attribute.sh \
	test_reclaim_issue.sh \
	test_reclaim_consume.sh \
  test_reclaim_revoke.sh

if ENABLE_TEST_RUN
 AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
 TESTS = $(check_SCRIPTS)
endif
