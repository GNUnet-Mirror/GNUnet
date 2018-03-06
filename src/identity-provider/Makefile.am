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
SQLITE_PLUGIN = libgnunet_plugin_identity_provider_sqlite.la
endif

EXTRA_DIST = \
  test_idp_defaults.conf \
	test_idp.conf \
	$(check_SCRIPTS)

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

pkgcfg_DATA = \
  identity-provider.conf

lib_LTLIBRARIES = \
  libgnunetidentityprovider.la
plugin_LTLIBRARIES = \
	libgnunet_plugin_rest_identity_provider.la \
	libgnunet_plugin_rest_openid_connect.la \
  libgnunet_plugin_gnsrecord_identity_provider.la \
	$(SQLITE_PLUGIN)

bin_PROGRAMS = \
 gnunet-idp

libexec_PROGRAMS = \
 gnunet-service-identity-provider

libgnunet_plugin_gnsrecord_identity_provider_la_SOURCES = \
  plugin_gnsrecord_identity_provider.c
libgnunet_plugin_gnsrecord_identity_provider_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(LTLIBINTL)
libgnunet_plugin_gnsrecord_identity_provider_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)

libgnunet_plugin_identity_provider_sqlite_la_SOURCES = \
  plugin_identity_provider_sqlite.c
libgnunet_plugin_identity_provider_sqlite_la_LIBADD = \
  libgnunetidentityprovider.la  \
  $(top_builddir)/src/sq/libgnunetsq.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la $(XLIBS) -lsqlite3 \
  $(LTLIBINTL)
libgnunet_plugin_identity_provider_sqlite_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)



gnunet_service_identity_provider_SOURCES = \
 gnunet-service-identity-provider.c
gnunet_service_identity_provider_LDADD = \
 $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/namestore/libgnunetnamestore.la \
 $(top_builddir)/src/identity/libgnunetidentity.la \
 $(top_builddir)/src/statistics/libgnunetstatistics.la \
 $(top_builddir)/src/abe/libgnunetabe.la \
 $(top_builddir)/src/credential/libgnunetcredential.la \
 $(top_builddir)/src/identity-attribute/libgnunetidentityattribute.la \
 libgnunetidentityprovider.la \
 $(top_builddir)/src/gns/libgnunetgns.la \
 $(GN_LIBINTL)

libgnunetidentityprovider_la_SOURCES = \
 identity_provider_api.c \
 identity_provider.h
libgnunetidentityprovider_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
	$(GN_LIBINTL) $(XLIB)
libgnunetidentityprovider_la_LDFLAGS = \
	$(GN_LIB_LDFLAGS)  $(WINFLAGS) \
	-version-info 0:0:0

libgnunet_plugin_rest_identity_provider_la_SOURCES = \
  plugin_rest_identity_provider.c \
	jwt.c
libgnunet_plugin_rest_identity_provider_la_LIBADD = \
	$(top_builddir)/src/identity/libgnunetidentity.la \
	libgnunetidentityprovider.la \
	$(top_builddir)/src/rest/libgnunetrest.la \
	$(top_builddir)/src/jsonapi/libgnunetjsonapi.la \
	$(top_builddir)/src/identity-attribute/libgnunetidentityattribute.la \
	$(top_builddir)/src/namestore/libgnunetnamestore.la \
  $(top_builddir)/src/util/libgnunetutil.la $(XLIBS) \
  $(LTLIBINTL) -ljansson -lmicrohttpd
libgnunet_plugin_rest_identity_provider_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)

libgnunet_plugin_rest_openid_connect_la_SOURCES = \
  plugin_rest_openid_connect.c \
	jwt.c
libgnunet_plugin_rest_openid_connect_la_LIBADD = \
	$(top_builddir)/src/identity/libgnunetidentity.la \
	libgnunetidentityprovider.la \
	$(top_builddir)/src/rest/libgnunetrest.la \
	$(top_builddir)/src/jsonapi/libgnunetjsonapi.la \
	$(top_builddir)/src/identity-attribute/libgnunetidentityattribute.la \
	$(top_builddir)/src/namestore/libgnunetnamestore.la \
  $(top_builddir)/src/util/libgnunetutil.la $(XLIBS) \
  $(LTLIBINTL) -ljansson -lmicrohttpd
libgnunet_plugin_rest_openid_connect_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)

gnunet_idp_SOURCES = \
 gnunet-idp.c
gnunet_idp_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
	$(top_builddir)/src/namestore/libgnunetnamestore.la \
	libgnunetidentityprovider.la \
	$(top_builddir)/src/identity/libgnunetidentity.la \
	$(top_builddir)/src/identity-attribute/libgnunetidentityattribute.la \
  $(GN_LIBINTL)

check_SCRIPTS = \
	test_idp_attribute.sh \
	test_idp_issue.sh \
	test_idp_consume.sh \
  test_idp_revoke.sh

if ENABLE_TEST_RUN
 AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
 TESTS = $(check_SCRIPTS)
endif
