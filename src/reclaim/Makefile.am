# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

 plugindir = $(libdir)/gnunet

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif


REST_PLUGIN = \
  libgnunet_plugin_rest_openid_connect.la \
  libgnunet_plugin_rest_reclaim.la

ATTESTATION_PLUGIN = \
  libgnunet_plugin_reclaim_attestation_jwt.la

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
  libgnunet_plugin_reclaim_attribute_basic.la \
  $(ATTESTATION_PLUGIN) \
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
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  $(top_builddir)/src/util/libgnunetutil.la $(XLIBS) \
  $(LTLIBINTL) -ljansson $(MHD_LIBS)
libgnunet_plugin_rest_reclaim_la_LDFLAGS = \
  $(GN_PLUGIN_LDFLAGS)
libgnunet_plugin_rest_reclaim_la_CFLAGS = $(MHD_CFLAGS) $(AM_CFLAGS)


libgnunet_plugin_rest_openid_connect_la_SOURCES = \
  plugin_rest_openid_connect.c \
  oidc_helper.h \
  oidc_helper.c
libgnunet_plugin_rest_openid_connect_la_LIBADD = \
  $(top_builddir)/src/identity/libgnunetidentity.la \
  libgnunetreclaim.la \
  $(top_builddir)/src/rest/libgnunetrest.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  $(top_builddir)/src/gns/libgnunetgns.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/util/libgnunetutil.la $(XLIBS) \
  $(LTLIBINTL) -ljansson $(MHD_LIBS) \
	$(LIBGCRYPT_LIBS)
libgnunet_plugin_rest_openid_connect_la_LDFLAGS = \
  $(GN_PLUGIN_LDFLAGS)
libgnunet_plugin_rest_openid_connect_la_CFLAGS = $(MHD_CFLAGS) $(AM_CFLAGS)


libgnunet_plugin_gnsrecord_reclaim_la_SOURCES = \
  plugin_gnsrecord_reclaim.c
libgnunet_plugin_gnsrecord_reclaim_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(LTLIBINTL)
libgnunet_plugin_gnsrecord_reclaim_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)


gnunet_service_reclaim_SOURCES = \
 gnunet-service-reclaim.c \
 gnunet-service-reclaim_tickets.c \
 gnunet-service-reclaim_tickets.h
gnunet_service_reclaim_LDADD = \
 $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/namestore/libgnunetnamestore.la \
 $(top_builddir)/src/statistics/libgnunetstatistics.la \
 libgnunetreclaim.la \
 $(top_builddir)/src/gns/libgnunetgns.la \
 $(GN_LIBINTL)

libgnunetreclaim_la_SOURCES = \
 reclaim_api.c \
 reclaim.h \
 reclaim_attribute.c \
 reclaim_attribute.h \
 reclaim_attestation.c \
 reclaim_attestation.h
libgnunetreclaim_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL) $(XLIB)
libgnunetreclaim_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)   \
  -version-info 0:0:0


libgnunet_plugin_reclaim_attribute_basic_la_SOURCES = \
  plugin_reclaim_attribute_basic.c
libgnunet_plugin_reclaim_attribute_basic_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(LTLIBINTL)
libgnunet_plugin_reclaim_attribute_basic_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)

libgnunet_plugin_reclaim_attestation_jwt_la_SOURCES = \
  plugin_reclaim_attestation_jwt.c
libgnunet_plugin_reclaim_attestation_jwt_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  libgnunetreclaim.la \
  -ljansson\
  $(LTLIBINTL)
libgnunet_plugin_reclaim_attestation_jwt_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)

gnunet_reclaim_SOURCES = \
 gnunet-reclaim.c
gnunet_reclaim_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  libgnunetreclaim.la \
  $(top_builddir)/src/identity/libgnunetidentity.la \
  $(GN_LIBINTL)

check_SCRIPTS = \
  test_reclaim_attribute.sh \
  test_reclaim_issue.sh \
  test_reclaim_consume.sh
#  test_reclaim_revoke.sh

if ENABLE_TEST_RUN
 AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
 TESTS = $(check_SCRIPTS)
endif
