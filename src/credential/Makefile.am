# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

EXTRA_DIST = \
  test_credential_defaults.conf \
  test_credential_lookup.conf


if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
endif

pkgcfgdir = $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

plugindir = $(libdir)/gnunet

pkgcfg_DATA = \
  credential.conf


# /usr/lib - compiles a layer which can be used to be communicagte with the service
lib_LTLIBRARIES = \
  libgnunetcredential.la

# /usr/lib/gnunet/libexec - Business logic . Separate process 
libexec_PROGRAMS = \
  gnunet-service-credential 

bin_PROGRAMS = \
  gnunet-credential

plugin_LTLIBRARIES = \
  libgnunet_plugin_gnsrecord_credential.la


if HAVE_MHD
if HAVE_JSON
plugin_LTLIBRARIES += libgnunet_plugin_rest_credential.la
endif
endif


gnunet_credential_SOURCES = \
 gnunet-credential.c
gnunet_credential_LDADD = \
  libgnunetcredential.la \
  $(top_builddir)/src/util/libgnunetutil.la \
	$(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/identity/libgnunetidentity.la \
  $(GN_LIBINTL)


libgnunet_plugin_gnsrecord_credential_la_SOURCES = \
  plugin_gnsrecord_credential.c
libgnunet_plugin_gnsrecord_credential_la_LIBADD = \
	libgnunetcredential.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(LTLIBINTL)
libgnunet_plugin_gnsrecord_credential_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)



gnunet_service_credential_SOURCES = \
 gnunet-service-credential.c
gnunet_service_credential_LDADD = \
	libgnunetcredential.la \
  $(top_builddir)/src/util/libgnunetutil.la \
	$(top_builddir)/src/gns/libgnunetgns.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(GN_LIBINTL)


libgnunetcredential_la_SOURCES = \
 credential_api.c credential.h \
 credential_serialization.c
libgnunetcredential_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la $(XLIB) 
libgnunetcredential_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)


libgnunet_plugin_rest_credential_la_SOURCES = \
  plugin_rest_credential.c
libgnunet_plugin_rest_credential_la_LIBADD = \
  libgnunetcredential.la \
	$(top_builddir)/src/rest/libgnunetrest.la \
	$(top_builddir)/src/jsonapi/libgnunetjsonapi.la \
  $(top_builddir)/src/jsonapi/libgnunetjsonapiutils.la \
  $(top_builddir)/src/util/libgnunetutil.la $(XLIBS) \
  $(LTLIBINTL) -ljansson -lmicrohttpd
libgnunet_plugin_rest_credential_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)


check_SCRIPTS = \
  test_credential_issue.sh \
	test_credential_verify_simple.sh \
	test_credential_verify.sh

if ENABLE_TEST_RUN
if HAVE_SQLITE
 AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;
 TESTS = $(check_SCRIPTS)
endif
endif
