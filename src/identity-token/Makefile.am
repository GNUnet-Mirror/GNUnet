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
  identity-token.conf

if HAVE_REST
plugin_LTLIBRARIES = \
	libgnunet_plugin_rest_identity_token.la
endif

bin_PROGRAMS = \
 gnunet-identity-token

libexec_PROGRAMS = \
 gnunet-service-identity-token

gnunet_service_identity_token_SOURCES = \
 gnunet-service-identity-token.c

gnunet_service_identity_token_LDADD = \
 $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/namestore/libgnunetnamestore.la \
 $(top_builddir)/src/identity/libgnunetidentity.la \
 $(GN_LIBINTL) \
 -ljansson

libgnunet_plugin_rest_identity_token_la_SOURCES = \
  plugin_rest_identity_token.c
libgnunet_plugin_rest_identity_token_la_LIBADD = \
	$(top_builddir)/src/identity/libgnunetidentity.la \
	$(top_builddir)/src/rest/libgnunetrest.la \
	$(top_builddir)/src/namestore/libgnunetnamestore.la \
  $(top_builddir)/src/util/libgnunetutil.la $(XLIBS) \
  $(LTLIBINTL) -ljansson -lmicrohttpd
libgnunet_plugin_rest_identity_token_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)


gnunet_identity_token_SOURCES = \
 gnunet-identity-token.c         
gnunet_identity_token_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  -ljansson -lmicrohttpd \
  $(GN_LIBINTL)


