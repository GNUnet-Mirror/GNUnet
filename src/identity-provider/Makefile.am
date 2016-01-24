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
  identity-provider.conf

plugin_LTLIBRARIES = \
  libgnunetidentityprovider.la \
	libgnunet_plugin_rest_identity_provider.la 

bin_PROGRAMS = \
 gnunet-identity-token

libexec_PROGRAMS = \
 gnunet-service-identity-provider

gnunet_service_identity_provider_SOURCES = \
 gnunet-service-identity-provider.c \
 identity_token.c
gnunet_service_identity_provider_LDADD = \
 $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/namestore/libgnunetnamestore.la \
 $(top_builddir)/src/identity/libgnunetidentity.la \
 $(top_builddir)/src/gns/libgnunetgns.la \
 $(GN_LIBINTL) \
 -ljansson

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
  plugin_rest_identity_provider.c
libgnunet_plugin_rest_identity_provider_la_LIBADD = \
	$(top_builddir)/src/identity/libgnunetidentity.la \
	libgnunetidentityprovider.la \
	$(top_builddir)/src/rest/libgnunetrest.la \
	$(top_builddir)/src/namestore/libgnunetnamestore.la \
  $(top_builddir)/src/util/libgnunetutil.la $(XLIBS) \
  $(LTLIBINTL) -ljansson -lmicrohttpd
libgnunet_plugin_rest_identity_provider_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)


gnunet_identity_token_SOURCES = \
 gnunet-identity-token.c         
gnunet_identity_token_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  -ljansson -lmicrohttpd \
  $(GN_LIBINTL)


