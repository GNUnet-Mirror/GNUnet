# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

plugindir = $(libdir)/gnunet

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

pkgcfg_DATA = \
   rest.conf


if MINGW
  WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIBS = -lgcov
endif

REST_PLUGINS = libgnunet_plugin_rest_gns.la \
							 libgnunet_plugin_rest_identity.la \
							 libgnunet_plugin_rest_namestore.la

lib_LTLIBRARIES = \
	libgnunetrest.la \
	$(REST_PLUGINS)

libexec_PROGRAMS = \
 gnunet-rest-server


gnunet_rest_server_SOURCES = \
 gnunet-rest-server.c

gnunet_rest_server_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL) -lmicrohttpd

libgnunetrest_la_SOURCES = \
  rest.c
libgnunetrest_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la $(XLIB) \
  $(GN_LIBINTL) -lmicrohttpd -ljansson
libgnunetrest_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS) \
  -version-info 0:0:0

libgnunet_plugin_rest_gns_la_SOURCES = \
  plugin_rest_gns.c
libgnunet_plugin_rest_gns_la_LIBADD = \
  $(top_builddir)/src/gns/libgnunetgns.la \
  $(top_builddir)/src/identity/libgnunetidentity.la \
  $(top_builddir)/src/util/libgnunetutil.la $(XLIBS) \
  $(LTLIBINTL) -ljansson -lmicrohttpd
libgnunet_plugin_rest_gns_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)


libgnunet_plugin_rest_identity_la_SOURCES = \
  plugin_rest_namestore.c
libgnunet_plugin_rest_identity_la_LIBADD = \
	$(top_builddir)/src/identity/libgnunetidentity.la \
  $(top_builddir)/src/util/libgnunetutil.la $(XLIBS) \
  $(LTLIBINTL) -ljansson -lmicrohttpd
libgnunet_plugin_rest_identity_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)

libgnunet_plugin_rest_namestore_la_SOURCES = \
  plugin_rest_namestore.c
libgnunet_plugin_rest_namestore_la_LIBADD = \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
	$(top_builddir)/src/identity/libgnunetidentity.la \
  $(top_builddir)/src/util/libgnunetutil.la $(XLIBS) \
  $(LTLIBINTL) -ljansson -lmicrohttpd
libgnunet_plugin_rest_namestore_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)

