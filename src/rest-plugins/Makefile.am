# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

plugindir = $(libdir)/gnunet

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/


if MINGW
  WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIBS = -lgcov
endif

plugin_LTLIBRARIES = \
  libgnunet_plugin_rest_copying.la \
	libgnunet_plugin_rest_peerinfo.la \
	libgnunet_plugin_rest_namestore.la 


#libgnunet_plugin_rest_credential_la_SOURCES = \
#  plugin_rest_credential.c
#libgnunet_plugin_rest_credential_la_LIBADD = \
#  $(top_builddir)/src/credential/libgnunetcredential.la \
#	$(top_builddir)/src/rest/libgnunetrest.la \
#	$(top_builddir)/src/identity/libgnunetidentity.la \
#  $(top_builddir)/src/util/libgnunetutil.la $(XLIBS) \
#  $(LTLIBINTL) -ljansson -lmicrohttpd
#libgnunet_plugin_rest_credential_la_LDFLAGS = \
# $(GN_PLUGIN_LDFLAGS)

libgnunet_plugin_rest_copying_la_SOURCES = \
  plugin_rest_copying.c
libgnunet_plugin_rest_copying_la_LIBADD = \
	$(top_builddir)/src/rest/libgnunetrest.la \
  $(top_builddir)/src/util/libgnunetutil.la $(XLIBS) \
  $(LTLIBINTL) -lmicrohttpd
libgnunet_plugin_rest_copying_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)




