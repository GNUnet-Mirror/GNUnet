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
	libgnunet_plugin_rest_identity.la \
	libgnunet_plugin_rest_namestore.la \
  libgnunet_plugin_rest_gns.la 
if HAVE_ABE
plugin_LTLIBRARIES += libgnunet_plugin_rest_openid_connect.la \
											libgnunet_plugin_rest_reclaim.la
endif

libgnunet_plugin_rest_reclaim_la_SOURCES = \
  plugin_rest_reclaim.c \
	json_reclaim.c
libgnunet_plugin_rest_reclaim_la_LIBADD = \
  $(top_builddir)/src/identity/libgnunetidentity.la \
  $(top_builddir)/src/reclaim/libgnunetreclaim.la \
	$(top_builddir)/src/json/libgnunetjson.la \
  $(top_builddir)/src/rest/libgnunetrest.la \
  $(top_builddir)/src/reclaim-attribute/libgnunetreclaimattribute.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  $(top_builddir)/src/util/libgnunetutil.la $(XLIBS) \
  $(LTLIBINTL) -ljansson -lmicrohttpd
libgnunet_plugin_rest_reclaim_la_LDFLAGS = \
 i$(GN_PLUGIN_LDFLAGS)


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

libgnunet_plugin_rest_peerinfo_la_SOURCES = \
  plugin_rest_peerinfo.c
libgnunet_plugin_rest_peerinfo_la_LIBADD = \
  $(top_builddir)/src/hello/libgnunethello.la \
	$(top_builddir)/src/peerinfo/libgnunetpeerinfo.la \
  $(top_builddir)/src/rest/libgnunetrest.la \
  $(top_builddir)/src/json/libgnunetjson.la \
  $(top_builddir)/src/transport/libgnunettransport.la \
  $(top_builddir)/src/util/libgnunetutil.la $(XLIBS) \
  $(LTLIBINTL) -ljansson -lmicrohttpd
libgnunet_plugin_rest_peerinfo_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)

libgnunet_plugin_rest_identity_la_SOURCES = \
  plugin_rest_identity.c
libgnunet_plugin_rest_identity_la_LIBADD = \
	$(top_builddir)/src/identity/libgnunetidentity.la \
  $(top_builddir)/src/rest/libgnunetrest.la \
  $(top_builddir)/src/util/libgnunetutil.la $(XLIBS) \
  $(LTLIBINTL) -ljansson -lmicrohttpd
libgnunet_plugin_rest_identity_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)



libgnunet_plugin_rest_namestore_la_SOURCES = \
  plugin_rest_namestore.c
libgnunet_plugin_rest_namestore_la_LIBADD = \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  $(top_builddir)/src/rest/libgnunetrest.la \
  $(top_builddir)/src/identity/libgnunetidentity.la \
  $(top_builddir)/src/json/libgnunetjson.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/util/libgnunetutil.la $(XLIBS) \
  $(LTLIBINTL) -ljansson -lmicrohttpd
libgnunet_plugin_rest_namestore_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)

libgnunet_plugin_rest_gns_la_SOURCES = \
  plugin_rest_gns.c
libgnunet_plugin_rest_gns_la_LIBADD = \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/gns/libgnunetgns.la \
	$(top_builddir)/src/rest/libgnunetrest.la \
  $(top_builddir)/src/identity/libgnunetidentity.la \
  $(top_builddir)/src/json/libgnunetjson.la \
  $(top_builddir)/src/util/libgnunetutil.la $(XLIBS) \
  $(LTLIBINTL) -ljansson -lmicrohttpd
libgnunet_plugin_rest_gns_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)

libgnunet_plugin_rest_openid_connect_la_SOURCES = \
  plugin_rest_openid_connect.c \
	oidc_helper.c
libgnunet_plugin_rest_openid_connect_la_LIBADD = \
	$(top_builddir)/src/identity/libgnunetidentity.la \
	$(top_builddir)/src/reclaim/libgnunetreclaim.la \
	$(top_builddir)/src/rest/libgnunetrest.la \
	$(top_builddir)/src/reclaim-attribute/libgnunetreclaimattribute.la \
	$(top_builddir)/src/namestore/libgnunetnamestore.la \
$(top_builddir)/src/gns/libgnunetgns.la \
	$(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/util/libgnunetutil.la $(XLIBS) \
  $(LTLIBINTL) -ljansson -lmicrohttpd
libgnunet_plugin_rest_openid_connect_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)

