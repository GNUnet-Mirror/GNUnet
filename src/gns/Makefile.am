# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

if HAVE_GLIBCNSS
NSS_SUBDIR = nss
endif

SUBDIRS = . $(NSS_SUBDIR)

EXTRA_DIST = \
  test_gns_defaults.conf \
  test_gns_lookup.conf \
  test_gns_proxy.conf \
  test_gns_simple_lookup.conf \
  gns-helper-service-w32.conf \
  w32nsp.def \
  openssl.cnf \
  gnunet-gns-proxy-setup-ca.in \
  zonefiles/J7POEUT41A8PBFS7KVVDRF88GBOU4HK8PSU5QKVLVE3R9T91E99G.zkey \
  zonefiles/OEFL7A4VEF1B40QLEMTG5D8G1CN6EN16QUSG5R2DT71GRJN34LSG.zkey \
  zonefiles/test_zonekey \
  $(check_SCRIPTS)

if MINGW
  WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols
  DO_W32_HELPER = gnunet-gns-helper-service-w32
  DO_W32_NSP = libw32nsp.la
  DO_W32_NSPTOOLS = w32nsp-install w32nsp-uninstall w32nsp-resolve
  DO_W32_HS_CONF = gns-helper-service-w32.conf
  DO_NONPOSIX_GNSIMPORT = gnunet-gns-import
endif
USE_VPN = $(top_builddir)/src/vpn/libgnunetvpn.la

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
endif

pkgcfgdir = $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

plugindir = $(libdir)/gnunet

pkgcfg_DATA = \
  gns.conf \
  $(DO_W32_HS_CONF)

lib_LTLIBRARIES = \
  $(DO_W32_NSP) \
  libgnunetgns.la


if HAVE_MHD
if HAVE_GNUTLS
if HAVE_LIBGNURL
  DO_PROXY=gnunet-gns-proxy
LIB_GNURL=@LIBGNURL@
CPP_GNURL=@LIBGNURL_CPPFLAGS@
else
if HAVE_LIBCURL
  DO_PROXY=gnunet-gns-proxy
LIB_GNURL=@LIBCURL@
CPP_GNURL=@LIBCURL_CPPFLAGS@
endif
endif
endif
endif

libexec_PROGRAMS = \
  gnunet-service-gns \
  gnunet-dns2gns \
  $(DO_W32_HELPER) \
  $(DO_PROXY)

bin_PROGRAMS = \
  $(DO_W32_NSPTOOLS) \
  $(DO_NONPOSIX_GNSIMPORT) \
  gnunet-gns

noinst_PROGRAMS = \
  gnunet-gns-benchmark

pkgdata_DATA = \
  openssl.cnf

if HAVE_MHD
if LINUX
bin_PROGRAMS += gnunet-bcd
endif
endif

if HAVE_MHD
if HAVE_JSON
REST_PLUGIN = libgnunet_plugin_rest_gns.la
endif
endif

plugin_LTLIBRARIES = \
  libgnunet_plugin_block_gns.la \
  libgnunet_plugin_gnsrecord_gns.la \
  $(REST_PLUGIN)


bin_SCRIPTS = \
  gnunet-gns-proxy-setup-ca

# See: https://www.gnu.org/software/automake/manual/html_node/Scripts.html#Scripts
do_subst = sed -e 's,[@]pkgdatadir[@],$(pkgdatadir),g'

gnunet-gns-proxy-setup-ca: gnunet-gns-proxy-setup-ca.in Makefile
	$(do_subst) < $(srcdir)/gnunet-gns-proxy-setup-ca.in > gnunet-gns-proxy-setup-ca
	chmod +x gnunet-gns-proxy-setup-ca


libgnunet_plugin_rest_gns_la_SOURCES = \
  plugin_rest_gns.c
libgnunet_plugin_rest_gns_la_LIBADD = \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  libgnunetgns.la \
  $(top_builddir)/src/rest/libgnunetrest.la \
  $(top_builddir)/src/identity/libgnunetidentity.la \
  $(top_builddir)/src/json/libgnunetjson.la \
  $(top_builddir)/src/util/libgnunetutil.la $(XLIBS) \
  $(LTLIBINTL) -ljansson -lmicrohttpd
libgnunet_plugin_rest_gns_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)


libgnunet_plugin_gnsrecord_gns_la_SOURCES = \
  plugin_gnsrecord_gns.c
libgnunet_plugin_gnsrecord_gns_la_LIBADD = \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(LTLIBINTL)
libgnunet_plugin_gnsrecord_gns_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)


gnunet_gns_SOURCES = \
 gnunet-gns.c
gnunet_gns_LDADD = \
  libgnunetgns.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)

gnunet_gns_benchmark_SOURCES = \
 gnunet-gns-benchmark.c
gnunet_gns_benchmark_LDADD = \
  libgnunetgns.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)


gnunet_bcd_SOURCES = \
 gnunet-bcd.c
gnunet_bcd_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL) -lmicrohttpd


gnunet_dns2gns_SOURCES = \
 gnunet-dns2gns.c
gnunet_dns2gns_LDADD = \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  libgnunetgns.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/identity/libgnunetidentity.la \
  $(GN_LIBINTL)

if LINUX
HIJACKBIN = gnunet-dns2gns
install-exec-hook:
	$(SUDO_BINARY) setcap 'cap_net_bind_service=+ep' $(DESTDIR)$(libexecdir)/gnunet-dns2gns || true
else
install-exec-hook:
endif

gnunet_gns_proxy_SOURCES = \
 gnunet-gns-proxy.c
gnunet_gns_proxy_CPPFLAGS = $(AM_CPPFLAGS) $(CPP_GNURL)
gnunet_gns_proxy_LDADD = -lmicrohttpd $(LIB_GNURL) -lgnutls \
  libgnunetgns.la \
  $(top_builddir)/src/identity/libgnunetidentity.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)
if HAVE_GNUTLS_DANE
gnunet_gns_proxy_LDADD += -lgnutls-dane
endif

test_gns_proxy_SOURCES = \
  test_gns_proxy.c
test_gns_proxy_LDADD = -lmicrohttpd $(LIB_GNURL) -lgnutls \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)

gnunet_gns_helper_service_w32_SOURCES = \
  gnunet-gns-helper-service-w32.c
gnunet_gns_helper_service_w32_LDADD = \
  libgnunetgns.la \
  $(top_builddir)/src/identity/libgnunetidentity.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)

gnunet_gns_import_SOURCES = \
  gnunet-gns-import.c
gnunet_gns_import_LDADD = \
  $(top_builddir)/src/identity/libgnunetidentity.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)


w32nsp_install_SOURCES = \
  w32nsp-install.c
w32nsp_install_LDADD = -lws2_32

w32nsp_uninstall_SOURCES = \
  w32nsp-uninstall.c
w32nsp_uninstall_LDADD = -lws2_32

w32nsp_resolve_SOURCES = \
  w32nsp-resolve.c
w32nsp_resolve_LDADD = -lws2_32

gnunet_service_gns_SOURCES = \
 gnunet-service-gns.c gnunet-service-gns.h \
 gnunet-service-gns_resolver.c gnunet-service-gns_resolver.h \
 gnunet-service-gns_interceptor.c gnunet-service-gns_interceptor.h
gnunet_service_gns_LDADD = \
  -lm \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/identity/libgnunetidentity.la \
  $(top_builddir)/src/revocation/libgnunetrevocation.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/dns/libgnunetdns.la \
  $(top_builddir)/src/dht/libgnunetdht.la \
  $(top_builddir)/src/namecache/libgnunetnamecache.la \
  $(USE_VPN) \
  $(GN_LIBINTL)


libw32nsp_la_SOURCES = \
  w32nsp.c
libw32nsp_la_LIBADD = \
  -lole32 -lws2_32
libw32nsp_la_LDFLAGS = \
  -export-symbols $(top_srcdir)/src/gns/w32nsp.def \
  -no-undefined -static-libgcc

libgnunetgns_la_SOURCES = \
 gns_api.c gns_api.h \
 gns_tld_api.c gns.h
libgnunetgns_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la $(XLIB) \
 $(top_builddir)/src/identity/libgnunetidentity.la \
 $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la
libgnunetgns_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)


libgnunet_plugin_block_gns_la_SOURCES = \
  plugin_block_gns.c
libgnunet_plugin_block_gns_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/block/libgnunetblock.la \
  $(top_builddir)/src/block/libgnunetblockgroup.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la
libgnunet_plugin_block_gns_la_LDFLAGS = \
  $(GN_PLUGIN_LDFLAGS)

check_PROGRAMS = \
  test_gns_proxy

check_SCRIPTS = \
  test_gns_lookup.sh \
  test_gns_config_lookup.sh \
  test_gns_ipv6_lookup.sh\
  test_gns_txt_lookup.sh\
  test_gns_mx_lookup.sh \
  test_gns_gns2dns_lookup.sh \
  test_gns_gns2dns_cname_lookup.sh \
  test_gns_dht_lookup.sh\
  test_gns_delegated_lookup.sh \
  test_gns_at_lookup.sh\
  test_gns_zkey_lookup.sh\
  test_gns_rel_expiration.sh\
  test_gns_soa_lookup.sh\
  test_gns_revocation.sh\
  test_gns_cname_lookup.sh \
	test_proxy.sh

if ENABLE_TEST_RUN
if HAVE_SQLITE
 AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
 TESTS = $(check_SCRIPTS)
endif
endif
