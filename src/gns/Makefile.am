AM_CPPFLAGS = -I$(top_srcdir)/src/include

if HAVE_GLIBCNSS
NSS_SUBDIR = nss
endif

SUBDIRS = . $(NSS_SUBDIR)

EXTRA_DIST = \
  test_gns_defaults.conf \
  test_gns_simple_lookup.conf \
  test_gns_dht_default.conf \
  gns-helper-service-w32.conf \
  gnunet-gns-proxy-setup-ca \
  zonefiles/J7POEUT41A8PBFS7KVVDRF88GBOU4HK8PSU5QKVLVE3R9T91E99G.zkey \
  zonefiles/OEFL7A4VEF1B40QLEMTG5D8G1CN6EN16QUSG5R2DT71GRJN34LSG.zkey \
  zonefiles/test_zonekey

if MINGW
  WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols
  DO_W32_HELPER = gnunet-gns-helper-service-w32
  DO_W32_NSP = libw32nsp.la
  DO_W32_NSPTOOLS = w32nsp-install w32nsp-uninstall w32nsp-resolve
  DO_W32_HS_CONF = gns-helper-service-w32.conf
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
if HAVE_LIBCURL
# does not compile right now...
if HAVE_EXPERIMENTAL
 DO_PROXY=gnunet-gns-proxy
endif
endif
endif
endif

libexec_PROGRAMS = \
  gnunet-service-gns \
  $(DO_PROXY) \
  $(DO_W32_HELPER) \
  gnunet-dns2gns

bin_PROGRAMS = \
  $(DO_W32_NSPTOOLS) \
  gnunet-gns 

bin_SCRIPTS = gnunet-gns-proxy-setup-ca

plugin_LTLIBRARIES = \
  libgnunet_plugin_block_gns.la

gnunet_gns_SOURCES = \
 gnunet-gns.c
gnunet_gns_LDADD = \
  $(top_builddir)/src/gns/libgnunetgns.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  $(top_builddir)/src/identity/libgnunetidentity.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)
gnunet_gns_DEPENDENCIES = \
  libgnunetgns.la

gnunet_dns2gns_SOURCES = \
 gnunet-dns2gns.c
gnunet_dns2gns_LDADD = \
  $(top_builddir)/src/gns/libgnunetgns.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/identity/libgnunetidentity.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  $(top_builddir)/src/dns/libgnunetdnsparser.la \
  $(top_builddir)/src/dns/libgnunetdnsstub.la \
  $(GN_LIBINTL)
gnunet_dns2gns_DEPENDENCIES = \
  $(top_builddir)/src/gns/libgnunetgns.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/identity/libgnunetidentity.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  $(top_builddir)/src/dns/libgnunetdnsparser.la \
  $(top_builddir)/src/dns/libgnunetdnsstub.la \
  libgnunetgns.la

gnunet_gns_proxy_SOURCES = \
 gnunet-gns-proxy.c 
gnunet_gns_proxy_LDADD = -lmicrohttpd -lcurl -lgnutls \
  $(top_builddir)/src/gns/libgnunetgns.la \
  $(top_builddir)/src/identity/libgnunetidentity.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)
gnunet_gns_proxy_DEPENDENCIES = \
  libgnunetgns.la

gnunet_gns_helper_service_w32_SOURCES = \
  gnunet-gns-helper-service-w32.c
gnunet_gns_helper_service_w32_LDADD = \
  $(top_builddir)/src/gns/libgnunetgns.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)
gnunet_gns_helper_service_w32_DEPENDENCIES = \
  libgnunetgns.la

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
 gnunet-service-gns.c \
 gnunet-service-gns_resolver.c gnunet-service-gns_resolver.h \
 gnunet-service-gns_shorten.c gnunet-service-gns_shorten.h \
 gnunet-service-gns_interceptor.c gnunet-service-gns_interceptor.h 
gnunet_service_gns_LDADD = \
  -lm \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/dns/libgnunetdns.la \
  $(top_builddir)/src/dns/libgnunetdnsparser.la \
  $(top_builddir)/src/dns/libgnunetdnsstub.la \
  $(top_builddir)/src/dht/libgnunetdht.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  $(USE_VPN) \
  $(GN_LIBINTL)
gnunet_service_gns_DEPENDENCIES = \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/dns/libgnunetdns.la \
  $(top_builddir)/src/dns/libgnunetdnsparser.la \
  $(top_builddir)/src/dht/libgnunetdht.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  $(USE_VPN)



libw32nsp_la_SOURCES = \
  w32nsp.c
libw32nsp_la_LIBADD = \
  -lole32 -lws2_32
libw32nsp_la_LDFLAGS = \
  -export-symbols $(top_srcdir)/src/gns/w32nsp.def \
  $(GN_LIB_LDFLAGS)

libgnunetgns_la_SOURCES = \
 gns_api.c gns.h
libgnunetgns_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la $(XLIB) \
 $(top_builddir)/src/namestore/libgnunetnamestore.la
libgnunetgns_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)
libgnunetgns_la_DEPENDENCIES = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/namestore/libgnunetnamestore.la


libgnunet_plugin_block_gns_la_SOURCES = \
  plugin_block_gns.c
libgnunet_plugin_block_gns_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/block/libgnunetblock.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la
libgnunet_plugin_block_gns_la_LDFLAGS = \
  $(GN_PLUGIN_LDFLAGS)
libgnunet_plugin_block_gns_la_DEPENDENCIES = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/block/libgnunetblock.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la

if HAVE_TESTING
#check_PROGRAMS = 
#  test_gns_simple_shorten 
#  test_gns_simple_lookup 
#  test_gns_simple_delegated_lookup 
#  test_gns_simple_mx_lookup 
#  test_gns_simple_srv_lookup 
#  test_gns_simple_zkey_lookup 
#  test_gns_dht_delegated_lookup 
#  test_gns_pseu_shorten 
#  test_gns_max_queries 
#  test_gns_cname_lookup 
#  test_gns_ns_lookup 
#  test_gns_revocation 
#  test_gns_dht_three_peers
# test_gns_proxy
endif

if ENABLE_TEST_RUN
if LINUX
if HAVE_SQLITE
# TESTS = $(check_PROGRAMS)
endif
endif
endif


#test_gns_proxy_SOURCES = \
#  test_gns_proxy.c
#test_gns_proxy_LDADD = -lmicrohttpd @LIBCURL@ \
#  $(top_builddir)/src/util/libgnunetutil.la \
#  $(top_builddir)/src/namestore/libgnunetnamestore.la \
#  $(top_builddir)/src/gns/libgnunetgns.la \
#  $(top_builddir)/src/testing/libgnunettesting.la
#test_gns_proxy_DEPENDENCIES = \
#  $(top_builddir)/src/util/libgnunetutil.la \
#  $(top_builddir)/src/namestore/libgnunetnamestore.la \
#  libgnunetgns.la \
#  $(top_builddir)/src/testing/libgnunettesting.la

test_gns_dht_three_peers_SOURCES = \
  test_gns_dht_three_peers.c
test_gns_dht_three_peers_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  $(top_builddir)/src/gns/libgnunetgns.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/testbed/libgnunettestbed.la
test_gns_dht_three_peers_DEPENDENCIES = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  libgnunetgns.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/testbed/libgnunettestbed.la

test_gns_simple_lookup_SOURCES = \
  test_gns_simple_lookup.c
test_gns_simple_lookup_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  $(top_builddir)/src/gns/libgnunetgns.la \
  $(top_builddir)/src/testing/libgnunettesting.la
test_gns_simple_lookup_DEPENDENCIES = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  libgnunetgns.la \
  $(top_builddir)/src/testing/libgnunettesting.la

test_gns_simple_delegated_lookup_SOURCES = \
  test_gns_simple_delegated_lookup.c
test_gns_simple_delegated_lookup_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  $(top_builddir)/src/gns/libgnunetgns.la \
  $(top_builddir)/src/testing/libgnunettesting.la
test_gns_simple_delegated_lookup_DEPENDENCIES = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  libgnunetgns.la \
  $(top_builddir)/src/testing/libgnunettesting.la

test_gns_simple_mx_lookup_SOURCES = \
  test_gns_simple_mx_lookup.c
test_gns_simple_mx_lookup_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  $(top_builddir)/src/gns/libgnunetgns.la \
  $(top_builddir)/src/testing/libgnunettesting.la
test_gns_simple_mx_lookup_DEPENDENCIES = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  libgnunetgns.la \
  $(top_builddir)/src/testing/libgnunettesting.la

test_gns_simple_srv_lookup_SOURCES = \
  test_gns_simple_srv_lookup.c
test_gns_simple_srv_lookup_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  $(top_builddir)/src/gns/libgnunetgns.la \
  $(top_builddir)/src/testing/libgnunettesting.la
test_gns_simple_srv_lookup_DEPENDENCIES = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  libgnunetgns.la \
  $(top_builddir)/src/testing/libgnunettesting.la

test_gns_simple_zkey_lookup_SOURCES = \
  test_gns_simple_zkey_lookup.c
test_gns_simple_zkey_lookup_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  $(top_builddir)/src/gns/libgnunetgns.la \
  $(top_builddir)/src/testing/libgnunettesting.la
test_gns_simple_zkey_lookup_DEPENDENCIES = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  libgnunetgns.la \
  $(top_builddir)/src/testing/libgnunettesting.la

test_gns_dht_delegated_lookup_SOURCES = \
  test_gns_dht_delegated_lookup.c
test_gns_dht_delegated_lookup_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  $(top_builddir)/src/dht/libgnunetdht.la \
  $(top_builddir)/src/gns/libgnunetgns.la \
  $(top_builddir)/src/testing/libgnunettesting.la
test_gns_dht_delegated_lookup_DEPENDENCIES = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  $(top_builddir)/src/dht/libgnunetdht.la \
  libgnunetgns.la \
  $(top_builddir)/src/testing/libgnunettesting.la

test_gns_simple_shorten_SOURCES = \
  test_gns_simple_shorten.c
test_gns_simple_shorten_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  $(top_builddir)/src/gns/libgnunetgns.la \
  $(top_builddir)/src/testing/libgnunettesting.la
test_gns_simple_shorten_DEPENDENCIES = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  libgnunetgns.la \
  $(top_builddir)/src/testing/libgnunettesting.la


test_gns_pseu_shorten_SOURCES = \
  test_gns_pseu_shorten.c
test_gns_pseu_shorten_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  $(top_builddir)/src/dht/libgnunetdht.la \
  $(top_builddir)/src/gns/libgnunetgns.la \
  $(top_builddir)/src/testing/libgnunettesting.la
test_gns_pseu_shorten_DEPENDENCIES = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  $(top_builddir)/src/dht/libgnunetdht.la \
  libgnunetgns.la \
  $(top_builddir)/src/testing/libgnunettesting.la


test_gns_max_queries_SOURCES = \
  test_gns_max_queries.c
test_gns_max_queries_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  $(top_builddir)/src/gns/libgnunetgns.la \
  $(top_builddir)/src/testing/libgnunettesting.la
test_gns_max_queries_DEPENDENCIES = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  libgnunetgns.la \
  $(top_builddir)/src/testing/libgnunettesting.la

test_gns_cname_lookup_SOURCES = \
  test_gns_cname_lookup.c
test_gns_cname_lookup_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  $(top_builddir)/src/gns/libgnunetgns.la \
  $(top_builddir)/src/testing/libgnunettesting.la
test_gns_cname_lookup_DEPENDENCIES = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  libgnunetgns.la \
  $(top_builddir)/src/testing/libgnunettesting.la


test_gns_ns_lookup_SOURCES = \
  test_gns_ns_lookup.c
test_gns_ns_lookup_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  $(top_builddir)/src/gns/libgnunetgns.la \
  $(top_builddir)/src/testing/libgnunettesting.la
test_gns_ns_lookup_DEPENDENCIES = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  libgnunetgns.la \
  $(top_builddir)/src/testing/libgnunettesting.la


test_gns_revocation_SOURCES = \
  test_gns_revocation.c
test_gns_revocation_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  $(top_builddir)/src/gns/libgnunetgns.la \
  $(top_builddir)/src/testing/libgnunettesting.la
test_gns_revocation_DEPENDENCIES = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  libgnunetgns.la \
  $(top_builddir)/src/testing/libgnunettesting.la



#Build stub api
#libgnunetnamestore_la_SOURCES = \
# namestore_stub_api.c
#libgnunetnamestore_la_LIBADD = \
# $(top_builddir)/src/util/libgnunetutil.la $(XLIB)
#libgnunetnamestore_la_LDFLAGS = \
#  $(GN_LIB_LDFLAGS)
#libgnunetnamestore_la_DEPENDENCIES = \
# $(top_builddir)/src/util/libgnunetutil.la



