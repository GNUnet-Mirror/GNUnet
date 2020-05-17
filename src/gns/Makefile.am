# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

if HAVE_GLIBCNSS
NSS_SUBDIR = nss
endif

SUBDIRS = . $(NSS_SUBDIR)

pkgdata_DATA = \
  gnunet-gns-proxy-ca.template

if HAVE_LIBIDN
  LIBIDN= -lidn
else
  LIBIDN=
endif

if HAVE_LIBIDN2
  LIBIDN2= -lidn2
else
  LIBIDN2=
endif

EXTRA_DIST = \
  test_gns_defaults.conf \
  test_gns_lookup.conf \
  test_gns_proxy.conf \
  test_gns_simple_lookup.conf \
  openssl.cnf \
  gnunet-gns-proxy-setup-ca.in \
  zonefiles/J7POEUT41A8PBFS7KVVDRF88GBOU4HK8PSU5QKVLVE3R9T91E99G.zkey \
  zonefiles/OEFL7A4VEF1B40QLEMTG5D8G1CN6EN16QUSG5R2DT71GRJN34LSG.zkey \
  zonefiles/test_zonekey \
  $(check_SCRIPTS) \
  $(pkgdata_DATA) \
  test_gnunet_gns.sh.in

USE_VPN = $(top_builddir)/src/vpn/libgnunetvpn.la

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
endif

pkgcfgdir = $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

plugindir = $(libdir)/gnunet

pkgcfg_DATA = \
  gns.conf

lib_LTLIBRARIES = \
  libgnunetgns.la


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

libexec_PROGRAMS = \
  gnunet-service-gns \
  gnunet-dns2gns \
  $(DO_PROXY)

bin_PROGRAMS = \
  gnunet-gns

noinst_PROGRAMS = \
  gnunet-gns-benchmark

if LINUX
bin_PROGRAMS += gnunet-bcd
endif

REST_PLUGIN = libgnunet_plugin_rest_gns.la

plugin_LTLIBRARIES = \
  libgnunet_plugin_block_gns.la \
  libgnunet_plugin_gnsrecord_gns.la \
  $(REST_PLUGIN)


bin_SCRIPTS = \
  gnunet-gns-proxy-setup-ca

gnunet-gns-proxy-setup-ca: gnunet-gns-proxy-setup-ca.in Makefile
	$(AWK) -v bdir="$(bindir)" -v py="$(PYTHON)" -v awkay="$(AWK_BINARY)" -v pfx="$(prefix)" -v prl="$(PERL)" -v sysconfdirectory="$(sysconfdir)" -v pkgdatadirectory="$(pkgdatadir)" -f $(top_srcdir)/bin/dosubst.awk < $(srcdir)/gnunet-gns-proxy-setup-ca.in > gnunet-gns-proxy-setup-ca
	@chmod +x gnunet-gns-proxy-setup-ca

test_gnunet_gns.sh: test_gnunet_gns.sh.in Makefile
	$(AWK) -v bdir="$(bindir)" -v py="$(PYTHON)" -v awkay="$(AWK_BINARY)" -v pfx="$(prefix)" -v prl="$(PERL)" -v sysconfdirectory="$(sysconfdir)" -v pkgdatadirectory="$(pkgdatadir)" -f $(top_srcdir)/bin/dosubst.awk < $(srcdir)/test_gnunet_gns.sh.in > test_gnunet_gns.sh
	@chmod +x test_gnunet_gns.sh

CLEANFILES = test_gnunet_gns.sh

libgnunet_plugin_rest_gns_la_SOURCES = \
  plugin_rest_gns.c
libgnunet_plugin_rest_gns_la_LIBADD = \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  libgnunetgns.la \
  $(top_builddir)/src/rest/libgnunetrest.la \
  $(top_builddir)/src/identity/libgnunetidentity.la \
  $(top_builddir)/src/json/libgnunetjson.la \
  $(top_builddir)/src/util/libgnunetutil.la $(XLIBS) \
  $(LTLIBINTL) -ljansson $(MHD_LIBS)
libgnunet_plugin_rest_gns_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)
libgnunet_plugin_rest_gns_la_CFLAGS = $(MHD_CFLAGS) $(AM_CFLAGS)


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
  $(LIBIDN) $(LIBIDN2) \
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
  $(GN_LIBINTL) $(MHD_LIBS)
gnunet_bcd_CFLAGS = $(MHD_CFLAGS) $(AM_CFLAGS)


gnunet_dns2gns_SOURCES = \
 gnunet-dns2gns.c
gnunet_dns2gns_LDADD = \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  libgnunetgns.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/identity/libgnunetidentity.la \
  $(GN_LIBINTL)

if HAVE_SUDO
SUDO_OR_DOAS_BINARY= $(SUDO_BINARY)
else
if HAVE_DOAS_BINARY
SUDO_OR_DOAS_BINARY= $(DOAS_BINARY)
endif
endif

if LINUX
HIJACKBIN = gnunet-dns2gns
install-exec-hook:
	$(SUDO_OR_DOAS_BINARY) setcap 'cap_net_bind_service=+ep' $(DESTDIR)$(libexecdir)/gnunet-dns2gns || true
else
install-exec-hook:
endif

gnunet_gns_proxy_SOURCES = \
 gnunet-gns-proxy.c
gnunet_gns_proxy_LDADD = $(MHD_LIBS) $(LIB_GNURL) -lgnutls \
  libgnunetgns.la \
  $(top_builddir)/src/identity/libgnunetidentity.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)
if HAVE_GNUTLS_DANE
gnunet_gns_proxy_LDADD += -lgnutls-dane
endif
gnunet_gns_proxy_CFLAGS = $(MHD_CFLAGS) $(CPP_GNURL) $(AM_CFLAGS)

test_gns_proxy_SOURCES = \
  test_gns_proxy.c
test_gns_proxy_LDADD = $(MHD_LIBS) $(LIB_GNURL) -lgnutls \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)
test_gns_proxy_CFLAGS = $(MHD_CFLAGS) $(CPP_GNURL) $(AM_CFLAGS)

#gnunet_gns_import_SOURCES = \
#  gnunet-gns-import.c
#gnunet_gns_import_LDADD = \
#  $(top_builddir)/src/identity/libgnunetidentity.la \
#  $(top_builddir)/src/namestore/libgnunetnamestore.la \
#  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
#  $(top_builddir)/src/util/libgnunetutil.la \
#  $(GN_LIBINTL)


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
  $(LIBIDN) $(LIBIDN2) \
  $(USE_VPN) \
  $(GN_LIBINTL)


libgnunetgns_la_SOURCES = \
 gns_api.c gns_api.h \
 gns_tld_api.c gns.h
libgnunetgns_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la $(XLIB) \
 $(top_builddir)/src/identity/libgnunetidentity.la \
 $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la
libgnunetgns_la_LDFLAGS = \
  $(GN_LIBINTL) \
  $(GN_LIB_LDFLAGS)


libgnunet_plugin_block_gns_la_SOURCES = \
  plugin_block_gns.c
libgnunet_plugin_block_gns_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/block/libgnunetblock.la \
  $(top_builddir)/src/block/libgnunetblockgroup.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la
libgnunet_plugin_block_gns_la_LDFLAGS = \
  $(GN_LIBINTL) \
  $(GN_PLUGIN_LDFLAGS)

if HAVE_GNUTLS
if HAVE_LIBGNURL
check_PROGRAMS = \
  test_gns_proxy
endif
endif

check_SCRIPTS = \
  test_gns_lookup.sh \
  test_gns_config_lookup.sh \
  test_gns_ipv6_lookup.sh\
  test_gns_txt_lookup.sh\
  test_gns_caa_lookup.sh\
  test_gns_mx_lookup.sh \
  test_gns_gns2dns_lookup.sh \
  test_gns_gns2dns_zkey_lookup.sh \
  test_gns_gns2dns_cname_lookup.sh \
  test_gns_dht_lookup.sh\
  test_gns_delegated_lookup.sh \
  test_gns_at_lookup.sh\
  test_gns_zkey_lookup.sh\
  test_gns_rel_expiration.sh\
  test_gns_soa_lookup.sh\
  test_gns_revocation.sh\
  test_gns_cname_lookup.sh

if HAVE_GNUTLS
if HAVE_LIBGNURL
check_SCRIPTS += \
  test_proxy.sh
endif
endif
check_SCRIPTS += \
  test_plugin_rest_gns.sh


if ENABLE_TEST_RUN
if HAVE_SQLITE
 AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
 TESTS = $(check_SCRIPTS)
endif
endif
