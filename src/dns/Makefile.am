# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

if MINGW
  WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
endif

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

plugindir = $(libdir)/gnunet

pkgcfg_DATA = \
  dns.conf

if LINUX
HIJACKBIN = gnunet-helper-dns
install-exec-hook:
	$(top_srcdir)/src/dns/install-dns-helper.sh $(libexecdir) $(GNUNETDNS_GROUP) $(SUDO_BINARY) || true
else
install-exec-hook:
endif

lib_LTLIBRARIES = \
  libgnunetdnsparser.la \
  libgnunetdnsstub.la \
  libgnunetdns.la

libexec_PROGRAMS = \
  gnunet-service-dns $(HIJACKBIN)

noinst_PROGRAMS = \
  gnunet-dns-monitor gnunet-dns-redirector

plugin_LTLIBRARIES = \
  libgnunet_plugin_block_dns.la

if LINUX
check_SCRIPTS = \
 test_gnunet_dns.sh
endif

check_PROGRAMS = \
 test_hexcoder

gnunet_helper_dns_SOURCES = \
 gnunet-helper-dns.c


gnunet_dns_monitor_SOURCES = \
 gnunet-dns-monitor.c
gnunet_dns_monitor_LDADD = \
  libgnunetdnsparser.la \
  libgnunetdns.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)

gnunet_dns_redirector_SOURCES = \
 gnunet-dns-redirector.c
gnunet_dns_redirector_LDADD = \
  libgnunetdnsparser.la \
  libgnunetdns.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)

gnunet_service_dns_SOURCES = \
 gnunet-service-dns.c
gnunet_service_dns_LDADD = \
  libgnunetdnsstub.la \
  $(top_builddir)/src/tun/libgnunettun.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)

libgnunetdnsparser_la_SOURCES = \
 dnsparser.c
libgnunetdnsparser_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la $(XLIB) \
  -lidn
libgnunetdnsparser_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS) \
  -version-info 1:0:1

libgnunetdnsstub_la_SOURCES = \
 dnsstub.c
libgnunetdnsstub_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la $(XLIB)
libgnunetdnsstub_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS) \
  -version-info 0:0:0

libgnunetdns_la_SOURCES = \
 dns_api.c dns.h
libgnunetdns_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la $(XLIB)
libgnunetdns_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS) \
  -version-info 0:0:0

libgnunet_plugin_block_dns_la_SOURCES = \
  plugin_block_dns.c
libgnunet_plugin_block_dns_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la
libgnunet_plugin_block_dns_la_LDFLAGS = \
  $(top_builddir)/src/block/$(GN_PLUGIN_LDFLAGS)


if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;
TESTS = $(check_PROGRAMS)  $(check_SCRIPTS)
endif

EXTRA_DIST = \
  $(check_SCRIPTS)


test_hexcoder_SOURCES = \
 test_hexcoder.c
test_hexcoder_LDADD = \
 libgnunetdnsparser.la \
 $(top_builddir)/src/util/libgnunetutil.la
