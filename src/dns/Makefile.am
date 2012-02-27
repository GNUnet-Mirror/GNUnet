INCLUDES = -I$(top_srcdir)/src/include

if MINGW
  WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
endif

pkgcfgdir= $(pkgdatadir)/config.d/

plugindir = $(libdir)/gnunet

pkgcfg_DATA = \
  dns.conf

if LINUX
HIJACKBIN = gnunet-helper-dns
install-exec-hook:
	$(SUDO_BINARY) chown root $(bindir)/gnunet-helper-dns || true
	$(SUDO_BINARY) chgrp $(GNUNETDNS_GROUP) $(bindir)/gnunet-helper-dns || true
	$(SUDO_BINARY) chmod 4750 $(bindir)/gnunet-helper-dns || true
	$(SUDO_BINARY) chgrp $(GNUNETDNS_GROUP) $(bindir)/gnunet-service-dns || true
	$(SUDO_BINARY) chmod 2750 $(bindir)/gnunet-service-dns || true
else
install-exec-hook:
endif

lib_LTLIBRARIES = \
  libgnunetdnsparser.la \
  libgnunetdns.la

bin_PROGRAMS = \
  gnunet-service-dns $(HIJACKBIN)

noinst_PROGRAMS = \
  gnunet-dns-monitor gnunet-dns-redirector

plugin_LTLIBRARIES = \
  libgnunet_plugin_block_dns.la 

check_SCRIPTS = \
 test_gnunet_dns.sh


gnunet_helper_dns_SOURCES = \
 gnunet-helper-dns.c


gnunet_dns_monitor_SOURCES = \
 gnunet-dns-monitor.c
gnunet_dns_monitor_LDADD = \
  $(top_builddir)/src/dns/libgnunetdnsparser.la \
  $(top_builddir)/src/dns/libgnunetdns.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)
gnunet_dns_monitor_DEPENDENCIES = \
  libgnunetdnsparser.la \
  libgnunetdns.la

gnunet_dns_redirector_SOURCES = \
 gnunet-dns-redirector.c
gnunet_dns_redirector_LDADD = \
  $(top_builddir)/src/dns/libgnunetdnsparser.la \
  $(top_builddir)/src/dns/libgnunetdns.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)
gnunet_dns_redirector_DEPENDENCIES = \
  libgnunetdnsparser.la \
  libgnunetdns.la

gnunet_service_dns_SOURCES = \
 gnunet-service-dns.c 
gnunet_service_dns_LDADD = \
  $(top_builddir)/src/tun/libgnunettun.la \
  $(top_builddir)/src/mesh/libgnunetmesh.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)

libgnunetdnsparser_la_SOURCES = \
 dnsparser.c 
libgnunetdnsparser_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la $(XLIB)
libgnunetdnsparser_la_LDFLAGS = \
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
TESTS = $(check_PROGRAMS)  $(check_SCRIPTS)
endif

EXTRA_DIST = \
  $(check_SCRIPTS) 
