INCLUDES = -I$(top_srcdir)/src/include

if MINGW
  WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
endif

pkgcfgdir= $(pkgdatadir)/config.d/

plugindir = $(libdir)/gnunet

dist_pkgcfg_DATA = \
  dns.conf

if LINUX
HIJACKBIN = gnunet-helper-hijack-dns gnunet-helper-dns
install-exec-hook:
	$(SUDO_BINARY) chown root:root $(bindir)/gnunet-helper-hijack-dns || true
	$(SUDO_BINARY) chmod u+s $(bindir)/gnunet-helper-hijack-dns || true
	$(SUDO_BINARY) chown root:root $(bindir)/gnunet-helper-dns || true
	$(SUDO_BINARY) chmod u+s $(bindir)/gnunet-helper-dns || true
else
install-exec-hook:
endif

lib_LTLIBRARIES = \
  libgnunetdnsparser.la \
  libgnunetdns.la

bin_PROGRAMS = \
  gnunet-service-dns $(HIJACKBIN)

plugin_LTLIBRARIES = \
  libgnunet_plugin_block_dns.la 


gnunet_helper_hijack_dns_SOURCES = \
 gnunet-helper-hijack-dns.c

gnunet_helper_dns_SOURCES = \
 gnunet-helper-dns.c

gnunet_service_dns_SOURCES = \
 gnunet-service-dns.c gnunet-service-dns-p.h 
gnunet_service_dns_LDADD = \
  $(top_builddir)/src/core/libgnunetcore.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/dht/libgnunetdht.la \
  $(top_builddir)/src/mesh/libgnunetmesh.la \
  $(top_builddir)/src/dns/libgnunetdnsparser.la \
  $(GN_LIBINTL)

libgnunetdnsparser_la_SOURCES = \
 dnsparser.c 
libgnunetdnsparser_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la $(XLIB)
libgnunetdnsparser_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)

libgnunetdns_la_SOURCES = \
 dns_api.c dns.h
libgnunetdns_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la $(XLIB)
libgnunetdns_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)

libgnunet_plugin_block_dns_la_SOURCES = \
  plugin_block_dns.c
libgnunet_plugin_block_dns_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la
libgnunet_plugin_block_dns_la_LDFLAGS = \
  $(top_builddir)/src/block/$(GN_PLUGIN_LDFLAGS)



