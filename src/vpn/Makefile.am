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
  vpn.conf

if LINUX
VPNBIN = gnunet-helper-vpn
install-exec-hook:
	$(SUDO_BINARY) chown root:root $(bindir)/gnunet-helper-vpn || true
	$(SUDO_BINARY) chmod u+s $(bindir)/gnunet-helper-vpn || true
else
install-exec-hook:
endif


bin_PROGRAMS = \
  gnunet-daemon-exit gnunet-daemon-vpn $(VPNBIN) $(HIJACKBIN)


gnunet_helper_vpn_SOURCES = \
 gnunet-helper-vpn.c

gnunet_daemon_vpn_SOURCES = \
 gnunet-daemon-vpn.c gnunet-daemon-vpn.h \
 gnunet-daemon-vpn-helper.c gnunet-daemon-vpn-helper.h \
 gnunet-daemon-vpn-dns.c gnunet-daemon-vpn-dns.h \
 gnunet-helper-vpn-api.c gnunet-helper-vpn-api.h \
 gnunet-vpn-checksum.c gnunet-vpn-checksum.h
gnunet_daemon_vpn_LDADD = \
  $(top_builddir)/src/core/libgnunetcore.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/mesh/libgnunetmesh.la \
  $(top_builddir)/src/dns/libgnunetdnsparser.la \
  $(GN_LIBINTL)

gnunet_daemon_exit_SOURCES = \
 gnunet-daemon-exit.c \
 gnunet-helper-vpn-api.c gnunet-helper-vpn-api.h \
 gnunet-vpn-checksum.c gnunet-vpn-checksum.h
gnunet_daemon_exit_LDADD = \
  $(top_builddir)/src/core/libgnunetcore.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/mesh/libgnunetmesh.la \
  $(GN_LIBINTL)


plugin_LTLIBRARIES = \
  libgnunet_plugin_block_dns.la 

libgnunet_plugin_block_dns_la_SOURCES = \
  plugin_block_dns.c
libgnunet_plugin_block_dns_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la
libgnunet_plugin_block_dns_la_LDFLAGS = \
  $(top_builddir)/src/block/$(GN_PLUGIN_LDFLAGS)


#check_PROGRAMS = \
# test_XXX

if ENABLE_TEST_RUN
#TESTS = \
# test_transport_api_tcp 
endif

#test_transport_api_tcp_SOURCES = \
# test_transport_api.c
#test_transport_api_tcp_LDADD = \
# $(top_builddir)/src/transport/libgnunettransport.la \
# $(top_builddir)/src/util/libgnunetutil.la  

EXTRA_DIST = \
  gnunet-vpn-packet.h \
  test-conf.conf
