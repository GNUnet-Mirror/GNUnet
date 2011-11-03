INCLUDES = -I$(top_srcdir)/src/include

if MINGW
  WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
endif

pkgcfgdir= $(pkgdatadir)/config.d/

dist_pkgcfg_DATA = \
  vpn.conf

if LINUX
VPNBIN = gnunet-helper-vpn
HIJACKBIN = gnunet-helper-hijack-dns
install-exec-hook:
	$(SUDO_BINARY) chown root:root $(bindir)/gnunet-helper-vpn || true
	$(SUDO_BINARY) chmod u+s $(bindir)/gnunet-helper-vpn || true
	$(SUDO_BINARY) chown root:root $(bindir)/gnunet-helper-hijack-dns || true
	$(SUDO_BINARY) chmod u+s $(bindir)/gnunet-helper-hijack-dns || true
else
install-exec-hook:
endif


bin_PROGRAMS = \
  gnunet-daemon-exit gnunet-daemon-vpn gnunet-service-dns $(VPNBIN) $(HIJACKBIN)


gnunet_helper_vpn_SOURCES = \
 gnunet-helper-vpn.c

gnunet_helper_hijack_dns_SOURCES = \
 gnunet-helper-hijack-dns.c

gnunet_daemon_vpn_SOURCES = \
 gnunet-daemon-vpn.c gnunet-daemon-vpn.h \
 gnunet-dns-parser.c gnunet-dns-parser.h \
 gnunet-daemon-vpn-helper.c gnunet-daemon-vpn-helper.h \
 gnunet-daemon-vpn-dns.c gnunet-daemon-vpn-dns.h \
 gnunet-helper-vpn-api.c gnunet-helper-vpn-api.h \
 gnunet-vpn-checksum.c gnunet-vpn-checksum.h
gnunet_daemon_vpn_LDADD = \
  $(top_builddir)/src/core/libgnunetcore.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/mesh/libgnunetmesh.la \
  $(GN_LIBINTL)

gnunet_service_dns_SOURCES = \
 gnunet-service-dns.c gnunet-service-dns-p.h \
 gnunet-dns-parser.c gnunet-dns-parser.h
gnunet_service_dns_LDADD = \
  $(top_builddir)/src/core/libgnunetcore.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/dht/libgnunetdht.la \
  $(top_builddir)/src/mesh/libgnunetmesh.la \
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
