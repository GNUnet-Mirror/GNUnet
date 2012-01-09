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


lib_LTLIBRARIES = \
  libgnunetvpn.la


bin_PROGRAMS = \
  gnunet-daemon-exit gnunet-daemon-vpn $(VPNBIN) gnunet-service-vpn gnunet-vpn


gnunet_helper_vpn_SOURCES = \
 gnunet-helper-vpn.c

gnunet_daemon_vpn_SOURCES = \
 gnunet-daemon-vpn.c 
gnunet_daemon_vpn_LDADD = \
  $(top_builddir)/src/core/libgnunetcore.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/mesh/libgnunetmesh.la \
  $(top_builddir)/src/dns/libgnunetdnsparser.la \
  $(top_builddir)/src/dns/libgnunetdns.la \
  $(GN_LIBINTL)

gnunet_service_vpn_SOURCES = \
 gnunet-service-vpn.c 
gnunet_service_vpn_LDADD = \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/mesh/libgnunetmesh.la \
  $(GN_LIBINTL)

gnunet_daemon_exit_SOURCES = \
 gnunet-daemon-exit.c 
gnunet_daemon_exit_LDADD = \
  $(top_builddir)/src/core/libgnunetcore.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/mesh/libgnunetmesh.la \
  $(GN_LIBINTL)

gnunet_vpn_SOURCES = \
 gnunet-vpn.c
gnunet_vpn_LDADD = \
  $(top_builddir)/src/vpn/libgnunetvpn.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)
gnunet_vpn_DEPENDENCIES = \
  libgnunetvpn.la

libgnunetvpn_la_SOURCES = \
 vpn_api.c vpn.h
libgnunetvpn_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la $(XLIB)
libgnunetvpn_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)


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
