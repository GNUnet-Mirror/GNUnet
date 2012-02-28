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
  vpn.conf

if LINUX
VPNBIN = gnunet-helper-vpn
install-exec-hook:
	$(SUDO_BINARY) chown root:root $(bindir)/gnunet-helper-vpn || true
	$(SUDO_BINARY) chmod u+s $(bindir)/gnunet-helper-vpn || true
if HAVE_MHD
 VPN_TEST = \
 test_gnunet_vpn-4_to_6 \
 test_gnunet_vpn-6_to_4 \
 test_gnunet_vpn-6_over \
 test_gnunet_vpn-4_over
endif
else
install-exec-hook:
endif


lib_LTLIBRARIES = \
  libgnunetvpn.la


bin_PROGRAMS = \
  $(VPNBIN) gnunet-service-vpn gnunet-vpn



check_PROGRAMS = $(VPN_TEST)

if ENABLE_TEST_RUN
TESTS = $(check_PROGRAMS)
endif

EXTRA_DIST = \
  test_gnunet_vpn.conf

gnunet_helper_vpn_SOURCES = \
 gnunet-helper-vpn.c

gnunet_service_vpn_SOURCES = \
 gnunet-service-vpn.c 
gnunet_service_vpn_LDADD = \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/tun/libgnunettun.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/mesh/libgnunetmesh.la \
  $(GN_LIBINTL)
gnunet_service_vpn_CFLAGS = \
  -I$(top_srcdir)/src/exit $(CFLAGS)

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


test_gnunet_vpn_4_over_SOURCES = \
 test_gnunet_vpn.c
test_gnunet_vpn_4_over_LDADD = -lmicrohttpd @LIBCURL@ \
 $(top_builddir)/src/vpn/libgnunetvpn.la \
 $(top_builddir)/src/arm/libgnunetarm.la \
 $(top_builddir)/src/util/libgnunetutil.la 

test_gnunet_vpn_6_over_SOURCES = \
 test_gnunet_vpn.c
test_gnunet_vpn_6_over_LDADD = -lmicrohttpd @LIBCURL@ \
 $(top_builddir)/src/vpn/libgnunetvpn.la \
 $(top_builddir)/src/arm/libgnunetarm.la \
 $(top_builddir)/src/util/libgnunetutil.la 

test_gnunet_vpn_4_to_6_SOURCES = \
 test_gnunet_vpn.c
test_gnunet_vpn_4_to_6_LDADD = -lmicrohttpd @LIBCURL@ \
 $(top_builddir)/src/vpn/libgnunetvpn.la \
 $(top_builddir)/src/arm/libgnunetarm.la \
 $(top_builddir)/src/util/libgnunetutil.la 

test_gnunet_vpn_6_to_4_SOURCES = \
 test_gnunet_vpn.c
test_gnunet_vpn_6_to_4_LDADD = -lmicrohttpd @LIBCURL@ \
 $(top_builddir)/src/vpn/libgnunetvpn.la \
 $(top_builddir)/src/arm/libgnunetarm.la \
 $(top_builddir)/src/util/libgnunetutil.la 
