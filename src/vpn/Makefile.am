AM_CPPFLAGS = -I$(top_srcdir)/src/include -I$(top_builddir)/src/include

if MINGW
  WINFLAGS = -Wl,--no-undefined,--export-all-symbols
  VPNBIN = gnunet-helper-vpn
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
endif

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

plugindir = $(libdir)/gnunet

pkgcfg_DATA = \
  vpn.conf

if LINUX
VPNBIN = gnunet-helper-vpn
install-exec-hook:
	$(top_srcdir)/src/vpn/install-vpn-helper.sh $(libexecdir) $(SUDO_BINARY) || true
else
install-exec-hook:
endif


lib_LTLIBRARIES = \
  libgnunetvpn.la


libexec_PROGRAMS = \
  $(VPNBIN) \
  gnunet-service-vpn

bin_PROGRAMS = \
  gnunet-vpn

if MINGW
  gnunet_helper_vpn_LDFLAGS = \
    -no-undefined -Wl,--export-all-symbols

  gnunet_helper_vpn_LDADD = \
    -lsetupapi -lnewdev -lshell32 -liconv -lstdc++ \
    -lcomdlg32 -lgdi32 -liphlpapi

  gnunet_helper_vpn_SOURCES = \
    gnunet-helper-vpn-windows.c
else
    gnunet_helper_vpn_SOURCES = \
	gnunet-helper-vpn.c
endif
gnunet_service_vpn_SOURCES = \
 gnunet-service-vpn.c
gnunet_service_vpn_LDADD = \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/tun/libgnunettun.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/cadet/libgnunetcadet.la \
  $(top_builddir)/src/regex/libgnunetregex.la \
  $(GN_LIBINTL)
gnunet_service_vpn_CFLAGS = \
  -I$(top_srcdir)/src/exit $(CFLAGS)

gnunet_vpn_SOURCES = \
 gnunet-vpn.c
gnunet_vpn_LDADD = \
  libgnunetvpn.la \
  $(top_builddir)/src/tun/libgnunettun.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)

libgnunetvpn_la_SOURCES = \
 vpn_api.c vpn.h
libgnunetvpn_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la $(XLIB)
libgnunetvpn_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)


