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
  pt.conf

bin_PROGRAMS = \
  gnunet-daemon-pt $(PTBIN) 

gnunet_daemon_pt_SOURCES = \
 gnunet-daemon-pt.c 
gnunet_daemon_pt_LDADD = \
  $(top_builddir)/src/vpn/libgnunetvpn.la \
  $(top_builddir)/src/mesh/libgnunetmesh.la \
  $(top_builddir)/src/dns/libgnunetdns.la \
  $(top_builddir)/src/dns/libgnunetdnsparser.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/mesh/libgnunetmesh.la \
  $(GN_LIBINTL)
