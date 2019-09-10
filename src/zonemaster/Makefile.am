# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

plugindir = $(libdir)/gnunet

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

pkgcfg_DATA = \
   zonemaster.conf

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIBS = -lgcov
endif

libexec_PROGRAMS = \
 gnunet-service-zonemaster \
 gnunet-service-zonemaster-monitor

gnunet_service_zonemaster_SOURCES = \
 gnunet-service-zonemaster.c
gnunet_service_zonemaster_LDADD = \
  $(top_builddir)/src/dht/libgnunetdht.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  $(GN_LIBINTL)


gnunet_service_zonemaster_monitor_SOURCES = \
 gnunet-service-zonemaster-monitor.c

gnunet_service_zonemaster_monitor_LDADD = \
  $(top_builddir)/src/dht/libgnunetdht.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  $(GN_LIBINTL)
