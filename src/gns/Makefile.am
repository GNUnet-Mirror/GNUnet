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

lib_LTLIBRARIES = \
  libgnunetgns.la

bin_PROGRAMS = \
  gnunet-service-gns $(HIJACKBIN)

noinst_PROGRAMS = \
  gnunet-gns-lookup gnunet-gns-add

#check_SCRIPTS = \
# test_gnunet_dns.sh


gnunet_gns_add_SOURCES = \
 gnunet-gns-add.c
gnunet_gns_add_LDADD = \
  $(top_builddir)/src/gns/libgnunetgns.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)
gnunet_dns_add_DEPENDENCIES = \
  libgnunetgns.la

gnunet_service_gns_SOURCES = \
 gnunet-service-gns.c 
gnunet_service_gns_LDADD = \
  $(top_builddir)/src/tun/libgnunettun.la \
  $(top_builddir)/src/mesh/libgnunetmesh.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la \
	$(top_builddir)/src/dns/libgnunetdns.la \
  $(GN_LIBINTL)

libgnunetgns_la_SOURCES = \
 gns_api.c gns.h
libgnunetgns_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la $(XLIB)
libgnunetgns_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)

if ENABLE_TEST_RUN
TESTS = $(check_PROGRAMS)  $(check_SCRIPTS)
endif

EXTRA_DIST = \
  $(check_SCRIPTS) 
