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
  gns.conf

lib_LTLIBRARIES = \
  libgnunetgns.la libgnunetnamestore.la

bin_PROGRAMS = \
  gnunet-service-gns

#noinst_PROGRAMS = \
#  gnunet-gns-lookup

check_SCRIPTS = \
 test_gnunet_gns.sh

check_PROGRAMS = \
  test_gns_twopeer


plugin_LTLIBRARIES = \
  libgnunet_plugin_block_gns.la

test_gns_twopeer_SOURCES = \
  test_gns_twopeer.c
test_gns_twopeer_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la
test_gns_twopeer_DEPENDENCIES = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la

#gnunet_gns_lookup_SOURCES = \
# gnunet-gns-lookup.c
#gnunet_gns_lookup_LDADD = \
#  $(top_builddir)/src/gns/libgnunetgns.la \
#  $(top_builddir)/src/util/libgnunetutil.la \
#  $(GN_LIBINTL)
#gnunet_dns_lookup_DEPENDENCIES = \
#  libgnunetgns.la

gnunet_service_gns_SOURCES = \
 gnunet-service-gns.c 
gnunet_service_gns_LDADD = \
  $(top_builddir)/src/tun/libgnunettun.la \
  $(top_builddir)/src/mesh/libgnunetmesh.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la \
	$(top_builddir)/src/dns/libgnunetdns.la \
	$(top_builddir)/src/dns/libgnunetdnsparser.la \
	$(top_builddir)/src/dht/libgnunetdht.la \
	$(top_builddir)/src/gns/libgnunetnamestore.la \
  $(GN_LIBINTL)
gnunet_service_gns_DEPENDENCIES = \
  $(top_builddir)/src/tun/libgnunettun.la \
  $(top_builddir)/src/mesh/libgnunetmesh.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la \
	$(top_builddir)/src/dns/libgnunetdns.la \
	$(top_builddir)/src/dns/libgnunetdnsparser.la \
	$(top_builddir)/src/dht/libgnunetdht.la \
	$(top_builddir)/src/gns/libgnunetnamestore.la

libgnunetgns_la_SOURCES = \
 gns_api.c gns.h
libgnunetgns_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la $(XLIB)
libgnunetgns_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)
libgnunetgns_la_DEPENDENCIES = \
 $(top_builddir)/src/util/libgnunetutil.la

libgnunet_plugin_block_gns_la_SOURCES = \
  plugin_block_gns.c
libgnunet_plugin_block_gns_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/block/libgnunetblock.la
libgnunet_plugin_block_gns_la_LDFLAGS = \
  $(GN_PLUGIN_LDFLAGS)
libgnunet_plugin_block_gns_la_DEPENDENCIES = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/block/libgnunetblock.la

#Build stub api
libgnunetnamestore_la_SOURCES = \
 namestore_stub_api.c
libgnunetnamestore_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la $(XLIB)
libgnunetnamestore_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)
libgnunetnamestore_la_DEPENDENCIES = \
 $(top_builddir)/src/util/libgnunetutil.la

if ENABLE_TEST_RUN
TESTS = $(check_PROGRAMS)  $(check_SCRIPTS)
endif

EXTRA_DIST = \
  $(check_SCRIPTS) \
  test_gns_twopeer.conf
