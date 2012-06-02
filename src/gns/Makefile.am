INCLUDES = -I$(top_srcdir)/src/include

if HAVE_GLIBCNSS
NSS_SUBDIR = nss
endif

SUBDIRS = . $(NSS_SUBDIR)

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
  libgnunetgns.la

if HAVE_MHD
 DO_FCFSD=gnunet-gns-fcfsd
 DO_PROXY=gnunet-gns-proxy
endif

bin_PROGRAMS = \
  gnunet-service-gns \
  $(DO_FCFSD) \
	$(DO_PROXY) \
  gnunet-gns

#noinst_PROGRAMS = \
#  gnunet-gns-lookup

check_PROGRAMS = \
  test_gns_simple_shorten \
  test_gns_simple_get_authority \
  test_gns_simple_lookup \
  test_gns_simple_delegated_lookup \
  test_gns_simple_mx_lookup \
  test_gns_simple_zkey_lookup \
  test_gns_dht_delegated_lookup \
  test_gns_pseu_shorten \
  test_gns_max_queries \
  test_gns_dht_threepeer


#  test_gns_simple_lookup
#  test_gns_simple_delegated_lookup
#  test_gns_dht_delegated_lookup


plugin_LTLIBRARIES = \
  libgnunet_plugin_block_gns.la

test_gns_dht_threepeer_SOURCES = \
  test_gns_dht_threepeer.c
test_gns_dht_threepeer_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  $(top_builddir)/src/gns/libgnunetgns.la \
  $(top_builddir)/src/testing/libgnunettesting.la
test_gns_dht_threepeer_DEPENDENCIES = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  $(top_builddir)/src/gns/libgnunetgns.la \
  $(top_builddir)/src/testing/libgnunettesting.la

test_gns_simple_lookup_SOURCES = \
  test_gns_simple_lookup.c
test_gns_simple_lookup_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  $(top_builddir)/src/gns/libgnunetgns.la \
  $(top_builddir)/src/testing/libgnunettesting.la
test_gns_simple_lookup_DEPENDENCIES = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  $(top_builddir)/src/gns/libgnunetgns.la \
  $(top_builddir)/src/testing/libgnunettesting.la

test_gns_simple_delegated_lookup_SOURCES = \
  test_gns_simple_delegated_lookup.c
test_gns_simple_delegated_lookup_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  $(top_builddir)/src/gns/libgnunetgns.la \
  $(top_builddir)/src/testing/libgnunettesting.la
test_gns_simple_delegated_lookup_DEPENDENCIES = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  $(top_builddir)/src/gns/libgnunetgns.la \
  $(top_builddir)/src/testing/libgnunettesting.la

test_gns_simple_mx_lookup_SOURCES = \
  test_gns_simple_mx_lookup.c
test_gns_simple_mx_lookup_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  $(top_builddir)/src/gns/libgnunetgns.la \
  $(top_builddir)/src/testing/libgnunettesting.la
test_gns_simple_mx_lookup_DEPENDENCIES = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  $(top_builddir)/src/gns/libgnunetgns.la \
  $(top_builddir)/src/testing/libgnunettesting.la

test_gns_simple_zkey_lookup_SOURCES = \
  test_gns_simple_zkey_lookup.c
test_gns_simple_zkey_lookup_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  $(top_builddir)/src/gns/libgnunetgns.la \
  $(top_builddir)/src/testing/libgnunettesting.la
test_gns_simple_zkey_lookup_DEPENDENCIES = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  $(top_builddir)/src/gns/libgnunetgns.la \
  $(top_builddir)/src/testing/libgnunettesting.la

test_gns_dht_delegated_lookup_SOURCES = \
  test_gns_dht_delegated_lookup.c
test_gns_dht_delegated_lookup_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  $(top_builddir)/src/dht/libgnunetdht.la \
  $(top_builddir)/src/gns/libgnunetgns.la \
  $(top_builddir)/src/testing/libgnunettesting.la
test_gns_dht_delegated_lookup_DEPENDENCIES = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  $(top_builddir)/src/dht/libgnunetdht.la \
  $(top_builddir)/src/gns/libgnunetgns.la \
  $(top_builddir)/src/testing/libgnunettesting.la

test_gns_simple_shorten_SOURCES = \
  test_gns_simple_shorten.c
test_gns_simple_shorten_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  $(top_builddir)/src/gns/libgnunetgns.la \
  $(top_builddir)/src/testing/libgnunettesting.la
test_gns_simple_shorten_DEPENDENCIES = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  $(top_builddir)/src/gns/libgnunetgns.la \
  $(top_builddir)/src/testing/libgnunettesting.la

test_gns_simple_get_authority_SOURCES = \
  test_gns_simple_get_authority.c
test_gns_simple_get_authority_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  $(top_builddir)/src/gns/libgnunetgns.la \
  $(top_builddir)/src/testing/libgnunettesting.la
test_gns_simple_get_authority_DEPENDENCIES = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  $(top_builddir)/src/gns/libgnunetgns.la \
  $(top_builddir)/src/testing/libgnunettesting.la


test_gns_pseu_shorten_SOURCES = \
  test_gns_pseu_shorten.c
test_gns_pseu_shorten_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  $(top_builddir)/src/dht/libgnunetdht.la \
  $(top_builddir)/src/gns/libgnunetgns.la \
  $(top_builddir)/src/testing/libgnunettesting.la
test_gns_pseu_shorten_DEPENDENCIES = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  $(top_builddir)/src/dht/libgnunetdht.la \
  $(top_builddir)/src/gns/libgnunetgns.la \
  $(top_builddir)/src/testing/libgnunettesting.la


test_gns_max_queries_SOURCES = \
  test_gns_max_queries.c
test_gns_max_queries_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  $(top_builddir)/src/gns/libgnunetgns.la \
  $(top_builddir)/src/testing/libgnunettesting.la
test_gns_max_queries_DEPENDENCIES = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  $(top_builddir)/src/gns/libgnunetgns.la \
  $(top_builddir)/src/testing/libgnunettesting.la

gnunet_gns_SOURCES = \
 gnunet-gns.c
gnunet_gns_LDADD = \
  $(top_builddir)/src/gns/libgnunetgns.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  $(GN_LIBINTL)
gnunet_gns_DEPENDENCIES = \
  libgnunetgns.la

gnunet_gns_proxy_SOURCES = \
 gnunet-gns-proxy.c gns_proxy_proto.h 
gnunet_gns_proxy_LDADD = -lmicrohttpd \
  $(top_builddir)/src/gns/libgnunetgns.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)
gnunet_gns_proxy_DEPENDENCIES = \
  libgnunetgns.la

gnunet_service_gns_SOURCES = \
 gnunet-service-gns.c \
 gnunet-service-gns_resolver.c gnunet-service-gns_resolver.h \
 gnunet-service-gns_interceptor.c gnunet-service-gns_interceptor.h 
gnunet_service_gns_LDADD = \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la \
	$(top_builddir)/src/dns/libgnunetdns.la \
	$(top_builddir)/src/dns/libgnunetdnsparser.la \
	$(top_builddir)/src/dht/libgnunetdht.la \
	$(top_builddir)/src/namestore/libgnunetnamestore.la \
  $(GN_LIBINTL)
gnunet_service_gns_DEPENDENCIES = \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la \
	$(top_builddir)/src/dns/libgnunetdns.la \
	$(top_builddir)/src/dns/libgnunetdnsparser.la \
	$(top_builddir)/src/dht/libgnunetdht.la \
	$(top_builddir)/src/namestore/libgnunetnamestore.la


gnunet_gns_fcfsd_SOURCES = \
 gnunet-gns-fcfsd.c 
gnunet_gns_fcfsd_LDADD = -lmicrohttpd \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  $(GN_LIBINTL)
gnunet_gns_fcfsd_DEPENDENCIES = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la


libgnunetgns_la_SOURCES = \
 gns_api.c gns.h
libgnunetgns_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la $(XLIB) \
 $(top_builddir)/src/namestore/libgnunetnamestore.la
libgnunetgns_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)
libgnunetgns_la_DEPENDENCIES = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/namestore/libgnunetnamestore.la

libgnunet_plugin_block_gns_la_SOURCES = \
  plugin_block_gns.c
libgnunet_plugin_block_gns_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/block/libgnunetblock.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la
libgnunet_plugin_block_gns_la_LDFLAGS = \
  $(GN_PLUGIN_LDFLAGS)
libgnunet_plugin_block_gns_la_DEPENDENCIES = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/block/libgnunetblock.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la

#Build stub api
#libgnunetnamestore_la_SOURCES = \
# namestore_stub_api.c
#libgnunetnamestore_la_LIBADD = \
# $(top_builddir)/src/util/libgnunetutil.la $(XLIB)
#libgnunetnamestore_la_LDFLAGS = \
#  $(GN_LIB_LDFLAGS)
#libgnunetnamestore_la_DEPENDENCIES = \
# $(top_builddir)/src/util/libgnunetutil.la

if ENABLE_TEST_RUN
if LINUX
TESTS = $(check_PROGRAMS)
endif
endif

EXTRA_DIST = \
  test_gns_defaults.conf \
  test_gns_simple_lookup.conf \
  test_gns_dht_default.conf

