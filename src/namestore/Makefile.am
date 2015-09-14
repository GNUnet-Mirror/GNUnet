# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include $(POSTGRESQL_CPPFLAGS)

plugindir = $(libdir)/gnunet

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

pkgcfg_DATA = \
   namestore.conf


if MINGW
  WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIBS = -lgcov
endif

if HAVE_EXPERIMENTAL
FLAT_PLUGIN = libgnunet_plugin_namestore_flat.la
if HAVE_TESTING
FLAT_TESTS = test_plugin_namestore_flat
endif
endif

if HAVE_SQLITE
SQLITE_PLUGIN = libgnunet_plugin_namestore_sqlite.la
if HAVE_TESTING
SQLITE_TESTS = test_plugin_namestore_sqlite
endif
endif

if HAVE_POSTGRESQL
# postgres doesn't even build yet; thus: experimental!
POSTGRES_PLUGIN = libgnunet_plugin_namestore_postgres.la
if HAVE_TESTING
POSTGRES_TESTS = test_plugin_namestore_postgres
endif
endif

# testcases do not even build yet; thus: experimental!
if HAVE_TESTING
TESTING_TESTS = \
 test_namestore_api_store \
 test_namestore_api_store_update \
 test_namestore_api_lookup_public \
 test_namestore_api_lookup_private \
 test_namestore_api_lookup_nick \
 test_namestore_api_lookup_shadow \
 test_namestore_api_lookup_shadow_filter \
 test_namestore_api_remove \
 test_namestore_api_remove_not_existing_record \
 test_namestore_api_zone_iteration \
 test_namestore_api_zone_iteration_nick \
 test_namestore_api_zone_iteration_specific_zone \
 test_namestore_api_zone_iteration_stop \
 test_namestore_api_monitoring \
 test_namestore_api_monitoring_existing
# test_namestore_api_zone_to_name
endif

if HAVE_SQLITE
check_PROGRAMS = \
 $(SQLITE_TESTS) \
 $(POSTGRES_TESTS) \
 $(FLAT_TESTS) \
 $(TESTING_TESTS)
endif

if HAVE_REST
REST_PLUGIN=libgnunet_plugin_rest_namestore.la
endif

if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;
TESTS = \
  $(check_PROGRAMS) \
  $(check_SCRIPTS)
endif

lib_LTLIBRARIES = \
  libgnunetnamestore.la


libgnunetnamestore_la_SOURCES = \
  namestore_api.c \
  namestore_api_monitor.c \
  namestore.h
libgnunetnamestore_la_LIBADD = \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la  \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/dns/libgnunetdnsparser.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)
libgnunetnamestore_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS) $(WINFLAGS) \
  -version-info 0:1:0

libexec_PROGRAMS = \
 gnunet-service-namestore

bin_PROGRAMS = \
 gnunet-namestore

if HAVE_MHD
libexec_PROGRAMS += \
 gnunet-namestore-fcfsd
endif


gnunet_namestore_SOURCES = \
 gnunet-namestore.c
gnunet_namestore_LDADD = \
  $(top_builddir)/src/identity/libgnunetidentity.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  libgnunetnamestore.la \
  $(GN_LIBINTL)


gnunet_namestore_fcfsd_SOURCES = \
 gnunet-namestore-fcfsd.c
gnunet_namestore_fcfsd_LDADD = -lmicrohttpd \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/identity/libgnunetidentity.la \
  libgnunetnamestore.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)



gnunet_service_namestore_SOURCES = \
 gnunet-service-namestore.c

gnunet_service_namestore_LDADD = \
  $(top_builddir)/src/namecache/libgnunetnamecache.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  libgnunetnamestore.la \
  $(GN_LIBINTL)


plugin_LTLIBRARIES = \
  $(SQLITE_PLUGIN) \
  $(POSTGRES_PLUGIN) \
	$(FLAT_PLUGIN) \
	$(REST_PLUGIN)



libgnunet_plugin_namestore_flat_la_SOURCES = \
  plugin_namestore_flat.c
libgnunet_plugin_namestore_flat_la_LIBADD = \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la  \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la $(XLIBS) \
  $(LTLIBINTL)
libgnunet_plugin_namestore_flat_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)


libgnunet_plugin_namestore_sqlite_la_SOURCES = \
  plugin_namestore_sqlite.c
libgnunet_plugin_namestore_sqlite_la_LIBADD = \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la  \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la $(XLIBS) -lsqlite3 \
  $(LTLIBINTL)
libgnunet_plugin_namestore_sqlite_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)

libgnunet_plugin_namestore_postgres_la_SOURCES = \
  plugin_namestore_postgres.c
libgnunet_plugin_namestore_postgres_la_LIBADD = \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la  \
  $(top_builddir)/src/postgres/libgnunetpostgres.la  \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la $(XLIBS) -lpq \
  $(LTLIBINTL)
libgnunet_plugin_namestore_postgres_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS) $(POSTGRESQL_LDFLAGS)

libgnunet_plugin_rest_namestore_la_SOURCES = \
  plugin_rest_namestore.c
libgnunet_plugin_rest_namestore_la_LIBADD = \
  libgnunetnamestore.la \
	$(top_builddir)/src/identity/libgnunetidentity.la \
  $(top_builddir)/src/util/libgnunetutil.la $(XLIBS) \
  $(LTLIBINTL) -ljansson -lmicrohttpd
libgnunet_plugin_rest_namestore_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)


test_namestore_api_store_SOURCES = \
 test_namestore_api_store.c
test_namestore_api_store_LDADD = \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  libgnunetnamestore.la

test_namestore_api_store_update_SOURCES = \
 test_namestore_api_store_update.c
test_namestore_api_store_update_LDADD = \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/namecache/libgnunetnamecache.la \
  libgnunetnamestore.la

test_namestore_api_lookup_public_SOURCES = \
 test_namestore_api_lookup_public.c
test_namestore_api_lookup_public_LDADD = \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/namecache/libgnunetnamecache.la \
  libgnunetnamestore.la

test_namestore_api_lookup_nick_SOURCES = \
 test_namestore_api_lookup_nick.c
test_namestore_api_lookup_nick_LDADD = \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/namecache/libgnunetnamecache.la \
  libgnunetnamestore.la

test_namestore_api_lookup_private_SOURCES = \
 test_namestore_api_lookup_private.c
test_namestore_api_lookup_private_LDADD = \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/namecache/libgnunetnamecache.la \
  libgnunetnamestore.la

test_namestore_api_lookup_shadow_SOURCES = \
 test_namestore_api_lookup_shadow.c
test_namestore_api_lookup_shadow_LDADD = \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/namecache/libgnunetnamecache.la \
  libgnunetnamestore.la

test_namestore_api_lookup_shadow_filter_SOURCES = \
 test_namestore_api_lookup_shadow_filter.c
test_namestore_api_lookup_shadow_filter_LDADD = \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/namecache/libgnunetnamecache.la \
  libgnunetnamestore.la

test_namestore_api_remove_SOURCES = \
 test_namestore_api_remove.c
test_namestore_api_remove_LDADD = \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  libgnunetnamestore.la

test_namestore_api_remove_not_existing_record_SOURCES = \
 test_namestore_api_remove_not_existing_record.c
test_namestore_api_remove_not_existing_record_LDADD = \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  libgnunetnamestore.la

#test_namestore_api_zone_to_name_SOURCES = \
# test_namestore_api_zone_to_name.c
#test_namestore_api_zone_to_name_LDADD = \
#  $(top_builddir)/src/testing/libgnunettesting.la \
#  $(top_builddir)/src/util/libgnunetutil.la \
#  libgnunetnamestore.la

test_namestore_api_monitoring_SOURCES = \
 test_namestore_api_monitoring.c
test_namestore_api_monitoring_LDADD = \
  $(top_builddir)/src/testing/libgnunettesting.la \
  libgnunetnamestore.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/util/libgnunetutil.la

test_namestore_api_monitoring_existing_SOURCES = \
 test_namestore_api_monitoring_existing.c
test_namestore_api_monitoring_existing_LDADD = \
  $(top_builddir)/src/testing/libgnunettesting.la \
  libgnunetnamestore.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/util/libgnunetutil.la

test_namestore_api_zone_iteration_SOURCES = \
 test_namestore_api_zone_iteration.c
test_namestore_api_zone_iteration_LDADD = \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  libgnunetnamestore.la

test_namestore_api_zone_iteration_nick_SOURCES = \
 test_namestore_api_zone_iteration_nick.c
test_namestore_api_zone_iteration_nick_LDADD = \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  libgnunetnamestore.la


test_namestore_api_zone_iteration_specific_zone_SOURCES = \
 test_namestore_api_zone_iteration_specific_zone.c
test_namestore_api_zone_iteration_specific_zone_LDADD = \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  libgnunetnamestore.la

test_namestore_api_zone_iteration_stop_SOURCES = \
 test_namestore_api_zone_iteration_stop.c
test_namestore_api_zone_iteration_stop_LDADD = \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  libgnunetnamestore.la

test_plugin_namestore_flat_SOURCES = \
 test_plugin_namestore.c
test_plugin_namestore_flat_LDADD = \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/util/libgnunetutil.la

test_plugin_namestore_sqlite_SOURCES = \
 test_plugin_namestore.c
test_plugin_namestore_sqlite_LDADD = \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/util/libgnunetutil.la

test_plugin_namestore_postgres_SOURCES = \
 test_plugin_namestore.c
test_plugin_namestore_postgres_LDADD = \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/util/libgnunetutil.la

check_SCRIPTS = \
	test_namestore_put.sh \
	test_namestore_lookup.sh \
	test_namestore_delete.sh

EXTRA_DIST = \
  test_namestore_api.conf \
  test_plugin_namestore_sqlite.conf \
  test_plugin_namestore_postgres.conf \
	test_plugin_namestore_flat.conf \
  test_hostkey \
  zonefiles/S5I9DSGQVAB5FVV16T3B3CC5H1B2JGL3Q412JBKURME8EKU0600G.zkey \
  zonefiles/AQ835GVL939H4O8QJQ7GBLPTQC0QAAO91BN7QK01BA63MDSK6I4G.zkey \
  zonefiles/HGU0A0VCU334DN7F2I9UIUMVQMM7JMSD142LIMNUGTTV9R0CF4EG.zkey \
  zonefiles/N0UJMP015AFUNR2BTNM3FKPBLG38913BL8IDMCO2H0A1LIB81960.zkey \
  $(check_SCRIPTS)

