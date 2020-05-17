# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include $(POSTGRESQL_CPPFLAGS)

plugindir = $(libdir)/gnunet

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

pkgcfg_DATA = \
   namestore.conf

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIBS = -lgcov
endif

HEAP_PLUGIN = libgnunet_plugin_namestore_flat.la
if HAVE_TESTING
HEAP_TESTS = test_plugin_namestore_flat \
 test_namestore_api_store_flat \
 test_namestore_api_store_update_flat \
 test_namestore_api_remove_flat \
 test_namestore_api_zone_iteration_flat \
 test_namestore_api_lookup_nick_flat \
 test_namestore_api_monitoring_flat \
 test_namestore_api_lookup_public_flat \
 test_namestore_api_lookup_private_flat \
 test_namestore_api_lookup_shadow_flat \
 test_namestore_api_lookup_shadow_filter_flat \
 test_namestore_api_remove_not_existing_record_flat \
 test_namestore_api_zone_iteration_nick_flat \
 test_namestore_api_zone_iteration_specific_zone_flat \
 test_namestore_api_zone_iteration_stop_flat \
 test_namestore_api_monitoring_existing_flat \
 test_namestore_api_zone_to_name_flat \
 perf_namestore_api_zone_iteration_flat
endif

if HAVE_SQLITE
SQLITE_PLUGIN = libgnunet_plugin_namestore_sqlite.la
if HAVE_TESTING
SQLITE_TESTS = test_plugin_namestore_sqlite \
 test_namestore_api_store_sqlite \
 test_namestore_api_store_update_sqlite \
 test_namestore_api_zone_iteration_sqlite \
 test_namestore_api_remove_sqlite \
 test_namestore_api_lookup_nick_sqlite \
 test_namestore_api_monitoring_sqlite \
 test_namestore_api_lookup_public_sqlite \
 test_namestore_api_lookup_private_sqlite \
 test_namestore_api_lookup_shadow_sqlite \
 test_namestore_api_lookup_shadow_filter_sqlite \
 test_namestore_api_remove_not_existing_record_sqlite \
 test_namestore_api_zone_iteration_nick_sqlite \
 test_namestore_api_zone_iteration_specific_zone_sqlite \
 test_namestore_api_zone_iteration_stop_sqlite \
 test_namestore_api_monitoring_existing_sqlite \
 test_namestore_api_zone_to_name_sqlite \
 perf_namestore_api_zone_iteration_sqlite
endif
endif

if HAVE_POSTGRESQL
POSTGRES_PLUGIN = libgnunet_plugin_namestore_postgres.la
if HAVE_TESTING
POSTGRES_TESTS = test_plugin_namestore_postgres \
 test_namestore_api_store_postgres \
 test_namestore_api_store_update_postgres \
 test_namestore_api_remove_postgres \
 test_namestore_api_zone_iteration_postgres \
 test_namestore_api_lookup_nick_postgres \
 test_namestore_api_monitoring_postgres \
 test_namestore_api_lookup_public_postgres \
 test_namestore_api_lookup_private_postgres \
 test_namestore_api_lookup_shadow_postgres \
 test_namestore_api_lookup_shadow_filter_postgres \
 test_namestore_api_remove_not_existing_record_postgres \
 test_namestore_api_zone_iteration_nick_postgres \
 test_namestore_api_zone_iteration_specific_zone_postgres \
 test_namestore_api_zone_iteration_stop_postgres \
 test_namestore_api_monitoring_existing_postgres \
 test_namestore_api_zone_to_name_postgres \
 perf_namestore_api_zone_iteration_postgres
endif
endif

if HAVE_SQLITE
check_PROGRAMS = \
 $(SQLITE_TESTS) \
 $(POSTGRES_TESTS) \
 $(HEAP_TESTS)
endif

if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
TESTS = \
  $(check_PROGRAMS) \
  $(check_SCRIPTS)
endif

REST_PLUGIN = libgnunet_plugin_rest_namestore.la

lib_LTLIBRARIES = \
  libgnunetnamestore.la


libexec_PROGRAMS = \
 gnunet-service-namestore

bin_PROGRAMS = \
 gnunet-namestore \
 gnunet-zoneimport

libexec_PROGRAMS += \
 gnunet-namestore-fcfsd


plugin_LTLIBRARIES = \
  $(SQLITE_PLUGIN) \
  $(POSTGRES_PLUGIN) \
  $(HEAP_PLUGIN) \
  $(REST_PLUGIN)


libgnunet_plugin_rest_namestore_la_SOURCES = \
  plugin_rest_namestore.c
libgnunet_plugin_rest_namestore_la_LIBADD = \
  libgnunetnamestore.la \
  $(top_builddir)/src/rest/libgnunetrest.la \
  $(top_builddir)/src/identity/libgnunetidentity.la \
  $(top_builddir)/src/json/libgnunetjson.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/util/libgnunetutil.la $(XLIBS) \
  $(LTLIBINTL) -ljansson $(MHD_LIBS)
libgnunet_plugin_rest_namestore_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)
libgnunet_plugin_rest_namestore_la_CFLAGS = $(MHD_CFLAGS) $(AM_CFLAGS)


libgnunetnamestore_la_SOURCES = \
  namestore_api.c \
  namestore_api_monitor.c \
  namestore.h
libgnunetnamestore_la_LIBADD = \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la  \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)
libgnunetnamestore_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)  \
  -version-info 0:1:0



gnunet_zoneimport_SOURCES = \
 gnunet-zoneimport.c
gnunet_zoneimport_LDADD = \
  libgnunetnamestore.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/identity/libgnunetidentity.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)

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
gnunet_namestore_fcfsd_LDADD = $(MHD_LIBS) \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/identity/libgnunetidentity.la \
  libgnunetnamestore.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)
gnunet_namestore_fcfsd_CFLAGS = $(MHD_CFLAGS) $(AM_CFLAGS)


gnunet_service_namestore_SOURCES = \
 gnunet-service-namestore.c

gnunet_service_namestore_LDADD = \
  $(top_builddir)/src/namecache/libgnunetnamecache.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  libgnunetnamestore.la \
  $(GN_LIBINTL)



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
  $(top_builddir)/src/sq/libgnunetsq.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la $(XLIBS) -lsqlite3 \
  $(LTLIBINTL)
libgnunet_plugin_namestore_sqlite_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)

libgnunet_plugin_namestore_postgres_la_SOURCES = \
  plugin_namestore_postgres.c
libgnunet_plugin_namestore_postgres_la_LIBADD = \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la  \
  $(top_builddir)/src/pq/libgnunetpq.la  \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la $(XLIBS) -lpq \
  $(LTLIBINTL)
libgnunet_plugin_namestore_postgres_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS) $(POSTGRESQL_LDFLAGS)

test_namestore_api_store_flat_SOURCES = \
 test_namestore_api_store.c
test_namestore_api_store_flat_LDADD = \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  libgnunetnamestore.la

test_namestore_api_store_sqlite_SOURCES = \
 test_namestore_api_store.c
test_namestore_api_store_sqlite_LDADD = \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  libgnunetnamestore.la

test_namestore_api_store_postgres_SOURCES = \
 test_namestore_api_store.c
test_namestore_api_store_postgres_LDADD = \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  libgnunetnamestore.la

test_namestore_api_store_update_flat_SOURCES = \
 test_namestore_api_store_update.c
test_namestore_api_store_update_flat_LDADD = \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/namecache/libgnunetnamecache.la \
  libgnunetnamestore.la

test_namestore_api_store_update_sqlite_SOURCES = \
 test_namestore_api_store_update.c
test_namestore_api_store_update_sqlite_LDADD = \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/namecache/libgnunetnamecache.la \
  libgnunetnamestore.la

test_namestore_api_store_update_postgres_SOURCES = \
 test_namestore_api_store_update.c
test_namestore_api_store_update_postgres_LDADD = \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/namecache/libgnunetnamecache.la \
  libgnunetnamestore.la

test_namestore_api_lookup_public_flat_SOURCES = \
 test_namestore_api_lookup_public.c
test_namestore_api_lookup_public_flat_LDADD = \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/namecache/libgnunetnamecache.la \
  libgnunetnamestore.la

test_namestore_api_lookup_public_sqlite_SOURCES = \
 test_namestore_api_lookup_public.c
test_namestore_api_lookup_public_sqlite_LDADD = \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/namecache/libgnunetnamecache.la \
  libgnunetnamestore.la

test_namestore_api_lookup_public_postgres_SOURCES = \
 test_namestore_api_lookup_public.c
test_namestore_api_lookup_public_postgres_LDADD = \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/namecache/libgnunetnamecache.la \
  libgnunetnamestore.la

test_namestore_api_lookup_nick_sqlite_SOURCES = \
 test_namestore_api_lookup_nick.c
test_namestore_api_lookup_nick_sqlite_LDADD = \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/namecache/libgnunetnamecache.la \
  libgnunetnamestore.la

test_namestore_api_lookup_nick_postgres_SOURCES = \
 test_namestore_api_lookup_nick.c
test_namestore_api_lookup_nick_postgres_LDADD = \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/namecache/libgnunetnamecache.la \
  libgnunetnamestore.la

test_namestore_api_lookup_nick_flat_SOURCES = \
 test_namestore_api_lookup_nick.c
test_namestore_api_lookup_nick_flat_LDADD = \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/namecache/libgnunetnamecache.la \
  libgnunetnamestore.la

test_namestore_api_lookup_private_flat_SOURCES = \
 test_namestore_api_lookup_private.c
test_namestore_api_lookup_private_flat_LDADD = \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/namecache/libgnunetnamecache.la \
  libgnunetnamestore.la

test_namestore_api_lookup_private_sqlite_SOURCES = \
 test_namestore_api_lookup_private.c
test_namestore_api_lookup_private_sqlite_LDADD = \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/namecache/libgnunetnamecache.la \
  libgnunetnamestore.la

test_namestore_api_lookup_private_postgres_SOURCES = \
 test_namestore_api_lookup_private.c
test_namestore_api_lookup_private_postgres_LDADD = \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/namecache/libgnunetnamecache.la \
  libgnunetnamestore.la

test_namestore_api_lookup_shadow_flat_SOURCES = \
 test_namestore_api_lookup_shadow.c
test_namestore_api_lookup_shadow_flat_LDADD = \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/namecache/libgnunetnamecache.la \
  libgnunetnamestore.la

test_namestore_api_lookup_shadow_sqlite_SOURCES = \
 test_namestore_api_lookup_shadow.c
test_namestore_api_lookup_shadow_sqlite_LDADD = \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/namecache/libgnunetnamecache.la \
  libgnunetnamestore.la

test_namestore_api_lookup_shadow_postgres_SOURCES = \
 test_namestore_api_lookup_shadow.c
test_namestore_api_lookup_shadow_postgres_LDADD = \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/namecache/libgnunetnamecache.la \
  libgnunetnamestore.la

test_namestore_api_lookup_shadow_filter_flat_SOURCES = \
 test_namestore_api_lookup_shadow_filter.c
test_namestore_api_lookup_shadow_filter_flat_LDADD = \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/namecache/libgnunetnamecache.la \
  libgnunetnamestore.la

test_namestore_api_lookup_shadow_filter_sqlite_SOURCES = \
 test_namestore_api_lookup_shadow_filter.c
test_namestore_api_lookup_shadow_filter_sqlite_LDADD = \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/namecache/libgnunetnamecache.la \
  libgnunetnamestore.la
test_namestore_api_lookup_shadow_filter_postgres_SOURCES = \
 test_namestore_api_lookup_shadow_filter.c
test_namestore_api_lookup_shadow_filter_postgres_LDADD = \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/namecache/libgnunetnamecache.la \
  libgnunetnamestore.la

test_namestore_api_remove_sqlite_SOURCES = \
 test_namestore_api_remove.c
test_namestore_api_remove_sqlite_LDADD = \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  libgnunetnamestore.la

test_namestore_api_remove_postgres_SOURCES = \
 test_namestore_api_remove.c
test_namestore_api_remove_postgres_LDADD = \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  libgnunetnamestore.la

test_namestore_api_remove_flat_SOURCES = \
 test_namestore_api_remove.c
test_namestore_api_remove_flat_LDADD = \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  libgnunetnamestore.la

test_namestore_api_remove_not_existing_record_flat_SOURCES = \
 test_namestore_api_remove_not_existing_record.c
test_namestore_api_remove_not_existing_record_flat_LDADD = \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  libgnunetnamestore.la

test_namestore_api_remove_not_existing_record_sqlite_SOURCES = \
 test_namestore_api_remove_not_existing_record.c
test_namestore_api_remove_not_existing_record_sqlite_LDADD = \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  libgnunetnamestore.la

test_namestore_api_remove_not_existing_record_postgres_SOURCES = \
 test_namestore_api_remove_not_existing_record.c
test_namestore_api_remove_not_existing_record_postgres_LDADD = \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  libgnunetnamestore.la

test_namestore_api_zone_to_name_flat_SOURCES = \
 test_namestore_api_zone_to_name.c
test_namestore_api_zone_to_name_flat_LDADD = \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  libgnunetnamestore.la

test_namestore_api_zone_to_name_sqlite_SOURCES = \
 test_namestore_api_zone_to_name.c
test_namestore_api_zone_to_name_sqlite_LDADD = \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  libgnunetnamestore.la

test_namestore_api_zone_to_name_postgres_SOURCES = \
 test_namestore_api_zone_to_name.c
test_namestore_api_zone_to_name_postgres_LDADD = \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  libgnunetnamestore.la

test_namestore_api_monitoring_flat_SOURCES = \
 test_namestore_api_monitoring.c
test_namestore_api_monitoring_flat_LDADD = \
  $(top_builddir)/src/testing/libgnunettesting.la \
  libgnunetnamestore.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/util/libgnunetutil.la

test_namestore_api_monitoring_sqlite_SOURCES = \
 test_namestore_api_monitoring.c
test_namestore_api_monitoring_sqlite_LDADD = \
  $(top_builddir)/src/testing/libgnunettesting.la \
  libgnunetnamestore.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/util/libgnunetutil.la

test_namestore_api_monitoring_postgres_SOURCES = \
 test_namestore_api_monitoring.c
test_namestore_api_monitoring_postgres_LDADD = \
  $(top_builddir)/src/testing/libgnunettesting.la \
  libgnunetnamestore.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/util/libgnunetutil.la

test_namestore_api_monitoring_existing_flat_SOURCES = \
 test_namestore_api_monitoring_existing.c
test_namestore_api_monitoring_existing_flat_LDADD = \
  $(top_builddir)/src/testing/libgnunettesting.la \
  libgnunetnamestore.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/util/libgnunetutil.la

test_namestore_api_monitoring_existing_sqlite_SOURCES = \
 test_namestore_api_monitoring_existing.c
test_namestore_api_monitoring_existing_sqlite_LDADD = \
  $(top_builddir)/src/testing/libgnunettesting.la \
  libgnunetnamestore.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/util/libgnunetutil.la

test_namestore_api_monitoring_existing_postgres_SOURCES = \
 test_namestore_api_monitoring_existing.c
test_namestore_api_monitoring_existing_postgres_LDADD = \
  $(top_builddir)/src/testing/libgnunettesting.la \
  libgnunetnamestore.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/util/libgnunetutil.la

test_namestore_api_zone_iteration_flat_SOURCES = \
 test_namestore_api_zone_iteration.c
test_namestore_api_zone_iteration_flat_LDADD = \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  libgnunetnamestore.la

test_namestore_api_zone_iteration_sqlite_SOURCES = \
 test_namestore_api_zone_iteration.c
test_namestore_api_zone_iteration_sqlite_LDADD = \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  libgnunetnamestore.la

test_namestore_api_zone_iteration_postgres_SOURCES = \
 test_namestore_api_zone_iteration.c
test_namestore_api_zone_iteration_postgres_LDADD = \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  libgnunetnamestore.la

perf_namestore_api_zone_iteration_postgres_SOURCES = \
 perf_namestore_api_zone_iteration.c
perf_namestore_api_zone_iteration_postgres_LDADD = \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  libgnunetnamestore.la

perf_namestore_api_zone_iteration_sqlite_SOURCES = \
 perf_namestore_api_zone_iteration.c
perf_namestore_api_zone_iteration_sqlite_LDADD = \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  libgnunetnamestore.la

perf_namestore_api_zone_iteration_flat_SOURCES = \
 perf_namestore_api_zone_iteration.c
perf_namestore_api_zone_iteration_flat_LDADD = \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  libgnunetnamestore.la

test_namestore_api_zone_iteration_nick_flat_SOURCES = \
 test_namestore_api_zone_iteration_nick.c
test_namestore_api_zone_iteration_nick_flat_LDADD = \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  libgnunetnamestore.la

test_namestore_api_zone_iteration_nick_sqlite_SOURCES = \
 test_namestore_api_zone_iteration_nick.c
test_namestore_api_zone_iteration_nick_sqlite_LDADD = \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  libgnunetnamestore.la

test_namestore_api_zone_iteration_nick_postgres_SOURCES = \
 test_namestore_api_zone_iteration_nick.c
test_namestore_api_zone_iteration_nick_postgres_LDADD = \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  libgnunetnamestore.la

test_namestore_api_zone_iteration_specific_zone_flat_SOURCES = \
 test_namestore_api_zone_iteration_specific_zone.c
test_namestore_api_zone_iteration_specific_zone_flat_LDADD = \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  libgnunetnamestore.la

test_namestore_api_zone_iteration_specific_zone_sqlite_SOURCES = \
 test_namestore_api_zone_iteration_specific_zone.c
test_namestore_api_zone_iteration_specific_zone_sqlite_LDADD = \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  libgnunetnamestore.la

test_namestore_api_zone_iteration_specific_zone_postgres_SOURCES = \
 test_namestore_api_zone_iteration_specific_zone.c
test_namestore_api_zone_iteration_specific_zone_postgres_LDADD = \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  libgnunetnamestore.la

test_namestore_api_zone_iteration_stop_flat_SOURCES = \
 test_namestore_api_zone_iteration_stop.c
test_namestore_api_zone_iteration_stop_flat_LDADD = \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  libgnunetnamestore.la

test_namestore_api_zone_iteration_stop_sqlite_SOURCES = \
 test_namestore_api_zone_iteration_stop.c
test_namestore_api_zone_iteration_stop_sqlite_LDADD = \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  libgnunetnamestore.la

test_namestore_api_zone_iteration_stop_postgres_SOURCES = \
 test_namestore_api_zone_iteration_stop.c
test_namestore_api_zone_iteration_stop_postgres_LDADD = \
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

check_SCRIPTS += \
  test_plugin_rest_namestore.sh

EXTRA_DIST = \
  test_common.c \
  test_namestore_api.conf \
  test_namestore_api_postgres.conf \
  test_namestore_api_sqlite.conf \
  test_namestore_api_flat.conf \
  perf_namestore_api_postgres.conf \
  perf_namestore_api_sqlite.conf \
  perf_namestore_api_flat.conf \
  test_plugin_namestore_sqlite.conf \
  test_plugin_namestore_postgres.conf \
  test_plugin_namestore_flat.conf \
  test_hostkey \
  zonefiles/S5I9DSGQVAB5FVV16T3B3CC5H1B2JGL3Q412JBKURME8EKU0600G.zkey \
  zonefiles/AQ835GVL939H4O8QJQ7GBLPTQC0QAAO91BN7QK01BA63MDSK6I4G.zkey \
  zonefiles/HGU0A0VCU334DN7F2I9UIUMVQMM7JMSD142LIMNUGTTV9R0CF4EG.zkey \
  zonefiles/N0UJMP015AFUNR2BTNM3FKPBLG38913BL8IDMCO2H0A1LIB81960.zkey \
  $(check_SCRIPTS)
