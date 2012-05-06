INCLUDES = -I$(top_srcdir)/src/include

plugindir = $(libdir)/gnunet

pkgcfgdir= $(pkgdatadir)/config.d/

pkgcfg_DATA = \
   namestore.conf


if MINGW
  WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIBS = -lgcov
endif

if HAVE_SQLITE
SQLITE_TESTS = \
 test_plugin_namestore_sqlite 
endif


check_PROGRAMS = \
 $(SQLITE_TESTS) \
 test_namestore_record_serialization \
 test_namestore_api_sign_verify \
 test_namestore_api \
 test_namestore_api_put \
 test_namestore_api_lookup \
 test_namestore_api_lookup_specific_type \
 test_namestore_api_create \
 test_namestore_api_create_update \
 test_namestore_api_remove \
 test_namestore_api_remove_not_existing_record \
 test_namestore_api_zone_to_name \
 test_namestore_api_zone_iteration \
 test_namestore_api_zone_iteration_specific_zone \
 test_namestore_api_zone_iteration_stop 

if ENABLE_TEST_RUN
TESTS = $(check_PROGRAMS)
endif

lib_LTLIBRARIES = \
  libgnunetnamestore.la

libgnunetnamestore_la_SOURCES = \
  namestore_api.c namestore_common.c namestore.h
libgnunetnamestore_la_LIBADD = \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL) 
libgnunetnamestore_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS) $(WINFLAGS) \
  -version-info 0:0:0

bin_PROGRAMS = \
 gnunet-service-namestore \
 gnunet-namestore


gnunet_namestore_SOURCES = \
 gnunet-namestore.c 
gnunet_namestore_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  libgnunetnamestore.la \
  $(GN_LIBINTL)
gnunet_namestore_DEPENDENCIES = \
  $(top_builddir)/src/util/libgnunetutil.la \
  libgnunetnamestore.la



gnunet_service_namestore_SOURCES = \
 gnunet-service-namestore.c

gnunet_service_namestore_LDADD = \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  libgnunetnamestore.la \
  $(GN_LIBINTL)
gnunet_service_namestore_DEPENDENCIES = \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  libgnunetnamestore.la

if HAVE_SQLITE
 SQLITE_PLUGIN = libgnunet_plugin_namestore_sqlite.la
endif

plugin_LTLIBRARIES = \
  $(SQLITE_PLUGIN) 

libgnunet_plugin_namestore_sqlite_la_SOURCES = \
  plugin_namestore_sqlite.c namestore_common.c
libgnunet_plugin_namestore_sqlite_la_LIBADD = \
  $(top_builddir)/src/namestore/libgnunetnamestore.la  \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la $(XLIBS) -lsqlite3
libgnunet_plugin_namestore_sqlite_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)
libgnunet_plugin_namestore_sqlite_la_DEPENDENCIES = \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  libgnunetnamestore.la

test_namestore_api_sign_verify_SOURCES = \
 test_namestore_api_sign_verify.c
test_namestore_api_sign_verify_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la

test_namestore_api_SOURCES = \
 test_namestore_api.c
test_namestore_api_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la

test_namestore_api_put_SOURCES = \
 test_namestore_api_put.c
test_namestore_api_put_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la

test_namestore_api_lookup_SOURCES = \
 test_namestore_api_lookup.c
test_namestore_api_lookup_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la

test_namestore_api_lookup_specific_type_SOURCES = \
 test_namestore_api_lookup_specific_type.c
test_namestore_api_lookup_specific_type_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la


test_namestore_api_create_SOURCES = \
 test_namestore_api_create.c
test_namestore_api_create_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la

test_namestore_api_create_update_SOURCES = \
 test_namestore_api_create_update.c
test_namestore_api_create_update_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la


test_namestore_api_remove_SOURCES = \
 test_namestore_api_remove.c
test_namestore_api_remove_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la

test_namestore_api_remove_not_existing_record_SOURCES = \
 test_namestore_api_remove_not_existing_record.c
test_namestore_api_remove_not_existing_record_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la

test_namestore_api_zone_to_name_SOURCES = \
 test_namestore_api_zone_to_name.c
test_namestore_api_zone_to_name_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la

test_namestore_api_zone_iteration_SOURCES = \
 test_namestore_api_zone_iteration.c
test_namestore_api_zone_iteration_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la  
  
test_namestore_api_zone_iteration_specific_zone_SOURCES = \
 test_namestore_api_zone_iteration_specific_zone.c
test_namestore_api_zone_iteration_specific_zone_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la  
  
test_namestore_api_zone_iteration_stop_SOURCES = \
 test_namestore_api_zone_iteration_stop.c
test_namestore_api_zone_iteration_stop_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la    

test_namestore_record_serialization_SOURCES = \
 test_namestore_record_serialization.c
test_namestore_record_serialization_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la  

EXTRA_DIST = \
  test_namestore_api.conf \
  test_plugin_namestore_sqlite.conf\
  test_hostkey \
  zonefiles/HGU0A0VCU334DN7F2I9UIUMVQMM7JMSD142LIMNUGTTV9R0CF4EG.zkey \
  zonefiles/N0UJMP015AFUNR2BTNM3FKPBLG38913BL8IDMCO2H0A1LIB81960.zkey


test_plugin_namestore_sqlite_SOURCES = \
 test_plugin_namestore.c
test_plugin_namestore_sqlite_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  
