INCLUDES = -I$(top_srcdir)/src/include

plugindir = $(libdir)/gnunet

pkgcfgdir= $(pkgdatadir)/config.d/

pkgcfg_DATA = \
  datastore.conf

if MINGW
  WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIBS = -lgcov
endif


lib_LTLIBRARIES = \
  libgnunetdatastore.la

libgnunetdatastore_la_SOURCES = \
  datastore_api.c datastore.h 
libgnunetdatastore_la_LIBADD = \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL) 
libgnunetdatastore_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS) $(WINFLAGS) \
  -version-info 1:0:0


bin_PROGRAMS = \
 gnunet-service-datastore

gnunet_service_datastore_SOURCES = \
 gnunet-service-datastore.c 
gnunet_service_datastore_LDADD = \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)

if HAVE_MYSQL
 MYSQL_PLUGIN = libgnunet_plugin_datastore_mysql.la
if HAVE_BENCHMARKS
  MYSQL_BENCHMARKS = \
   perf_datastore_api_mysql \
   perf_plugin_datastore_mysql
endif
 MYSQL_TESTS = \
  test_datastore_api_mysql \
  test_datastore_api_management_mysql \
  test_plugin_datastore_mysql \
  $(MYSQL_BENCHMARKS)
endif
if HAVE_SQLITE
 SQLITE_PLUGIN = libgnunet_plugin_datastore_sqlite.la
if HAVE_BENCHMARKS
  SQLITE_BENCHMARKS = \
   perf_datastore_api_sqlite \
   perf_plugin_datastore_sqlite
endif
 SQLITE_TESTS = \
  test_datastore_api_sqlite \
  test_datastore_api_management_sqlite \
  test_plugin_datastore_sqlite \
  $(SQLITE_BENCHMARKS)
endif
if HAVE_POSTGRES
 POSTGRES_PLUGIN = libgnunet_plugin_datastore_postgres.la
if HAVE_BENCHMARKS
  POSTGRES_BENCHMARKS = \
   perf_datastore_api_postgres \
   perf_plugin_datastore_postgres
endif
 POSTGRES_TESTS = \
  test_datastore_api_postgres \
  test_datastore_api_management_postgres \
  test_plugin_datastore_postgres \
  $(POSTGRES_BENCHMARKS)
endif

plugin_LTLIBRARIES = \
  $(SQLITE_PLUGIN) \
  $(MYSQL_PLUGIN) \
  $(POSTGRES_PLUGIN) \
  libgnunet_plugin_datastore_template.la 


libgnunet_plugin_datastore_sqlite_la_SOURCES = \
  plugin_datastore_sqlite.c
libgnunet_plugin_datastore_sqlite_la_LIBADD = \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la $(XLIBS) -lsqlite3
libgnunet_plugin_datastore_sqlite_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)


libgnunet_plugin_datastore_mysql_la_SOURCES = \
  plugin_datastore_mysql.c
libgnunet_plugin_datastore_mysql_la_LIBADD = \
  $(top_builddir)/src/mysql/libgnunetmysql.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la $(XLIBS) -lz -lmysqlclient
libgnunet_plugin_datastore_mysql_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS) $(MYSQL_LDFLAGS) -lmysqlclient
libgnunet_plugin_datastore_mysql_la_CPPFLAGS = \
 $(MYSQL_CPPFLAGS)

libgnunet_plugin_datastore_postgres_la_SOURCES = \
  plugin_datastore_postgres.c
libgnunet_plugin_datastore_postgres_la_LIBADD = \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/postgres/libgnunetpostgres.la \
  $(top_builddir)/src/util/libgnunetutil.la $(XLIBS) -lpq
libgnunet_plugin_datastore_postgres_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS) $(POSTGRES_LDFLAGS) -lpq
libgnunet_plugin_datastore_postgres_la_CPPFLAGS = \
 $(POSTGRES_CPPFLAGS)


libgnunet_plugin_datastore_template_la_SOURCES = \
  plugin_datastore_template.c
libgnunet_plugin_datastore_template_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la $(XLIBS)
libgnunet_plugin_datastore_template_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)

check_PROGRAMS = \
  $(SQLITE_TESTS) \
  $(MYSQL_TESTS) \
  $(POSTGRES_TESTS)

if ENABLE_TEST_RUN
TESTS = $(check_PROGRAMS)
endif

test_datastore_api_sqlite_SOURCES = \
 test_datastore_api.c
test_datastore_api_sqlite_LDADD = \
 $(top_builddir)/src/datastore/libgnunetdatastore.la \
 $(top_builddir)/src/util/libgnunetutil.la  

test_datastore_api_management_sqlite_SOURCES = \
 test_datastore_api_management.c
test_datastore_api_management_sqlite_LDADD = \
 $(top_builddir)/src/datastore/libgnunetdatastore.la \
 $(top_builddir)/src/util/libgnunetutil.la  

perf_datastore_api_sqlite_SOURCES = \
 perf_datastore_api.c
perf_datastore_api_sqlite_LDADD = \
 $(top_builddir)/src/datastore/libgnunetdatastore.la \
 $(top_builddir)/src/util/libgnunetutil.la  

perf_plugin_datastore_sqlite_SOURCES = \
 perf_plugin_datastore.c
perf_plugin_datastore_sqlite_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

test_plugin_datastore_sqlite_SOURCES = \
 test_plugin_datastore.c
test_plugin_datastore_sqlite_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  


test_datastore_api_mysql_SOURCES = \
 test_datastore_api.c
test_datastore_api_mysql_LDADD = \
 $(top_builddir)/src/datastore/libgnunetdatastore.la \
 $(top_builddir)/src/util/libgnunetutil.la  

test_datastore_api_management_mysql_SOURCES = \
 test_datastore_api_management.c
test_datastore_api_management_mysql_LDADD = \
 $(top_builddir)/src/datastore/libgnunetdatastore.la \
 $(top_builddir)/src/util/libgnunetutil.la  

perf_datastore_api_mysql_SOURCES = \
 perf_datastore_api.c
perf_datastore_api_mysql_LDADD = \
 $(top_builddir)/src/datastore/libgnunetdatastore.la \
 $(top_builddir)/src/util/libgnunetutil.la  

test_plugin_datastore_mysql_SOURCES = \
 test_plugin_datastore.c
test_plugin_datastore_mysql_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

perf_plugin_datastore_mysql_SOURCES = \
 perf_plugin_datastore.c
perf_plugin_datastore_mysql_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  


test_datastore_api_postgres_SOURCES = \
 test_datastore_api.c
test_datastore_api_postgres_LDADD = \
 $(top_builddir)/src/datastore/libgnunetdatastore.la \
 $(top_builddir)/src/util/libgnunetutil.la  

test_datastore_api_management_postgres_SOURCES = \
 test_datastore_api_management.c
test_datastore_api_management_postgres_LDADD = \
 $(top_builddir)/src/datastore/libgnunetdatastore.la \
 $(top_builddir)/src/util/libgnunetutil.la  

perf_datastore_api_postgres_SOURCES = \
 perf_datastore_api.c
perf_datastore_api_postgres_LDADD = \
 $(top_builddir)/src/datastore/libgnunetdatastore.la \
 $(top_builddir)/src/util/libgnunetutil.la  

test_plugin_datastore_postgres_SOURCES = \
 test_plugin_datastore.c
test_plugin_datastore_postgres_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

perf_plugin_datastore_postgres_SOURCES = \
 perf_plugin_datastore.c
perf_plugin_datastore_postgres_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  


EXTRA_DIST = \
 test_defaults.conf \
 test_datastore_api_data_sqlite.conf \
 perf_plugin_datastore_data_sqlite.conf \
 test_datastore_api_data_mysql.conf \
 perf_plugin_datastore_data_mysql.conf \
 test_datastore_api_data_postgres.conf \
 perf_plugin_datastore_data_postgres.conf \
 test_plugin_datastore_data_mysql.conf \
 test_plugin_datastore_data_postgres.conf \
 test_plugin_datastore_data_sqlite.conf