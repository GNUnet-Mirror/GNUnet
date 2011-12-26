INCLUDES = -I$(top_srcdir)/src/include

plugindir = $(libdir)/gnunet

pkgcfgdir= $(pkgdatadir)/config.d/

dist_pkgcfg_DATA = \
  datacache.conf

if MINGW
  WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIBS = -lgcov
endif

if HAVE_SQLITE
  SQLITE_PLUGIN = libgnunet_plugin_datacache_sqlite.la
endif
if HAVE_MYSQL
  MYSQL_PLUGIN = libgnunet_plugin_datacache_mysql.la
endif
if HAVE_POSTGRES
  POSTGRES_PLUGIN = libgnunet_plugin_datacache_postgres.la
endif

lib_LTLIBRARIES = \
  libgnunetdatacache.la

libgnunetdatacache_la_SOURCES = \
  datacache.c 
libgnunetdatacache_la_LIBADD = \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL) 
libgnunetdatacache_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS) $(WINFLAGS) \
  -version-info 0:1:0


plugin_LTLIBRARIES = \
  $(SQLITE_PLUGIN) \
  $(MYSQL_PLUGIN) \
  $(POSTGRES_PLUGIN) \
  libgnunet_plugin_datacache_template.la 


libgnunet_plugin_datacache_sqlite_la_SOURCES = \
  plugin_datacache_sqlite.c
libgnunet_plugin_datacache_sqlite_la_LIBADD = \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la $(XLIBS) -lsqlite3
libgnunet_plugin_datacache_sqlite_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)

libgnunet_plugin_datacache_mysql_la_SOURCES = \
  plugin_datacache_mysql.c
libgnunet_plugin_datacache_mysql_la_LIBADD = \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_PLUGIN_LDFLAGS) $(MYSQL_LDFLAGS) -lmysqlclient
libgnunet_plugin_datacache_mysql_la_CPPFLAGS = \
 $(MYSQL_CPPFLAGS)
libgnunet_plugin_datacache_mysql_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS) $(MYSQL_LDFLAGS) -lmysqlclient

libgnunet_plugin_datacache_postgres_la_SOURCES = \
  plugin_datacache_postgres.c
libgnunet_plugin_datacache_postgres_la_LIBADD = \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_PLUGIN_LDFLAGS) $(POSTGRES_LDFLAGS) -lpq
libgnunet_plugin_datacache_postgres_la_CPPFLAGS = \
 $(POSTGRES_CPPFLAGS)
libgnunet_plugin_datacache_postgres_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS) $(POSTGRES_LDFLAGS) -lpq

libgnunet_plugin_datacache_template_la_SOURCES = \
  plugin_datacache_template.c
libgnunet_plugin_datacache_template_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la $(XLIBS)
libgnunet_plugin_datacache_template_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)


if HAVE_SQLITE
if HAVE_BENCHMARKS
 SQLITE_BENCHMARKS = \
  perf_datacache_sqlite
endif
SQLITE_TESTS = \
 test_datacache_sqlite \
 test_datacache_quota_sqlite \
 $(SQLITE_BENCHMARKS)
endif

if HAVE_MYSQL
if HAVE_BENCHMARKS
 MYSQL_BENCHMARKS = \
  perf_datacache_mysql
endif
MYSQL_TESTS = \
 test_datacache_mysql \
 test_datacache_quota_mysql \
 $(MYSQL_BENCHMARKS)
endif

if HAVE_POSTGRES
if HAVE_BENCHMARKS
 POSTGRES_BENCHMARKS = \
  perf_datacache_postgres
endif
POSTGRES_TESTS = \
 test_datacache_postgres \
 test_datacache_quota_postgres \
 $(POSTGRES_BENCHMARKS)
endif

check_PROGRAMS = \
 $(SQLITE_TESTS) \
 $(MYSQL_TESTS) \
 $(POSTGRES_TESTS) 

if ENABLE_TEST_RUN
TESTS = $(check_PROGRAMS)
endif

test_datacache_sqlite_SOURCES = \
 test_datacache.c
test_datacache_sqlite_LDADD = \
 $(top_builddir)/src/datacache/libgnunetdatacache.la \
 $(top_builddir)/src/util/libgnunetutil.la  

test_datacache_quota_sqlite_SOURCES = \
 test_datacache_quota.c
test_datacache_quota_sqlite_LDADD = \
 $(top_builddir)/src/datacache/libgnunetdatacache.la \
 $(top_builddir)/src/util/libgnunetutil.la  

perf_datacache_sqlite_SOURCES = \
 perf_datacache.c
perf_datacache_sqlite_LDADD = \
 $(top_builddir)/src/datacache/libgnunetdatacache.la \
 $(top_builddir)/src/util/libgnunetutil.la  

test_datacache_mysql_SOURCES = \
 test_datacache.c
test_datacache_mysql_LDADD = \
 $(top_builddir)/src/datacache/libgnunetdatacache.la \
 $(top_builddir)/src/util/libgnunetutil.la  

test_datacache_quota_mysql_SOURCES = \
 test_datacache_quota.c
test_datacache_quota_mysql_LDADD = \
 $(top_builddir)/src/datacache/libgnunetdatacache.la \
 $(top_builddir)/src/util/libgnunetutil.la  

perf_datacache_mysql_SOURCES = \
 perf_datacache.c
perf_datacache_mysql_LDADD = \
 $(top_builddir)/src/datacache/libgnunetdatacache.la \
 $(top_builddir)/src/util/libgnunetutil.la  

test_datacache_postgres_SOURCES = \
 test_datacache.c
test_datacache_postgres_LDADD = \
 $(top_builddir)/src/datacache/libgnunetdatacache.la \
 $(top_builddir)/src/util/libgnunetutil.la  

test_datacache_quota_postgres_SOURCES = \
 test_datacache_quota.c
test_datacache_quota_postgres_LDADD = \
 $(top_builddir)/src/datacache/libgnunetdatacache.la \
 $(top_builddir)/src/util/libgnunetutil.la  

perf_datacache_postgres_SOURCES = \
 perf_datacache.c
perf_datacache_postgres_LDADD = \
 $(top_builddir)/src/datacache/libgnunetdatacache.la \
 $(top_builddir)/src/util/libgnunetutil.la  

EXTRA_DIST = \
 test_datacache_data_sqlite.conf \
 perf_datacache_data_sqlite.conf \
 test_datacache_data_mysql.conf \
 perf_datacache_data_mysql.conf \
 test_datacache_data_postgres.conf \
 perf_datacache_data_postgres.conf
