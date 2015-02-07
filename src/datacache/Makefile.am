# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

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
if HAVE_POSTGRESQL
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
  $(POSTGRES_PLUGIN) \
  libgnunet_plugin_datacache_heap.la \
  libgnunet_plugin_datacache_template.la 


libgnunet_plugin_datacache_sqlite_la_SOURCES = \
  plugin_datacache_sqlite.c
libgnunet_plugin_datacache_sqlite_la_LIBADD = \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la $(XLIBS) -lsqlite3 \
  $(LTLIBINTL)
libgnunet_plugin_datacache_sqlite_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)

libgnunet_plugin_datacache_heap_la_SOURCES = \
  plugin_datacache_heap.c
libgnunet_plugin_datacache_heap_la_LIBADD = \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la $(XLIBS) \
  $(LTLIBINTL)
libgnunet_plugin_datacache_heap_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)

libgnunet_plugin_datacache_postgres_la_SOURCES = \
  plugin_datacache_postgres.c
libgnunet_plugin_datacache_postgres_la_LIBADD = \
  $(top_builddir)/src/postgres/libgnunetpostgres.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_PLUGIN_LDFLAGS) -lpq
libgnunet_plugin_datacache_postgres_la_CPPFLAGS = \
 $(POSTGRESQL_CPPFLAGS) $(AM_CPPFLAGS)
libgnunet_plugin_datacache_postgres_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS) $(POSTGRESQL_LDFLAGS)

libgnunet_plugin_datacache_template_la_SOURCES = \
  plugin_datacache_template.c
libgnunet_plugin_datacache_template_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la $(XLIBS) \
  $(LTLIBINTL)
libgnunet_plugin_datacache_template_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)


if HAVE_TESTING
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

if HAVE_BENCHMARKS
 HEAP_BENCHMARKS = \
  perf_datacache_heap
endif
HEAP_TESTS = \
 test_datacache_heap \
 test_datacache_quota_heap \
 $(HEAP_BENCHMARKS)

if HAVE_POSTGRESQL
if HAVE_BENCHMARKS
 POSTGRES_BENCHMARKS = \
  perf_datacache_postgres
endif
POSTGRES_TESTS = \
 test_datacache_postgres \
 test_datacache_quota_postgres \
 $(POSTGRES_BENCHMARKS)
endif
endif

check_PROGRAMS = \
 $(SQLITE_TESTS) \
 $(HEAP_TESTS) \
 $(POSTGRES_TESTS) 

if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;
TESTS = $(check_PROGRAMS)
endif

test_datacache_sqlite_SOURCES = \
 test_datacache.c
test_datacache_sqlite_LDADD = \
 $(top_builddir)/src/testing/libgnunettesting.la \
 libgnunetdatacache.la \
 $(top_builddir)/src/util/libgnunetutil.la  

test_datacache_quota_sqlite_SOURCES = \
 test_datacache_quota.c
test_datacache_quota_sqlite_LDADD = \
 $(top_builddir)/src/testing/libgnunettesting.la \
 libgnunetdatacache.la \
 $(top_builddir)/src/util/libgnunetutil.la  

perf_datacache_sqlite_SOURCES = \
 perf_datacache.c
perf_datacache_sqlite_LDADD = \
 $(top_builddir)/src/testing/libgnunettesting.la \
 libgnunetdatacache.la \
 $(top_builddir)/src/util/libgnunetutil.la  

test_datacache_heap_SOURCES = \
 test_datacache.c
test_datacache_heap_LDADD = \
 $(top_builddir)/src/testing/libgnunettesting.la \
 libgnunetdatacache.la \
 $(top_builddir)/src/util/libgnunetutil.la  

test_datacache_quota_heap_SOURCES = \
 test_datacache_quota.c
test_datacache_quota_heap_LDADD = \
 $(top_builddir)/src/testing/libgnunettesting.la \
 libgnunetdatacache.la \
 $(top_builddir)/src/util/libgnunetutil.la  

perf_datacache_heap_SOURCES = \
 perf_datacache.c
perf_datacache_heap_LDADD = \
 $(top_builddir)/src/testing/libgnunettesting.la \
 libgnunetdatacache.la \
 $(top_builddir)/src/util/libgnunetutil.la  

test_datacache_postgres_SOURCES = \
 test_datacache.c
test_datacache_postgres_LDADD = \
 $(top_builddir)/src/testing/libgnunettesting.la \
 libgnunetdatacache.la \
 $(top_builddir)/src/util/libgnunetutil.la  

test_datacache_quota_postgres_SOURCES = \
 test_datacache_quota.c
test_datacache_quota_postgres_LDADD = \
 $(top_builddir)/src/testing/libgnunettesting.la \
 libgnunetdatacache.la \
 $(top_builddir)/src/util/libgnunetutil.la  

perf_datacache_postgres_SOURCES = \
 perf_datacache.c
perf_datacache_postgres_LDADD = \
 $(top_builddir)/src/testing/libgnunettesting.la \
 libgnunetdatacache.la \
 $(top_builddir)/src/util/libgnunetutil.la  

EXTRA_DIST = \
 test_datacache_data_sqlite.conf \
 perf_datacache_data_sqlite.conf \
 test_datacache_data_heap.conf \
 perf_datacache_data_heap.conf \
 test_datacache_data_postgres.conf \
 perf_datacache_data_postgres.conf
