AM_CPPFLAGS = -I$(top_srcdir)/src/include $(POSTGRESQL_CPPFLAGS)

plugindir = $(libdir)/gnunet

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

pkgcfg_DATA = \
   namecache.conf


if MINGW
  WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIBS = -lgcov
endif

if HAVE_SQLITE
SQLITE_PLUGIN = libgnunet_plugin_namecache_sqlite.la
if HAVE_TESTING
SQLITE_TESTS = test_plugin_namecache_sqlite
endif
endif

if HAVE_POSTGRESQL
POSTGRES_PLUGIN = libgnunet_plugin_namecache_postgres.la
if HAVE_TESTING
POSTGRES_TESTS = test_plugin_namecache_postgres
endif
endif

# testcases do not even build yet; thus: experimental!
if HAVE_TESTING
TESTING_TESTS = \
 test_namecache_api_cache_block
endif

if HAVE_SQLITE
check_PROGRAMS = \
 $(SQLITE_TESTS) \
 $(POSTGRES_TESTS) \
 $(TESTING_TESTS)
endif

if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;
TESTS = \
  $(check_PROGRAMS)
endif

lib_LTLIBRARIES = \
  libgnunetnamecache.la


libgnunetnamecache_la_SOURCES = \
  namecache_api.c \
  namecache.h
libgnunetnamecache_la_LIBADD = \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)
libgnunetnamecache_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS) $(WINFLAGS) \
  -version-info 0:0:0


libexec_PROGRAMS = \
 gnunet-service-namecache

bin_PROGRAMS = \
 gnunet-namecache

gnunet_namecache_SOURCES = \
 gnunet-namecache.c
gnunet_namecache_LDADD = \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  libgnunetnamecache.la \
  $(GN_LIBINTL)

gnunet_service_namecache_SOURCES = \
 gnunet-service-namecache.c

gnunet_service_namecache_LDADD = \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  libgnunetnamecache.la \
  $(GN_LIBINTL)


plugin_LTLIBRARIES = \
  $(SQLITE_PLUGIN) \
  $(POSTGRES_PLUGIN)

libgnunet_plugin_namecache_sqlite_la_SOURCES = \
  plugin_namecache_sqlite.c
libgnunet_plugin_namecache_sqlite_la_LIBADD = \
  libgnunetnamecache.la  \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la $(XLIBS) -lsqlite3 \
  $(LTLIBINTL)
libgnunet_plugin_namecache_sqlite_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)


libgnunet_plugin_namecache_postgres_la_SOURCES = \
  plugin_namecache_postgres.c
libgnunet_plugin_namecache_postgres_la_LIBADD = \
  libgnunetnamecache.la  \
  $(top_builddir)/src/postgres/libgnunetpostgres.la  \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la $(XLIBS) -lpq \
  $(LTLIBINTL)
libgnunet_plugin_namecache_postgres_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS) $(POSTGRESQL_LDFLAGS)

test_namecache_api_cache_block_SOURCES = \
 test_namecache_api_cache_block.c
test_namecache_api_cache_block_LDADD = \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  libgnunetnamecache.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la

test_plugin_namecache_sqlite_SOURCES = \
 test_plugin_namecache.c
test_plugin_namecache_sqlite_LDADD = \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/util/libgnunetutil.la

test_plugin_namecache_postgres_SOURCES = \
 test_plugin_namecache.c
test_plugin_namecache_postgres_LDADD = \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/util/libgnunetutil.la

EXTRA_DIST = \
  test_namecache_api.conf \
  test_plugin_namecache_sqlite.conf \
  test_plugin_namecache_postgres.conf 

