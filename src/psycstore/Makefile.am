# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

plugindir = $(libdir)/gnunet

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

pkgcfg_DATA = \
  psycstore.conf


if MINGW
 WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

if HAVE_MYSQL
MYSQL_PLUGIN = libgnunet_plugin_psycstore_mysql.la
if HAVE_TESTING
MYSQL_TESTS = test_plugin_psycstore_mysql
endif
endif

if HAVE_POSTGRESQL
POSTGRES_PLUGIN = libgnunet_plugin_psycstore_postgres.la
if HAVE_TESTING
POSTGRES_TESTS = test_plugin_psycstore_postgres
endif
endif

if HAVE_SQLITE
SQLITE_PLUGIN = libgnunet_plugin_psycstore_sqlite.la
if HAVE_TESTING
SQLITE_TESTS = test_plugin_psycstore_sqlite
endif
endif

lib_LTLIBRARIES = libgnunetpsycstore.la

libgnunetpsycstore_la_SOURCES = \
  psycstore_api.c \
  psycstore.h
libgnunetpsycstore_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL) $(XLIB)
libgnunetpsycstore_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)  $(WINFLAGS) \
  -version-info 0:0:0

bin_PROGRAMS =

libexec_PROGRAMS = \
 gnunet-service-psycstore

gnunet_service_psycstore_SOURCES = \
 gnunet-service-psycstore.c
gnunet_service_psycstore_LDADD = \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/psycutil/libgnunetpsycutil.la \
  $(GN_LIBINTL)

plugin_LTLIBRARIES = \
  $(SQLITE_PLUGIN) \
  $(MYSQL_PLUGIN) \
  $(POSTGRES_PLUGIN)


libgnunet_plugin_psycstore_mysql_la_SOURCES = \
  plugin_psycstore_mysql.c
libgnunet_plugin_psycstore_mysql_la_LIBADD = \
  libgnunetpsycstore.la  \
  $(top_builddir)/src/my/libgnunetmy.la \
  $(top_builddir)/src/mysql/libgnunetmysql.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la $(XLIBS) \
  $(LTLIBINTL)
libgnunet_plugin_psycstore_mysql_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)

libgnunet_plugin_psycstore_postgres_la_SOURCES = \
  plugin_psycstore_postgres.c
libgnunet_plugin_psycstore_postgres_la_LIBADD = \
  libgnunetpsycstore.la  \
  $(top_builddir)/src/pq/libgnunetpq.la  \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la $(XLIBS) -lpq \
  $(LTLIBINTL)
libgnunet_plugin_psycstore_postgres_la_LDFLAGS = \
  $(GN_PLUGIN_LDFLAGS) $(POSTGRESQL_LDFLAGS)
libgnunet_plugin_psycstore_postgres_la_CPPFLAGS = \
  $(POSTGRESQL_CPPFLAGS) $(AM_CPPFLAGS)


libgnunet_plugin_psycstore_sqlite_la_SOURCES = \
  plugin_psycstore_sqlite.c
libgnunet_plugin_psycstore_sqlite_la_LIBADD = \
  libgnunetpsycstore.la  \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la $(XLIBS) -lsqlite3 \
  $(LTLIBINTL)
libgnunet_plugin_psycstore_sqlite_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)


if HAVE_SQLITE
if HAVE_TESTING
check_PROGRAMS = \
 $(SQLITE_TESTS) \
 $(MYSQL_TESTS) \
 $(POSTGRES_TESTS) \
 test_psycstore
endif
endif

if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
TESTS = $(check_PROGRAMS)
endif

test_psycstore_SOURCES = \
 test_psycstore.c
test_psycstore_LDADD = \
  libgnunetpsycstore.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la

EXTRA_DIST = \
  test_psycstore.conf


test_plugin_psycstore_sqlite_SOURCES = \
 test_plugin_psycstore.c
test_plugin_psycstore_sqlite_LDADD = \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la

test_plugin_psycstore_mysql_SOURCES = \
 test_plugin_psycstore.c
test_plugin_psycstore_mysql_LDADD = \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la

test_plugin_psycstore_postgres_SOURCES = \
 test_plugin_psycstore.c
test_plugin_psycstore_postgres_LDADD = \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/util/libgnunetutil.la

