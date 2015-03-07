# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

plugindir = $(libdir)/gnunet

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

dist_pkgcfg_DATA = \
  peerstore.conf

if MINGW
 WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols
endif

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif

bin_PROGRAMS = \
 gnunet-peerstore

libexec_PROGRAMS = \
 gnunet-service-peerstore

lib_LTLIBRARIES = \
 libgnunetpeerstore.la

gnunet_peerstore_SOURCES = \
 gnunet-peerstore.c
gnunet_peerstore_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  libgnunetpeerstore.la \
  $(GN_LIBINTL)

gnunet_service_peerstore_SOURCES = \
 gnunet-service-peerstore.c \
 peerstore_common.c peerstore_common.h \
 peerstore.h
gnunet_service_peerstore_CFLAGS = $(AM_CFLAGS)
gnunet_service_peerstore_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)

libgnunetpeerstore_la_SOURCES = \
  peerstore_api.c \
  peerstore_common.c
libgnunetpeerstore_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la
libgnunetpeerstore_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)

plugin_LTLIBRARIES = \
  libgnunet_plugin_peerstore_sqlite.la

libgnunet_plugin_peerstore_sqlite_la_SOURCES = \
  plugin_peerstore_sqlite.c
libgnunet_plugin_peerstore_sqlite_la_LIBADD = \
  libgnunetpeerstore.la  \
  $(top_builddir)/src/util/libgnunetutil.la $(XLIBS) -lsqlite3 \
  $(LTLIBINTL)
libgnunet_plugin_peerstore_sqlite_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)

check_PROGRAMS = \
 test_peerstore_api_store \
 test_peerstore_api_iterate \
 test_peerstore_api_watch \
 test_peerstore_api_sync \
 perf_peerstore_store

if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;
TESTS = $(check_PROGRAMS)
endif

test_peerstore_api_store_SOURCES = \
 test_peerstore_api_store.c
test_peerstore_api_store_LDADD = \
  libgnunetpeerstore.la  \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la

test_peerstore_api_iterate_SOURCES = \
 test_peerstore_api_iterate.c
test_peerstore_api_iterate_LDADD = \
  libgnunetpeerstore.la  \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la

test_peerstore_api_watch_SOURCES = \
 test_peerstore_api_watch.c
test_peerstore_api_watch_LDADD = \
  libgnunetpeerstore.la  \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la

test_peerstore_api_sync_SOURCES = \
 test_peerstore_api_sync.c
test_peerstore_api_sync_LDADD = \
  libgnunetpeerstore.la  \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la

perf_peerstore_store_SOURCES = \
 perf_peerstore_store.c
perf_peerstore_store_LDADD = \
  libgnunetpeerstore.la  \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la
