# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

if MINGW
  WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage
endif

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

plugindir = $(libdir)/gnunet

pkgcfg_DATA = \
  regex.conf

libexec_PROGRAMS = \
  gnunet-service-regex \
  gnunet-daemon-regexprofiler


gnunet_service_regex_SOURCES =  \
 gnunet-service-regex.c
gnunet_service_regex_LDADD =  -lm \
 libgnunetregex_internal.a \
 libgnunetregexblock.la \
 $(top_builddir)/src/dht/libgnunetdht.la \
 $(top_builddir)/src/statistics/libgnunetstatistics.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(GN_LIBINTL)

noinst_LIBRARIES = \
  libgnunetregex_internal.a \
  libgnunetregextest.a

lib_LTLIBRARIES = \
  libgnunetregexblock.la \
  libgnunetregex.la


libgnunetregexblock_la_SOURCES = \
  regex_block_lib.c regex_block_lib.h
libgnunetregexblock_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(XLIB) \
  $(LTLIBINTL)
libgnunetregexblock_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS) $(WINFLAGS) \
  -version-info 1:0:0


libgnunetregex_internal_a_SOURCES = \
  regex_internal_lib.h \
  regex_internal.h regex_internal.c \
  regex_internal_dht.c
libgnunetregex_internal_a_DEPENDENCIES = \
  libgnunetregexblock.la


libgnunetregex_la_SOURCES = \
  regex_api.c regex_ipc.h
libgnunetregex_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la
libgnunetregex_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS) \
   -version-info 3:1:0


plugin_LTLIBRARIES = \
 libgnunet_plugin_block_regex.la

libgnunet_plugin_block_regex_la_SOURCES = \
 plugin_block_regex.c
libgnunet_plugin_block_regex_la_LIBADD = \
 libgnunetregexblock.la \
 $(top_builddir)/src/block/libgnunetblock.la \
 $(top_builddir)/src/util/libgnunetutil.la
libgnunet_plugin_block_regex_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)

if HAVE_MYSQL
noinst_mysql_progs = \
  gnunet-regex-simulation-profiler

gnunet_regex_simulation_profiler_SOURCES = \
  gnunet-regex-simulation-profiler.c
gnunet_regex_simulation_profiler_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  libgnunetregex_internal.a \
  $(top_builddir)/src/dht/libgnunetdht.la \
  $(top_builddir)/src/mysql/libgnunetmysql.la
endif

libgnunetregextest_a_SOURCES = \
  regex_test_lib.c regex_test_lib.h \
  regex_test_graph.c \
  regex_test_random.c
libgnunetregextest_a_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunetregex_internal.a

if HAVE_TESTING
noinst_PROGRAMS = $(noinst_mysql_progs) \
  perf-regex \
  gnunet-regex-profiler
endif

perf_regex_SOURCES = \
  perf-regex.c
perf_regex_LDADD = -lm \
  libgnunetregex_internal.a \
  $(top_builddir)/src/dht/libgnunetdht.la \
  libgnunetregexblock.la \
  libgnunetregextest.a \
  $(top_builddir)/src/util/libgnunetutil.la

gnunet_regex_profiler_SOURCES = \
  gnunet-regex-profiler.c
gnunet_regex_profiler_LDADD = -lm \
  $(top_builddir)/src/arm/libgnunetarm.la \
  $(top_builddir)/src/testbed/libgnunettestbed.la \
  libgnunetregex_internal.a \
  $(top_builddir)/src/dht/libgnunetdht.la \
  libgnunetregexblock.la \
  libgnunetregextest.a \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la

gnunet_daemon_regexprofiler_SOURCES = \
  gnunet-daemon-regexprofiler.c
gnunet_daemon_regexprofiler_LDADD = -lm \
  libgnunetregex_internal.a \
  $(top_builddir)/src/dht/libgnunetdht.la \
  libgnunetregexblock.la \
  libgnunetregextest.a \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la

check_PROGRAMS = \
  test_regex_integration \
  test_regex_eval_api \
  test_regex_iterate_api \
  test_regex_proofs \
  test_regex_graph_api \
  test_regex_api

if ENABLE_TEST_RUN
 AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;
 TESTS = $(check_PROGRAMS)
endif

test_regex_eval_api_SOURCES = \
  test_regex_eval_api.c
test_regex_eval_api_LDADD = -lm \
  libgnunetregex_internal.a \
  $(top_builddir)/src/dht/libgnunetdht.la \
  libgnunetregextest.a \
  libgnunetregexblock.la \
  $(top_builddir)/src/util/libgnunetutil.la

test_regex_integration_SOURCES = \
  test_regex_integration.c
test_regex_integration_LDADD = -lm \
  libgnunetregex.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/tun/libgnunettun.la \
  $(top_builddir)/src/util/libgnunetutil.la

test_regex_api_SOURCES = \
  test_regex_api.c
test_regex_api_LDADD = -lm \
  libgnunetregex.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la

test_regex_iterate_api_SOURCES = \
  test_regex_iterate_api.c
test_regex_iterate_api_LDADD = -lm \
  libgnunetregex_internal.a \
  libgnunetregexblock.la \
  $(top_builddir)/src/dht/libgnunetdht.la \
  $(top_builddir)/src/util/libgnunetutil.la

test_regex_proofs_SOURCES = \
  test_regex_proofs.c
test_regex_proofs_LDADD = -lm \
  libgnunetregex_internal.a \
  $(top_builddir)/src/dht/libgnunetdht.la \
  libgnunetregextest.a \
  libgnunetregexblock.la \
  $(top_builddir)/src/util/libgnunetutil.la

test_regex_graph_api_SOURCES = \
  test_regex_graph_api.c
test_regex_graph_api_LDADD = -lm \
  libgnunetregex_internal.a \
  $(top_builddir)/src/dht/libgnunetdht.la \
  libgnunetregextest.a \
  libgnunetregexblock.la \
  $(top_builddir)/src/util/libgnunetutil.la


EXTRA_DIST = \
  regex_simulation_profiler_test.conf \
  test_regex_api_data.conf
