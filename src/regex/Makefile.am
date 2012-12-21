INCLUDES = -I$(top_srcdir)/src/include

if MINGW
  WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage
endif

lib_LTLIBRARIES = libgnunetregex.la

libgnunetregex_la_SOURCES = \
  regex_internal.h regex.c \
  regex_graph.c regex_random.c
libgnunetregex_la_LIBADD = -lm \
  $(top_builddir)/src/util/libgnunetutil.la
libgnunetregex_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS) \
   -version-info 1:1:0

if HAVE_MYSQL
noinst_mysql_progs = \
gnunet-regex-simulation-profiler

gnunet_regex_simulation_profiler_SOURCES = \
  gnunet-regex-simulation-profiler.c
gnunet_regex_simulation_profiler_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/regex/libgnunetregex.la \
  $(top_builddir)/src/mysql/libgnunetmysql.la
gnunet_regex_simulation_profiler_DEPENDENCIES = \
  libgnunetregex.la
endif

noinst_LTLIBRARIES = libgnunetregextest.la

libgnunetregextest_la_SOURCES = \
  regex_test_lib.c regex_test_lib.h
libgnunetregextest_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/regex/libgnunetregex.la
libgnunetregextest_la_DEPENDENCIES = \
  libgnunetregex.la


noinst_PROGRAMS = $(noinst_mysql_progs) \
  perf-regex

perf_regex_SOURCES = \
  perf-regex.c
perf_regex_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/regex/libgnunetregex.la \
  $(top_builddir)/src/regex/libgnunetregextest.la
perf_regex_DEPENDENCIES = \
  libgnunetregex.la


check_PROGRAMS = \
  test_regex_eval_api \
  test_regex_iterate_api \
  test_regex_proofs \
  test_regex_graph_api \
  test_regex_iptoregex

if ENABLE_TEST_RUN
 TESTS = $(check_PROGRAMS)
endif

test_regex_eval_api_SOURCES = \
  test_regex_eval_api.c
test_regex_eval_api_LDADD = \
  $(top_builddir)/src/regex/libgnunetregex.la \
  $(top_builddir)/src/util/libgnunetutil.la

test_regex_iterate_api_SOURCES = \
  test_regex_iterate_api.c
test_regex_iterate_api_LDADD = \
  $(top_builddir)/src/regex/libgnunetregex.la \
  $(top_builddir)/src/util/libgnunetutil.la

test_regex_proofs_SOURCES = \
  test_regex_proofs.c
test_regex_proofs_LDADD = \
  $(top_builddir)/src/regex/libgnunetregex.la \
  $(top_builddir)/src/util/libgnunetutil.la

test_regex_graph_api_SOURCES = \
  test_regex_graph_api.c
test_regex_graph_api_LDADD = \
  $(top_builddir)/src/regex/libgnunetregex.la \
  $(top_builddir)/src/util/libgnunetutil.la

test_regex_iptoregex_SOURCES = \
  test_regex_iptoregex.c
test_regex_iptoregex_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/regex/libgnunetregex.la


EXTRA_DIST = \
  regex_simulation_profiler_test.conf
