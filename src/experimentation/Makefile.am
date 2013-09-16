AM_CPPFLAGS = -I$(top_srcdir)/src/include

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

pkgcfg_DATA = \
  experimentation.conf

if MINGW
 WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols -lole32 -lshell32 -liconv -lstdc++ -lcomdlg32 -lgdi32
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif


if HAVE_EXPERIMENTAL
 TEXT_EXP_CLIQUE = test_experimentation_clique_connect test_experimentation_clique_run
endif 

check_PROGRAMS = \
 $(TEXT_EXP_CLIQUE)
 
if ENABLE_TEST_RUN
 TESTS = \
 $(TEXT_EXP_CLIQUE)
endif

libexec_PROGRAMS = \
 gnunet-daemon-experimentation

gnunet_daemon_experimentation_SOURCES = \
 gnunet-daemon-experimentation.c \
 gnunet-daemon-experimentation_capabilities.c \
 gnunet-daemon-experimentation_nodes.c \
 gnunet-daemon-experimentation_scheduler.c \
 gnunet-daemon-experimentation_experiments.c \
 gnunet-daemon-experimentation_storage.c
gnunet_daemon_experimentation_LDADD = \
  $(top_builddir)/src/core/libgnunetcore.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la 

test_experimentation_clique_connect_SOURCES = \
 test_experimentation_clique_connect.c
test_experimentation_clique_connect_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/statistics/libgnunetstatistics.la \
 $(top_builddir)/src/testbed/libgnunettestbed.la

test_experimentation_clique_run_SOURCES = \
 test_experimentation_clique_run.c
test_experimentation_clique_run_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/statistics/libgnunetstatistics.la \
 $(top_builddir)/src/testbed/libgnunettestbed.la
 
#test_experimentation_clique_run_SOURCES = \
# test_experimentation_clique_run.c
#test_experimentation_clique_run_LDADD = \
# $(top_builddir)/src/util/libgnunetutil.la \
# $(top_builddir)/src/statistics/libgnunetstatistics.la \
# $(top_builddir)/src/testbed/libgnunettestbed.la 
 

EXTRA_DIST = \
 test_experimentation_clique.conf \
 test_experiments.exp