INCLUDES = -I$(top_srcdir)/src/include

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

check_PROGRAMS = \
 test_experimentation_clique
 
if ENABLE_TEST_RUN
 TESTS = \
 test_experimentation_clique
endif

libexec_PROGRAMS = \
 gnunet-daemon-experimentation

gnunet_daemon_experimentation_SOURCES = \
 gnunet-daemon-experimentation.c         
gnunet_daemon_experimentation_LDADD = \
  $(top_builddir)/src/core/libgnunetcore.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la 

test_experimentation_clique_SOURCES = \
 test_experimentation_clique.c
test_experimentation_clique_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/statistics/libgnunetstatistics.la \
 $(top_builddir)/src/testbed/libgnunettestbed.la
 
EXTRA_DIST = \ 
 test_experimentation_clique.conf