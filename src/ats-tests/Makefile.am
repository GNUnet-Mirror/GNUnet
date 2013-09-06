INCLUDES = -I$(top_srcdir)/src/include

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

if MINGW
 WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols 
endif

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif

if HAVE_LIBGLPK

endif

if HAVE_TESTING
TESTING_TESTS = \
 perf_ats_proportional_bandwidth \
 perf_ats_proportional_delay
endif

check_PROGRAMS = \
 $(TESTING_TESTS)
 
if ENABLE_TEST_RUN
TESTS = $(check_PROGRAMS)
endif

perf_ats_proportional_bandwidth_SOURCES = \
  perf_ats.c  
perf_ats_proportional_bandwidth_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testbed/libgnunettestbed.la \
  $(top_builddir)/src/ats/libgnunetats.la \
  $(top_builddir)/src/core/libgnunetcore.la  

perf_ats_proportional_delay_SOURCES = \
  perf_ats.c  
perf_ats_proportional_delay_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testbed/libgnunettestbed.la \
  $(top_builddir)/src/ats/libgnunetats.la \
  $(top_builddir)/src/core/libgnunetcore.la  

EXTRA_DIST = \
  perf_ats_proportional_bandwidth.conf \
  perf_ats_proportional_delay.conf
