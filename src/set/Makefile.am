AM_CPPFLAGS = -I$(top_srcdir)/src/include

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

pkgcfg_DATA = \
  set.conf

if MINGW
 WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols 
endif

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif

bin_PROGRAMS = \
 gnunet-set-profiler gnunet-set-ibf-profiler

libexec_PROGRAMS = \
 gnunet-service-set

lib_LTLIBRARIES = \
  libgnunetset.la

gnunet_set_profiler_SOURCES = \
 gnunet-set-profiler.c
gnunet_set_profiler_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/set/libgnunetset.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(GN_LIBINTL)
gnunet_set_profiler_DEPENDENCIES = \
  libgnunetset.la


gnunet_set_ibf_profiler_SOURCES = \
 gnunet-set-ibf-profiler.c \
 ibf.c
gnunet_set_ibf_profiler_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)

gnunet_service_set_SOURCES = \
 gnunet-service-set.c \
 gnunet-service-set_union.c \
 ibf.c \
 strata_estimator.c
gnunet_service_set_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/core/libgnunetcore.la \
  $(top_builddir)/src/mesh/libgnunetmesh.la \
  $(GN_LIBINTL)

libgnunetset_la_SOURCES = \
  set_api.c
libgnunetset_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(LTLIBINTL)
libgnunetset_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)

if HAVE_TESTING
check_PROGRAMS = \
 test_set_api 
endif

if ENABLE_TEST_RUN
TESTS = $(check_PROGRAMS)
endif

test_set_api_SOURCES = \
 test_set_api.c
test_set_api_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/set/libgnunetset.la
test_set_api_DEPENDENCIES = \
  libgnunetset.la

EXTRA_DIST = \
  test_set.conf

