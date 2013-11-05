AM_CPPFLAGS = -I$(top_srcdir)/src/include

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

pkgcfg_DATA = \
  secretsharing.conf

if MINGW
 WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols 
endif

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif

libexec_PROGRAMS = \
 gnunet-service-secretsharing

lib_LTLIBRARIES = \
  libgnunetsecretsharing.la

gnunet_service_secretsharing_SOURCES = \
 gnunet-service-secretsharing.c
gnunet_service_secretsharing_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/core/libgnunetcore.la \
  $(top_builddir)/src/mesh/libgnunetmesh.la \
  $(top_builddir)/src/set/libgnunetset.la \
  $(GN_LIBINTL)
gnunet_service_secretsharing_DEPENDENCIES = \
  $(top_builddir)/src/set/libgnunetset.la

libgnunetsecretsharing_la_SOURCES = \
  secretsharing_api.c
libgnunetsecretsharing_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(LTLIBINTL)
libgnunetsecretsharing_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)

check_PROGRAMS = \
 test_secretsharing_api

if ENABLE_TEST_RUN
TESTS = $(check_PROGRAMS)
endif

test_secretsharing_api_SOURCES = \
 test_secretsharing_api.c
test_secretsharing_api_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/secretsharing/libgnunetsecretsharing.la

EXTRA_DIST = \
  test_secretsharing.conf

