AM_CPPFLAGS = -I$(top_srcdir)/src/include

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

pkgcfg_DATA = \
  social.conf


if MINGW
 WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

lib_LTLIBRARIES = libgnunetsocial.la

libgnunetsocial_la_SOURCES = \
  social_api.c social.h
libgnunetsocial_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/env/libgnunetenv.la \
  $(top_builddir)/src/psyc/libgnunetpsycutil.la \
  $(top_builddir)/src/core/libgnunetcore.la \
  $(top_builddir)/src/identity/libgnunetidentity.la \
  $(top_builddir)/src/gns/libgnunetgns.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  $(GN_LIBINTL) $(XLIB)
libgnunetsocial_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)  $(WINFLAGS) \
  -version-info 0:0:0
libgnunetsocial_la_DEPENDENCIES = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/env/libgnunetenv.la

bin_PROGRAMS =

libexec_PROGRAMS = \
 gnunet-service-social

gnunet_service_social_SOURCES = \
 gnunet-service-social.c
gnunet_service_social_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/psyc/libgnunetpsyc.la \
  $(GN_LIBINTL)
gnunet_service_social_DEPENDENCIES = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/psyc/libgnunetpsyc.la
gnunet_service_social_CFLAGS = $(AM_CFLAGS)


if HAVE_TESTING
check_PROGRAMS = \
 test_social
endif

if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;
TESTS = $(check_PROGRAMS)
endif

test_social_SOURCES = \
 test_social.c
test_social_LDADD = \
  libgnunetsocial.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/env/libgnunetenv.la \
  $(top_builddir)/src/util/libgnunetutil.la
test_social_DEPENDENCIES = \
  libgnunetsocial.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/env/libgnunetenv.la \
  $(top_builddir)/src/util/libgnunetutil.la

EXTRA_DIST = \
  test_social.conf
