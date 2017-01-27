# This Makefile.am is in the public domain
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
  $(top_builddir)/src/psycutil/libgnunetpsycutil.la \
  $(GN_LIBINTL) $(XLIB)
libgnunetsocial_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)  $(WINFLAGS) \
  -version-info 0:0:0

bin_PROGRAMS = \
 gnunet-social

libexec_PROGRAMS = \
 gnunet-service-social

gnunet_social_SOURCES = \
  gnunet-social.c
gnunet_social_LDADD = \
  libgnunetsocial.la \
  $(top_builddir)/src/psycutil/libgnunetpsycutil.la \
  $(top_builddir)/src/util/libgnunetutil.la

gnunet_service_social_SOURCES = \
 gnunet-service-social.c
gnunet_service_social_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/psycutil/libgnunetpsycutil.la \
  $(top_builddir)/src/psyc/libgnunetpsyc.la \
  $(top_builddir)/src/identity/libgnunetidentity.la \
  $(top_builddir)/src/gns/libgnunetgns.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  $(GN_LIBINTL)


if HAVE_TESTING
check_PROGRAMS = \
 test_social
endif

if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
TESTS = $(check_PROGRAMS)
endif

test_social_SOURCES = \
 test_social.c
test_social_LDADD = \
  libgnunetsocial.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/psycutil/libgnunetpsycutil.la \
  $(top_builddir)/src/identity/libgnunetidentity.la

EXTRA_DIST = \
  test_social.conf
