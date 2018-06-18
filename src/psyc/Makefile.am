# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

pkgcfg_DATA = \
  psyc.conf


if MINGW
 WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

lib_LTLIBRARIES = libgnunetpsyc.la

libgnunetpsyc_la_SOURCES = \
  psyc_api.c psyc.h
libgnunetpsyc_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/psycutil/libgnunetpsycutil.la \
  $(GN_LIBINTL) $(XLIB)
libgnunetpsyc_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)  $(WINFLAGS) \
  -version-info 0:0:0

bin_PROGRAMS =

libexec_PROGRAMS = \
  gnunet-service-psyc

gnunet_service_psyc_SOURCES = \
  gnunet-service-psyc.c
gnunet_service_psyc_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/multicast/libgnunetmulticast.la \
  $(top_builddir)/src/psycstore/libgnunetpsycstore.la \
  $(top_builddir)/src/psycutil/libgnunetpsycutil.la \
  $(GN_LIBINTL)
gnunet_service_psyc_CFLAGS = $(AM_CFLAGS)


if HAVE_TESTING
check_PROGRAMS = \
 test_psyc2
# test_psyc
endif

if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
TESTS = $(check_PROGRAMS)
endif

#test_psyc_SOURCES = \
# test_psyc.c
#test_psyc_LDADD = \
#  libgnunetpsyc.la \
#  $(top_builddir)/src/psycutil/libgnunetpsycutil.la \
#  $(top_builddir)/src/testing/libgnunettesting.la \
#  $(top_builddir)/src/util/libgnunetutil.la
test_psyc2_SOURCES = \
  test_psyc2.c
test_psyc2_LDADD = \
  libgnunetpsyc.la \
  $(top_builddir)/src/psycutil/libgnunetpsycutil.la \
  $(top_builddir)/src/testbed/libgnunettestbed.la \
  $(top_builddir)/src/util/libgnunetutil.la

EXTRA_DIST = \
  test_psyc.conf
