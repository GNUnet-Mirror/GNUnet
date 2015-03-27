# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

if MINGW
 WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

pkgcfg_DATA = \
  rps.conf

bin_PROGRAMS = gnunet-rps

gnunet_rps_SOURCES = gnunet-rps.c
gnunet_rps_LDADD = \
  libgnunetrps.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(XLIB) $(GN_LIBINTL)

lib_LTLIBRARIES = libgnunetrps.la

libgnunetrps_la_SOURCES = \
  rps_api.c rps.h
libgnunetrps_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL) $(XLIB)
libgnunetrps_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)  $(WINFLAGS) \
  -version-info 0:0:0


libexec_PROGRAMS = \
 gnunet-service-rps


gnunet_service_rps_SOURCES = \
 gnunet-service-rps_sampler.h gnunet-service-rps_sampler.c \
 gnunet-service-rps.c


gnunet_service_rps_LDADD = \
  libgnunetrps.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/cadet/libgnunetcadet.la \
  $(top_builddir)/src/nse/libgnunetnse.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(LIBGCRYPT_LIBS) \
  -lm -lgcrypt \
  $(GN_LIBINTL)

if HAVE_TESTING
check_PROGRAMS = \
 test_rps_malicious_1 \
 test_rps_malicious_2 \
 test_rps_seed_request \
 test_rps_single_req
endif

ld_rps_test_lib = \
	libgnunetrps.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testbed/libgnunettestbed.la \
  -lm


if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;
TESTS = $(check_PROGRAMS)
endif

test_rps_malicious_1_SOURCES = \
	test_rps.c
test_rps_malicious_1_LDADD = $(ld_rps_test_lib)

test_rps_malicious_2_SOURCES = \
	test_rps.c
test_rps_malicious_2_LDADD = $(ld_rps_test_lib)

test_rps_single_req_SOURCES = \
 test_rps.c
test_rps_single_req_LDADD = $(ld_rps_test_lib)

test_rps_seed_request_SOURCES = \
 test_rps.c
test_rps_seed_request_LDADD = $(ld_rps_test_lib)

EXTRA_DIST = \
  test_rps.conf

