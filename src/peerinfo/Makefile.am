# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

pkgcfg_DATA = \
  peerinfo.conf

if MINGW
 WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols -lole32 -lshell32 -liconv -lstdc++ -lcomdlg32 -lgdi32
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

lib_LTLIBRARIES = libgnunetpeerinfo.la

libgnunetpeerinfo_la_SOURCES = \
  peerinfo_api.c peerinfo.h \
  peerinfo_api_notify.c
libgnunetpeerinfo_la_LIBADD = \
  $(top_builddir)/src/hello/libgnunethello.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(XLIB) \
  $(LTLIBINTL)
libgnunetpeerinfo_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS) $(WINFLAGS) \
  -version-info 0:0:0


libexec_PROGRAMS = \
 gnunet-service-peerinfo

gnunet_service_peerinfo_SOURCES = \
 gnunet-service-peerinfo.c
gnunet_service_peerinfo_LDADD = \
  $(top_builddir)/src/hello/libgnunethello.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la

if HAVE_BENCHMARKS
 PEERINFO_BENCHMARKS = \
 perf_peerinfo_api
endif

if HAVE_TESTING
check_PROGRAMS = \
 test_peerinfo_shipped_hellos \
 test_peerinfo_api \
 test_peerinfo_api_friend_only \
 test_peerinfo_api_notify_friend_only \
 $(PEERINFO_BENCHMARKS)
endif


if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;
TESTS = $(check_PROGRAMS)
endif

test_peerinfo_shipped_hellos_SOURCES = \
 test_peerinfo_shipped_hellos.c
test_peerinfo_shipped_hellos_LDADD = \
 $(top_builddir)/src/hello/libgnunethello.la \
 libgnunetpeerinfo.la \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/util/libgnunetutil.la

test_peerinfo_api_SOURCES = \
 test_peerinfo_api.c
test_peerinfo_api_LDADD = \
 $(top_builddir)/src/hello/libgnunethello.la \
 libgnunetpeerinfo.la \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/util/libgnunetutil.la

test_peerinfo_api_friend_only_SOURCES = \
 test_peerinfo_api_friend_only.c
test_peerinfo_api_friend_only_LDADD = \
 $(top_builddir)/src/hello/libgnunethello.la \
 libgnunetpeerinfo.la \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/util/libgnunetutil.la

test_peerinfo_api_notify_friend_only_SOURCES = \
 test_peerinfo_api_notify_friend_only.c
test_peerinfo_api_notify_friend_only_LDADD = \
 $(top_builddir)/src/hello/libgnunethello.la \
 libgnunetpeerinfo.la \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/util/libgnunetutil.la

perf_peerinfo_api_SOURCES = \
 perf_peerinfo_api.c
perf_peerinfo_api_LDADD = \
 $(top_builddir)/src/hello/libgnunethello.la \
 libgnunetpeerinfo.la \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/util/libgnunetutil.la

EXTRA_DIST = \
  test_peerinfo_api_data.conf
