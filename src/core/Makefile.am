INCLUDES = -I$(top_srcdir)/src/include

pkgcfgdir= $(pkgdatadir)/config.d/

pkgcfg_DATA = \
  core.conf

if MINGW
  WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif


lib_LTLIBRARIES = \
  libgnunetcore.la

libgnunetcore_la_SOURCES = \
  core_api.c core.h \
  core_api_iterate_peers.c \
  core_api_is_connected.c 
libgnunetcore_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL) $(XLIB)
libgnunetcore_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS) $(WINFLAGS) \
  -version-info 0:0:0


bin_PROGRAMS = \
 gnunet-service-core \
 gnunet-core

gnunet_service_core_SOURCES = \
 gnunet-service-core.c gnunet-service-core.h \
 gnunet-service-core_clients.c gnunet-service-core_clients.h \
 gnunet-service-core_neighbours.c gnunet-service-core_neighbours.h \
 gnunet-service-core_kx.c gnunet-service-core_kx.h \
 gnunet-service-core_sessions.c gnunet-service-core_sessions.h \
 gnunet-service-core_typemap.c gnunet-service-core_typemap.h
gnunet_service_core_LDADD = \
  $(top_builddir)/src/hello/libgnunethello.la \
  $(top_builddir)/src/peerinfo/libgnunetpeerinfo.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/transport/libgnunettransport.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL) -lz


gnunet_core_SOURCES = \
 gnunet-core.c         
gnunet_core_LDADD = \
  $(top_builddir)/src/core/libgnunetcore.la \
  $(top_builddir)/src/util/libgnunetutil.la
gnunet_core_DEPENDENCIES = \
  libgnunetcore.la

check_PROGRAMS = \
 test_core_api_start_only \
 test_core_api \
 test_core_api_reliability \
 test_core_quota_compliance_symmetric \
 test_core_quota_compliance_asymmetric_send_limited \
 test_core_quota_compliance_asymmetric_recv_limited \
 test_core_api_send_to_self

if ENABLE_TEST_RUN
TESTS = $(check_PROGRAMS)
endif

test_core_api_SOURCES = \
 test_core_api.c
test_core_api_LDADD = \
 $(top_builddir)/src/core/libgnunetcore.la \
 $(top_builddir)/src/transport/libgnunettransport.la \
 $(top_builddir)/src/util/libgnunetutil.la  

test_core_api_reliability_SOURCES = \
 test_core_api_reliability.c
test_core_api_reliability_LDADD = \
 $(top_builddir)/src/core/libgnunetcore.la \
 $(top_builddir)/src/transport/libgnunettransport.la \
 $(top_builddir)/src/util/libgnunetutil.la

test_core_api_send_to_self_SOURCES = \
 test_core_api_send_to_self.c
test_core_api_send_to_self_LDADD = \
 $(top_builddir)/src/core/libgnunetcore.la \
 $(top_builddir)/src/transport/libgnunettransport.la \
 $(top_builddir)/src/util/libgnunetutil.la

test_core_api_start_only_SOURCES = \
 test_core_api_start_only.c
test_core_api_start_only_LDADD = \
 $(top_builddir)/src/core/libgnunetcore.la \
 $(top_builddir)/src/util/libgnunetutil.la

test_core_quota_compliance_symmetric_SOURCES = \
 test_core_quota_compliance.c
test_core_quota_compliance_symmetric_LDADD = \
 $(top_builddir)/src/core/libgnunetcore.la \
 $(top_builddir)/src/transport/libgnunettransport.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/statistics/libgnunetstatistics.la

test_core_quota_compliance_asymmetric_send_limited_SOURCES = \
 test_core_quota_compliance.c
test_core_quota_compliance_asymmetric_send_limited_LDADD = \
 $(top_builddir)/src/core/libgnunetcore.la \
 $(top_builddir)/src/transport/libgnunettransport.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/statistics/libgnunetstatistics.la

test_core_quota_compliance_asymmetric_recv_limited_SOURCES = \
 test_core_quota_compliance.c
test_core_quota_compliance_asymmetric_recv_limited_LDADD = \
 $(top_builddir)/src/core/libgnunetcore.la \
 $(top_builddir)/src/transport/libgnunettransport.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/statistics/libgnunetstatistics.la

EXTRA_DIST = \
  test_core_defaults.conf \
  test_core_api_data.conf \
  test_core_api_peer1.conf \
  test_core_api_peer2.conf \
  test_core_api_send_to_self.conf \
  test_core_quota_asymmetric_recv_limited_peer1.conf \
  test_core_quota_asymmetric_recv_limited_peer2.conf \
  test_core_quota_asymmetric_send_limit_peer1.conf \
  test_core_quota_asymmetric_send_limit_peer2.conf \
  test_core_quota_peer1.conf \
  test_core_quota_peer2.conf
