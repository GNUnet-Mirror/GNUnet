INCLUDES = -I$(top_srcdir)/src/include

pkgcfgdir= $(pkgdatadir)/config.d/

pkgcfg_DATA = \
  ats.conf

if MINGW
 WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols 
endif

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif

if HAVE_LIBGLPK
  GN_LIBGLPK = -lglpk
  GN_MLP_SRC = gnunet-service-ats_addresses_mlp.c gnunet-service-ats_addresses_mlp.h
  GN_MLP_TEST = test_ats_mlp 
  GN_MLP_TEST_AVG = test_ats_mlp_averaging
  GN_MLP_PERF = perf_ats_mlp
endif

lib_LTLIBRARIES = libgnunetats.la

libgnunetats_la_SOURCES = \
  ats_api_scheduling.c \
  ats_api_performance.c 

libgnunetats_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la

libgnunetats_la_LDFLAGS = \
 $(GN_LIB_LDFLAGS) \
  -version-info 2:0:2


bin_PROGRAMS = \
 gnunet-service-ats

gnunet_service_ats_SOURCES = \
 gnunet-service-ats.c gnunet-service-ats.h\
 gnunet-service-ats_addresses.c gnunet-service-ats_addresses.h \
 $(GN_MLP_SRC) \
 gnunet-service-ats_performance.c gnunet-service-ats_performance.h \
 gnunet-service-ats_scheduling.c gnunet-service-ats_scheduling.h \
 gnunet-service-ats_reservations.c gnunet-service-ats_reservations.h
gnunet_service_ats_LDADD = \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBGLPK) \
  $(GN_LIBINTL)


check_PROGRAMS = \
 test_ats_api_scheduling \
 test_ats_api_reset_backoff \
 $(GN_MLP_TEST) \
 $(GN_MLP_TEST_AVG) \
 $(GN_MLP_PERF)
# test_ats_api_scheduling_get_type
# test_ats_api_bandwidth_consumption

if ENABLE_TEST_RUN
TESTS = $(check_PROGRAMS)
endif

if HAVE_LIBGLPK
test_ats_mlp_SOURCES = \
 $(GN_MLP_SRC) \
 test_ats_mlp.c
test_ats_mlp_LDADD = \
  $(GN_LIBGLPK) \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la

test_ats_mlp_averaging_SOURCES = \
 $(GN_MLP_SRC) \
 test_ats_mlp_averaging.c
test_ats_mlp_averaging_LDADD = \
  $(GN_LIBGLPK) \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la

perf_ats_mlp_SOURCES = \
 $(GN_MLP_SRC) \
 perf_ats_mlp.c
perf_ats_mlp_LDADD = \
  $(GN_LIBGLPK) \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la
endif

test_ats_api_scheduling_SOURCES = \
 test_ats_api_scheduling.c
test_ats_api_scheduling_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/ats/libgnunetats.la  

test_ats_api_reset_backoff_SOURCES = \
 test_ats_api_reset_backoff.c
test_ats_api_reset_backoff_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/ats/libgnunetats.la  

#test_ats_api_scheduling_get_type_SOURCES = \
# test_ats_api_scheduling_get_type.c
#test_ats_api_scheduling_get_type_LDADD = \
#  $(top_builddir)/src/util/libgnunetutil.la \
#  $(top_builddir)/src/ats/libgnunetats.la  

#test_ats_api_bandwidth_consumption_SOURCES = \
# test_ats_api_bandwidth_consumption.c
#test_ats_api_bandwidth_consumption_LDADD = \
#  $(top_builddir)/src/util/libgnunetutil.la \
#  $(top_builddir)/src/ats/libgnunetats.la  

#test_ats_api_update_address_SOURCES = \
# test_ats_api_update_address.c
#test_ats_api_update_address_LDADD = \
#  $(top_builddir)/src/util/libgnunetutil.la \
#  $(top_builddir)/src/ats/libgnunetats.la  


EXTRA_DIST = \
  ats.h \
  test_ats_api.conf

