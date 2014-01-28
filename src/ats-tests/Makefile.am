AM_CPPFLAGS = -I$(top_srcdir)/src/include

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

if MINGW
 WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols
endif

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif

if HAVE_LIBGLPK
 PERF_MLP =  perf_ats_mlp_transport_none \
 perf_ats_mlp_core_none \
 perf_ats_mlp_transport_bandwidth \
 perf_ats_mlp_core_bandwidth \
 perf_ats_mlp_transport_latency \
 perf_ats_mlp_core_latency
endif

if HAVE_TESTING
TESTING_TESTS = \
 perf_ats_proportional_transport_none \
 perf_ats_proportional_core_none \
 perf_ats_proportional_transport_bandwidth \
 perf_ats_proportional_core_bandwidth \
 perf_ats_proportional_transport_latency \
 perf_ats_proportional_core_latency \
 perf_ats_ril_transport_none \
 perf_ats_ril_core_none \
 perf_ats_ril_transport_bandwidth \
 perf_ats_ril_core_bandwidth \
 perf_ats_ril_transport_latency \
 perf_ats_ril_core_latency \
 $(PERF_MLP)
endif

lib_LTLIBRARIES = \
  libgnunetatstesting.la 

check_PROGRAMS = \
 $(TESTING_TESTS)

if ENABLE_TEST_RUN
TESTS_ENVIRONMENT=export GNUNET_PREFIX=@prefix@;export PATH=@prefix@/bin:$$PATH;
TESTS = $(check_PROGRAMS)
endif

noinst_PROGRAMS = \
 gnunet-ats-sim
 
libgnunetatstesting_la_SOURCES = \
  ats-testing.c ats-testing-log.c ats-testing-traffic.c \
  ats-testing-experiment.c
libgnunetatstesting_la_LIBADD = \
  $(top_builddir)/src/transport/libgnunettransport.la \
  $(top_builddir)/src/hello/libgnunethello.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(GN_LIBINTL)
libgnunettransporttesting_la_DEPENDENCIES = \
  libgnunettransport.la
libgnunettransporttesting_la_LDFLAGS = \
 $(GN_LIB_LDFLAGS)
 
gnunet_ats_sim_SOURCES = \
 gnunet-ats-sim.c 
gnunet_ats_sim_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/ats-tests/libgnunetatstesting.la \
 $(top_builddir)/src/testbed/libgnunettestbed.la \
 $(top_builddir)/src/ats/libgnunetats.la \
 $(top_builddir)/src/core/libgnunetcore.la \
 $(top_builddir)/src/transport/libgnunettransport.la  
gnunet_ats_sim_DEPENDENCIES = \
 libgnunetatstesting.la \
 $(top_builddir)/src/util/libgnunetutil.la


perf_ats_proportional_core_none_SOURCES = \
  perf_ats.c
perf_ats_proportional_core_none_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/ats-tests/libgnunetatstesting.la \
  $(top_builddir)/src/testbed/libgnunettestbed.la \
  $(top_builddir)/src/ats/libgnunetats.la \
  $(top_builddir)/src/core/libgnunetcore.la \
  $(top_builddir)/src/transport/libgnunettransport.la
perf_ats_proportional_core_DEPENDENCIES = \
 libgnunetatstesting.la \
 $(top_builddir)/src/util/libgnunetutil.la  

perf_ats_proportional_transport_none_SOURCES = \
  perf_ats.c
perf_ats_proportional_transport_none_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/ats-tests/libgnunetatstesting.la \
  $(top_builddir)/src/testbed/libgnunettestbed.la \
  $(top_builddir)/src/ats/libgnunetats.la \
  $(top_builddir)/src/core/libgnunetcore.la \
  $(top_builddir)/src/transport/libgnunettransport.la
perf_ats_proportional_transport_none_DEPENDENCIES = \
 libgnunetatstesting.la \
 $(top_builddir)/src/util/libgnunetutil.la    

perf_ats_proportional_core_bandwidth_SOURCES = \
  perf_ats.c
perf_ats_proportional_core_bandwidth_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/ats-tests/libgnunetatstesting.la \
  $(top_builddir)/src/testbed/libgnunettestbed.la \
  $(top_builddir)/src/ats/libgnunetats.la \
  $(top_builddir)/src/core/libgnunetcore.la \
  $(top_builddir)/src/transport/libgnunettransport.la
perf_ats_proportional_core_bandwidth_DEPENDENCIES = \
 libgnunetatstesting.la \
 $(top_builddir)/src/util/libgnunetutil.la  

perf_ats_proportional_transport_bandwidth_SOURCES = \
  perf_ats.c
perf_ats_proportional_transport_bandwidth_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/ats-tests/libgnunetatstesting.la \
  $(top_builddir)/src/testbed/libgnunettestbed.la \
  $(top_builddir)/src/ats/libgnunetats.la \
  $(top_builddir)/src/core/libgnunetcore.la \
  $(top_builddir)/src/transport/libgnunettransport.la
perf_ats_proportional_transport_bandwidth_DEPENDENCIES = \
 libgnunetatstesting.la \
 $(top_builddir)/src/util/libgnunetutil.la    

perf_ats_proportional_core_latency_SOURCES = \
  perf_ats.c
perf_ats_proportional_core_latency_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/ats-tests/libgnunetatstesting.la \
  $(top_builddir)/src/testbed/libgnunettestbed.la \
  $(top_builddir)/src/ats/libgnunetats.la \
  $(top_builddir)/src/core/libgnunetcore.la \
  $(top_builddir)/src/transport/libgnunettransport.la
perf_ats_proportional_core_latency_DEPENDENCIES = \
 libgnunetatstesting.la \
 $(top_builddir)/src/util/libgnunetutil.la  
  
perf_ats_proportional_transport_latency_SOURCES = \
  perf_ats.c
perf_ats_proportional_transport_latency_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/ats-tests/libgnunetatstesting.la \
  $(top_builddir)/src/testbed/libgnunettestbed.la \
  $(top_builddir)/src/ats/libgnunetats.la \
  $(top_builddir)/src/core/libgnunetcore.la \
  $(top_builddir)/src/transport/libgnunettransport.la
perf_ats_proportional_transport_latency_DEPENDENCIES = \
 libgnunetatstesting.la \
 $(top_builddir)/src/util/libgnunetutil.la    

if HAVE_LIBGLPK
perf_ats_mlp_core_none_SOURCES = \
  perf_ats.c
perf_ats_mlp_core_none_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/ats-tests/libgnunetatstesting.la \
  $(top_builddir)/src/testbed/libgnunettestbed.la \
  $(top_builddir)/src/ats/libgnunetats.la \
  $(top_builddir)/src/core/libgnunetcore.la \
  $(top_builddir)/src/transport/libgnunettransport.la
perf_ats_mlp_core_none_DEPENDENCIES = \
 libgnunetatstesting.la \
 $(top_builddir)/src/util/libgnunetutil.la    
  
perf_ats_mlp_transport_none_SOURCES = \
  perf_ats.c
perf_ats_mlp_transport_none_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/ats-tests/libgnunetatstesting.la \
  $(top_builddir)/src/testbed/libgnunettestbed.la \
  $(top_builddir)/src/ats/libgnunetats.la \
  $(top_builddir)/src/core/libgnunetcore.la \
  $(top_builddir)/src/transport/libgnunettransport.la
perf_ats_mlp_transport_none_DEPENDENCIES = \
 libgnunetatstesting.la \
 $(top_builddir)/src/util/libgnunetutil.la    

perf_ats_mlp_core_bandwidth_SOURCES = \
  perf_ats.c
perf_ats_mlp_core_bandwidth_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/ats-tests/libgnunetatstesting.la \
  $(top_builddir)/src/testbed/libgnunettestbed.la \
  $(top_builddir)/src/ats/libgnunetats.la \
  $(top_builddir)/src/core/libgnunetcore.la \
  $(top_builddir)/src/transport/libgnunettransport.la
perf_ats_mlp_core_bandwidth_DEPENDENCIES = \
 libgnunetatstesting.la \
 $(top_builddir)/src/util/libgnunetutil.la    

perf_ats_mlp_transport_bandwidth_SOURCES = \
  perf_ats.c
perf_ats_mlp_transport_bandwidth_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/ats-tests/libgnunetatstesting.la \
  $(top_builddir)/src/testbed/libgnunettestbed.la \
  $(top_builddir)/src/ats/libgnunetats.la \
  $(top_builddir)/src/core/libgnunetcore.la \
  $(top_builddir)/src/transport/libgnunettransport.la
perf_ats_mlp_transport_bandwidth_DEPENDENCIES = \
 libgnunetatstesting.la \
 $(top_builddir)/src/util/libgnunetutil.la    

perf_ats_mlp_core_latency_SOURCES = \
  perf_ats.c
perf_ats_mlp_core_latency_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/ats-tests/libgnunetatstesting.la \
  $(top_builddir)/src/testbed/libgnunettestbed.la \
  $(top_builddir)/src/ats/libgnunetats.la \
  $(top_builddir)/src/core/libgnunetcore.la \
  $(top_builddir)/src/transport/libgnunettransport.la
perf_ats_mlp_core_latency_DEPENDENCIES = \
 libgnunetatstesting.la \
 $(top_builddir)/src/util/libgnunetutil.la    

perf_ats_mlp_transport_latency_SOURCES = \
  perf_ats.c
perf_ats_mlp_transport_latency_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/ats-tests/libgnunetatstesting.la \
  $(top_builddir)/src/testbed/libgnunettestbed.la \
  $(top_builddir)/src/ats/libgnunetats.la \
  $(top_builddir)/src/core/libgnunetcore.la \
  $(top_builddir)/src/transport/libgnunettransport.la
perf_ats_mlp_transport_latencyDEPENDENCIES = \
 $(top_builddir)/src/ats-tests/libgnunetatstesting.la \
 $(top_builddir)/src/util/libgnunetutil.la    
endif

perf_ats_ril_core_none_SOURCES = \
  perf_ats.c
perf_ats_ril_core_none_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/ats-tests/libgnunetatstesting.la \
  $(top_builddir)/src/testbed/libgnunettestbed.la \
  $(top_builddir)/src/ats/libgnunetats.la \
  $(top_builddir)/src/core/libgnunetcore.la \
  $(top_builddir)/src/transport/libgnunettransport.la
perf_ats_ril_core_none_DEPENDENCIES = \
 libgnunetatstesting.la \
 $(top_builddir)/src/util/libgnunetutil.la    

perf_ats_ril_transport_none_SOURCES = \
  perf_ats.c
perf_ats_ril_transport_none_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/ats-tests/libgnunetatstesting.la \
  $(top_builddir)/src/testbed/libgnunettestbed.la \
  $(top_builddir)/src/ats/libgnunetats.la \
  $(top_builddir)/src/core/libgnunetcore.la \
  $(top_builddir)/src/transport/libgnunettransport.la
perf_ats_ril_transport_none_DEPENDENCIES = \
 libgnunetatstesting.la \
 $(top_builddir)/src/util/libgnunetutil.la    

perf_ats_ril_core_bandwidth_SOURCES = \
  perf_ats.c
perf_ats_ril_core_bandwidth_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/ats-tests/libgnunetatstesting.la \
  $(top_builddir)/src/testbed/libgnunettestbed.la \
  $(top_builddir)/src/ats/libgnunetats.la \
  $(top_builddir)/src/core/libgnunetcore.la \
  $(top_builddir)/src/transport/libgnunettransport.la
perf_ats_ril_core_bandwidth_DEPENDENCIES = \
 libgnunetatstesting.la \
 $(top_builddir)/src/util/libgnunetutil.la    

perf_ats_ril_transport_bandwidth_SOURCES = \
  perf_ats.c
perf_ats_ril_transport_bandwidth_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/ats-tests/libgnunetatstesting.la \
  $(top_builddir)/src/testbed/libgnunettestbed.la \
  $(top_builddir)/src/ats/libgnunetats.la \
  $(top_builddir)/src/core/libgnunetcore.la \
  $(top_builddir)/src/transport/libgnunettransport.la
perf_ats_ril_transport_DEPENDENCIES = \
 libgnunetatstesting.la \
 $(top_builddir)/src/util/libgnunetutil.la  
   

perf_ats_ril_core_latency_SOURCES = \
  perf_ats.c
perf_ats_ril_core_latency_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/ats-tests/libgnunetatstesting.la \
  $(top_builddir)/src/testbed/libgnunettestbed.la \
  $(top_builddir)/src/ats/libgnunetats.la \
  $(top_builddir)/src/core/libgnunetcore.la \
  $(top_builddir)/src/transport/libgnunettransport.la
perf_ats_ril_core_latency_DEPENDENCIES = \
 libgnunetatstesting.la \
 $(top_builddir)/src/util/libgnunetutil.la  
 
perf_ats_ril_transport_latency_SOURCES = \
  perf_ats.c
perf_ats_ril_transport_latency_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/ats-tests/libgnunetatstesting.la \
  $(top_builddir)/src/testbed/libgnunettestbed.la \
  $(top_builddir)/src/ats/libgnunetats.la \
  $(top_builddir)/src/core/libgnunetcore.la \
  $(top_builddir)/src/transport/libgnunettransport.la
perf_ats_ril_transport_latency_DEPENDENCIES = \
 libgnunetatstesting.la \
 $(top_builddir)/src/util/libgnunetutil.la  

EXTRA_DIST = \
	gnunet_ats_sim_default.conf \
  perf_ats_proportional_none.conf \
  perf_ats_proportional_bandwidth.conf \
  perf_ats_proportional_latency.conf \
  perf_ats_mlp_none.conf \
  perf_ats_mlp_bandwidth.conf \
  perf_ats_mlp_latency.conf \
  perf_ats_ril_none.conf \
  perf_ats_ril_bandwidth.conf \
  perf_ats_ril_latency.conf
