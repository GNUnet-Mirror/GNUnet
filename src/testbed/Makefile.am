INCLUDES = -I$(top_srcdir)/src/include

if MINGW
  WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

if ENABLE_LL
  ll_binaries = \
    gnunet-testbed-mpi-spawn
endif

libexecdir= $(pkglibdir)/libexec/

pkgcfgdir= $(pkgdatadir)/config.d/

pkgcfg_DATA = \
  testbed.conf

libexec_PROGRAMS = \
  gnunet-service-testbed \
  gnunet-helper-testbed \
  gnunet-service-testbed-logger

bin_PROGRAMS = \
  $(ll_binaries) \
  gnunet-testbed-profiler

gnunet_service_testbed_SOURCES = \
  gnunet-service-testbed.h \
  gnunet-service-testbed.c \
  gnunet-service-testbed_links.c \
  gnunet-service-testbed_peers.c \
  gnunet-service-testbed_cache.c \
  gnunet-service-testbed_oc.c \
  gnunet-service-testbed_cpustatus.c \
  gnunet-service-testbed_meminfo.c \
  gnunet-service-testbed_meminfo.h
gnunet_service_testbed_LDADD = $(XLIB) \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/core/libgnunetcore.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/transport/libgnunettransport.la \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/testbed/libgnunettestbed.la \
 $(top_builddir)/src/arm/libgnunetarm.la \
 $(LTLIBINTL) $(Z_LIBS)
gnunet_service_testbed_DEPENDENCIES = \
 libgnunettestbed.la

gnunet_service_testbed_logger_SOURCES = \
  gnunet-service-testbed-logger.c
gnunet_service_testbed_logger_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la

gnunet_testbed_profiler_SOURCES = \
  gnunet-testbed-profiler.c
gnunet_testbed_profiler_LDADD = $(XLIB) \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/testbed/libgnunettestbed.la
gnunet_testbed_profiler_DEPENDENCIES = \
 libgnunettestbed.la

gnunet_helper_testbed_SOURCES = \
  gnunet-helper-testbed.c
gnunet_helper_testbed_LDADD = $(XLIB) \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/testing/libgnunettesting.la \
 libgnunettestbed.la \
 $(LTLIBINTL) $(Z_LIBS)
gnunet_helper_testbed_DEPENDENCIES = \
  gnunet-service-testbed.$(OBJEXT) \
  libgnunettestbed.la

gnunet_testbed_mpi_spawn_SOURCES = gnunet_testbed_mpi_spawn.c
gnunet_testbed_mpi_spawn_LDADD = $(XLIB) \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/testbed/libgnunettestbed.la
gnunet_testbed_mpi_spawn_DEPENDENCIES = \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettestbed.la

lib_LTLIBRARIES = \
  libgnunettestbed.la \
  libgnunettestbedlogger.la

libgnunettestbed_la_SOURCES = \
  testbed_api.c testbed_api.h testbed.h \
  testbed_api_hosts.c testbed_api_hosts.h testbed_helper.h \
  testbed_api_operations.c testbed_api_operations.h \
  testbed_api_peers.c testbed_api_peers.h \
  testbed_api_services.c \
  testbed_api_statistics.c \
  testbed_api_testbed.c \
  testbed_api_test.c \
  testbed_api_topology.c testbed_api_topology.h \
  testbed_api_sd.c testbed_api_sd.h
libgnunettestbed_la_LIBADD = $(XLIB) \
 $(top_builddir)/src/core/libgnunetcore.la \
 $(top_builddir)/src/statistics/libgnunetstatistics.la \
 $(top_builddir)/src/transport/libgnunettransport.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 -lm \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(LTLIBINTL)
libgnunettestbed_la_LDFLAGS = \
 $(GN_LIB_LDFLAGS) \
 -version-info 0:0:0

libgnunettestbedlogger_la_SOURCES = \
  testbed_logger_api.c
libgnunettestbedlogger_la_LIBADD = $(XLIB) \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(LTLIBINTL)
libgnunettestbedlogger_la_LDFLAGS = \
 $(GN_LIB_LDFLAGS) \
 -version-info 0:0:0

check_PROGRAMS = \
  test_testbed_api_hosts \
  test_testbed_logger_api \
  test_gnunet_helper_testbed \
  test_testbed_api_controllerlink \
  test_testbed_api_2peers_1controller \
  test_testbed_api_3peers_3controllers \
  test_testbed_api \
  test_testbed_api_sd \
  test_testbed_api_operations \
  test_testbed_api_testbed_run \
  test_testbed_api_test \
  test_testbed_api_test_timeout \
  test_testbed_api_peer_reconfiguration \
  test_testbed_api_peers_manage_services \
  test_testbed_api_topology \
  test_testbed_api_topology_clique \
  test_testbed_api_testbed_run_topologyrandom \
  test_testbed_api_testbed_run_topologyline \
  test_testbed_api_testbed_run_topologyclique \
  test_testbed_api_testbed_run_topologyring \
  test_testbed_api_testbed_run_topologysmallworldring \
  test_testbed_api_testbed_run_topology2dtorus \
  test_testbed_api_testbed_run_topologysmallworld \
  test_testbed_api_testbed_run_topologyfromfile \
  test_testbed_api_testbed_run_topologyscalefree \
  test_testbed_api_testbed_run_waitforever \
  test_testbed_api_statistics

if ENABLE_TEST_RUN
 TESTS = \
  test_testbed_api \
  test_testbed_logger_api \
  test_testbed_api_sd \
  test_testbed_api_operations \
  test_testbed_api_hosts \
  test_gnunet_helper_testbed \
  test_testbed_api_2peers_1controller \
  test_testbed_api_controllerlink \
  test_testbed_api_3peers_3controllers \
  test_testbed_api_testbed_run \
  test_testbed_api_test \
  test_testbed_api_test_timeout \
  test_testbed_api_statistics \
  test_testbed_api_peer_reconfiguration \
  test_testbed_api_peers_manage_services \
  test_testbed_api_topology \
  test_testbed_api_topology_clique \
  test_testbed_api_testbed_run_topologyrandom \
  test_testbed_api_testbed_run_topologyline \
  test_testbed_api_testbed_run_topologyclique \
  test_testbed_api_testbed_run_topologyring \
  test_testbed_api_testbed_run_topology2dtorus \
  test_testbed_api_testbed_run_topologysmallworld \
  test_testbed_api_testbed_run_topologysmallworldring \
  test_testbed_api_testbed_run_topologyfromfile \
  test_testbed_api_testbed_run_topologyscalefree
endif

test_testbed_api_hosts_SOURCES = \
 test_testbed_api_hosts.c
test_testbed_api_hosts_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettestbed.la

test_testbed_api_SOURCES = \
 test_testbed_api.c
test_testbed_api_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/arm/libgnunetarm.la \
 libgnunettestbed.la

test_testbed_logger_api_SOURCES = \
 test_testbed_logger_api.c
test_testbed_logger_api_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/testing/libgnunettesting.la \
 libgnunettestbedlogger.la

test_testbed_api_sd_SOURCES = \
 test_testbed_api_sd.c
test_testbed_api_sd_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettestbed.la

test_testbed_api_2peers_1controller_SOURCES = \
 test_testbed_api_2peers_1controller.c
test_testbed_api_2peers_1controller_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/testing/libgnunettesting.la \
 libgnunettestbed.la

test_testbed_api_3peers_3controllers_SOURCES = \
 test_testbed_api_3peers_3controllers.c
test_testbed_api_3peers_3controllers_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/testing/libgnunettesting.la \
 libgnunettestbed.la

test_testbed_api_operations_SOURCES = \
 test_testbed_api_operations.c
test_testbed_api_operations_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettestbed.la

test_testbed_api_controllerlink_SOURCES = \
 test_testbed_api_controllerlink.c
test_testbed_api_controllerlink_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettestbed.la

test_testbed_api_testbed_run_SOURCES = \
 test_testbed_api_testbed_run.c
test_testbed_api_testbed_run_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettestbed.la

test_testbed_api_test_SOURCES = \
 test_testbed_api_test.c
test_testbed_api_test_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettestbed.la

test_testbed_api_test_timeout_SOURCES = \
 test_testbed_api_test_timeout.c
test_testbed_api_test_timeout_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettestbed.la

test_testbed_api_topology_SOURCES = \
 test_testbed_api_topology.c
test_testbed_api_topology_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettestbed.la

test_testbed_api_topology_clique_SOURCES = \
 test_testbed_api_topology_clique.c
test_testbed_api_topology_clique_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettestbed.la

test_gnunet_helper_testbed_SOURCES = \
 test_gnunet_helper_testbed.c
test_gnunet_helper_testbed_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettestbed.la \
 $(Z_LIBZ)

test_testbed_api_testbed_run_topologyrandom_SOURCES = \
 test_testbed_api_testbed_run.c
test_testbed_api_testbed_run_topologyrandom_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettestbed.la

test_testbed_api_testbed_run_topologyline_SOURCES = \
 test_testbed_api_testbed_run.c
test_testbed_api_testbed_run_topologyline_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettestbed.la

test_testbed_api_testbed_run_topologyclique_SOURCES = \
 test_testbed_api_testbed_run.c
test_testbed_api_testbed_run_topologyclique_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettestbed.la

test_testbed_api_testbed_run_topologyring_SOURCES = \
 test_testbed_api_testbed_run.c
test_testbed_api_testbed_run_topologyring_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettestbed.la

test_testbed_api_testbed_run_topologysmallworldring_SOURCES = \
 test_testbed_api_testbed_run.c
test_testbed_api_testbed_run_topologysmallworldring_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettestbed.la

test_testbed_api_testbed_run_topology2dtorus_SOURCES = \
 test_testbed_api_testbed_run.c
test_testbed_api_testbed_run_topology2dtorus_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettestbed.la

test_testbed_api_testbed_run_topologysmallworld_SOURCES = \
 test_testbed_api_testbed_run.c
test_testbed_api_testbed_run_topologysmallworld_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettestbed.la

test_testbed_api_testbed_run_topologyfromfile_SOURCES = \
 test_testbed_api_testbed_run.c
test_testbed_api_testbed_run_topologyfromfile_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettestbed.la

test_testbed_api_testbed_run_topologyscalefree_SOURCES = \
 test_testbed_api_testbed_run.c
test_testbed_api_testbed_run_topologyscalefree_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettestbed.la

test_testbed_api_testbed_run_waitforever_SOURCES = \
 test_testbed_api_testbed_run.c
test_testbed_api_testbed_run_waitforever_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettestbed.la

test_testbed_api_statistics_SOURCES = \
 test_testbed_api_statistics.c
test_testbed_api_statistics_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettestbed.la

test_testbed_api_peers_manage_services_SOURCES = \
 test_testbed_api_peers_manage_services.c
test_testbed_api_peers_manage_services_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettestbed.la

test_testbed_api_peer_reconfiguration_SOURCES = \
 test_testbed_api_peer_reconfiguration.c
test_testbed_api_peer_reconfiguration_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettestbed.la

EXTRA_DIST = \
  test_testbed_api.conf \
  test_testbed_api_test_timeout.conf \
  test_testbed_api_testbed_run_topologyring.conf \
  test_testbed_api_testbed_run_topologyclique.conf \
  test_testbed_api_testbed_run_topologyline.conf \
  test_testbed_api_testbed_run_topologyrandom.conf \
  test_testbed_api_testbed_run_topologysmallworldring.conf \
  test_testbed_api_testbed_run_topology2dtorus.conf \
  test_testbed_api_testbed_run_topologysmallworld.conf \
  test_testbed_api_testbed_run_topologyfromfile.conf \
  test_testbed_api_testbed_run_topologyscalefree.conf \
  overlay_topology.txt \
  sample_hosts.txt \
  sample.job
