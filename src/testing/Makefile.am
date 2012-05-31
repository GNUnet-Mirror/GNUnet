INCLUDES = -I$(top_srcdir)/src/include

if MINGW
  WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

pkgcfgdir= $(pkgdatadir)/config.d/

dist_pkgcfg_DATA = \
  testing.conf

if HAVE_EXPENSIVE_TESTS
  EXPENSIVE_TESTS = \
   test_testing_topology_stability \
   test_testing_topology_clique_random \
   test_testing_topology_clique_minimum \
   test_testing_topology_clique_dfs \
   test_testing_topology_churn \
   test_testing_topology_line \
   test_testing_topology_blacklist \
   test_testing_group_remote \
   test_testing_topology_ring \
   test_testing_topology_2d_torus \
   test_testing_topology_small_world_ring \
   test_testing_topology_small_world_torus \
   test_testing_topology_erdos_renyi \
   test_testing_topology_internat \
   test_testing_topology_scale_free
endif

lib_LTLIBRARIES = \
  libgnunettesting.la \
  libgnunettesting_new.la

libgnunettesting_la_SOURCES = \
  helper.c \
  testing.c  \
  testing_group.c \
  testing_peergroup.c
libgnunettesting_la_LIBADD = $(XLIB) \
 $(top_builddir)/src/core/libgnunetcore.la \
 $(top_builddir)/src/statistics/libgnunetstatistics.la \
 $(top_builddir)/src/transport/libgnunettransport.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 -lm \
 $(top_builddir)/src/util/libgnunetutil.la 
libgnunettesting_la_LDFLAGS = \
 $(GN_LIB_LDFLAGS) \
 -version-info 0:1:0


libgnunettesting_new_la_SOURCES = \
  testing_new.c  
libgnunettesting_new_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la 
libgnunettesting_new_la_LDFLAGS = \
 $(GN_LIB_LDFLAGS) \
 -version-info 0:1:0


bin_PROGRAMS = \
 gnunet-testing

check_PROGRAMS = \
 test_testing \
 test_testing_connect \
 test_testing_reconnect \
 test_testing_group \
 test_testing_peergroup \
 test_testing_topology_stability \
 test_testing_topology_clique \
 test_testing_topology_clique_random \
 test_testing_topology_clique_minimum \
 test_testing_topology_clique_dfs \
 test_testing_topology_churn \
 test_testing_topology_line \
 test_testing_topology_blacklist \
 test_testing_group_remote \
 test_testing_2dtorus \
 test_testing_topology_ring \
 test_testing_topology_2d_torus \
 test_testing_topology_small_world_ring \
 test_testing_topology_small_world_torus \
 test_testing_topology_erdos_renyi \
 test_testing_topology_internat \
 test_testing_topology_none \
 test_testing_topology_scale_free \
 test_testing_new_portreservation \
 test_testing_new_peerstartup \
 test_testing_new_servicestartup

if ENABLE_TEST_RUN 
TESTS = \
 test_testing \
 test_testing_connect \
 test_testing_reconnect \
 test_testing_group \
 test_testing_peergroup \
 test_testing_new_portreservation \
 test_testing_new_peerstartup \
 test_testing_new_servicestartup
endif

gnunet_testing_SOURCES = \
 gnunet-testing.c         
gnunet_testing_LDADD = \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(GN_LIBINTL)
gnunet_testing_DEPENDENCIES = \
 libgnunettesting.la


test_testing_SOURCES = \
 test_testing.c
test_testing_LDADD = \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/util/libgnunetutil.la  

test_testing_connect_SOURCES = \
 test_testing_connect.c
test_testing_connect_LDADD = \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/util/libgnunetutil.la  

test_testing_reconnect_SOURCES = \
 test_testing_reconnect.c
test_testing_reconnect_LDADD = \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/util/libgnunetutil.la  

test_testing_group_SOURCES = \
 test_testing_group.c
test_testing_group_LDADD = \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/util/libgnunetutil.la  

test_testing_peergroup_SOURCES = \
 test_testing_peergroup.c
test_testing_peergroup_LDADD = \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/util/libgnunetutil.la 

test_testing_topology_clique_SOURCES = \
 test_testing_topology.c
test_testing_topology_clique_LDADD = \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/core/libgnunetcore.la \
 $(top_builddir)/src/util/libgnunetutil.la

test_testing_topology_stability_SOURCES = \
 test_testing_topology.c
test_testing_topology_stability_LDADD = \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/core/libgnunetcore.la \
 $(top_builddir)/src/util/libgnunetutil.la

test_testing_topology_blacklist_SOURCES = \
 test_testing_topology_blacklist.c
test_testing_topology_blacklist_LDADD = \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/util/libgnunetutil.la 

test_testing_topology_churn_SOURCES = \
 test_testing_topology_churn.c
test_testing_topology_churn_LDADD = \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/util/libgnunetutil.la 

test_testing_topology_clique_random_SOURCES = \
 test_testing_topology.c
test_testing_topology_clique_random_LDADD = \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/core/libgnunetcore.la \
 $(top_builddir)/src/util/libgnunetutil.la  

test_testing_topology_clique_minimum_SOURCES = \
 test_testing_topology.c
test_testing_topology_clique_minimum_LDADD = \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/core/libgnunetcore.la \
 $(top_builddir)/src/util/libgnunetutil.la

test_testing_topology_clique_dfs_SOURCES = \
 test_testing_topology.c
test_testing_topology_clique_dfs_LDADD = \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/core/libgnunetcore.la \
 $(top_builddir)/src/util/libgnunetutil.la  

test_testing_topology_line_SOURCES = \
 test_testing_topology.c
test_testing_topology_line_LDADD = \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/core/libgnunetcore.la \
 $(top_builddir)/src/util/libgnunetutil.la  


test_testing_group_remote_SOURCES = \
 test_testing_group_remote.c
test_testing_group_remote_LDADD = \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/util/libgnunetutil.la  

test_testing_2dtorus_SOURCES = \
  test_testing_2dtorus.c
test_testing_2dtorus_LDADD = \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/util/libgnunetutil.la 

test_testing_topology_ring_SOURCES = \
 test_testing_topology.c
test_testing_topology_ring_LDADD = \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/core/libgnunetcore.la \
 $(top_builddir)/src/util/libgnunetutil.la  

test_testing_topology_2d_torus_SOURCES = \
  test_testing_topology.c
test_testing_topology_2d_torus_LDADD = \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/core/libgnunetcore.la \
 $(top_builddir)/src/util/libgnunetutil.la 

test_testing_topology_small_world_ring_SOURCES = \
  test_testing_topology.c
test_testing_topology_small_world_ring_LDADD = \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/core/libgnunetcore.la \
 $(top_builddir)/src/util/libgnunetutil.la

test_testing_topology_small_world_torus_SOURCES = \
  test_testing_topology.c
test_testing_topology_small_world_torus_LDADD = \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/core/libgnunetcore.la \
 $(top_builddir)/src/util/libgnunetutil.la

test_testing_topology_internat_SOURCES = \
  test_testing_topology.c
test_testing_topology_internat_LDADD = \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/core/libgnunetcore.la \
 $(top_builddir)/src/util/libgnunetutil.la

test_testing_topology_erdos_renyi_SOURCES = \
  test_testing_topology.c
test_testing_topology_erdos_renyi_LDADD = \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/core/libgnunetcore.la \
 $(top_builddir)/src/util/libgnunetutil.la

test_testing_topology_scale_free_SOURCES = \
  test_testing_topology.c
test_testing_topology_scale_free_LDADD = \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/core/libgnunetcore.la \
 $(top_builddir)/src/util/libgnunetutil.la

test_testing_topology_none_SOURCES = \
 test_testing_topology.c
test_testing_topology_none_LDADD = \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/core/libgnunetcore.la \
 $(top_builddir)/src/util/libgnunetutil.la

test_testing_new_portreservation_SOURCES = \
 test_testing_new_portreservation.c
test_testing_new_portreservation_LDADD = \
 $(top_builddir)/src/testing/libgnunettesting_new.la \
 $(top_builddir)/src/util/libgnunetutil.la

test_testing_new_peerstartup_SOURCES = \
 test_testing_new_peerstartup.c
test_testing_new_peerstartup_LDADD = \
 $(top_builddir)/src/testing/libgnunettesting_new.la \
 $(top_builddir)/src/util/libgnunetutil.la

test_testing_new_servicestartup_SOURCES = \
 test_testing_new_servicestartup.c
test_testing_new_servicestartup_LDADD = \
 $(top_builddir)/src/testing/libgnunettesting_new.la \
 $(top_builddir)/src/util/libgnunetutil.la

EXTRA_DIST = \
 test_testing_defaults.conf \
 test_testing_data.conf \
 test_testing_connect_peer1.conf \
 test_testing_connect_peer2.conf \
 test_testing_2dtorus.conf \
 test_testing_data_topology_clique.conf \
 test_testing_data_topology_clique_random.conf \
 test_testing_data_topology_clique_minimum.conf \
 test_testing_data_topology_clique_dfs.conf \
 test_testing_data_topology_ring.conf \
 test_testing_data_topology_2d_torus.conf \
 test_testing_data_topology_small_world_ring.conf \
 test_testing_data_topology_small_world_torus.conf \
 test_testing_data_topology_erdos_renyi.conf \
 test_testing_data_topology_internat.conf \
 test_testing_data_topology_scale_free.conf \
 test_testing_data_topology_blacklist.conf \
 test_testing_data_topology_churn.conf \
 test_testing_data_topology_none.conf \
 test_testing_data_remote.conf \
 test_testing_data_topology_stability.conf \
 test_testing_peergroup_data.conf
