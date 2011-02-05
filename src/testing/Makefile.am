INCLUDES = -I$(top_srcdir)/src/include

if MINGW
  WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

lib_LTLIBRARIES = libgnunettesting.la

libgnunettesting_la_SOURCES = \
  testing.c  \
  testing_group.c 
libgnunettesting_la_LIBADD = $(XLIB) \
 $(top_builddir)/src/core/libgnunetcore.la \
 $(top_builddir)/src/statistics/libgnunetstatistics.la \
 $(top_builddir)/src/transport/libgnunettransport.la \
 -lm \
 $(top_builddir)/src/util/libgnunetutil.la 
 
noinst_PROGRAMS = ${check_PROGRAMS}

check_PROGRAMS = \
 test_testing \
 test_testing_connect \
 test_testing_reconnect \
 test_testing_group \
 test_testing_topology_stability \
 test_testing_large_topology_clique \
 test_testing_topology_from_file \
 test_testing_topology_clique \
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
 test_testing_topology_none \
 test_testing_topology_scale_free \
 test_testing_topology_connect_only \
 test_testing_topology_2d_torus_plus

# test_testing_topology_stability
if !DISABLE_TEST_RUN 
TESTS = \
 test_testing \
 test_testing_connect \
 test_testing_reconnect \
 test_testing_group \
 test_testing_topology_clique \
 test_testing_topology_from_file \
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
 test_testing_topology_scale_free \
 test_testing_topology_connect_only \
 test_testing_topology_2d_torus_plus
endif

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

test_testing_group_SOURCES = \
 test_testing_group.c
test_testing_group_LDADD = \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/util/libgnunetutil.la  
 
test_testing_topology_clique_SOURCES = \
 test_testing_topology.c
test_testing_topology_clique_LDADD = \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/util/libgnunetutil.la
 
test_testing_topology_connect_only_SOURCES = \
 test_testing_topology.c
test_testing_topology_connect_only_LDADD = \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/util/libgnunetutil.la
 
test_testing_topology_from_file_SOURCES = \
 test_testing_topology.c
test_testing_topology_from_file_LDADD = \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/util/libgnunetutil.la
 
test_testing_large_topology_clique_SOURCES = \
 test_testing_large_topology.c
test_testing_large_topology_clique_LDADD = \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/util/libgnunetutil.la
 
test_testing_topology_stability_SOURCES = \
 test_testing_topology.c
test_testing_topology_stability_LDADD = \
 $(top_builddir)/src/testing/libgnunettesting.la \
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
 $(top_builddir)/src/util/libgnunetutil.la  

test_testing_topology_clique_minimum_SOURCES = \
 test_testing_topology.c
test_testing_topology_clique_minimum_LDADD = \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/util/libgnunetutil.la
 
test_testing_topology_clique_dfs_SOURCES = \
 test_testing_topology.c
test_testing_topology_clique_dfs_LDADD = \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/util/libgnunetutil.la  

test_testing_topology_line_SOURCES = \
 test_testing_topology.c
test_testing_topology_line_LDADD = \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/util/libgnunetutil.la  
   
test_testing_reconnect_SOURCES = \
 test_testing_reconnect.c
test_testing_reconnect_LDADD = \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/util/libgnunetutil.la

test_testing_group_remote_SOURCES = \
 test_testing_group_remote.c
test_testing_group_remote_LDADD = \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/util/libgnunetutil.la  

test_testing_topology_ring_SOURCES = \
 test_testing_topology.c
test_testing_topology_ring_LDADD = \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/util/libgnunetutil.la  
 
test_testing_topology_2d_torus_SOURCES = \
  test_testing_topology.c
test_testing_topology_2d_torus_LDADD = \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/util/libgnunetutil.la 
 
test_testing_topology_2d_torus_plus_SOURCES = \
  test_testing_topology.c
test_testing_topology_2d_torus_plus_LDADD = \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/util/libgnunetutil.la 
 
test_testing_topology_small_world_ring_SOURCES = \
  test_testing_topology.c
test_testing_topology_small_world_ring_LDADD = \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/util/libgnunetutil.la
 
test_testing_topology_small_world_torus_SOURCES = \
  test_testing_topology.c
test_testing_topology_small_world_torus_LDADD = \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/util/libgnunetutil.la
 
test_testing_topology_internat_SOURCES = \
  test_testing_topology.c
test_testing_topology_internat_LDADD = \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/util/libgnunetutil.la

test_testing_topology_erdos_renyi_SOURCES = \
  test_testing_topology.c
test_testing_topology_erdos_renyi_LDADD = \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/util/libgnunetutil.la
 
test_testing_topology_scale_free_SOURCES = \
  test_testing_topology.c
test_testing_topology_scale_free_LDADD = \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/util/libgnunetutil.la

test_testing_topology_none_SOURCES = \
 test_testing_topology.c
test_testing_topology_none_LDADD = \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/util/libgnunetutil.la
 
 
EXTRA_DIST = \
 test_testing_data.conf \
 test_testing_connect_peer1.conf \
 test_testing_connect_peer2.conf \
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
 test_testing_data_topology_none.conf
 
