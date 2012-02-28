INCLUDES = -I$(top_srcdir)/src/include

if MINGW
  WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

pkgcfgdir= $(pkgdatadir)/config.d/

pkgcfg_DATA = \
  mesh.conf

AM_CLFAGS = -g

bin_PROGRAMS = \
 gnunet-service-mesh

lib_LTLIBRARIES = \
  libgnunetmesh.la

gnunet_service_mesh_SOURCES = \
 gnunet-service-mesh.c \
 mesh_tunnel_tree.c mesh_tunnel_tree.h
gnunet_service_mesh_LDADD = \
  $(top_builddir)/src/core/libgnunetcore.la\
  $(top_builddir)/src/dht/libgnunetdht.la \
  $(top_builddir)/src/util/libgnunetutil.la
 gnunet_service_mesh_DEPENDENCIES = \
  $(top_builddir)/src/core/libgnunetcore.la\
  $(top_builddir)/src/dht/libgnunetdht.la \
  $(top_builddir)/src/util/libgnunetutil.la

libgnunetmesh_la_SOURCES = \
  mesh_api.c mesh.h mesh_protocol.h
libgnunetmesh_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(XLIB)
libgnunetmesh_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS) $(WINFLAGS) \
  -version-info 0:0:0

check_PROGRAMS = \
 test_mesh_api \
 test_mesh_tree_api \
 test_mesh_local_1 \
 test_mesh_local_2 \
 test_mesh_2dtorus \
 test_mesh_small_unicast \
 test_mesh_small_multicast \
 test_mesh_small_speed \
 test_mesh_small_speed_ack

test_mesh_api_SOURCES = \
 test_mesh_api.c
test_mesh_api_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/mesh/libgnunetmesh.la
test_mesh_api_DEPENDENCIES = \
  libgnunetmesh.la \
   $(top_builddir)/src/util/libgnunetutil.la

test_mesh_tree_api_SOURCES = \
 test_mesh_tree_api.c
test_mesh_tree_api_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/dht/libgnunetdht.la
test_mesh_tree_api_DEPENDENCIES = \
  libgnunetmesh.la \
  $(top_builddir)/src/dht/libgnunetdht.la

test_mesh_local_1_SOURCES = \
 test_mesh_local_1.c
test_mesh_local_1_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/mesh/libgnunetmesh.la
test_mesh_local_1_DEPENDENCIES = \
  libgnunetmesh.la

test_mesh_local_2_SOURCES = \
 test_mesh_local_2.c
test_mesh_local_2_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/mesh/libgnunetmesh.la
test_mesh_local_2_DEPENDENCIES = \
  libgnunetmesh.la

test_mesh_2dtorus_SOURCES = \
 test_mesh_2dtorus.c
test_mesh_2dtorus_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la

test_mesh_small_unicast_SOURCES = \
 test_mesh_small.c
test_mesh_small_unicast_LDADD = \
  $(top_builddir)/src/mesh/libgnunetmesh.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la
test_mesh_small_unicast_DEPENDENCIES = \
  libgnunetmesh.la

test_mesh_small_multicast_SOURCES = \
 test_mesh_small.c
test_mesh_small_multicast_LDADD = \
  $(top_builddir)/src/mesh/libgnunetmesh.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la
test_mesh_small_multicast_DEPENDENCIES = \
  libgnunetmesh.la

test_mesh_small_speed_SOURCES = \
 test_mesh_small.c
test_mesh_small_speed_LDADD = \
  $(top_builddir)/src/mesh/libgnunetmesh.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la
test_mesh_small_speed_DEPENDENCIES = \
  libgnunetmesh.la

test_mesh_small_speed_ack_SOURCES = \
 test_mesh_small.c
test_mesh_small_speed_ack_LDADD = \
  $(top_builddir)/src/mesh/libgnunetmesh.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la
test_mesh_small_speed_ack_DEPENDENCIES = \
  libgnunetmesh.la

if ENABLE_TEST_RUN
TESTS = test_mesh_api test_mesh_tree_api test_mesh_local_1 test_mesh_local_2 \
 test_mesh_2dtorus test_mesh_small_unicast test_mesh_small_multicast
endif

EXTRA_DIST = \
  test_mesh.conf \
  test_mesh_2dtorus.conf \
  test_mesh_small.conf \
  test_mesh_path.conf
