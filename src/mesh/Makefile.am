INCLUDES = -I$(top_srcdir)/src/include

if MINGW
  WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

AM_CLFAGS = -g

bin_PROGRAMS = \
 gnunet-service-mesh

lib_LTLIBRARIES = \
  libgnunetmesh.la

gnunet_service_mesh_SOURCES = \
 gnunet-service-mesh.c mesh_tunnel_tree.c
gnunet_service_mesh_LDADD = \
  $(top_builddir)/src/core/libgnunetcore.la\
  $(top_builddir)/src/dht/libgnunetdht.la \
  $(top_builddir)/src/util/libgnunetutil.la
 gnunet_service_mesh_DEPENDENCIES = \
  $(top_builddir)/src/core/libgnunetcore.la\
  $(top_builddir)/src/dht/libgnunetdht.la \
  $(top_builddir)/src/util/libgnunetutil.la

libgnunetmesh_la_SOURCES = \
  mesh_api.c mesh.h
libgnunetmesh_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(XLIB)
libgnunetmesh_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS) $(WINFLAGS) \
  -version-info 0:0:0

check_PROGRAMS = \
 test_mesh_api \
 test_mesh_path_api \
 test_mesh_local_1 \
 test_mesh_local_2 \
 test_mesh_small_unicast \
 test_mesh_small_unicast_far \
 test_mesh_small_multicast

test_mesh_api_SOURCES = \
 test_mesh_api.c
test_mesh_api_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/mesh/libgnunetmesh.la
test_mesh_api_DEPENDENCIES = \
  libgnunetmesh.la \
   $(top_builddir)/src/util/libgnunetutil.la

test_mesh_path_api_SOURCES = \
 test_mesh_path_api.c mesh_tunnel_tree.c
test_mesh_path_api_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/dht/libgnunetdht.la
test_mesh_path_api_DEPENDENCIES = \
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

test_mesh_small_unicast_SOURCES = \
 test_mesh_small.c
test_mesh_small_unicast_LDADD = \
  $(top_builddir)/src/mesh/libgnunetmesh.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la
test_mesh_small_unicast_DEPENDENCIES = \
  libgnunetmesh.la

test_mesh_small_unicast_far_SOURCES = \
 test_mesh_small.c
test_mesh_small_unicast_far_LDADD = \
  $(top_builddir)/src/mesh/libgnunetmesh.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la
test_mesh_small_unicast_far_DEPENDENCIES = \
  libgnunetmesh.la

test_mesh_small_multicast_SOURCES = \
 test_mesh_small.c
test_mesh_small_multicast_LDADD = \
  $(top_builddir)/src/mesh/libgnunetmesh.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la
test_mesh_small_multicast_DEPENDENCIES = \
  libgnunetmesh.la


if ENABLE_TEST_RUN
TESTS = test_0 test_mesh_api test_mesh_path_api test_mesh_local_1 test_mesh_local_2 test_1 test_mesh_small_unicast
endif

EXTRA_DIST = \
  test_mesh.conf \
  test_mesh_path.conf \
  test_mesh_small.conf