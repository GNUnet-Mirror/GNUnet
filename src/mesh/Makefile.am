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
  mesh.conf

plugindir = $(libdir)/gnunet

AM_CLFAGS = -g

libexec_PROGRAMS = \
 gnunet-service-mesh $(EXP_LIBEXEC)

bin_PROGRAMS = \
 gnunet-mesh

lib_LTLIBRARIES = \
  libgnunetmesh.la $(EXP_LIB)

libgnunetmesh_la_SOURCES = \
  mesh_api.c mesh_common.c
libgnunetmesh_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(XLIB) \
  $(LTLIBINTL)
libgnunetmesh_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS) $(WINFLAGS) \
  -version-info 4:0:0

gnunet_mesh_SOURCES = \
  gnunet-mesh.c
gnunet_mesh_LDADD = \
  $(top_builddir)/src/mesh/libgnunetmesh.la \
  $(top_builddir)/src/util/libgnunetutil.la
gnunet_mesh_DEPENDENCIES = \
  libgnunetmesh.la

gnunet_service_mesh_SOURCES = \
 gnunet-service-mesh_tunnel.c gnunet-service-mesh_tunnel.h \
 gnunet-service-mesh_connection.c gnunet-service-mesh_connection.h \
 gnunet-service-mesh_channel.c gnunet-service-mesh_channel.h \
 gnunet-service-mesh_local.c gnunet-service-mesh_local.h \
 gnunet-service-mesh_peer.c gnunet-service-mesh_peer.h \
 gnunet-service-mesh_dht.c gnunet-service-mesh_dht.h \
 gnunet-service-mesh_hello.c gnunet-service-mesh_hello.h \
 mesh_path.c mesh_path.h \
 mesh_common.c \
 gnunet-service-mesh.c
gnunet_service_mesh_CFLAGS = $(AM_CFLAGS)
gnunet_service_mesh_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/transport/libgnunettransport.la \
  $(top_builddir)/src/core/libgnunetcore.la \
  $(top_builddir)/src/dht/libgnunetdht.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/peerinfo/libgnunetpeerinfo.la \
  $(top_builddir)/src/hello/libgnunethello.la \
  $(top_builddir)/src/block/libgnunetblock.la
gnunet_service_mesh_DEPENDENCIES = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/transport/libgnunettransport.la \
  $(top_builddir)/src/core/libgnunetcore.la \
  $(top_builddir)/src/dht/libgnunetdht.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/peerinfo/libgnunetpeerinfo.la \
  $(top_builddir)/src/hello/libgnunethello.la \
  $(top_builddir)/src/block/libgnunetblock.la
if LINUX
  gnunet_service_mesh_LDFLAGS = -lrt
endif


if HAVE_TESTING
 noinst_LIBRARIES = libgnunetmeshtest.a $(noinst_LIB_EXP)
 noinst_PROGRAMS = gnunet-mesh-profiler
endif

libgnunetmeshtest_a_SOURCES = \
  mesh_test_lib.c mesh_test_lib.h
libgnunetmeshtest_a_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/testbed/libgnunettestbed.la \
 $(top_builddir)/src/mesh/libgnunetmesh.la
libgnunetmeshtest_a_DEPENDENCIES = \
  libgnunetmesh.la

if HAVE_TESTING
check_PROGRAMS = \
  test_mesh_single \
  test_mesh_local \
  test_mesh_small_forward \
  test_mesh_small_signal \
  test_mesh_small_keepalive \
  test_mesh_small_speed \
  test_mesh_small_speed_ack \
  test_mesh_small_speed_backwards \
  test_mesh_small_speed_reliable \
  test_mesh_small_speed_reliable_backwards
endif

ld_mesh_test_lib = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/mesh/libgnunetmeshtest.a \
  $(top_builddir)/src/mesh/libgnunetmesh.la \
  $(top_builddir)/src/testbed/libgnunettestbed.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la

dep_mesh_test_lib = \
  libgnunetmesh.la \
  libgnunetmeshtest.a \
  $(top_builddir)/src/statistics/libgnunetstatistics.la


gnunet_mesh_profiler_SOURCES = \
  gnunet-mesh-profiler.c
gnunet_mesh_profiler_LDADD = $(ld_mesh_test_lib)
gnunet_mesh_profiler_DEPENDENCIES = $(dep_mesh_test_lib)


test_mesh_single_SOURCES = \
  test_mesh_single.c
test_mesh_single_LDADD = $(ld_mesh_test_lib)
test_mesh_single_DEPENDENCIES = $(dep_mesh_test_lib)

test_mesh_local_SOURCES = \
  test_mesh_local.c
test_mesh_local_LDADD = $(ld_mesh_test_lib)
test_mesh_local_DEPENDENCIES = $(dep_mesh_test_lib)

test_mesh_small_forward_SOURCES = \
  test_mesh_small.c
test_mesh_small_forward_LDADD = $(ld_mesh_test_lib)
test_mesh_small_forward_DEPENDENCIES = $(dep_mesh_test_lib)

test_mesh_small_signal_SOURCES = \
  test_mesh_small.c
test_mesh_small_signal_LDADD = $(ld_mesh_test_lib)
test_mesh_small_signal_DEPENDENCIES = $(dep_mesh_test_lib)

test_mesh_small_keepalive_SOURCES = \
  test_mesh_small.c
test_mesh_small_keepalive_LDADD = $(ld_mesh_test_lib)
test_mesh_small_keepalive_DEPENDENCIES = $(dep_mesh_test_lib)

test_mesh_small_speed_SOURCES = \
  test_mesh_small.c
test_mesh_small_speed_LDADD = $(ld_mesh_test_lib)
test_mesh_small_speed_DEPENDENCIES = $(dep_mesh_test_lib)

test_mesh_small_speed_ack_SOURCES = \
  test_mesh_small.c
test_mesh_small_speed_ack_LDADD = $(ld_mesh_test_lib)
test_mesh_small_speed_ack_DEPENDENCIES = $(dep_mesh_test_lib)

test_mesh_small_speed_backwards_SOURCES = \
  test_mesh_small.c
test_mesh_small_speed_backwards_LDADD = $(ld_mesh_test_lib)
test_mesh_small_speed_backwards_DEPENDENCIES = $(dep_mesh_test_lib)

test_mesh_small_speed_reliable_SOURCES = \
  test_mesh_small.c
test_mesh_small_speed_reliable_LDADD = $(ld_mesh_test_lib)
test_mesh_small_speed_reliable_DEPENDENCIES = $(dep_mesh_test_lib)

test_mesh_small_speed_reliable_backwards_SOURCES = \
  test_mesh_small.c
test_mesh_small_speed_reliable_backwards_LDADD = $(ld_mesh_test_lib)
test_mesh_small_speed_reliable_backwards_DEPENDENCIES = $(dep_mesh_test_lib)


if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;
TESTS = \
 $(check_PROGRAMS)
endif

EXTRA_DIST = \
  mesh.h mesh_protocol.h \
  test_mesh.conf \
  test_mesh_drop.conf

