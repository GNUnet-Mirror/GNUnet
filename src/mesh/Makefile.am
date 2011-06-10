INCLUDES = -I$(top_srcdir)/src/include

if MINGW
  WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

bin_PROGRAMS = \
 gnunet-service-mesh

lib_LTLIBRARIES = \
  libgnunetmesh.la \
  libgnunetmeshnew.la

libgnunetmesh_la_SOURCES = \
  mesh_api.c mesh_protocol.h
libgnunetmesh_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/core/libgnunetcore.la \
  $(GN_LIBINTL) $(XLIB)
libgnunetmesh_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS) $(WINFLAGS) \
  -version-info 0:0:0

gnunet_service_mesh_SOURCES = \
 gnunet-service-mesh.c

gnunet_service_mesh_LDADD = \
  $(top_builddir)/src/core/libgnunetcore.la\
  $(top_builddir)/src/dht/libgnunetdht.la \
  $(top_builddir)/src/util/libgnunetutil.la


libgnunetmeshnew_la_SOURCES = \
  mesh_api_new.c mesh.h
libgnunetmeshnew_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(XLIB)
libgnunetmeshnew_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS) $(WINFLAGS) \
  -version-info 0:0:0

check_PROGRAMS = \
 test_mesh_api

test_mesh_api_SOURCES = \
 test_mesh_api.c
test_mesh_api_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/mesh/libgnunetmeshnew.la \
 $(top_builddir)/src/dht/libgnunetdht.la
test_mesh_api_DEPENDENCIES = \
  libgnunetmeshnew.la

TESTS = test_mesh_api

EXTRA_DIST = \
  test_mesh.conf