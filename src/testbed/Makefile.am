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
  testbed.conf

lib_LTLIBRARIES = \
  libgnunettestbed.la

libgnunettestbed_la_SOURCES = \
  testbed_api.c testbed.h \
  testbed_api_hosts.c testbed_api_hosts.h \
  testbed_api_operations.c testbed_api_operations.h \
  testbed_api_peers.c testbed_api_peers.h \
  testbed_api_services.c \
  testbed_api_testbed.c \
  testbed_api_test.c \
  testbed_api_topology.c
libgnunettestbed_la_LIBADD = $(XLIB) \
 $(top_builddir)/src/core/libgnunetcore.la \
 $(top_builddir)/src/statistics/libgnunetstatistics.la \
 $(top_builddir)/src/transport/libgnunettransport.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 -lm \
 $(top_builddir)/src/util/libgnunetutil.la 
libgnunettestbed_la_LDFLAGS = \
 $(GN_LIB_LDFLAGS) \
 -version-info 0:0:0

