INCLUDES = -I$(top_srcdir)/src/include

plugindir = $(libdir)/gnunet

pkgcfgdir= $(pkgnamedir)/config.d/

pkgcfg_NAME = \
  namestore.conf

if MINGW
  WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIBS = -lgcov
endif

if HAVE_SQLITE
SQLITE_TESTS = \
 test_plugin_namestore_sqlite 
endif


check_PROGRAMS = \
 $(SQLITE_TESTS) \
 test_namestore_api \
 test_namestore_api_zone_iteration \
 test_namestore_record_serialization

if HAVE_EXPERIMENTAL
 check_PROGRAMS
endif

lib_LTLIBRARIES = \
  libgnunetnamestore.la
  
libgnunetnamestore_la_SOURCES = \
  namestore_api.c namestore.h
libgnunetnamestore_la_LIBADD = \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL) 
libgnunetnamestore_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS) $(WINFLAGS) \
  -version-info 0:0:0

bin_PROGRAMS = \
 gnunet-service-namestore

gnunet_service_namestore_SOURCES = \
 gnunet-service-namestore.c \
 namestore_common.c
gnunet_service_namestore_LDADD = \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)

if HAVE_SQLITE
 SQLITE_PLUGIN = libgnunet_plugin_namestore_sqlite.la
endif

plugin_LTLIBRARIES = \
  $(SQLITE_PLUGIN) 

libgnunet_plugin_namestore_sqlite_la_SOURCES = \
  plugin_namestore_sqlite.c
libgnunet_plugin_namestore_sqlite_la_LIBADD = \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la $(XLIBS) -lsqlite3
libgnunet_plugin_namestore_sqlite_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)


test_namestore_api_SOURCES = \
 test_namestore_api.c \
 namestore_common.c
test_namestore_api_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la
  
test_namestore_api_zone_iteration_SOURCES = \
 test_namestore_api_zone_iteration.c \
 namestore_common.c
test_namestore_api_zone_iteration_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la  

test_namestore_record_serialization_SOURCES = \
 test_namestore_record_serialization.c \
 namestore_common.c
test_namestore_record_serialization_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la  

EXTRA_DIST = \
  test_namestore_api.conf \
  test_plugin_namestore_sqlite.conf\
  hostkey


test_plugin_namestore_sqlite_SOURCES = \
 test_plugin_namestore.c
test_plugin_namestore_sqlite_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  
