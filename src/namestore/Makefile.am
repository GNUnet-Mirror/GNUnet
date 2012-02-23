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
 $(SQLITE_TESTS) 

if HAVE_EXPERIMENTAL
check_PROGRAMS += test_namestore_api
endif

if HAVE_EXPERIMENTAL
lib_LTLIBRARIES = \
  libgnunetnamestore.la
endif

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
 gnunet-service-namestore.c 
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
 test_namestore_api.c
test_namestore_api_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la

EXTRADIST = \
  test_namestore_api.conf \
  test_plugin_namestore_sqlite.conf


test_plugin_namestore_sqlite_SOURCES = \
 test_plugin_namestore.c
test_plugin_namestore_sqlite_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  
