INCLUDES = -I$(top_srcdir)/src/include

plugindir = $(libdir)/gnunet

if MINGW
  WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIBS = -lgcov
endif


lib_LTLIBRARIES = \
  libgnunetdatacache.la

libgnunetdatacache_la_SOURCES = \
  datacache.c plugin_datacache.h
libgnunetdatacache_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL) 
libgnunetdatacache_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS) $(WINFLAGS) \
  -version-info 0:0:0


plugin_LTLIBRARIES = \
  libgnunet_plugin_datacache_sqlite.la \
  libgnunet_plugin_datacache_template.la 


libgnunet_plugin_datacache_sqlite_la_SOURCES = \
  plugin_datacache_sqlite.c
libgnunet_plugin_datacache_sqlite_la_LIBADD = \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la $(XLIBS) -lsqlite3
libgnunet_plugin_datacache_sqlite_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)

libgnunet_plugin_datacache_template_la_SOURCES = \
  plugin_datacache_template.c
libgnunet_plugin_datacache_template_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la $(XLIBS)
libgnunet_plugin_datacache_template_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)


check_PROGRAMS = \
 test_datacache \
 test_datacache_quota \
 perf_datacache 

TESTS = $(check_PROGRAMS)

test_datacache_SOURCES = \
 test_datacache.c
test_datacache_LDADD = \
 $(top_builddir)/src/datacache/libgnunetdatacache.la \
 $(top_builddir)/src/util/libgnunetutil.la  

test_datacache_quota_SOURCES = \
 test_datacache_quota.c
test_datacache_quota_LDADD = \
 $(top_builddir)/src/datacache/libgnunetdatacache.la \
 $(top_builddir)/src/util/libgnunetutil.la  

perf_datacache_SOURCES = \
 perf_datacache.c
perf_datacache_LDADD = \
 $(top_builddir)/src/datacache/libgnunetdatacache.la \
 $(top_builddir)/src/util/libgnunetutil.la  

EXTRA_DIST = \
 test_datacache_data.conf \
 perf_datacache_data.conf
