AM_CPPFLAGS = -I$(top_srcdir)/src/include

plugindir = $(libdir)/gnunet

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

if MINGW
  WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIBS = -lgcov
endif

if ENABLE_TEST_RUN
TESTS = \
  $(check_PROGRAMS) \
  $(check_SCRIPTS)
endif

lib_LTLIBRARIES = \
  libgnunetgnsrecord.la

libgnunetgnsrecord_la_SOURCES = \
  gnsrecord.c
libgnunetgnsrecord_la_LIBADD = \
  $(top_builddir)/src/dns/libgnunetdnsparser.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)
libgnunetgnsrecord_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS) $(WINFLAGS) \
  -version-info 0:0:0


plugin_LTLIBRARIES = \
  libgnunet_plugin_gnsrecord_dns.la


libgnunet_plugin_gnsrecord_dns_la_SOURCES = \
  plugin_gnsrecord_dns.c
libgnunet_plugin_gnsrecord_dns_la_LIBADD = \
  $(top_builddir)/src/dns/libgnunetdnsparser.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(LTLIBINTL)
libgnunet_plugin_gnsrecord_dns_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)


EXTRA_DIST = \
  $(check_SCRIPTS)

