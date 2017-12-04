# This Makefile.am is in the public domain
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

lib_LTLIBRARIES = \
  libgnunetidentityattribute.la

libgnunetidentityattribute_la_SOURCES = \
  identity_attribute.c
libgnunetidentityattribute_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)
libgnunetidentityattribute_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS) $(WINFLAGS) \
  -version-info 0:0:0


plugin_LTLIBRARIES = \
  libgnunet_plugin_identity_attribute_gnuid.la


libgnunet_plugin_identity_attribute_gnuid_la_SOURCES = \
  plugin_identity_attribute_gnuid.c
libgnunet_plugin_identity_attribute_gnuid_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(LTLIBINTL)
libgnunet_plugin_identity_attribute_gnuid_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)


