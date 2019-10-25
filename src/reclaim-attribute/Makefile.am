# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

plugindir = $(libdir)/gnunet

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIBS = -lgcov
endif

lib_LTLIBRARIES = \
  libgnunetreclaimattribute.la

libgnunetreclaimattribute_la_SOURCES = \
  reclaim_attribute.h \
  reclaim_attribute.c
libgnunetreclaimattribute_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)
libgnunetreclaimattribute_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)  \
  -version-info 0:0:0


plugin_LTLIBRARIES = \
  libgnunet_plugin_reclaim_attribute_gnuid.la


libgnunet_plugin_reclaim_attribute_gnuid_la_SOURCES = \
  plugin_reclaim_attribute_gnuid.c
libgnunet_plugin_reclaim_attribute_gnuid_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(LTLIBINTL)
libgnunet_plugin_reclaim_attribute_gnuid_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)


