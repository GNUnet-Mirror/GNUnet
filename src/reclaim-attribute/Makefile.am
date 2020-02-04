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
  reclaim_attribute.c \
  reclaim_attestation.c
libgnunetreclaimattribute_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)
libgnunetreclaimattribute_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)  \
  -version-info 0:0:0


plugin_LTLIBRARIES = \
  libgnunet_plugin_reclaim_attribute_basic.la \
  libgnunet_plugin_reclaim_attestation_jwt.la


libgnunet_plugin_reclaim_attribute_basic_la_SOURCES = \
  plugin_reclaim_attribute_basic.c
libgnunet_plugin_reclaim_attribute_basic_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(LTLIBINTL)
libgnunet_plugin_reclaim_attribute_basic_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)

libgnunet_plugin_reclaim_attestation_jwt_la_SOURCES = \
  plugin_reclaim_attestation_jwt.c
libgnunet_plugin_reclaim_attestation_jwt_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(LTLIBINTL)
libgnunet_plugin_reclaim_attestation_jwt_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)

