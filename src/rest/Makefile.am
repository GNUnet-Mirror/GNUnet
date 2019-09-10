# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

plugindir = $(libdir)/gnunet

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

pkgcfg_DATA = \
   rest.conf

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIBS = -lgcov
endif

lib_LTLIBRARIES = \
  libgnunetrest.la 

libexec_PROGRAMS = \
  gnunet-rest-server

plugin_LTLIBRARIES = \
  libgnunet_plugin_rest_copying.la \
  libgnunet_plugin_rest_config.la

EXTRA_DIST = \
 rest.conf

libgnunet_plugin_rest_copying_la_SOURCES = \
  plugin_rest_copying.c
libgnunet_plugin_rest_copying_la_LIBADD = \
  libgnunetrest.la \
  $(top_builddir)/src/util/libgnunetutil.la $(XLIBS) \
  $(LTLIBINTL) $(MHD_LIBS)
libgnunet_plugin_rest_copying_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)
libgnunet_plugin_rest_copying_la_CFLAGS = $(MHD_CFLAGS) $(AM_CFLAGS)

libgnunet_plugin_rest_config_la_SOURCES = \
  plugin_rest_config.c
libgnunet_plugin_rest_config_la_LIBADD = \
  libgnunetrest.la \
  $(top_builddir)/src/util/libgnunetutil.la $(XLIBS) \
  $(LTLIBINTL) $(MHD_LIBS) -ljansson
libgnunet_plugin_rest_config_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)
libgnunet_plugin_rest_config_la_CFLAGS = $(MHD_CFLAGS) $(AM_CFLAGS)



gnunet_rest_server_SOURCES = \
 gnunet-rest-server.c
gnunet_rest_server_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL) $(MHD_LIBS)
gnunet_rest_server_CFLAGS = $(MHD_CFLAGS) $(AM_CFLAGS)

libgnunetrest_la_SOURCES = \
  rest.c
libgnunetrest_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la $(XLIB) \
  $(GN_LIBINTL) $(MHD_LIBS)
libgnunetrest_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS) \
  -version-info 0:0:0
libgnunetrest_la_CFLAGS = $(MHD_CFLAGS) $(AM_CFLAGS)
