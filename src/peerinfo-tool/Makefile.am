# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

REST_PLUGIN = libgnunet_plugin_rest_peerinfo.la

plugindir = $(libdir)/gnunet

plugin_LTLIBRARIES = $(REST_PLUGIN)

bin_PROGRAMS = \
 gnunet-peerinfo

libgnunet_plugin_rest_peerinfo_la_SOURCES = \
  plugin_rest_peerinfo.c
libgnunet_plugin_rest_peerinfo_la_LIBADD = \
  $(top_builddir)/src/hello/libgnunethello.la \
  $(top_builddir)/src/peerinfo/libgnunetpeerinfo.la \
  $(top_builddir)/src/transport/libgnunettransport.la \
  $(top_builddir)/src/rest/libgnunetrest.la \
  $(top_builddir)/src/json/libgnunetjson.la \
  $(top_builddir)/src/util/libgnunetutil.la $(XLIBS) \
  $(LTLIBINTL) -ljansson $(MHD_LIBS)
libgnunet_plugin_rest_peerinfo_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)
libgnunet_plugin_rest_peerinfo_la_CFLAGS = $(MHD_CFLAGS) $(AM_CFLAGS)


gnunet_peerinfo_SOURCES = \
 gnunet-peerinfo.c \
 gnunet-peerinfo_plugins.c gnunet-peerinfo_plugins.h
gnunet_peerinfo_LDADD = \
  $(top_builddir)/src/peerinfo/libgnunetpeerinfo.la \
  $(top_builddir)/src/transport/libgnunettransport.la \
  $(top_builddir)/src/hello/libgnunethello.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la
gnunet_peerinfo_LDFLAGS = \
  $(GN_LIBINTL)

if HAVE_PYTHON
check_SCRIPTS = \
 test_gnunet_peerinfo.py
endif

if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
TESTS = $(check_SCRIPTS)
endif

test_gnunet_peerinfo.py: test_gnunet_peerinfo.py.in Makefile
	$(AWK) -v bdir="$(bindir)" -v py="$(PYTHON)" -v awkay="$(AWK_BINARY)" -v pfx="$(prefix)" -v prl="$(PERL)" -v sysconfdirectory="$(sysconfdir)" -v pkgdatadirectory="$(pkgdatadir)" -f $(top_srcdir)/bin/dosubst.awk < $(srcdir)/test_gnunet_peerinfo.py.in > test_gnunet_peerinfo.py
	chmod +x test_gnunet_peerinfo.py

EXTRA_DIST = \
  test_gnunet_peerinfo.py.in \
  test_gnunet_peerinfo_data.conf

CLEANFILES = $(check_SCRIPTS)
