# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
endif

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

dist_pkgcfg_DATA = \
  topology.conf


lib_LTLIBRARIES = libgnunetfriends.la

libgnunetfriends_la_SOURCES = \
  friends.c
libgnunetfriends_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL) $(XLIB)
libgnunetfriends_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)  $(WINFLAGS) \
  -version-info 0:0:0


libexec_PROGRAMS = \
 gnunet-daemon-topology

gnunet_daemon_topology_SOURCES = \
 gnunet-daemon-topology.c
gnunet_daemon_topology_LDADD = \
  libgnunetfriends.la \
  $(top_builddir)/src/core/libgnunetcore.la \
  $(top_builddir)/src/peerinfo/libgnunetpeerinfo.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/transport/libgnunettransport.la \
  $(top_builddir)/src/ats/libgnunetats.la \
  $(top_builddir)/src/hello/libgnunethello.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)


if HAVE_TESTING
check_PROGRAMS = \
 test_gnunet_daemon_topology
endif

if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;
TESTS = $(check_PROGRAMS)
endif

test_gnunet_daemon_topology_SOURCES = \
 test_gnunet_daemon_topology.c
test_gnunet_daemon_topology_LDADD = \
 $(top_builddir)/src/testbed/libgnunettestbed.la \
 $(top_builddir)/src/util/libgnunetutil.la

EXTRA_DIST = \
 test_gnunet_daemon_topology_data.conf
