INCLUDES = -I$(top_srcdir)/src/include

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
endif

pkgcfgdir= $(pkgdatadir)/config.d/

dist_pkgcfg_DATA = \
  topology.conf


bin_PROGRAMS = \
 gnunet-daemon-topology

gnunet_daemon_topology_SOURCES = \
 gnunet-daemon-topology.c 
gnunet_daemon_topology_LDADD = \
  $(top_builddir)/src/core/libgnunetcore.la \
  $(top_builddir)/src/peerinfo/libgnunetpeerinfo.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/transport/libgnunettransport.la \
  $(top_builddir)/src/hello/libgnunethello.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)



check_PROGRAMS = \
 test_gnunet_daemon_topology

if ENABLE_TEST_RUN
TESTS = $(check_PROGRAMS)
endif

test_gnunet_daemon_topology_SOURCES = \
 test_gnunet_daemon_topology.c
test_gnunet_daemon_topology_LDADD = \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/util/libgnunetutil.la  

EXTRA_DIST = \
 test_gnunet_daemon_topology_data.conf 
