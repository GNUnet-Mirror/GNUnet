INCLUDES = -I$(top_srcdir)/src/include

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif


bin_PROGRAMS = \
 gnunet-daemon-topology

gnunet_daemon_topology_SOURCES = \
 gnunet-daemon-topology.c 
gnunet_daemon_topology_LDADD = \
  $(top_builddir)/src/core/libgnunetcore.la \
  $(top_builddir)/src/peerinfo/libgnunetpeerinfo.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)


