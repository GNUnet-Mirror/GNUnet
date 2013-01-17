INCLUDES = -I$(top_srcdir)/src/include

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

pkgcfg_DATA = \
  consensus.conf

if MINGW
 WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols 
endif

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif

bin_PROGRAMS = \
 gnunet-consensus \
 gnunet-consensus-start-peers \
 gnunet-consensus-ibf

libexec_PROGRAMS = \
 gnunet-service-consensus

lib_LTLIBRARIES = \
  libgnunetconsensus.la

gnunet_consensus_SOURCES = \
 gnunet-consensus.c
gnunet_consensus_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/consensus/libgnunetconsensus.la \
  $(top_builddir)/src/testbed/libgnunettestbed.la \
  $(GN_LIBINTL)
gnunet_consensus_DEPENDENCIES = \
  libgnunetconsensus.la

gnunet_consensus_start_peers_SOURCES = \
 gnunet-consensus-start-peers.c
gnunet_consensus_start_peers_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testbed/libgnunettestbed.la \
  $(top_builddir)/src/consensus/libgnunetconsensus.la \
  $(GN_LIBINTL)
gnunet_consensus_start_peers_DEPENDENCIES = \
  libgnunetconsensus.la

gnunet_consensus_ibf_SOURCES = \
 gnunet-consensus-ibf.c \
 ibf.c
gnunet_consensus_ibf_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)

gnunet_service_consensus_SOURCES = \
 gnunet-service-consensus.c \
 ibf.c
gnunet_service_consensus_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/core/libgnunetcore.la \
  $(top_builddir)/src/stream/libgnunetstream.la \
  $(top_builddir)/src/mesh/libgnunetmesh.la \
  $(GN_LIBINTL)

libgnunetconsensus_la_SOURCES = \
  consensus_api.c
libgnunetconsensus_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(LTLIBINTL)
libgnunetconsensus_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)

check_PROGRAMS = \
 test_consensus_api

if ENABLE_TEST_RUN
TESTS = $(check_PROGRAMS)
endif

test_consensus_api_SOURCES = \
 test_consensus_api.c
test_consensus_api_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/consensus/libgnunetconsensus.la

EXTRA_DIST = \
  test_consensus.conf

