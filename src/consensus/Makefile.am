# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

plugindir = $(libdir)/gnunet

pkgcfg_DATA = \
  consensus.conf

if MINGW
 WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols
endif

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif

bin_PROGRAMS = \
 gnunet-consensus-profiler

libexec_PROGRAMS = \
 gnunet-service-consensus

if ENABLE_MALICIOUS
libexec_PROGRAMS += \
 gnunet-service-evil-consensus
endif

lib_LTLIBRARIES = \
  libgnunetconsensus.la

gnunet_consensus_profiler_SOURCES = \
 gnunet-consensus-profiler.c
gnunet_consensus_profiler_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  libgnunetconsensus.la \
  $(top_builddir)/src/testbed/libgnunettestbed.la \
  $(GN_LIBINTL)

gnunet_service_consensus_SOURCES = \
 gnunet-service-consensus.c
gnunet_service_consensus_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/core/libgnunetcore.la \
  $(top_builddir)/src/set/libgnunetset.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(GN_LIBINTL)

gnunet_service_evil_consensus_SOURCES = \
 gnunet-service-consensus.c \
 consensus_protocol.h
gnunet_service_evil_consensus_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/core/libgnunetcore.la \
  $(top_builddir)/src/set/libgnunetset.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(GN_LIBINTL)
gnunet_service_evil_consensus_CFLAGS = -DEVIL

libgnunetconsensus_la_SOURCES = \
  consensus_api.c \
  consensus.h
libgnunetconsensus_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(LTLIBINTL)
libgnunetconsensus_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)


plugin_LTLIBRARIES = \
  libgnunet_plugin_block_consensus.la

libgnunet_plugin_block_consensus_la_SOURCES = \
  plugin_block_consensus.c
libgnunet_plugin_block_consensus_la_LIBADD = \
  $(top_builddir)/src/block/libgnunetblock.la \
  $(top_builddir)/src/block/libgnunetblockgroup.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(LTLIBINTL)
libgnunet_plugin_block_consensus_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)



if HAVE_TESTING
check_PROGRAMS = \
 test_consensus_api

if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
TESTS = $(check_PROGRAMS)
endif
endif

test_consensus_api_SOURCES = \
 test_consensus_api.c
test_consensus_api_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  libgnunetconsensus.la

EXTRA_DIST = \
  test_consensus.conf
