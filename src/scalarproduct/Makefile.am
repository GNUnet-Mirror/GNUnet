INCLUDES = -I$(top_srcdir)/src/include

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

pkgcfg_DATA = \
  vectorproduct.conf 

if MINGW
 WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols 
endif

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif

bin_PROGRAMS = \
 gnunet-vectorproduct

libexec_PROGRAMS = \
 gnunet-service-vectorproduct

# FIXME: add option "configure --with-evil"?
#if HAVE_EXPERIMENTAL
#libexec_PROGRAMS += \
# gnunet-service-evil-consensus
#endif

lib_LTLIBRARIES = \
  libgnunetvectorproduct.la

gnunet_vectorproduct_SOURCES = \
  gnunet-vectorproduct.c
gnunet_vectorproduct_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/vectorproduct/libgnunetvectorproduct.la \
  -lgcrypt \
  $(GN_LIBINTL) 
gnunet_vectorproduct_DEPENDENCIES = \
  libgnunetvectorproduct.la

gnunet_service_vectorproduct_SOURCES = \
  gnunet-service-vectorproduct.c
gnunet_service_vectorproduct_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/core/libgnunetcore.la \
  $(top_builddir)/src/mesh/libgnunetmesh.la \
  $(top_builddir)/src/set/libgnunetset.la \
  -lgcrypt \
  $(GN_LIBINTL)

libgnunetvectorproduct_la_SOURCES = \
  vectorproduct_api.c 
libgnunetvectorproduct_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  -lgcrypt \
  $(LTLIBINTL)
libgnunetvectorproduct_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)

check_PROGRAMS = \
	test_vectorproduct_api_regression \
	test_vectorproduct_api \
	test_vectorproduct_api_4peers
#FIXME unfinished
#test_vectorproduct_api_regression2 

if ENABLE_TEST_RUN
  TESTS = $(check_PROGRAMS)
endif

test_consensus_api_SOURCES = \
 test_consensus_api.c
test_consensus_api_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/consensus/libgnunetconsensus.la

test_vectorproduct_api_SOURCES = \
  test_vectorproduct_api.c
test_vectorproduct_api_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/vectorproduct/libgnunetvectorproduct.la \
  -lgcrypt

#FIXME unfinished
#test_vectorproduct_api_regression2_SOURCES = \
#	test_vectorproduct_api_regression2.c
#test_vectorproduct_api_regression2_LDADD = \
#  $(top_builddir)/src/vectorproduct/libgnunetvectorproduct.la \
#  $(top_builddir)/src/util/libgnunetutil.la \
#  -lgcrypt

test_vectorproduct_api_regression_SOURCES = \
        test_vectorproduct_api_regression.c
test_vectorproduct_api_regression_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/vectorproduct/libgnunetvectorproduct.la \
  -lgcrypt

test_vectorproduct_api_4peers_SOURCES = \
 test_vectorproduct_api_4peers.c
test_vectorproduct_api_4peers_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/vectorproduct/libgnunetvectorproduct.la \
  -lgcrypt
 
EXTRA_DIST = \
  test_vectorproduct.conf
 
