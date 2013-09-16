INCLUDES = -I$(top_srcdir)/src/include

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

pkgcfg_DATA = \
  scalarproduct.conf 

if MINGW
 WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols 
endif

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif

bin_PROGRAMS = \
 gnunet-scalarproduct

libexec_PROGRAMS = \
 gnunet-service-scalarproduct

lib_LTLIBRARIES = \
  libgnunetscalarproduct.la

gnunet_scalarproduct_SOURCES = \
  gnunet-scalarproduct.c
gnunet_scalarproduct_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/scalarproduct/libgnunetscalarproduct.la \
  -lgcrypt \
  $(GN_LIBINTL) 
gnunet_scalarproduct_DEPENDENCIES = \
  libgnunetscalarproduct.la

gnunet_service_scalarproduct_SOURCES = \
  gnunet-service-scalarproduct.c
gnunet_service_scalarproduct_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/mesh/libgnunetmesh.la \
  $(top_builddir)/src/set/libgnunetset.la \
  -lgcrypt \
  $(GN_LIBINTL)

libgnunetscalarproduct_la_SOURCES = \
  scalarproduct_api.c 
libgnunetscalarproduct_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  -lgcrypt \
  $(LTLIBINTL)
libgnunetscalarproduct_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)

#check_PROGRAMS = \
#	test_scalarproduct_api_regression \
#	test_scalarproduct_api \
#	test_scalarproduct_api_4peers
#FIXME unfinished
#test_scalarproduct_api_regression2 

if ENABLE_TEST_RUN
  TESTS = $(check_PROGRAMS)
endif

test_scalarproduct_api_SOURCES = \
  test_scalarproduct_api.c
test_scalarproduct_api_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/scalarproduct/libgnunetscalarproduct.la \
  -lgcrypt

#FIXME unfinished
#test_scalarproduct_api_regression2_SOURCES = \
#	test_scalarproduct_api_regression2.c
#test_scalarproduct_api_regression2_LDADD = \
#  $(top_builddir)/src/scalarproduct/libgnunetscalarproduct.la \
#  $(top_builddir)/src/util/libgnunetutil.la \
#  -lgcrypt

test_scalarproduct_api_regression_SOURCES = \
        test_scalarproduct_api_regression.c
test_scalarproduct_api_regression_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/scalarproduct/libgnunetscalarproduct.la \
  -lgcrypt

test_scalarproduct_api_4peers_SOURCES = \
 test_scalarproduct_api_4peers.c
test_scalarproduct_api_4peers_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/scalarproduct/libgnunetscalarproduct.la \
  -lgcrypt

EXTRA_DIST = \
  test_scalarproduct.conf

