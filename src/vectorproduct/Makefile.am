SUBDIRS = .

INCLUDES = \
  -I$(top_srcdir)/src/include \
  -I$(top_srcdir)

AM_CPPFLAGS = \
  $(GNUNET_CPPFLAGS)

# Set this variable if you are using GNUNET libraries for all programs and
# libraries. You don't then need to target-specific _LDFLAGS with GNUNET_LDFLAGS
# AM_LDFLAGS = \
#   $(GNUNET_LDFLAGS) \
#   $(WINFLAGS) \
#   -export-dynamic

lib_LTLIBRARIES = libgnunetvectorproduct.la

pkgcfgdir= $(prefix)/share/gnunet/config.d/

libexecdir= $(prefix)/lib/gnunet/libexec/

libgnunetvectorproduct_la_SOURCES = \
  vectorproduct_api.c 
libgnunetvectorproduct_la_LIBADD = \
  -lgnunetutil -lgcrypt -lgnunetstatistics
libgnunetvectorproduct_la_LDFLAGS = \
  $(GNUNET_LDFLAGS)  $(WINFLAGS) \
  -version-info 0:0:0


bin_PROGRAMS = gnunet-vectorproduct 

libexec_PROGRAMS = gnunet-service-vectorproduct

check_PROGRAMS = \
	test_vectorproduct_api_regression \
	test_vectorproduct_api \
	test_vectorproduct_api_4peers
#FIXME unfinished
#test_vectorproduct_api_regression2 

TESTS = $(check_PROGRAMS)

gnunet_service_vectorproduct_SOURCES = \
  gnunet-service-vectorproduct.c
gnunet_service_vectorproduct_LDADD = \
  -lgnunetutil -lgnunettransport -lgnunetcore -lgnunetmesh -lgnunetdht -lgcrypt \
  $(INTLLIBS) 
gnunet_service_vectorproduct_LDFLAGS = \
  $(GNUNET_LDFLAGS)  $(WINFLAGS) -export-dynamic 

gnunet_vectorproduct_SOURCES = \
  gnunet-vectorproduct.c
gnunet_vectorproduct_LDADD = \
  $(top_builddir)/src/vectorproduct/libgnunetvectorproduct.la \
  -lgnunetutil -lgcrypt \
  $(INTLLIBS) 
gnunet_vectorproduct_LDFLAGS = \
 $(GNUNET_LDFLAGS) $(WINFLAGS) -export-dynamic 


test_vectorproduct_api_SOURCES = \
  test_vectorproduct_api.c
test_vectorproduct_api_LDADD = \
  $(top_builddir)/src/vectorproduct/libgnunetvectorproduct.la \
  -lgnunetutil -lgcrypt -lgnunetstatistics -lgnunettestbed
test_vectorproduct_api_LDFLAGS = \
 $(GNUNET_LDFLAGS)  $(WINFLAGS) -export-dynamic

#FIXME unfinished
#test_vectorproduct_api_regression2_SOURCES = \
#	test_vectorproduct_api_regression2.c
#test_vectorproduct_api_regression2_LDADD = \
#  $(top_builddir)/src/vectorproduct/libgnunetvectorproduct.la \
#  -lgnunetutil -lgcrypt -lgnunetstatistics -lgnunettestbed
#test_vectorproduct_api_regression2_LDFLAGS = \
# $(GNUNET_LDFLAGS)  $(WINFLAGS) -export-dynamic

test_vectorproduct_api_regression_SOURCES = \
        test_vectorproduct_api_regression.c
test_vectorproduct_api_regression_LDADD = \
  $(top_builddir)/src/vectorproduct/libgnunetvectorproduct.la \
  -lgnunetutil -lgcrypt -lgnunetstatistics -lgnunettestbed
test_vectorproduct_api_regression_LDFLAGS = \
 $(GNUNET_LDFLAGS)  $(WINFLAGS) -export-dynamic

test_vectorproduct_api_4peers_SOURCES = \
 test_vectorproduct_api_4peers.c
test_vectorproduct_api_4peers_LDADD = \
  $(top_builddir)/src/vectorproduct/libgnunetvectorproduct.la \
  -lgnunetutil -lgcrypt -lgnunetstatistics -lgnunettestbed
test_vectorproduct_api_4peers_LDFLAGS = \
 $(GNUNET_LDFLAGS)  $(WINFLAGS) -export-dynamic
 
 pkgcfg_DATA = vectorproduct.conf 
 
