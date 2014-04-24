AM_CPPFLAGS = -I$(top_srcdir)/src/include

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

dist_pkgcfg_DATA = \
  peerstore.conf

if MINGW
 WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols 
endif

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif

bin_PROGRAMS = \
 gnunet-peerstore 

libexec_PROGRAMS = \
 gnunet-service-peerstore

lib_LTLIBRARIES = \
 libgnunetpeerstore.la

gnunet_peerstore_SOURCES = \
 gnunet-peerstore.c         
gnunet_peerstore_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  libgnunetpeerstore.la \
  $(GN_LIBINTL)

gnunet_service_peerstore_SOURCES = \
 gnunet-service-peerstore.c         
gnunet_service_peerstore_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)

libgnunetpeerstore_la_SOURCES = \
  peerstore_api.c 
libgnunetpeerstore_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la
libgnunetpeerstore_la_LDFLAGS = \
  $(GNUNET_LDFLAGS)

check_PROGRAMS = \
 test_peerstore_api

if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;
TESTS = $(check_PROGRAMS)
endif

test_peerstore_api_SOURCES = \
 test_peerstore_api.c
test_peerstore_api_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la  

