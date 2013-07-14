INCLUDES = -I$(top_srcdir)/src/include

if MINGW
 WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols 
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

pkgcfg_DATA = \
  identity.conf


lib_LTLIBRARIES = libgnunetidentity.la

libgnunetidentity_la_SOURCES = \
  identity_api.c identity.h
libgnunetidentity_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL) $(XLIB)
libgnunetidentity_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)  $(WINFLAGS) \
  -version-info 0:0:0

bin_PROGRAMS = \
 gnunet-identity

libexec_PROGRAMS = \
 gnunet-service-identity 

gnunet_service_identity_SOURCES = \
 gnunet-service-identity.c         
gnunet_service_identity_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(GN_LIBINTL)
gnunet_service_identity_DEPENDENCIES = \
  libgnunetidentity.la				 

gnunet_identity_SOURCES = \
 gnunet-identity.c         
gnunet_identity_LDADD = \
  $(top_builddir)/src/identity/libgnunetidentity.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(GN_LIBINTL)
gnunet_service_identity_DEPENDENCIES = \
  libgnunetidentity.la				 


if HAVE_TESTING
check_PROGRAMS = \
 test_identity_api 
endif

if ENABLE_TEST_RUN
TESTS = $(check_PROGRAMS) 
endif

test_identity_api_SOURCES = \
 test_identity_api.c
test_identity_api_LDADD = \
  $(top_builddir)/src/identity/libgnunetidentity.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la 


EXTRA_DIST = \
  test_identity.conf 


