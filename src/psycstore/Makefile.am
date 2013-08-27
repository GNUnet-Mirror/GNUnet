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
  psycstore.conf


lib_LTLIBRARIES = libgnunetpsycstore.la

libgnunetpsycstore_la_SOURCES = \
  psycstore_api.c \
  psycstore.h
libgnunetpsycstore_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL) $(XLIB)
libgnunetpsycstore_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)  $(WINFLAGS) \
  -version-info 0:0:0
libgnunetpsycstore_la_DEPENDENCIES = \
  $(top_builddir)/src/util/libgnunetutil.la 

bin_PROGRAMS =

libexec_PROGRAMS = \
 gnunet-service-psycstore 

gnunet_service_psycstore_SOURCES = \
 gnunet-service-psycstore.c         
gnunet_service_psycstore_LDADD = \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)
gnunet_service_psycstore_DEPENDENCIES = \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la 

if HAVE_TESTING
check_PROGRAMS = \
 test_psycstore
endif

if ENABLE_TEST_RUN
TESTS = $(check_PROGRAMS) 
endif

test_psycstore_SOURCES = \
 test_psycstore.c
test_psycstore_LDADD = \
  libgnunetpsycstore.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la 
test_psycstore_DEPENDENCIES = \
  libgnunetpsycstore.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la 

EXTRA_DIST = \
  test_psycstore.conf 


