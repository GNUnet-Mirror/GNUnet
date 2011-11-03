INCLUDES = -I$(top_srcdir)/src/include

pkgcfgdir= $(pkgdatadir)/config.d/

dist_pkgcfg_DATA = \
  template.conf

if MINGW
 WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols 
endif

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif

bin_PROGRAMS = \
 gnunet-template \
 gnunet-service-template

gnunet_template_SOURCES = \
 gnunet-template.c         
gnunet_template_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)

gnunet_service_template_SOURCES = \
 gnunet-service-template.c         
gnunet_service_template_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)


check_PROGRAMS = \
 test_template_api

if ENABLE_TEST_RUN
TESTS = $(check_PROGRAMS)
endif

test_template_api_SOURCES = \
 test_template_api.c
test_template_api_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la  

