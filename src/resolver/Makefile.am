INCLUDES = -I$(top_srcdir)/src/include

if MINGW
 WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols 
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif


lib_LTLIBRARIES = libgnunetresolver.la

libgnunetresolver_la_SOURCES = \
  resolver_api.c resolver.h
libgnunetresolver_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL) $(XLIB)
libgnunetresolver_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)  $(WINFLAGS) \
  -version-info 0:0:0


bin_PROGRAMS = \
 gnunet-service-resolver

gnunet_service_resolver_SOURCES = \
 gnunet-service-resolver.c         
gnunet_service_resolver_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)


check_PROGRAMS = \
 test_resolver_api

TESTS = $(check_PROGRAMS)

test_resolver_api_SOURCES = \
 test_resolver_api.c
test_resolver_api_LDADD = \
  $(top_builddir)/src/resolver/libgnunetresolver.la  \
  $(top_builddir)/src/util/libgnunetutil.la  

EXTRA_DIST = \
  test_resolver_api_data.conf
