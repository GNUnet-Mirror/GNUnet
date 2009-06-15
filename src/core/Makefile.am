INCLUDES = -I$(top_srcdir)/src/include

if MINGW
  WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif


lib_LTLIBRARIES = \
  libgnunetcore.la

libgnunetcore_la_SOURCES = \
  core_api.c core.h
libgnunetcore_la_LIBADD = \
  $(top_builddir)/src/arm/libgnunetarm.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL) $(XLIB)
libgnunetcore_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS) $(WINFLAGS) \
  -version-info 0:0:0


bin_PROGRAMS = \
 gnunet-service-core

gnunet_service_core_SOURCES = \
 gnunet-service-core.c 
gnunet_service_core_LDADD = \
  $(top_builddir)/src/hello/libgnunethello.la \
  $(top_builddir)/src/peerinfo/libgnunetpeerinfo.la \
  $(top_builddir)/src/transport/libgnunettransport.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)


check_PROGRAMS = \
 test_core_api_start_only \
 test_core_api 

TESTS = $(check_PROGRAMS)

test_core_api_SOURCES = \
 test_core_api.c
test_core_api_LDADD = \
 $(top_builddir)/src/arm/libgnunetarm.la \
 $(top_builddir)/src/core/libgnunetcore.la \
 $(top_builddir)/src/transport/libgnunettransport.la \
 $(top_builddir)/src/util/libgnunetutil.la  


test_core_api_start_only_SOURCES = \
 test_core_api_start_only.c
test_core_api_start_only_LDADD = \
 $(top_builddir)/src/arm/libgnunetarm.la \
 $(top_builddir)/src/core/libgnunetcore.la \
 $(top_builddir)/src/util/libgnunetutil.la  


EXTRA_DIST = \
  test_core_api_data.conf \
  test_core_api_peer1.conf \
  test_core_api_peer2.conf 

