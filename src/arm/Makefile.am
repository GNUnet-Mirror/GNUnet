INCLUDES = -I$(top_srcdir)/src/include

if MINGW
 WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols 
endif

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif

lib_LTLIBRARIES = libgnunetarm.la

libgnunetarm_la_SOURCES = \
  arm_api.c arm.h
libgnunetarm_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)
libgnunetarm_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)  $(WINFLAGS) \
  -version-info 0:0:0


bin_PROGRAMS = \
 gnunet-arm \
 gnunet-service-arm

gnunet_arm_SOURCES = \
 gnunet-arm.c         
gnunet_arm_LDADD = \
  $(top_builddir)/src/arm/libgnunetarm.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)

gnunet_service_arm_SOURCES = \
 gnunet-service-arm.c         
gnunet_service_arm_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)


check_PROGRAMS = \
 test_arm_api

check_SCRIPTS = \
 test_gnunet_arm.sh

TESTS = $(check_PROGRAMS) $(check_SCRIPTS)

test_arm_api_SOURCES = \
 test_arm_api.c
test_arm_api_LDADD = \
  $(top_builddir)/src/arm/libgnunetarm.la \
  $(top_builddir)/src/resolver/libgnunetresolver.la \
  $(top_builddir)/src/util/libgnunetutil.la  


EXTRA_DIST = \
  test_arm_api_data.conf
