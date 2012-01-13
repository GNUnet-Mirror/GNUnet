INCLUDES = -I$(top_srcdir)/src/include

pkgcfgdir= $(pkgdatadir)/config.d/

pkgcfg_DATA = \
  arm.conf

if MINGW
 WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols 
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

lib_LTLIBRARIES = libgnunetarm.la

libgnunetarm_la_SOURCES = \
  arm_api.c arm.h
libgnunetarm_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL) $(XLIB)
libgnunetarm_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)  $(WINFLAGS) \
  -version-info 1:1:0


bin_PROGRAMS = \
 gnunet-arm \
 gnunet-service-arm \
 mockup-service 

gnunet_arm_SOURCES = \
 gnunet-arm.c         
gnunet_arm_LDADD = \
  $(top_builddir)/src/arm/libgnunetarm.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)
gnunet_arm_DEPENDENCIES = \
  libgnunetarm.la			  

gnunet_service_arm_SOURCES = \
 gnunet-service-arm.c 
gnunet_service_arm_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)
gnunet_service_arm_DEPENDENCIES = \
  libgnunetarm.la			  


mockup_service_SOURCES = \
  mockup-service.c
 mockup_service_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  


check_PROGRAMS = \
 test_arm_api \
 test_exponential_backoff \
 test_gnunet_service_manager

check_SCRIPTS = \
 test_gnunet_arm.sh

if ENABLE_TEST_RUN
TESTS = $(check_PROGRAMS)  $(check_SCRIPTS)
endif

test_arm_api_SOURCES = \
 test_arm_api.c
test_arm_api_LDADD = \
  $(top_builddir)/src/arm/libgnunetarm.la \
  $(top_builddir)/src/util/libgnunetutil.la  

test_exponential_backoff_SOURCES = \
 test_exponential_backoff.c
test_exponential_backoff_LDADD = \
  $(top_builddir)/src/arm/libgnunetarm.la \
  $(top_builddir)/src/util/libgnunetutil.la

test_gnunet_service_manager_SOURCES = \
 test_gnunet_service_manager.c
 test_gnunet_service_manager_LDADD = \
  $(top_builddir)/src/arm/libgnunetarm.la \
  $(top_builddir)/src/util/libgnunetutil.la  

EXTRA_DIST = \
  test_arm_api_data.conf \
  do_start_process.c \
  $(check_SCRIPTS) 
