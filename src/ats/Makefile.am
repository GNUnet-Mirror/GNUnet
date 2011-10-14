INCLUDES = -I$(top_srcdir)/src/include

if MINGW
 WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols 
endif

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif

lib_LTLIBRARIES = libgnunetats.la

libgnunetats_la_SOURCES = \
  ats_api_scheduling.c \
  ats_api_performance.c 

libgnunetats_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la


bin_PROGRAMS = \
 gnunet-service-ats

gnunet_service_ats_SOURCES = \
 gnunet-service-ats.c \
 gnunet-service-ats_addresses.c gnunet-service-ats_addresses.h \
 gnunet-service-ats_performance.c gnunet-service-ats_performance.h \
 gnunet-service-ats_scheduling.c gnunet-service-ats_scheduling.h
gnunet_service_ats_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)


check_PROGRAMS = \
 test_ats_api_scheduling 
# test_ats_api_update_address

if ENABLE_TEST_RUN
TESTS = $(check_PROGRAMS)
endif

test_ats_api_scheduling_SOURCES = \
 test_ats_api_scheduling.c
test_ats_api_scheduling_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/ats/libgnunetats.la  

#test_ats_api_update_address_SOURCES = \
# test_ats_api_update_address.c
#test_ats_api_update_address_LDADD = \
#  $(top_builddir)/src/util/libgnunetutil.la \
#  $(top_builddir)/src/ats/libgnunetats.la  


EXTRA_DIST = \
  test_ats_api.conf

