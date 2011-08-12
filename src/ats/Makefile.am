INCLUDES = -I$(top_srcdir)/src/include

if MINGW
 WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols 
endif

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif

lib_LTLIBRARIES = libgnunetats.la

libgnunetats_la_SOURCES = \
  ats_api.c


#bin_PROGRAMS = \
# gnunet-service-ats

#gnunet_service_ats_SOURCES = \
# gnunet-service-ats.c         
#gnunet_service_ats_LDADD = \
#  $(top_builddir)/src/util/libgnunetutil.la \
#  $(GN_LIBINTL)


#check_PROGRAMS = \
# test_ats_api

#if ENABLE_TEST_RUN
#TESTS = $(check_PROGRAMS)
#endif

#test_ats_api_SOURCES = \
# test_ats_api.c
#test_ats_api_LDADD = \
#  $(top_builddir)/src/util/libgnunetutil.la  

