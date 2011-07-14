INCLUDES = -I$(top_srcdir)/src/include

if MINGW
 WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols 
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif


lib_LTLIBRARIES = libgnunetnse.la

libgnunetnse_la_SOURCES = \
  nse_api.c nse.h
libgnunetnse_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL) $(XLIB)
libgnunetnse_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)  $(WINFLAGS) \
  -version-info 0:0:0


bin_PROGRAMS = \
 gnunet-service-nse

# gnunet_nse_SOURCES = \
# gnunet-nse.c         
# gnunet_nse_LDADD = \
#  $(top_builddir)/src/nse/libgnunetnse.la \
#  $(top_builddir)/src/util/libgnunetutil.la \
#  $(GN_LIBINTL)
# gnunet_nse_DEPENDENCIES = \
#  libgnunetnse.la				 

gnunet_service_nse_SOURCES = \
 gnunet-service-nse.c         
gnunet_service_nse_LDADD = \
  $(top_builddir)/src/nse/libgnunetnse.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/core/libgnunetcore.la \
  -lm \
  $(GN_LIBINTL)
gnunet_service_nse_DEPENDENCIES = \
  libgnunetnse.la				 

check_PROGRAMS = \
 test_nse_api

if ENABLE_TEST_RUN
TESTS = $(check_PROGRAMS) $(check_SCRIPTS)
endif

test_nse_api_SOURCES = \
 test_nse_api.c
test_nse_api_LDADD = \
  $(top_builddir)/src/nse/libgnunetnse.la \
  $(top_builddir)/src/util/libgnunetutil.la 


EXTRA_DIST = \
  test_nse_api_data.conf \
  $(check_SCRIPTS) 


