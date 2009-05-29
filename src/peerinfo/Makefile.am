INCLUDES = -I$(top_srcdir)/src/include

if MINGW
 WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols -lole32 -lshell32 -luuid -liconv -lstdc++ -lcomdlg32 -lgdi32
endif

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif

lib_LTLIBRARIES = libgnunetpeerinfo.la

libgnunetpeerinfo_la_SOURCES = \
  peerinfo_api.c peerinfo.h
libgnunetpeerinfo_la_LIBADD = \
  $(top_builddir)/src/hello/libgnunethello.la \
  $(top_builddir)/src/util/libgnunetutil.la 
libgnunetpeerinfo_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS) $(WINFLAGS) \
  -version-info 0:0:0


bin_PROGRAMS = \
 gnunet-peerinfo \
 gnunet-service-peerinfo

gnunet_peerinfo_SOURCES = \
 gnunet-peerinfo.c         
gnunet_peerinfo_LDADD = \
  $(top_builddir)/src/peerinfo/libgnunetpeerinfo.la \
  $(top_builddir)/src/util/libgnunetutil.la 

gnunet_service_peerinfo_SOURCES = \
 gnunet-service-peerinfo.c         
gnunet_service_peerinfo_LDADD = \
  $(top_builddir)/src/hello/libgnunethello.la \
  $(top_builddir)/src/util/libgnunetutil.la 


check_PROGRAMS = \
 test_peerinfo_api

TESTS = $(check_PROGRAMS) # $(check_SCRIPTS)

test_peerinfo_api_SOURCES = \
 test_peerinfo_api.c
test_peerinfo_api_LDADD = \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/peerinfo/libgnunetpeerinfo.la \
 $(top_builddir)/src/util/libgnunetutil.la  

EXTRA_DIST = \
  test_peerinfo_api_data.conf 

#check_SCRIPTS = \
#  test_gnunet_peerinfo.sh
