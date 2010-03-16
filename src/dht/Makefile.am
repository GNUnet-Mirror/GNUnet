INCLUDES = -I$(top_srcdir)/src/include

if MINGW
 WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols -lole32 -lshell32 -luuid -liconv -lstdc++ -lcomdlg32 -lgdi32
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

lib_LTLIBRARIES = libgnunetdht.la

libgnunetdht_la_SOURCES = \
  dht_api.c dht.h
libgnunetdht_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(XLIB)
libgnunetdht_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS) $(WINFLAGS) \
  -version-info 0:0:0


bin_PROGRAMS = \
 gnunet-service-dht

gnunet_service_dht_SOURCES = \
 gnunet-service-dht.c         
gnunet_service_dht_LDADD = \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/core/libgnunetcore.la \
  $(top_builddir)/src/datastore/libgnunetdatastore.la \
  $(top_builddir)/src/util/libgnunetutil.la 


check_PROGRAMS = \
 test_dht_api

TESTS = $(check_PROGRAMS) # $(check_SCRIPTS)

test_dht_api_SOURCES = \
 test_dht_api.c
test_dht_api_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/dht/libgnunetdht.la    

EXTRA_DIST = \
  test_dht_api_data.conf 

#check_SCRIPTS = \
#  test_gnunet_peerinfo.sh
