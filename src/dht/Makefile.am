INCLUDES = -I$(top_srcdir)/src/include
if MINGW
 WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols -lole32 -lshell32 -liconv -lstdc++ -lcomdlg32 -lgdi32
endif

plugindir = $(libdir)/gnunet

pkgcfgdir= $(pkgdatadir)/config.d/

pkgcfg_DATA = \
  dht.conf 

if HAVE_ZLIB
 ZLIB_LNK = -lz
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

lib_LTLIBRARIES = \
 libgnunetdht.la 

libgnunetdht_la_SOURCES = \
  dht_api.c dht.h 
libgnunetdht_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(XLIB)
libgnunetdht_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS) $(WINFLAGS) \
  -version-info 1:0:1


plugin_LTLIBRARIES = \
  libgnunet_plugin_block_dht.la 

libgnunet_plugin_block_dht_la_SOURCES = \
  plugin_block_dht.c
libgnunet_plugin_block_dht_la_LIBADD = \
  $(top_builddir)/src/hello/libgnunethello.la \
  $(top_builddir)/src/block/libgnunetblock.la \
  $(top_builddir)/src/util/libgnunetutil.la 
libgnunet_plugin_block_dht_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)
libgnunet_plugin_block_dht_la_DEPENDENCIES = \
  $(top_builddir)/src/block/libgnunetblock.la 



bin_PROGRAMS = \
 gnunet-service-dht \
 gnunet-dht-get \
 gnunet-dht-put

gnunet_service_dht_SOURCES = \
 gnunet-service-dht.c gnunet-service-dht.h \
 gnunet-service-dht_clients.c gnunet-service-dht_clients.h \
 gnunet-service-dht_datacache.c gnunet-service-dht_datacache.h \
 gnunet-service-dht_hello.c gnunet-service-dht_hello.h \
 gnunet-service-dht_nse.c gnunet-service-dht_nse.h \
 gnunet-service-dht_neighbours.c gnunet-service-dht_neighbours.h \
 gnunet-service-dht_routing.c gnunet-service-dht_routing.h 
gnunet_service_dht_LDADD = \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/core/libgnunetcore.la \
  $(top_builddir)/src/nse/libgnunetnse.la \
  $(top_builddir)/src/ats/libgnunetats.la \
  $(top_builddir)/src/transport/libgnunettransport.la \
  $(top_builddir)/src/peerinfo/libgnunetpeerinfo.la \
  $(top_builddir)/src/hello/libgnunethello.la \
  $(top_builddir)/src/block/libgnunetblock.la \
  $(top_builddir)/src/datacache/libgnunetdatacache.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  -lm

gnunet_dht_get_SOURCES = \
 gnunet-dht-get.c         
gnunet_dht_get_LDADD = \
  $(top_builddir)/src/dht/libgnunetdht.la \
  $(top_builddir)/src/core/libgnunetcore.la \
  $(top_builddir)/src/util/libgnunetutil.la 
gnunet_dht_get_DEPENDENCIES = \
  libgnunetdht.la			      

gnunet_dht_put_SOURCES = \
 gnunet-dht-put.c         
gnunet_dht_put_LDADD = \
  $(top_builddir)/src/dht/libgnunetdht.la \
  $(top_builddir)/src/core/libgnunetcore.la \
  $(top_builddir)/src/util/libgnunetutil.la 
gnunet_dht_put_DEPENDENCIES = \
  libgnunetdht.la			      

check_PROGRAMS = \
 test_dht_api \
 test_dht_twopeer \
 test_dht_twopeer_put_get \
 test_dht_twopeer_get_put \
 test_dht_twopeer_path_tracking \
 test_dht_multipeer \
 test_dht_line \
 test_dht_2dtorus \
 test_dht_monitor

if ENABLE_TEST_RUN
TESTS = test_dht_api $(check_SCRIPTS) \
 test_dht_twopeer \
 test_dht_twopeer_put_get \
 test_dht_twopeer_get_put \
 test_dht_twopeer_path_tracking \
 test_dht_multipeer  \
 test_dht_line \
 test_dht_2dtorus \
 test_dht_monitor
endif

test_dht_api_SOURCES = \
 test_dht_api.c
test_dht_api_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/dht/libgnunetdht.la
test_dht_api_DEPENDENCIES = \
  libgnunetdht.la			    

test_dht_twopeer_SOURCES = \
 test_dht_twopeer.c
test_dht_twopeer_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/dht/libgnunetdht.la    
test_dht_twopeer_DEPENDENCIES = \
  libgnunetdht.la			    

test_dht_twopeer_put_get_SOURCES = \
 test_dht_twopeer_put_get.c
test_dht_twopeer_put_get_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/dht/libgnunetdht.la   

test_dht_twopeer_get_put_SOURCES = \
 test_dht_twopeer_get_put.c
test_dht_twopeer_get_put_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/dht/libgnunetdht.la   

test_dht_twopeer_path_tracking_SOURCES = \
 test_dht_twopeer_path_tracking.c
test_dht_twopeer_path_tracking_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/dht/libgnunetdht.la   

test_dht_multipeer_SOURCES = \
 test_dht_multipeer.c
test_dht_multipeer_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/statistics/libgnunetstatistics.la \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/dht/libgnunetdht.la  
test_dht_multipeer_DEPENDENCIES = \
  libgnunetdht.la			    

test_dht_2dtorus_SOURCES = \
 test_dht_topo.c
test_dht_2dtorus_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/dht/libgnunetdht.la
test_dht_2dtorus_DEPENDENCIES = \
  libgnunetdht.la

test_dht_line_SOURCES = \
 test_dht_topo.c
test_dht_line_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/dht/libgnunetdht.la
test_dht_line_DEPENDENCIES = \
  libgnunetdht.la

test_dht_monitor_SOURCES = test_dht_monitor.c
test_dht_monitor_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/dht/libgnunetdht.la
test_dht_monitor_DEPENDENCIES = \
  libgnunetdht.la

EXTRA_DIST = \
  $(check_SCRIPTS) \
  test_dht_api_data.conf \
  test_dht_api_peer1.conf \
  test_dht_twopeer_data.conf \
  test_dht_multipeer_data.conf \
  test_dht_2dtorus.conf \
  test_dht_line.conf \
  multipeer_topo.dat

check_SCRIPTS = \
  test_dht_tools.sh
