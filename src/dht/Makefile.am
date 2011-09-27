INCLUDES = -I$(top_srcdir)/src/include
if MINGW
 WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols -lole32 -lshell32 -liconv -lstdc++ -lcomdlg32 -lgdi32
endif

plugindir = $(libdir)/gnunet

if HAVE_MYSQL
 MYSQL_PLUGIN = libgnunet_plugin_dhtlog_mysql.la
endif

if HAVE_ZLIB
 ZLIB_LNK = -lz
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

lib_LTLIBRARIES = libgnunetdht.la \
 libgnunetdhtlog.la

plugin_LTLIBRARIES = \
 $(MYSQL_PLUGIN) \
 libgnunet_plugin_dhtlog_dummy.la \
 libgnunet_plugin_dhtlog_mysql_dump.la \
 libgnunet_plugin_dhtlog_mysql_dump_load.la  


libgnunet_plugin_dhtlog_mysql_la_SOURCES = \
  plugin_dhtlog_mysql.c
libgnunet_plugin_dhtlog_mysql_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la $(XLIBS) -lz -lsqlite3
libgnunet_plugin_dhtlog_mysql_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS) $(MYSQL_LDFLAGS) -lmysqlclient
libgnunet_plugin_dhtlog_mysql_la_CPFLAGS = \
 $(MYSQL_CPPFLAGS)

libgnunet_plugin_dhtlog_dummy_la_SOURCES = \
  plugin_dhtlog_dummy.c
libgnunet_plugin_dhtlog_dummy_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(XLIB)
libgnunet_plugin_dhtlog_dummy_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)

libgnunet_plugin_dhtlog_mysql_dump_la_SOURCES = \
  plugin_dhtlog_mysql_dump.c
libgnunet_plugin_dhtlog_mysql_dump_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(XLIB)
libgnunet_plugin_dhtlog_mysql_dump_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)

libgnunet_plugin_dhtlog_mysql_dump_load_la_SOURCES = \
  plugin_dhtlog_mysql_dump_load.c
libgnunet_plugin_dhtlog_mysql_dump_load_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(XLIB)
libgnunet_plugin_dhtlog_mysql_dump_load_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)

libgnunetdhtlog_la_SOURCES = \
  dhtlog.c dhtlog.h
libgnunetdhtlog_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la
libgnunetdhtlog_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS) $(WINFLAGS) \
  -version-info 0:0:0

libgnunetdht_la_SOURCES = \
  dht_api.c dht.h \
  dht_api_get_put.c \
  dht_api_find_peer.c 
libgnunetdht_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(XLIB)
libgnunetdht_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS) $(WINFLAGS) \
  -version-info 0:0:0

libgnunetdhtnew_la_SOURCES = \
  dht_api_new.c dht_new.h 
libgnunetdhtnew_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(XLIB)
libgnunetdhtnew_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS) $(WINFLAGS) \
  -version-info 0:0:0

bin_PROGRAMS = \
 gnunet-service-dht \
 gnunet-service-dht-new \
 gnunet-dht-get \
 gnunet-dht-get-peer \
 gnunet-dht-put

if HAVE_MALICIOUS
noinst_PROGRAMS = \
 gnunet-dht-driver 
endif

gnunet_service_dht_SOURCES = \
 gnunet-service-dht.c         
gnunet_service_dht_LDADD = \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/core/libgnunetcore.la \
  $(top_builddir)/src/nse/libgnunetnse.la \
  $(top_builddir)/src/transport/libgnunettransport.la \
  $(top_builddir)/src/hello/libgnunethello.la \
  $(top_builddir)/src/block/libgnunetblock.la \
  $(top_builddir)/src/datacache/libgnunetdatacache.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/dht/libgnunetdhtlog.la -lm
gnunet_service_dht_DEPENDENCIES = \
  libgnunetdhtlog.la				  

gnunet_service_dht_new_SOURCES = \
 gnunet-service-dht-new.c gnunet-service-dht.h \
 gnunet-service-dht_clients.c gnunet-service-dht_clients.h \
 gnunet-service-dht_datacache.c gnunet-service-dht_datacache.h \
 gnunet-service-dht_nse.c gnunet-service-dht_nse.h \
 gnunet-service-dht_neighbours.c gnunet-service-dht_neighbours.h \
 gnunet-service-dht_routing.c gnunet-service-dht_routing.h 
gnunet_service_dht_new_LDADD = \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/core/libgnunetcore.la \
  $(top_builddir)/src/nse/libgnunetnse.la \
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

gnunet_dht_get_peer_SOURCES = \
 gnunet-dht-get-peer.c         
gnunet_dht_get_peer_LDADD = \
  $(top_builddir)/src/dht/libgnunetdht.la \
  $(top_builddir)/src/hello/libgnunethello.la \
  $(top_builddir)/src/core/libgnunetcore.la \
  $(top_builddir)/src/util/libgnunetutil.la 
gnunet_dht_get_peer_DEPENDENCIES = \
  libgnunetdht.la			      

gnunet_dht_put_SOURCES = \
 gnunet-dht-put.c         
gnunet_dht_put_LDADD = \
  $(top_builddir)/src/dht/libgnunetdht.la \
  $(top_builddir)/src/core/libgnunetcore.la \
  $(top_builddir)/src/util/libgnunetutil.la 
gnunet_dht_put_DEPENDENCIES = \
  libgnunetdht.la			      

gnunet_dht_driver_SOURCES = \
 gnunet-dht-driver.c         
gnunet_dht_driver_LDADD = \
  $(top_builddir)/src/dht/libgnunetdht.la \
  $(top_builddir)/src/dht/libgnunetdhtlog.la \
  $(top_builddir)/src/core/libgnunetcore.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/dht/libgnunetdhtlog.la
gnunet_dht_driver_DEPENDENCIES = \
  libgnunetdht.la \
  libgnunetdhtlog.la  


check_PROGRAMS = \
 test_dht_api \
 test_dht_twopeer \
 test_dht_twopeer_put_get \
 test_dht_twopeer_get_put \
 test_dht_twopeer_path_tracking \
 test_dht_multipeer \
 test_dhtlog 
# test_hash_operations

if ENABLE_TEST_RUN
TESTS = test_dht_api $(check_SCRIPTS) \
 test_dht_twopeer \
 test_dht_twopeer_put_get \
 test_dht_twopeer_get_put \
 test_dht_twopeer_path_tracking \
 test_dht_multipeer \
 test_dhtlog
endif

test_dht_api_SOURCES = \
 test_dht_api.c
test_dht_api_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/dht/libgnunetdht.la
test_dht_api_DEPENDENCIES = \
  libgnunetdht.la			    

test_dht_multipeer_SOURCES = \
 test_dht_multipeer.c
test_dht_multipeer_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/dht/libgnunetdht.la  
test_dht_multipeer_DEPENDENCIES = \
  libgnunetdht.la			    
 
#test_hash_operations_SOURCES = \
# test_hash_operations.c
#test_hash_operations_LDADD = \
# $(top_builddir)/src/util/libgnunetutil.la \
# $(top_builddir)/src/testing/libgnunettesting.la \
# $(top_builddir)/src/dht/libgnunetdht.la 

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

test_dhtlog_SOURCES = \
 test_dhtlog.c
test_dhtlog_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/dht/libgnunetdht.la \
 $(top_builddir)/src/dht/libgnunetdhtlog.la

EXTRA_DIST = \
  $(check_SCRIPTS) \
  test_dht_api_data.conf \
  test_dht_api_peer1.conf \
  test_dht_twopeer_data.conf \
  test_dht_multipeer_data.conf \
  test_dhtlog_data.conf \
  multipeer_topo.dat

check_SCRIPTS = \
  test_dht_tools.sh
