INCLUDES = -I$(top_srcdir)/src/include

plugindir = $(libdir)/gnunet

if MINGW
  WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols
endif

 GN_LIBMHD = -lmicrohttpd
 HTTP_PLUGIN_LA = libgnunet_plugin_transport_http.la
 HTTP_PLUGIN_CHECK = test_plugin_transport_http

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
endif

if LINUX
NATBIN = gnunet-nat-server gnunet-nat-client
install-exec-hook:
	chown root $(bindir)/gnunet-nat-server $(bindir)/gnunet-nat-client || true
	chmod u+s $(bindir)/gnunet-nat-server $(bindir)/gnunet-nat-client || true
else
install-exec-hook:
endif


lib_LTLIBRARIES = \
  libgnunettransport.la

libgnunettransport_la_SOURCES = \
  transport_api.c transport.h \
  transport_api_blacklist.c \
  transport_api_address_lookup.c 
libgnunettransport_la_LIBADD = \
  $(top_builddir)/src/hello/libgnunethello.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL) 
libgnunettransport_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS) $(WINFLAGS) \
  -version-info 0:0:0


bin_PROGRAMS = \
 gnunet-transport \
 gnunet-service-transport $(NATBIN)


gnunet_nat_server_SOURCES = \
 gnunet-nat-server.c         

gnunet_nat_client_SOURCES = \
 gnunet-nat-client.c         

gnunet_transport_SOURCES = \
 gnunet-transport.c         
gnunet_transport_LDADD = \
  $(top_builddir)/src/transport/libgnunettransport.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)

gnunet_service_transport_SOURCES = \
 gnunet-service-transport.c plugin_transport.h 
gnunet_service_transport_LDADD = \
  $(top_builddir)/src/hello/libgnunethello.la \
  $(top_builddir)/src/peerinfo/libgnunetpeerinfo.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)


plugin_LTLIBRARIES = \
  libgnunet_plugin_transport_tcp.la \
  libgnunet_plugin_transport_udp.la \
  $(HTTP_PLUGIN_LA) \
  libgnunet_plugin_transport_template.la
# TODO: add nat, etc.

libgnunet_plugin_transport_tcp_la_SOURCES = \
  plugin_transport_tcp.c
libgnunet_plugin_transport_tcp_la_LIBADD = \
  $(top_builddir)/src/hello/libgnunethello.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/peerinfo/libgnunetpeerinfo.la \
  $(top_builddir)/src/util/libgnunetutil.la 
libgnunet_plugin_transport_tcp_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)

libgnunet_plugin_transport_template_la_SOURCES = \
  plugin_transport_template.c
libgnunet_plugin_transport_template_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la 
libgnunet_plugin_transport_template_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)

libgnunet_plugin_transport_udp_la_SOURCES = \
  plugin_transport_udp.c
libgnunet_plugin_transport_udp_la_LIBADD = \
  $(top_builddir)/src/hello/libgnunethello.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/peerinfo/libgnunetpeerinfo.la \
  $(top_builddir)/src/util/libgnunetutil.la 
libgnunet_plugin_transport_udp_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)

#libgnunet_plugin_transport_udp_nat_la_SOURCES = \
#  plugin_transport_udp_nat.c
#libgnunet_plugin_transport_udp_nat_la_LIBADD = \
#  $(top_builddir)/src/hello/libgnunethello.la \
#  $(top_builddir)/src/statistics/libgnunetstatistics.la \
#  $(top_builddir)/src/peerinfo/libgnunetpeerinfo.la \
#  $(top_builddir)/src/util/libgnunetutil.la 
#libgnunet_plugin_transport_udp_nat_la_LDFLAGS = \
# $(GN_PLUGIN_LDFLAGS)

if HAVE_MHD 
libgnunet_plugin_transport_http_la_SOURCES = \
  plugin_transport_http.c
libgnunet_plugin_transport_http_la_LIBADD = \
  $(top_builddir)/src/hello/libgnunethello.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/peerinfo/libgnunetpeerinfo.la \
  @LIBCURL@ \
  $(top_builddir)/src/util/libgnunetutil.la 
libgnunet_plugin_transport_http_la_LDFLAGS = \
 $(GN_LIBMHD) \
 $(GN_PLUGIN_LDFLAGS)
endif

check_PROGRAMS = \
 test_transport_api_tcp \
 test_transport_api_tcp_nat \
 test_transport_api_udp \
 $(HTTP_PLUGIN_CHECK) \
 test_transport_api_udp_nat \
 test_transport_api_reliability_tcp \
 test_transport_api_reliability_tcp_nat \
 test_transport_api_reliability_udp \
 test_transport_api_http \
 test_transport_api_reliability_http 
# TODO: add tests for nat, etc.

TESTS = \
 test_transport_api_tcp \
 test_transport_api_tcp_nat \
 test_transport_api_udp \
 test_transport_api_udp_nat \
 test_plugin_transport_http \
 test_transport_api_http \
 test_transport_api_reliability_tcp \
 test_transport_api_reliability_tcp_nat \ 
 test_transport_api_reliability_http

test_transport_api_tcp_SOURCES = \
 test_transport_api.c
test_transport_api_tcp_LDADD = \
 $(top_builddir)/src/transport/libgnunettransport.la \
 $(top_builddir)/src/util/libgnunetutil.la  

test_transport_api_tcp_nat_SOURCES = \
 test_transport_api.c
test_transport_api_tcp_nat_LDADD = \
 $(top_builddir)/src/transport/libgnunettransport.la \
 $(top_builddir)/src/util/libgnunetutil.la  

test_transport_api_reliability_tcp_SOURCES = \
 test_transport_api_reliability.c
test_transport_api_reliability_tcp_LDADD = \
 $(top_builddir)/src/transport/libgnunettransport.la \
 $(top_builddir)/src/util/libgnunetutil.la  

test_transport_api_reliability_tcp_nat_SOURCES = \
 test_transport_api_reliability.c
test_transport_api_reliability_tcp_nat_LDADD = \
 $(top_builddir)/src/transport/libgnunettransport.la \
 $(top_builddir)/src/util/libgnunetutil.la 

test_transport_api_reliability_udp_SOURCES = \
 test_transport_api_reliability.c
test_transport_api_reliability_udp_LDADD = \
 $(top_builddir)/src/transport/libgnunettransport.la \
 $(top_builddir)/src/util/libgnunetutil.la   
 
test_transport_api_reliability_http_SOURCES = \
 test_transport_api_reliability.c
test_transport_api_reliability_http_LDADD = \
 $(top_builddir)/src/transport/libgnunettransport.la \
 $(top_builddir)/src/util/libgnunetutil.la   

test_transport_api_udp_SOURCES = \
 test_transport_api.c
test_transport_api_udp_LDADD = \
 $(top_builddir)/src/transport/libgnunettransport.la \
 $(top_builddir)/src/util/libgnunetutil.la  

test_transport_api_udp_nat_SOURCES = \
 test_transport_api.c
test_transport_api_udp_nat_LDADD = \
 $(top_builddir)/src/transport/libgnunettransport.la \
 $(top_builddir)/src/util/libgnunetutil.la  

test_transport_api_http_SOURCES = \
 test_transport_api.c
test_transport_api_http_LDADD = \
 $(top_builddir)/src/transport/libgnunettransport.la \
 $(top_builddir)/src/util/libgnunetutil.la  

test_plugin_transport_http_SOURCES = \
 test_plugin_transport_http.c
test_plugin_transport_http_LDADD = \
 $(top_builddir)/src/transport/libgnunettransport.la \
 $(top_builddir)/src/statistics/libgnunetstatistics.la \
 @LIBCURL@ \
 $(top_builddir)/src/util/libgnunetutil.la  


EXTRA_DIST = \
  test_transport_api_data.conf \
  test_transport_api_tcp_peer1.conf \
  test_transport_api_tcp_peer2.conf \
  test_transport_api_udp_peer1.conf \
  test_transport_api_udp_peer2.conf \
  test_transport_api_udp_nat_peer1.conf \
  test_transport_api_udp_nat_peer2.conf \
  test_transport_api_tcp_nat_peer1.conf \
  test_transport_api_tcp_nat_peer2.conf \
  test_plugin_transport_data.conf \
  test_transport_api_http_peer1.conf \
  test_transport_api_http_peer2.conf \
  test_transport_api_rel_http_peer1.conf \
  test_transport_api_rel_http_peer2.conf \
  test_plugin_transport_data_http.conf
