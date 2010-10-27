INCLUDES = -I$(top_srcdir)/src/include

plugindir = $(libdir)/gnunet

if MINGW
  WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols
  NATBIN = gnunet-nat-server gnunet-nat-client
  NATSERVER = gnunet-nat-server-windows.c
  NATCLIENT = gnunet-nat-client-windows.c
else
  NATSERVER = gnunet-nat-server.c
  NATCLIENT = gnunet-nat-client.c
endif

if HAVE_MHD
 GN_LIBMHD = -lmicrohttpd
 HTTP_PLUGIN_LA = libgnunet_plugin_transport_http.la
 HTTP_PLUGIN_TEST = test_plugin_transport_http
 HTTP_API_TEST = test_transport_api_http
 HTTP_REL_TEST = test_transport_api_reliability_http

 HTTPS_PLUGIN_LA = libgnunet_plugin_transport_https.la
 HTTPS_PLUGIN_TEST = test_plugin_transport_https
 HTTPS_API_TEST = test_transport_api_https
 HTTPS_REL_TEST = test_transport_api_reliability_https                     
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
endif

if HAVE_PCAP
if LINUX
 WANBIN = gnunet-transport-wlan-helper
 WLAN_PLUGIN_LA = libgnunet_plugin_transport_wlan.la
endif
endif

if LINUX
NATBIN = gnunet-nat-server gnunet-nat-client
install-exec-hook:
	chown root $(bindir)/gnunet-nat-server $(bindir)/gnunet-nat-client $(bindir)/gnunet-wlan || true
	chmod u+s $(bindir)/gnunet-nat-server $(bindir)/gnunet-nat-client $(bindir)/gnunet-wlan || true
else
install-exec-hook:
endif

#noinst_PROGRAMS = ${check_PROGRAMS}

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
 $(WANBIN) \
 gnunet-service-transport $(NATBIN)

bin_SCRIPTS = \
 gnunet-transport-certificate-creation

gnunet_nat_server_SOURCES = \
 $(NATSERVER)

gnunet_transport_wlan_helper_SOURCES = \
 gnunet-transport-wlan-helper.c         
gnunet_transport_wlan_helper_LDADD = \
 -lpcap

gnunet_nat_client_SOURCES = \
 $(NATCLIENT)         

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
  $(HTTPS_PLUGIN_LA) \
  $(WLAN_PLUGIN_LA) \
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

if HAVE_PCAP
if LINUX
libgnunet_plugin_transport_wlan_la_SOURCES = \
	plugin_transport_wlan.c
libgnunet_plugin_transport_wlan_la_LIBADD = \
	$(top_builddir)/src/hello/libgnunethello.la \
	$(top_builddir)/src/statistics/libgnunetstatistics.la \
	$(top_builddir)/src/peerinfo/libgnunetpeerinfo.la \
	$(top_builddir)/src/util/libgnunetutil.la 
libgnunet_plugin_transport_wlan_la_LDFLAGS = \
	$(GN_PLUGIN_LDFLAGS)
endif
endif

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
 
libgnunet_plugin_transport_https_la_SOURCES = \
  plugin_transport_http.c
libgnunet_plugin_transport_https_la_LIBADD = \
  $(top_builddir)/src/hello/libgnunethello.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/peerinfo/libgnunetpeerinfo.la \
  @LIBCURL@ \
  $(top_builddir)/src/util/libgnunetutil.la 
libgnunet_plugin_transport_https_la_LDFLAGS = \
 $(GN_LIBMHD) \
 $(GN_PLUGIN_LDFLAGS)
libgnunet_plugin_transport_https_la_CFLAGS = \
 $(CFLAGS) -DBUILD_HTTPS  
endif

check_PROGRAMS = \
 test_transport_api_tcp \
 test_transport_api_tcp_nat \
 test_transport_api_udp \
 test_transport_api_udp_nat \
 $(HTTP_PLUGIN_TEST) \
 $(HTTP_API_TEST) \
 $(HTTPS_PLUGIN_TEST) \
 $(HTTPS_API_TEST) \
 test_transport_api_reliability_tcp \
 test_transport_api_reliability_tcp_nat \
 test_transport_api_reliability_udp \
 $(HTTP_REL_TEST) \
 $(HTTPS_REL_TEST) \
 test_quota_compliance
# TODO: add tests for nat, etc.

if !DISABLE_TEST_RUN
TESTS = \
 test_transport_api_tcp \
 test_transport_api_tcp_nat \
 test_transport_api_udp \
 test_transport_api_udp_nat \
 $(HTTP_PLUGIN_TEST) \
 $(HTTP_API_TEST) \
 $(HTTPS_PLUGIN_TEST) \
 $(HTTPS_API_TEST) \
 test_transport_api_reliability_tcp \
 test_transport_api_reliability_tcp_nat \
 $(HTTP_REL_TEST) \
 $(HTTPS_REL_TEST) \
 test_quota_compliance
endif

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

if HAVE_MHD

test_plugin_transport_http_SOURCES = \
 test_plugin_transport_http.c
test_plugin_transport_http_LDADD = \
 $(top_builddir)/src/transport/libgnunettransport.la \
 $(top_builddir)/src/statistics/libgnunetstatistics.la \
 @LIBCURL@ \
 $(top_builddir)/src/util/libgnunetutil.la  

test_transport_api_http_SOURCES = \
 test_transport_api.c
test_transport_api_http_LDADD = \
 $(top_builddir)/src/transport/libgnunettransport.la \
 $(top_builddir)/src/util/libgnunetutil.la  

test_transport_api_reliability_http_SOURCES = \
 test_transport_api_reliability.c
test_transport_api_reliability_http_LDADD = \
 $(top_builddir)/src/transport/libgnunettransport.la \
 $(top_builddir)/src/util/libgnunetutil.la
 
test_plugin_transport_https_SOURCES = \
 test_plugin_transport_https.c
test_plugin_transport_https_LDADD = \
 $(top_builddir)/src/transport/libgnunettransport.la \
 $(top_builddir)/src/statistics/libgnunetstatistics.la \
 @LIBCURL@ \
 $(top_builddir)/src/util/libgnunetutil.la  

test_transport_api_https_SOURCES = \
 test_transport_api.c
test_transport_api_https_LDADD = \
 $(top_builddir)/src/transport/libgnunettransport.la \
 $(top_builddir)/src/util/libgnunetutil.la  

test_transport_api_reliability_https_SOURCES = \
 test_transport_api_reliability.c
test_transport_api_reliability_https_LDADD = \
 $(top_builddir)/src/transport/libgnunettransport.la \
 $(top_builddir)/src/util/libgnunetutil.la

test_quota_compliance_SOURCES = \
 test_quota_compliance.c
test_quota_compliance_LDADD = \
 $(top_builddir)/src/transport/libgnunettransport.la \
 $(top_builddir)/src/util/libgnunetutil.la

endif

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
  test_transport_api_https_peer1.conf \
  test_transport_api_https_peer2.conf \
  test_transport_api_rel_http_peer1.conf \
  test_transport_api_rel_http_peer2.conf \
  test_transport_api_rel_https_peer1.conf \
  test_transport_api_rel_https_peer2.conf \
  test_plugin_transport_data_http.conf \
  test_plugin_transport_data.conf \
  test_quota_compliance_data.conf \
  test_quota_compliance_peer1.conf \
  test_quota_compliance_peer2.conf