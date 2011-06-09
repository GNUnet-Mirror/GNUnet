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
 HTTP_QUOTA_TEST = test_quota_compliance_http \
		   test_quota_compliance_http_asymmetric_recv_constant
 HTTPS_PLUGIN_LA = libgnunet_plugin_transport_https.la
 HTTPS_PLUGIN_TEST = test_plugin_transport_https
 HTTPS_API_TEST = test_transport_api_https
 HTTPS_REL_TEST = test_transport_api_reliability_https
 HTTPS_QUOTA_TEST = test_quota_compliance_https \
		test_quota_compliance_https_asymmetric_recv_constant
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
endif

if LINUX
 WLAN_BIN = gnunet-transport-wlan-helper
 WLAN_BIN_DUMMY = gnunet-transport-wlan-helper-dummy
 WLAN_PLUGIN_LA = libgnunet_plugin_transport_wlan.la
 WLAN_API_TEST = test_transport_api_wlan
 WLAN_REL_TEST = test_transport_api_reliability_wlan
 WLAN_UREL_TEST = test_transport_api_unreliability_wlan
endif

if !MINGW
UNIX_PLUGIN_LA = libgnunet_plugin_transport_unix.la
UNIX_PLUGIN_TEST = test_transport_api_unix 
UNIX_REL_TEST = test_transport_api_unreliability_unix
UNIX_QUOTA_TEST = test_quota_compliance_unix \
     test_quota_compliance_unix_asymmetric_recv_constant
endif

if LINUX
NATBIN = gnunet-nat-server gnunet-nat-client
install-exec-hook:
	chown root $(bindir)/gnunet-nat-server $(bindir)/gnunet-nat-client $(bindir)/gnunet-transport-wlan-helper || true
	chmod u+s $(bindir)/gnunet-nat-server $(bindir)/gnunet-nat-client $(bindir)/gnunet-transport-wlan-helper || true
else
install-exec-hook:
endif

#noinst_PROGRAMS = ${check_PROGRAMS}

lib_LTLIBRARIES = \
  libgnunettransport.la \
  libgnunettransportnew.la

libgnunettransportnew_la_SOURCES = \
  transport_api_new.c transport.h \
  transport_api_blacklist.c \
  transport_api_address_lookup.c 
libgnunettransportnew_la_LIBADD = \
  $(top_builddir)/src/hello/libgnunethello.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL) 
libgnunettransportnew_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS) $(WINFLAGS) \
  -version-info 0:0:0

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
 $(WLAN_BIN) \
 gnunet-service-transport $(NATBIN) \
 $(WLAN_BIN_DUMMY)

bin_SCRIPTS = \
 gnunet-transport-certificate-creation

gnunet_nat_server_SOURCES = \
 $(NATSERVER)


gnunet_transport_wlan_helper_SOURCES = \
 wlan/radiotap-parser.c \
 wlan/helper_common.c \
 gnunet-transport-wlan-helper.c

gnunet_transport_wlan_helper_dummy_SOURCES = \
 wlan/radiotap-parser.c \
 wlan/helper_common.c \
 test_plugin_transport_wlan_dummy.c

gnunet_transport_wlan_helper_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la 

gnunet_transport_wlan_helper_dummy_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la 

gnunet_nat_client_SOURCES = \
 $(NATCLIENT)         

gnunet_transport_SOURCES = \
 gnunet-transport.c         
gnunet_transport_LDADD = \
  $(top_builddir)/src/transport/libgnunettransportnew.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)
gnunet_transport_DEPENDENCIES = \
  libgnunettransportnew.la				

if HAVE_LIBGLPK
  GN_GLPK = -lglpk
endif

gnunet_service_transport_SOURCES = \
 gnunet-service-transport.c
gnunet_service_transport_LDADD = \
  $(top_builddir)/src/hello/libgnunethello.la \
  $(top_builddir)/src/peerinfo/libgnunetpeerinfo.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_GLPK) \
  $(GN_LIBINTL)

plugin_LTLIBRARIES = \
  libgnunet_plugin_transport_tcp.la \
  libgnunet_plugin_transport_udp.la \
  $(UNIX_PLUGIN_LA) \
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
  $(top_builddir)/src/nat/libgnunetnat.la \
  $(top_builddir)/src/util/libgnunetutil.la 
libgnunet_plugin_transport_tcp_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)

libgnunet_plugin_transport_template_la_SOURCES = \
  plugin_transport_template.c
libgnunet_plugin_transport_template_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la 
libgnunet_plugin_transport_template_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)

libgnunet_plugin_transport_wlan_la_SOURCES = \
  plugin_transport_wlan.c
libgnunet_plugin_transport_wlan_la_LIBADD = \
  $(top_builddir)/src/hello/libgnunethello.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/peerinfo/libgnunetpeerinfo.la \
  $(top_builddir)/src/util/libgnunetutil.la 
libgnunet_plugin_transport_wlan_la_LDFLAGS = \
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

libgnunet_plugin_transport_unix_la_SOURCES = \
  plugin_transport_unix.c
libgnunet_plugin_transport_unix_la_LIBADD = \
  $(top_builddir)/src/hello/libgnunethello.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/peerinfo/libgnunetpeerinfo.la \
  $(top_builddir)/src/util/libgnunetutil.la 
libgnunet_plugin_transport_unix_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)

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
libgnunet_plugin_transport_http_la_CFLAGS = \
 $(CFLAGS) 
libgnunet_plugin_transport_http_la_CPPFLAGS = \
 @LIBCURL_CPPFLAGS@

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
libgnunet_plugin_transport_https_la_CPPFLAGS = \
 @LIBCURL_CPPFLAGS@


check_PROGRAMS = \
 test_transport_ats \
 perf_transport_ats \
 test_transport_api_tcp \
 test_transport_api_tcp_nat \
 test_transport_api_udp \
 $(UNIX_PLUGIN_TEST) \
 test_transport_api_udp_nat \
 $(HTTP_PLUGIN_TEST) \
 $(HTTP_API_TEST) \
 $(HTTPS_PLUGIN_TEST) \
 $(HTTPS_API_TEST) \
 test_transport_api_multi \
 test_transport_api_reliability_tcp \
 test_transport_api_reliability_tcp_nat \
 test_transport_api_unreliability_udp \
 $(UNIX_REL_TEST) \
 $(HTTP_REL_TEST) \
 $(HTTPS_REL_TEST) \
 test_quota_compliance_tcp \
 test_quota_compliance_tcp_asymmetric_recv_constant \
 test_quota_compliance_udp \
 test_quota_compliance_udp_asymmetric_recv_constant \
 $(UNIX_QUOTA_TEST) \
 $(HTTP_QUOTA_TEST) \
 $(HTTPS_QUOTA_TEST) \
 $(WLAN_API_TEST) \
 $(WLAN_REL_TEST) \
 $(WLAN_UREL_TEST)
# TODO: add tests for nat, etc.

if !DISABLE_TEST_RUN
TESTS = \
 test_transport_ats \
 perf_transport_ats \
 test_transport_api_tcp \
 test_transport_api_tcp_nat \
 test_transport_api_udp \
 $(UNIX_PLUGIN_TEST) \
 test_transport_api_udp_nat \
 $(HTTP_PLUGIN_TEST) \
 $(HTTP_API_TEST) \
 $(HTTPS_PLUGIN_TEST) \
 $(HTTPS_API_TEST) \
 test_transport_api_multi \
 test_transport_api_reliability_tcp \
 test_transport_api_reliability_tcp_nat \
 test_transport_api_unreliability_udp \
 $(UNIX_REL_TEST) \
 $(HTTP_REL_TEST) \
 $(HTTPS_REL_TEST) \
 test_quota_compliance_tcp \
 test_quota_compliance_tcp_asymmetric_recv_constant \
 test_quota_compliance_udp \
 test_quota_compliance_udp_asymmetric_recv_constant \
 $(UNIX_QUOTA_TEST) \
 $(HTTP_QUOTA_TEST) \
 $(HTTPS_QUOTA_TEST) \
 $(WLAN_API_TEST) \
 $(WLAN_REL_TEST) \
 $(WLAN_UREL_TEST)
endif

test_transport_ats_SOURCES = \
 test_transport_ats.c
test_transport_ats_LDADD = -lm \
 $(top_builddir)/src/transport/libgnunettransportnew.la \
 $(top_builddir)/src/statistics/libgnunetstatistics.la \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/util/libgnunetutil.la  

perf_transport_ats_SOURCES = \
 perf_transport_ats.c
perf_transport_ats_LDADD = \
 $(GN_GLPK) \
 $(top_builddir)/src/util/libgnunetutil.la  

test_transport_api_tcp_SOURCES = \
 test_transport_api.c
test_transport_api_tcp_LDADD = \
 $(top_builddir)/src/transport/libgnunettransportnew.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la  

test_transport_api_tcp_nat_SOURCES = \
 test_transport_api.c
test_transport_api_tcp_nat_LDADD = \
 $(top_builddir)/src/transport/libgnunettransportnew.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la  

test_transport_api_reliability_tcp_SOURCES = \
 test_transport_api_reliability.c
test_transport_api_reliability_tcp_LDADD = \
 $(top_builddir)/src/transport/libgnunettransportnew.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la  

test_transport_api_reliability_tcp_nat_SOURCES = \
 test_transport_api_reliability.c
test_transport_api_reliability_tcp_nat_LDADD = \
 $(top_builddir)/src/transport/libgnunettransportnew.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la 

test_transport_api_reliability_wlan_SOURCES = \
 test_transport_api_reliability.c
test_transport_api_reliability_wlan_LDADD = \
 $(top_builddir)/src/transport/libgnunettransportnew.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la

test_transport_api_unreliability_wlan_SOURCES = \
 test_transport_api_unreliability.c
test_transport_api_unreliability_wlan_LDADD = \
 $(top_builddir)/src/transport/libgnunettransportnew.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la

test_transport_api_udp_SOURCES = \
 test_transport_api.c
test_transport_api_udp_LDADD = \
 $(top_builddir)/src/transport/libgnunettransportnew.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la  

test_transport_api_udp_nat_SOURCES = \
 test_transport_api.c
test_transport_api_udp_nat_LDADD = \
 $(top_builddir)/src/transport/libgnunettransportnew.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la   

test_transport_api_unix_SOURCES = \
 test_transport_api.c
test_transport_api_unix_LDADD = \
 $(top_builddir)/src/transport/libgnunettransportnew.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la 

test_plugin_transport_http_SOURCES = \
 test_plugin_transport_http.c
test_plugin_transport_http_LDADD = \
 $(top_builddir)/src/statistics/libgnunetstatistics.la \
 @LIBCURL@ \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la  

test_transport_api_http_SOURCES = \
 test_transport_api.c
test_transport_api_http_LDADD = \
 $(top_builddir)/src/transport/libgnunettransportnew.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la  

test_transport_api_reliability_http_SOURCES = \
 test_transport_api_reliability.c
test_transport_api_reliability_http_LDADD = \
 $(top_builddir)/src/transport/libgnunettransportnew.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la

test_plugin_transport_https_SOURCES = \
 test_plugin_transport_https.c
test_plugin_transport_https_LDADD = \
 $(top_builddir)/src/statistics/libgnunetstatistics.la \
 @LIBCURL@ \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la  

test_transport_api_https_SOURCES = \
 test_transport_api.c
test_transport_api_https_LDADD = \
 $(top_builddir)/src/transport/libgnunettransportnew.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la  

test_transport_api_reliability_https_SOURCES = \
 test_transport_api_reliability.c
test_transport_api_reliability_https_LDADD = \
 $(top_builddir)/src/transport/libgnunettransportnew.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la

test_transport_api_unreliability_unix_SOURCES = \
 test_transport_api_unreliability.c
test_transport_api_unreliability_unix_LDADD = \
 $(top_builddir)/src/transport/libgnunettransportnew.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la

test_transport_api_unreliability_udp_SOURCES = \
 test_transport_api_unreliability.c
test_transport_api_unreliability_udp_LDADD = \
 $(top_builddir)/src/transport/libgnunettransportnew.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la

if LINUX
test_transport_api_wlan_SOURCES = \
 test_transport_api.c
test_transport_api_wlan_LDADD = \
 $(top_builddir)/src/transport/libgnunettransportnew.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la  
endif

test_quota_compliance_tcp_SOURCES = \
 test_quota_compliance.c
test_quota_compliance_tcp_LDADD = \
 $(top_builddir)/src/transport/libgnunettransportnew.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la

test_quota_compliance_tcp_asymmetric_recv_constant_SOURCES = \
 test_quota_compliance.c
test_quota_compliance_tcp_asymmetric_recv_constant_LDADD = \
 $(top_builddir)/src/transport/libgnunettransportnew.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la

#test_quota_compliance_tcp_asymmetric_send_constant_SOURCES = \
# test_quota_compliance.c
#test_quota_compliance_tcp_asymmetric_send_constant_LDADD = \
# $(top_builddir)/src/transport/libgnunettransportnew.la \
# $(top_builddir)/src/util/libgnunetutil.la

test_quota_compliance_http_SOURCES = \
 test_quota_compliance.c
test_quota_compliance_http_LDADD = \
 $(top_builddir)/src/transport/libgnunettransportnew.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la

 test_quota_compliance_http_asymmetric_recv_constant_SOURCES = \
 test_quota_compliance.c
test_quota_compliance_http_asymmetric_recv_constant_LDADD = \
 $(top_builddir)/src/transport/libgnunettransportnew.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la

#test_quota_compliance_http_asymmetric_send_constant_SOURCES = \
# test_quota_compliance.c
#test_quota_compliance_http_asymmetric_send_constant_LDADD = \
# $(top_builddir)/src/transport/libgnunettransportnew.la \
# $(top_builddir)/src/util/libgnunetutil.la

test_quota_compliance_https_SOURCES = \
 test_quota_compliance.c
test_quota_compliance_https_LDADD = \
 $(top_builddir)/src/transport/libgnunettransportnew.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la

 test_quota_compliance_https_asymmetric_recv_constant_SOURCES = \
 test_quota_compliance.c
test_quota_compliance_https_asymmetric_recv_constant_LDADD = \
 $(top_builddir)/src/transport/libgnunettransportnew.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la

#test_quota_compliance_https_asymmetric_send_constant_SOURCES = \
# test_quota_compliance.c
#test_quota_compliance_https_asymmetric_send_constant_LDADD = \
# $(top_builddir)/src/transport/libgnunettransportnew.la \
# $(top_builddir)/src/util/libgnunetutil.la

test_quota_compliance_udp_SOURCES = \
 test_quota_compliance.c
test_quota_compliance_udp_LDADD = \
 $(top_builddir)/src/transport/libgnunettransportnew.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la

test_quota_compliance_udp_asymmetric_recv_constant_SOURCES = \
 test_quota_compliance.c
test_quota_compliance_udp_asymmetric_recv_constant_LDADD = \
 $(top_builddir)/src/transport/libgnunettransportnew.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la

#test_quota_compliance_udp_asymmetric_send_constant_SOURCES = \
# test_quota_compliance.c
#test_quota_compliance_udp_asymmetric_send_constant_LDADD = \
# $(top_builddir)/src/transport/libgnunettransportnew.la \
# $(top_builddir)/src/util/libgnunetutil.la 

test_quota_compliance_unix_SOURCES = \
 test_quota_compliance.c
test_quota_compliance_unix_LDADD = \
 $(top_builddir)/src/transport/libgnunettransportnew.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la

test_quota_compliance_unix_asymmetric_recv_constant_SOURCES = \
 test_quota_compliance.c
test_quota_compliance_unix_asymmetric_recv_constant_LDADD = \
 $(top_builddir)/src/transport/libgnunettransportnew.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la


test_transport_api_multi_SOURCES = \
 test_transport_api.c
test_transport_api_multi_LDADD = \
 $(top_builddir)/src/transport/libgnunettransportnew.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la  
EXTRA_DIST = \
  gnunet-transport-certificate-creation \
  ats_mlp_p100_m400.problem \
  test_transport_api_data.conf \
  test_transport_api_tcp_peer1.conf \
  test_transport_api_tcp_peer2.conf \
  test_transport_api_udp_peer1.conf \
  test_transport_api_udp_peer2.conf \
  test_transport_api_unix_peer1.conf \
  test_transport_api_unix_peer2.conf \
  test_transport_api_udp_nat_peer1.conf \
  test_transport_api_udp_nat_peer2.conf \
  test_transport_api_tcp_nat_peer1.conf \
  test_transport_api_tcp_nat_peer2.conf \
  test_plugin_transport_data.conf \
  test_transport_api_http_peer1.conf \
  test_transport_api_http_peer2.conf \
  test_transport_api_https_peer1.conf \
  test_transport_api_https_peer2.conf \
  test_transport_api_wlan_peer1.conf \
  test_transport_api_wlan_peer2.conf \
  test_transport_api_multi_peer1.conf \
  test_transport_api_multi_peer2.conf \
  test_transport_api_rel_http_peer1.conf \
  test_transport_api_rel_http_peer2.conf \
  test_transport_api_rel_https_peer1.conf \
  test_transport_api_rel_https_peer2.conf \
  test_plugin_transport_data_http.conf \
  test_plugin_transport_data.conf \
  test_quota_compliance_data.conf \
  test_quota_compliance_tcp_peer1.conf \
  test_quota_compliance_tcp_peer2.conf \
  test_quota_compliance_http_peer1.conf \
  test_quota_compliance_http_peer2.conf \
  test_quota_compliance_https_peer1.conf \
  test_quota_compliance_https_peer2.conf \
  test_quota_compliance_udp_peer1.conf \
  test_quota_compliance_udp_peer2.conf \
  test_quota_compliance_unix_peer1.conf \
  test_quota_compliance_unix_peer2.conf
