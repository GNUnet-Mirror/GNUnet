# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include -I$(top_builddir)/src/include

plugindir = $(libdir)/gnunet

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

pkgcfg_DATA = \
  transport.conf \
  communicator-unix.conf

HTTP_SERVER_PLUGIN_LA = libgnunet_plugin_transport_http_server.la
HTTPS_SERVER_PLUGIN_LA = libgnunet_plugin_transport_https_server.la
HTTP_SERVER_PLUGIN_TEST = test_plugin_http_server
HTTPS_SERVER_PLUGIN_TEST = test_plugin_https_server

if HAVE_LIBGNURL
 HTTP_CLIENT_PLUGIN_TEST = test_plugin_http_client
 HTTPS_CLIENT_PLUGIN_TEST = test_plugin_https_client
 HTTP_CLIENT_PLUGIN_LA = libgnunet_plugin_transport_http_client.la
 HTTPS_CLIENT_PLUGIN_LA = libgnunet_plugin_transport_https_client.la
LIB_GNURL=@LIBGNURL@
CPP_GNURL=@LIBGNURL_CPPFLAGS@
else
if HAVE_LIBCURL
 HTTP_CLIENT_PLUGIN_TEST = test_plugin_http_client
 HTTPS_CLIENT_PLUGIN_TEST = test_plugin_https_client
 HTTP_CLIENT_PLUGIN_LA = libgnunet_plugin_transport_http_client.la
 HTTPS_CLIENT_PLUGIN_LA = libgnunet_plugin_transport_https_client.la
LIB_GNURL=@LIBCURL@
CPP_GNURL=@LIBCURL_CPPFLAGS@
endif
endif

if HAVE_LIBGNURL
 HTTP_API_TEST = test_transport_api_http
 HTTP_REVERSE_API_TEST = test_transport_api_http_reverse
 HTTP_API_TIMEOUT_TEST = test_transport_api_timeout_http
 HTTP_REL_TEST = test_transport_api_reliability_http \
		 test_transport_api_reliability_http_xhr
 HTTP_QUOTA_TEST = test_quota_compliance_http \
		   test_quota_compliance_http_asymmetric
 HTTP_SWITCH = test_transport_address_switch_http
 HTTPS_API_TEST = test_transport_api_https
 HTTPS_API_TIMEOUT_TEST = test_transport_api_timeout_https
if HAVE_EXPERIMENTAL
 HTTPS_REL_TEST = test_transport_api_reliability_https \
		  test_transport_api_reliability_https_xhr
endif
 HTTPS_QUOTA_TEST = test_quota_compliance_https \
		test_quota_compliance_https_asymmetric
 HTTPS_SWITCH = test_transport_address_switch_https
else
if HAVE_LIBCURL
 HTTP_API_TEST = test_transport_api_http
 HTTP_REVERSE_API_TEST = test_transport_api_http_reverse
 HTTP_API_TIMEOUT_TEST = test_transport_api_timeout_http
 HTTP_REL_TEST = test_transport_api_reliability_http \
		 test_transport_api_reliability_http_xhr
 HTTP_QUOTA_TEST = test_quota_compliance_http \
		   test_quota_compliance_http_asymmetric
 HTTP_SWITCH = test_transport_address_switch_http
 HTTPS_API_TEST = test_transport_api_https
 HTTPS_API_TIMEOUT_TEST = test_transport_api_timeout_https
if HAVE_EXPERIMENTAL
 HTTPS_REL_TEST = test_transport_api_reliability_https \
		  test_transport_api_reliability_https_xhr
endif
 HTTPS_QUOTA_TEST = test_quota_compliance_https \
		test_quota_compliance_https_asymmetric
 HTTPS_SWITCH = test_transport_address_switch_https
endif
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
endif

if HAVE_EXPERIMENTAL
if LINUX
 WLAN_BIN = gnunet-helper-transport-wlan
 WLAN_BIN_DUMMY = gnunet-helper-transport-wlan-dummy
 WLAN_BIN_SENDER = gnunet-transport-wlan-sender
 WLAN_BIN_RECEIVER = gnunet-transport-wlan-receiver
 WLAN_PLUGIN_LA = libgnunet_plugin_transport_wlan.la
 WLAN_PLUGIN_TEST = test_plugin_wlan
 WLAN_API_TEST = test_transport_api_wlan
 WLAN_TIMEOUT_TEST = test_transport_api_timeout_wlan
 WLAN_REL_TEST = test_transport_api_reliability_wlan
 WLAN_QUOTA_TEST = test_quota_compliance_wlan \
		test_quota_compliance_wlan_asymmetric
endif

if LINUX
if HAVE_LIBBLUETOOTH
 BT_BIN = gnunet-helper-transport-bluetooth
 BT_PLUGIN_LA = libgnunet_plugin_transport_bluetooth.la
 BT_PLUGIN_TEST = test_plugin_bluetooth
 BT_API_TEST = test_transport_api_bluetooth
 BT_TIMEOUT_TEST = test_transport_api_timeout_bluetooth
 BT_REL_TEST = test_transport_api_reliability_bluetooth
 BT_QUOTA_TEST = test_quota_compliance_bluetooth \
    test_quota_compliance_bluetooth_asymmetric
endif
endif

# end of HAVE_EXPERIMENTAL
endif


UNIX_PLUGIN_LA = libgnunet_plugin_transport_unix.la
UNIX_PLUGIN_TEST = test_transport_api_unix
UNIX_TEST = test_plugin_unix
UNIX_PLUGIN_TIMEOUT_TEST = test_transport_api_timeout_unix
UNIX_REL_TEST = test_transport_api_reliability_unix
UNIX_QUOTA_TEST = test_quota_compliance_unix \
     test_quota_compliance_unix_asymmetric
if LINUX
 UNIX_API_ABSTRACT_TEST = test_transport_api_unix_abstract
endif


noinst_PROGRAMS = \
 gnunet-transport-profiler \
 gnunet-communicator-tcp \
 gnunet-communicator-udp \
 gnunet-service-tng \
 $(WLAN_BIN_SENDER) \
 $(WLAN_BIN_RECEIVER)

if HAVE_TESTING
TESTING_LIBS = libgnunettransporttesting.la \
							 libgnunettransporttesting2.la
endif

lib_LTLIBRARIES = \
  libgnunettransport.la \
  libgnunettransportapplication.la \
  libgnunettransportcore.la \
  libgnunettransportcommunicator.la \
  libgnunettransportmonitor.la \
  $(TESTING_LIBS)

libgnunettransporttesting_la_SOURCES = \
  transport-testing.c transport-testing.h \
  transport-testing-filenames.c \
  transport-testing-loggers.c \
  transport-testing-main.c \
  transport-testing-send.c
libgnunettransporttesting_la_LIBADD = \
  libgnunettransport.la \
  $(top_builddir)/src/hello/libgnunethello.la \
  $(top_builddir)/src/ats/libgnunetats.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(GN_LIBINTL)
libgnunettransporttesting_la_LDFLAGS = \
 $(GN_LIB_LDFLAGS)

libgnunettransporttesting2_la_SOURCES = \
  transport-testing2.c transport-testing2.h
libgnunettransporttesting2_la_LIBADD = \
  libgnunettransport.la \
  $(top_builddir)/src/hello/libgnunethello.la \
  $(top_builddir)/src/util/libgnunetutil.la
libgnunettransporttesting2_la_LDFLAGS = \
  $(GN_LIBINTL) \
  $(GN_LIB_LDFLAGS)

libgnunettransport_la_SOURCES = \
  transport.h \
  transport_api_address_to_string.c \
  transport_api_blacklist.c \
  transport_api_core.c \
  transport_api_hello_get.c \
  transport_api_manipulation.c \
  transport_api_monitor_peers.c \
  transport_api_monitor_plugins.c \
  transport_api_offer_hello.c

libgnunettransport_la_LIBADD = \
  $(top_builddir)/src/hello/libgnunethello.la \
  $(top_builddir)/src/ats/libgnunetats.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)
libgnunettransport_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)  \
  -version-info 4:0:2

libgnunettransportapplication_la_SOURCES = \
  transport_api2_application.c
libgnunettransportapplication_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(LTLIBINTL)
libgnunettransportapplication_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)  \
  -version-info 0:0:0


libgnunettransportcore_la_SOURCES = \
  transport_api2_core.c
libgnunettransportcore_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)
libgnunettransportcore_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)  \
  -version-info 0:0:0

libgnunettransportcommunicator_la_SOURCES = \
  transport_api2_communication.c
libgnunettransportcommunicator_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)
libgnunettransportcommunicator_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)  \
  -version-info 0:0:0


libgnunettransportmonitor_la_SOURCES = \
  transport_api2_monitor.c
libgnunettransportmonitor_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)
libgnunettransportmonitor_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)  \
  -version-info 0:0:0


libexec_PROGRAMS = \
 $(WLAN_BIN) \
 $(WLAN_BIN_DUMMY) \
 $(BT_BIN) \
 gnunet-service-transport \
 gnunet-communicator-unix \
 gnunet-communicator-udp \
 gnunet-communicator-tcp



bin_PROGRAMS = \
 gnunet-transport

bin_SCRIPTS = \
 gnunet-transport-certificate-creation

# See: https://www.gnu.org/software/automake/manual/html_node/Scripts.html#Scripts
do_subst = sed -e 's,[@]pkgdatadir[@],$(pkgdatadir),g'


gnunet-transport-certificate-creation: gnunet-transport-certificate-creation.in Makefile
	$(do_subst) < $(srcdir)/gnunet-transport-certificate-creation.in > gnunet-transport-certificate-creation
	chmod +x gnunet-transport-certificate-creation



gnunet_communicator_unix_SOURCES = \
 gnunet-communicator-unix.c
gnunet_communicator_unix_LDADD = \
  libgnunettransportcommunicator.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la

gnunet_communicator_tcp_SOURCES = \
 gnunet-communicator-tcp.c
gnunet_communicator_tcp_LDADD = \
  libgnunettransportcommunicator.la \
  $(top_builddir)/src/nat/libgnunetnatnew.la \
  $(top_builddir)/src/nt/libgnunetnt.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(LIBGCRYPT_LIBS)

gnunet_communicator_udp_SOURCES = \
 gnunet-communicator-udp.c
gnunet_communicator_udp_LDADD = \
  libgnunettransportapplication.la \
  libgnunettransportcommunicator.la \
  $(top_builddir)/src/nat/libgnunetnatnew.la \
  $(top_builddir)/src/nt/libgnunetnt.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(LIBGCRYPT_LIBS)


gnunet_helper_transport_wlan_SOURCES = \
 gnunet-helper-transport-wlan.c

gnunet_helper_transport_wlan_dummy_SOURCES = \
 gnunet-helper-transport-wlan-dummy.c
gnunet_helper_transport_wlan_dummy_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la

gnunet_transport_wlan_sender_SOURCES = \
 gnunet-transport-wlan-sender.c
gnunet_transport_wlan_sender_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la

gnunet_transport_wlan_receiver_SOURCES = \
 gnunet-transport-wlan-receiver.c
gnunet_transport_wlan_receiver_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la

gnunet_helper_transport_bluetooth_SOURCES = \
 gnunet-helper-transport-bluetooth.c

gnunet_helper_transport_bluetooth_LDFLAGS = -lbluetooth


gnunet_transport_profiler_SOURCES = \
 gnunet-transport-profiler.c
gnunet_transport_profiler_LDADD = \
  libgnunettransport.la \
  $(top_builddir)/src/hello/libgnunethello.la \
  $(top_builddir)/src/ats/libgnunetats.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)

gnunet_transport_SOURCES = \
 gnunet-transport.c
gnunet_transport_LDADD = \
  libgnunettransport.la \
  $(top_builddir)/src/hello/libgnunethello.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)

gnunet_service_transport_SOURCES = \
 gnunet-service-transport.c gnunet-service-transport.h \
 gnunet-service-transport_ats.h gnunet-service-transport_ats.c \
 gnunet-service-transport_hello.h gnunet-service-transport_hello.c \
 gnunet-service-transport_neighbours.h gnunet-service-transport_neighbours.c \
 gnunet-service-transport_plugins.h gnunet-service-transport_plugins.c \
 gnunet-service-transport_validation.h gnunet-service-transport_validation.c \
 gnunet-service-transport_manipulation.h gnunet-service-transport_manipulation.c
# Note that while gnunet-service-transport does not use libgnunetnat
# directly, we must link against it as GNUNET_NAT_mini_map_stop will
# leave a 'dangling' task to process_unmap_output which will cause
# a crash on unloading of a plugin unless the service links against
# that library as well.
gnunet_service_transport_LDADD = \
  libgnunettransport.la \
  $(top_builddir)/src/ats/libgnunetats.la \
  $(top_builddir)/src/hello/libgnunethello.la \
  $(top_builddir)/src/nt/libgnunetnt.la \
  $(top_builddir)/src/peerinfo/libgnunetpeerinfo.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_GLPK) \
  $(GN_LIBINTL)
gnunet_service_transport_CFLAGS = \
  $(AM_CFLAGS)
# -DANALYZE


gnunet_service_tng_SOURCES = \
 gnunet-service-tng.c
gnunet_service_tng_LDADD = \
  $(top_builddir)/src/peerstore/libgnunetpeerstore.la \
  $(top_builddir)/src/hello/libgnunethello.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(LIBGCRYPT_LIBS) \
  $(GN_LIBINTL)

plugin_LTLIBRARIES = \
  libgnunet_plugin_transport_tcp.la \
  $(UNIX_PLUGIN_LA) \
  $(HTTP_CLIENT_PLUGIN_LA) \
  $(HTTPS_CLIENT_PLUGIN_LA) \
  $(HTTP_SERVER_PLUGIN_LA) \
  $(HTTPS_SERVER_PLUGIN_LA) \
  $(WLAN_PLUGIN_LA) \
  $(BT_PLUGIN_LA)

if HAVE_EXPERIMENTAL
plugin_LTLIBRARIES += libgnunet_plugin_transport_udp.la
endif

# Note: real plugins of course need to be added
# to the plugin_LTLIBRARIES above
noinst_LTLIBRARIES = \
  libgnunet_plugin_transport_template.la

libgnunet_plugin_transport_tcp_la_SOURCES = \
  plugin_transport_tcp.c
libgnunet_plugin_transport_tcp_la_LIBADD = \
  $(top_builddir)/src/hello/libgnunethello.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/peerinfo/libgnunetpeerinfo.la \
  $(top_builddir)/src/nat/libgnunetnatnew.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(LTLIBINTL)
libgnunet_plugin_transport_tcp_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)

libgnunet_plugin_transport_template_la_SOURCES = \
  plugin_transport_template.c
libgnunet_plugin_transport_template_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(LTLIBINTL)
libgnunet_plugin_transport_template_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)

libgnunet_plugin_transport_wlan_la_SOURCES = \
  plugin_transport_wlan.c plugin_transport_wlan.h
libgnunet_plugin_transport_wlan_la_LIBADD = \
  $(top_builddir)/src/hello/libgnunethello.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/peerinfo/libgnunetpeerinfo.la \
  $(top_builddir)/src/fragmentation/libgnunetfragmentation.la \
  $(top_builddir)/src/util/libgnunetutil.la
libgnunet_plugin_transport_wlan_la_LDFLAGS = \
  $(GN_PLUGIN_LDFLAGS)
libgnunet_plugin_transport_wlan_la_CFLAGS = \
 $(AM_CFLAGS) -DBUILD_WLAN

libgnunet_plugin_transport_bluetooth_la_SOURCES = \
  plugin_transport_wlan.c plugin_transport_wlan.h
libgnunet_plugin_transport_bluetooth_la_LIBADD = \
  $(top_builddir)/src/hello/libgnunethello.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/peerinfo/libgnunetpeerinfo.la \
  $(top_builddir)/src/fragmentation/libgnunetfragmentation.la \
  $(top_builddir)/src/util/libgnunetutil.la
libgnunet_plugin_transport_bluetooth_la_LDFLAGS = \
  $(GN_PLUGIN_LDFLAGS)
libgnunet_plugin_transport_bluetooth_la_CFLAGS = \
 $(AM_CFLAGS) -DBUILD_BLUETOOTH

if HAVE_EXPERIMENTAL
libgnunet_plugin_transport_udp_la_SOURCES = \
  plugin_transport_udp.c plugin_transport_udp.h \
  plugin_transport_udp_broadcasting.c
libgnunet_plugin_transport_udp_la_LIBADD = \
  $(top_builddir)/src/hello/libgnunethello.la \
  $(top_builddir)/src/fragmentation/libgnunetfragmentation.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/peerinfo/libgnunetpeerinfo.la \
  $(top_builddir)/src/nat/libgnunetnatnew.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(LTLIBINTL)
libgnunet_plugin_transport_udp_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)
endif

libgnunet_plugin_transport_unix_la_SOURCES = \
  plugin_transport_unix.c
libgnunet_plugin_transport_unix_la_LIBADD = \
  $(top_builddir)/src/hello/libgnunethello.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/peerinfo/libgnunetpeerinfo.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(LTLIBINTL)
libgnunet_plugin_transport_unix_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)


libgnunet_plugin_transport_http_client_la_SOURCES = \
  plugin_transport_http_client.c plugin_transport_http_common.c plugin_transport_http_common.h
libgnunet_plugin_transport_http_client_la_LIBADD = \
  $(top_builddir)/src/hello/libgnunethello.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/peerinfo/libgnunetpeerinfo.la \
  $(LIB_GNURL) \
  $(top_builddir)/src/util/libgnunetutil.la
libgnunet_plugin_transport_http_client_la_LDFLAGS = \
  $(GN_LIBINTL) \
  $(GN_PLUGIN_LDFLAGS)
libgnunet_plugin_transport_http_client_la_CFLAGS = \
 $(CPP_GNURL) $(AM_CFLAGS)


libgnunet_plugin_transport_http_server_la_SOURCES = \
  plugin_transport_http_server.c plugin_transport_http_common.c
libgnunet_plugin_transport_http_server_la_LIBADD = \
  $(MHD_LIBS) \
  $(top_builddir)/src/hello/libgnunethello.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/peerinfo/libgnunetpeerinfo.la \
  $(top_builddir)/src/nat/libgnunetnatnew.la \
  $(top_builddir)/src/util/libgnunetutil.la
libgnunet_plugin_transport_http_server_la_LDFLAGS = \
  $(GN_LIBINTL) \
 $(GN_PLUGIN_LDFLAGS)
libgnunet_plugin_transport_http_server_la_CFLAGS = \
 $(MHD_CFLAGS) $(AM_CFLAGS)

libgnunet_plugin_transport_https_client_la_SOURCES = \
  plugin_transport_http_client.c plugin_transport_http_common.c
libgnunet_plugin_transport_https_client_la_LIBADD = \
  $(top_builddir)/src/hello/libgnunethello.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/peerinfo/libgnunetpeerinfo.la \
  $(LIB_GNURL) \
  $(top_builddir)/src/util/libgnunetutil.la
libgnunet_plugin_transport_https_client_la_LDFLAGS = \
  $(GN_LIBINTL) \
  $(GN_PLUGIN_LDFLAGS)
libgnunet_plugin_transport_https_client_la_CFLAGS = \
 $(CPP_GNURL) $(AM_CFLAGS) -DBUILD_HTTPS


libgnunet_plugin_transport_https_server_la_SOURCES = \
  plugin_transport_http_server.c plugin_transport_http_common.c
libgnunet_plugin_transport_https_server_la_LIBADD = \
  $(MHD_LIBS) \
  $(top_builddir)/src/hello/libgnunethello.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/peerinfo/libgnunetpeerinfo.la \
  $(top_builddir)/src/nat/libgnunetnatnew.la \
  $(top_builddir)/src/util/libgnunetutil.la
libgnunet_plugin_transport_https_server_la_LDFLAGS = \
  $(GN_LIBINTL) \
 $(GN_PLUGIN_LDFLAGS)
libgnunet_plugin_transport_https_server_la_CFLAGS = \
 $(MHD_CFLAGS) $(AM_CFLAGS) -DBUILD_HTTPS

if HAVE_TESTING
check_PROGRAMS = \
 test_transport_address_switch_tcp \
 test_transport_testing_startstop \
 test_transport_testing_restart \
 test_plugin_tcp \
 $(UNIX_TEST) \
 $(WLAN_PLUGIN_TEST) \
 $(BT_PLUGIN_TEST) \
 test_http_common \
 $(HTTP_CLIENT_PLUGIN_TEST) \
 $(HTTPS_CLIENT_PLUGIN_TEST) \
 $(HTTP_SERVER_PLUGIN_TEST) \
 $(HTTPS_SERVER_PLUGIN_TEST) \
 test_transport_api_blacklisting_tcp \
 test_transport_api_disconnect_tcp \
 test_transport_api_tcp \
 test_transport_api_restart_1peer \
 test_transport_api_restart_2peers \
 test_transport_api_timeout_tcp \
 test_transport_api_limited_sockets_tcp \
 test_transport_api_tcp_nat \
 $(UNIX_PLUGIN_TEST) \
 $(UNIX_PLUGIN_TIMEOUT_TEST) \
 $(UNIX_API_ABSTRACT_TEST) \
 $(HTTP_API_TEST) \
 $(HTTP_REVERSE_API_TEST) \
 $(HTTP_API_TIMEOUT_TEST) \
 $(HTTP_SWITCH) \
 $(HTTPS_API_TEST) \
 $(HTTPS_API_TIMEOUT_TEST) \
 $(HTTPS_SWITCH) \
 $(WLAN_API_TEST) \
 $(WLAN_TIMEOUT_TEST) \
 $(BT_API_TEST) \
 $(BT_TIMEOUT_TEST) \
 test_transport_api_multi \
 test_transport_api_monitor_peers \
 test_transport_blacklisting_no_bl \
 test_transport_blacklisting_outbound_bl_full \
 test_transport_blacklisting_outbound_bl_plugin \
 test_transport_blacklisting_inbound_bl_plugin \
 test_transport_blacklisting_inbound_bl_full \
 test_transport_blacklisting_multiple_plugins \
 test_transport_api_manipulation_send_tcp \
 test_transport_api_manipulation_recv_tcp \
 test_transport_api_manipulation_cfg \
 test_transport_api_reliability_tcp \
 test_transport_api_reliability_tcp_nat \
 $(UNIX_REL_TEST) \
 $(HTTP_REL_TEST) \
 $(HTTPS_REL_TEST) \
 $(WLAN_REL_TEST) \
 $(WLAN_UREL_TEST) \
 $(BT_REL_TEST) \
 $(BT_UREL_TEST) \
 test_quota_compliance_tcp \
 test_quota_compliance_tcp_asymmetric \
 $(UNIX_QUOTA_TEST) \
 $(HTTP_QUOTA_TEST) \
 $(HTTPS_QUOTA_TEST) \
 $(WLAN_QUOTA_TEST) \
 $(BT_QUOTA_TEST)
if HAVE_GETOPT_BINARY
check_PROGRAMS += \
test_transport_api_slow_ats
endif
if HAVE_EXPERIMENTAL
check_PROGRAMS += \
  test_transport_address_switch_udp \
  test_plugin_udp \
  test_transport_api_udp \
  test_transport_api_timeout_udp \
  test_transport_api_udp_nat \
  test_transport_api_reliability_udp \
  test_quota_compliance_udp \
  test_communicator_basic-unix \
  test_communicator_basic-tcp \
  test_communicator_basic-udp \
  test_communicator_rekey-tcp \
  test_communicator_rekey-udp \
  test_communicator_backchannel-udp
endif
endif

if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
TESTS = \
 test_transport_address_switch_tcp \
 $(HTTP_SWITCH) \
 $(HTTPS_SWITCH) \
 test_transport_testing_startstop \
 test_transport_testing_restart \
 test_plugin_tcp \
 $(UNIX_TEST) \
 $(WLAN_PLUGIN_TEST) \
 $(BT_PLUGIN_TEST) \
 test_transport_api_blacklisting_tcp \
 test_transport_api_disconnect_tcp \
 test_transport_api_tcp \
 test_transport_api_restart_1peer \
 test_transport_api_restart_2peers \
 test_transport_api_limited_sockets_tcp \
 test_transport_api_tcp_nat \
 $(UNIX_PLUGIN_TEST) \
 $(UNIX_API_ABSTRACT_TEST) \
 $(HTTP_API_TEST) \
 $(HTTPS_API_TEST) \
 $(WLAN_API_TEST) \
 $(BT_API_TEST) \
 test_transport_api_multi \
 test_transport_api_monitor_peers \
 test_transport_blacklisting_no_bl \
 test_transport_blacklisting_outbound_bl_full \
 test_transport_blacklisting_outbound_bl_plugin \
 test_transport_blacklisting_inbound_bl_plugin \
 test_transport_blacklisting_inbound_bl_full \
 test_transport_blacklisting_multiple_plugins \
 test_transport_api_manipulation_send_tcp \
 test_transport_api_manipulation_recv_tcp \
 test_transport_api_manipulation_cfg \
 test_transport_api_reliability_tcp \
 test_transport_api_reliability_tcp_nat \
 $(UNIX_REL_TEST) \
 $(HTTP_REL_TEST) \
 $(HTTPS_REL_TEST) \
 $(WLAN_REL_TEST) \
 $(WLAN_UREL_TEST) \
 $(BT_REL_TEST) \
 $(BT_UREL_TEST) \
 test_quota_compliance_tcp \
 test_quota_compliance_tcp_asymmetric \
 $(UNIX_QUOTA_TEST) \
 $(HTTP_QUOTA_TEST) \
 $(HTTPS_QUOTA_TEST) \
 test_transport_api_timeout_tcp \
 $(UNIX_PLUGIN_TIMEOUT_TEST) \
 $(HTTP_API_TIMEOUT_TEST) \
 $(HTTPS_API_TIMEOUT_TEST) \
 $(WLAN_TIMEOUT_TEST) \
 $(BT_TIMEOUT_TEST)
if HAVE_GETOPT_BINARY
TESTS += \
test_transport_api_slow_ats
endif
if HAVE_EXPERIMENTAL
TESTS += \
  test_transport_address_switch_udp \
  test_plugin_udp \
  test_transport_api_udp \
  test_transport_api_timeout_udp \
  test_transport_api_udp_nat \
  test_transport_api_reliability_udp \
  test_quota_compliance_udp \
  test_communicator_basic-unix \
  test_communicator_basic-tcp \
  test_communicator_basic-udp \
  test_communicator_rekey-tcp \
  test_communicator_rekey-udp \
  test_communicator_backchannel-udp
endif
endif

test_transport_testing_startstop_SOURCES = \
 test_transport_testing_startstop.c
test_transport_testing_startstop_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettransport.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 libgnunettransporttesting.la

test_transport_testing_restart_SOURCES = \
 test_transport_testing_restart.c
test_transport_testing_restart_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettransport.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 libgnunettransporttesting.la

test_transport_api_blacklisting_tcp_SOURCES = \
 test_transport_api_blacklisting.c
test_transport_api_blacklisting_tcp_LDADD = \
 libgnunettransport.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/statistics/libgnunetstatistics.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettransporttesting.la

test_transport_blacklisting_no_bl_SOURCES = \
 test_transport_blacklisting.c
test_transport_blacklisting_no_bl_LDADD = \
 libgnunettransport.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/statistics/libgnunetstatistics.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettransporttesting.la

test_transport_blacklisting_outbound_bl_full_SOURCES = \
 test_transport_blacklisting.c
test_transport_blacklisting_outbound_bl_full_LDADD = \
 libgnunettransport.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/statistics/libgnunetstatistics.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettransporttesting.la

test_transport_blacklisting_outbound_bl_plugin_SOURCES = \
 test_transport_blacklisting.c
test_transport_blacklisting_outbound_bl_plugin_LDADD = \
 libgnunettransport.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/statistics/libgnunetstatistics.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettransporttesting.la

test_transport_blacklisting_inbound_bl_full_SOURCES = \
 test_transport_blacklisting.c
test_transport_blacklisting_inbound_bl_full_LDADD = \
 libgnunettransport.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/statistics/libgnunetstatistics.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettransporttesting.la

test_transport_blacklisting_inbound_bl_plugin_SOURCES = \
 test_transport_blacklisting.c
test_transport_blacklisting_inbound_bl_plugin_LDADD = \
 libgnunettransport.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/statistics/libgnunetstatistics.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettransporttesting.la

test_transport_blacklisting_multiple_plugins_SOURCES = \
 test_transport_blacklisting.c
test_transport_blacklisting_multiple_plugins_LDADD = \
 libgnunettransport.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/statistics/libgnunetstatistics.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettransporttesting.la


test_transport_api_disconnect_tcp_SOURCES = \
 test_transport_api_disconnect.c
test_transport_api_disconnect_tcp_LDADD = \
 libgnunettransport.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/statistics/libgnunetstatistics.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettransporttesting.la

test_plugin_tcp_SOURCES = \
 test_plugin_transport.c
test_plugin_tcp_LDADD = \
 libgnunettransport.la \
 $(top_builddir)/src/statistics/libgnunetstatistics.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la  \
 libgnunettransporttesting.la

if HAVE_EXPERIMENTAL
test_plugin_udp_SOURCES = \
 test_plugin_transport.c
test_plugin_udp_LDADD = \
 libgnunettransport.la \
 $(top_builddir)/src/statistics/libgnunetstatistics.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la  \
 libgnunettransporttesting.la
endif

if HAVE_EXPERIMENTAL
test_communicator_basic_unix_SOURCES = \
 test_communicator_basic.c
test_communicator_basic_unix_LDADD = \
 libgnunettransporttesting2.la \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/util/libgnunetutil.la

test_communicator_basic_tcp_SOURCES = \
 test_communicator_basic.c
test_communicator_basic_tcp_LDADD = \
 libgnunettransporttesting2.la \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/util/libgnunetutil.la

test_communicator_basic_udp_SOURCES = \
 test_communicator_basic.c
test_communicator_basic_udp_LDADD = \
 libgnunettransporttesting2.la \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/util/libgnunetutil.la

test_communicator_rekey_tcp_SOURCES = \
 test_communicator_basic.c
test_communicator_rekey_tcp_LDADD = \
 libgnunettransporttesting2.la \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/util/libgnunetutil.la

test_communicator_rekey_udp_SOURCES = \
 test_communicator_basic.c
test_communicator_rekey_udp_LDADD = \
 libgnunettransporttesting2.la \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/util/libgnunetutil.la

test_communicator_backchannel_udp_SOURCES = \
 test_communicator_basic.c
test_communicator_backchannel_udp_LDADD = \
 libgnunettransporttesting2.la \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/util/libgnunetutil.la
endif

test_plugin_unix_SOURCES = \
 test_plugin_transport.c
test_plugin_unix_LDADD = \
 libgnunettransport.la \
 $(top_builddir)/src/statistics/libgnunetstatistics.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la  \
 libgnunettransporttesting.la

test_plugin_wlan_SOURCES = \
 test_plugin_transport.c
test_plugin_wlan_LDADD = \
 libgnunettransport.la \
 $(top_builddir)/src/statistics/libgnunetstatistics.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la  \
 libgnunettransporttesting.la

test_plugin_bluetooth_SOURCES = \
 test_plugin_transport.c
test_plugin_bluetooth_LDADD = \
 libgnunettransport.la \
 $(top_builddir)/src/statistics/libgnunetstatistics.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la  \
 libgnunettransporttesting.la

test_http_common_SOURCES = \
 test_http_common.c plugin_transport_http_common.c
test_http_common_LDADD = \
 libgnunettransport.la \
 $(top_builddir)/src/statistics/libgnunetstatistics.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la  \
 libgnunettransporttesting.la

test_plugin_http_server_SOURCES = \
 test_plugin_transport.c
test_plugin_http_server_LDADD = \
 libgnunettransport.la \
 $(top_builddir)/src/statistics/libgnunetstatistics.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la  \
 libgnunettransporttesting.la

test_plugin_https_server_SOURCES = \
 test_plugin_transport.c
test_plugin_https_server_LDADD = \
 libgnunettransport.la \
 $(top_builddir)/src/statistics/libgnunetstatistics.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la  \
 libgnunettransporttesting.la

test_plugin_http_client_SOURCES = \
 test_plugin_transport.c
test_plugin_http_client_LDADD = \
 libgnunettransport.la \
 $(top_builddir)/src/statistics/libgnunetstatistics.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la  \
 libgnunettransporttesting.la

test_plugin_https_client_SOURCES = \
 test_plugin_transport.c
test_plugin_https_client_LDADD = \
 libgnunettransport.la \
 $(top_builddir)/src/statistics/libgnunetstatistics.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la  \
 libgnunettransporttesting.la

test_transport_api_tcp_SOURCES = \
 test_transport_api.c
test_transport_api_tcp_LDADD = \
 libgnunettransport.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la  \
 libgnunettransporttesting.la

test_transport_api_restart_1peer_SOURCES = \
 test_transport_api_restart_reconnect.c
test_transport_api_restart_1peer_LDADD = \
 libgnunettransport.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/ats/libgnunetats.la \
 $(top_builddir)/src/statistics/libgnunetstatistics.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettransporttesting.la

test_transport_api_restart_2peers_SOURCES = \
 test_transport_api_restart_reconnect.c
test_transport_api_restart_2peers_LDADD = \
 libgnunettransport.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/ats/libgnunetats.la \
$(top_builddir)/src/statistics/libgnunetstatistics.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettransporttesting.la

test_transport_api_limited_sockets_tcp_SOURCES = \
 test_transport_api_limited_sockets.c
test_transport_api_limited_sockets_tcp_LDADD = \
 libgnunettransport.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la  \
 libgnunettransporttesting.la

test_transport_api_tcp_nat_SOURCES = \
 test_transport_api.c
test_transport_api_tcp_nat_LDADD = \
 libgnunettransport.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettransporttesting.la

test_transport_api_manipulation_send_tcp_SOURCES = \
 test_transport_api_manipulation_send_tcp.c
test_transport_api_manipulation_send_tcp_LDADD = \
 libgnunettransport.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettransporttesting.la

test_transport_api_manipulation_recv_tcp_SOURCES = \
 test_transport_api_manipulation_recv_tcp.c
test_transport_api_manipulation_recv_tcp_LDADD = \
 libgnunettransport.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettransporttesting.la

test_transport_api_manipulation_cfg_SOURCES = \
 test_transport_api_manipulation_cfg.c
test_transport_api_manipulation_cfg_LDADD = \
 libgnunettransport.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettransporttesting.la

test_transport_api_reliability_tcp_SOURCES = \
 test_transport_api_reliability.c
test_transport_api_reliability_tcp_LDADD = \
 libgnunettransport.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettransporttesting.la

test_transport_api_timeout_tcp_SOURCES = \
 test_transport_api_timeout.c
test_transport_api_timeout_tcp_LDADD = \
 libgnunettransport.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettransporttesting.la

test_transport_api_timeout_unix_SOURCES = \
 test_transport_api_timeout.c
test_transport_api_timeout_unix_LDADD = \
 libgnunettransport.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettransporttesting.la

test_transport_api_timeout_wlan_SOURCES = \
 test_transport_api_timeout.c
test_transport_api_timeout_wlan_LDADD = \
 libgnunettransport.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettransporttesting.la

test_transport_api_timeout_bluetooth_SOURCES = \
 test_transport_api_timeout.c
test_transport_api_timeout_bluetooth_LDADD = \
 libgnunettransport.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettransporttesting.la

test_transport_api_reliability_tcp_nat_SOURCES = \
 test_transport_api_reliability.c
test_transport_api_reliability_tcp_nat_LDADD = \
 libgnunettransport.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettransporttesting.la

test_transport_api_reliability_bluetooth_SOURCES = \
 test_transport_api_reliability.c
test_transport_api_reliability_bluetooth_LDADD = \
 libgnunettransport.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettransporttesting.la

test_transport_api_reliability_wlan_SOURCES = \
 test_transport_api_reliability.c
test_transport_api_reliability_wlan_LDADD = \
 libgnunettransport.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettransporttesting.la

if HAVE_EXPERIMENTAL
test_transport_api_udp_SOURCES = \
 test_transport_api.c
test_transport_api_udp_LDADD = \
 libgnunettransport.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la  \
 libgnunettransporttesting.la

test_transport_api_timeout_udp_SOURCES = \
 test_transport_api_timeout.c
test_transport_api_timeout_udp_LDADD = \
 libgnunettransport.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettransporttesting.la

test_transport_api_udp_nat_SOURCES = \
 test_transport_api.c
test_transport_api_udp_nat_LDADD = \
 libgnunettransport.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la  \
 libgnunettransporttesting.la
endif

test_transport_api_unix_SOURCES = \
 test_transport_api.c
test_transport_api_unix_LDADD = \
 libgnunettransport.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettransporttesting.la

test_transport_api_unix_abstract_SOURCES = \
 test_transport_api.c
test_transport_api_unix_abstract_LDADD = \
 libgnunettransport.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettransporttesting.la

# HTTP tests
test_transport_api_http_SOURCES = \
 test_transport_api.c
test_transport_api_http_LDADD = \
 libgnunettransport.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettransporttesting.la

test_transport_api_http_reverse_SOURCES = \
 test_transport_api.c
test_transport_api_http_reverse_LDADD = \
 libgnunettransport.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettransporttesting.la

test_transport_api_timeout_http_SOURCES = \
 test_transport_api_timeout.c
test_transport_api_timeout_http_LDADD = \
 libgnunettransport.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettransporttesting.la

test_transport_api_reliability_http_SOURCES = \
 test_transport_api_reliability.c
test_transport_api_reliability_http_LDADD = \
 libgnunettransport.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettransporttesting.la

test_transport_api_reliability_http_xhr_SOURCES = \
 test_transport_api_reliability.c
test_transport_api_reliability_http_xhr_LDADD = \
 libgnunettransport.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettransporttesting.la

test_quota_compliance_http_SOURCES = \
 test_quota_compliance.c
test_quota_compliance_http_LDADD = \
 libgnunettransport.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/ats/libgnunetats.la \
 $(top_builddir)/src/nt/libgnunetnt.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettransporttesting.la

test_quota_compliance_http_asymmetric_SOURCES = \
 test_quota_compliance.c
test_quota_compliance_http_asymmetric_LDADD = \
 libgnunettransport.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/ats/libgnunetats.la \
 $(top_builddir)/src/nt/libgnunetnt.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettransporttesting.la

test_quota_compliance_https_SOURCES = \
 test_quota_compliance.c
test_quota_compliance_https_LDADD = \
 libgnunettransport.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/ats/libgnunetats.la \
 $(top_builddir)/src/nt/libgnunetnt.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettransporttesting.la

test_quota_compliance_https_asymmetric_SOURCES = \
 test_quota_compliance.c
test_quota_compliance_https_asymmetric_LDADD = \
 libgnunettransport.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/ats/libgnunetats.la \
 $(top_builddir)/src/nt/libgnunetnt.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettransporttesting.la

# HTTPS tests
test_transport_api_https_SOURCES = \
 test_transport_api.c
test_transport_api_https_LDADD = \
 libgnunettransport.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la  \
 libgnunettransporttesting.la

test_transport_api_timeout_https_SOURCES = \
 test_transport_api_timeout.c
test_transport_api_timeout_https_LDADD = \
 libgnunettransport.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettransporttesting.la


test_transport_api_reliability_https_SOURCES = \
 test_transport_api_reliability.c
test_transport_api_reliability_https_LDADD = \
 libgnunettransport.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettransporttesting.la

test_transport_api_reliability_https_xhr_SOURCES = \
 test_transport_api_reliability.c
test_transport_api_reliability_https_xhr_LDADD = \
 libgnunettransport.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettransporttesting.la

test_transport_api_reliability_unix_SOURCES = \
 test_transport_api_reliability.c
test_transport_api_reliability_unix_LDADD = \
 libgnunettransport.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettransporttesting.la

if HAVE_EXPERIMENTAL
test_transport_api_reliability_udp_SOURCES = \
 test_transport_api_reliability.c
test_transport_api_reliability_udp_LDADD = \
 libgnunettransport.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettransporttesting.la
endif

if LINUX
test_transport_api_wlan_SOURCES = \
 test_transport_api.c
test_transport_api_wlan_LDADD = \
 libgnunettransport.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettransporttesting.la
endif

if LINUX
if HAVE_LIBBLUETOOTH
test_transport_api_bluetooth_SOURCES = \
 test_transport_api.c
test_transport_api_bluetooth_LDADD = \
 libgnunettransport.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettransporttesting.la
endif
endif

test_transport_address_switch_tcp_SOURCES = \
 test_transport_address_switch.c
test_transport_address_switch_tcp_LDADD = \
 libgnunettransport.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/statistics/libgnunetstatistics.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettransporttesting.la

if HAVE_EXPERIMENTAL
test_transport_address_switch_udp_SOURCES = \
 test_transport_address_switch.c
test_transport_address_switch_udp_LDADD = \
 libgnunettransport.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/statistics/libgnunetstatistics.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettransporttesting.la
endif

 test_transport_address_switch_http_SOURCES = \
 test_transport_address_switch.c
test_transport_address_switch_http_LDADD = \
 libgnunettransport.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/statistics/libgnunetstatistics.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettransporttesting.la

 test_transport_address_switch_https_SOURCES = \
 test_transport_address_switch.c
test_transport_address_switch_https_LDADD = \
 libgnunettransport.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/statistics/libgnunetstatistics.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettransporttesting.la

test_quota_compliance_tcp_SOURCES = \
 test_quota_compliance.c
test_quota_compliance_tcp_LDADD = \
 libgnunettransport.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/ats/libgnunetats.la \
 $(top_builddir)/src/nt/libgnunetnt.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettransporttesting.la

test_quota_compliance_tcp_asymmetric_SOURCES = \
 test_quota_compliance.c
test_quota_compliance_tcp_asymmetric_LDADD = \
 libgnunettransport.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/nt/libgnunetnt.la \
 $(top_builddir)/src/ats/libgnunetats.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettransporttesting.la

if HAVE_EXPERIMENTAL
test_quota_compliance_udp_SOURCES = \
 test_quota_compliance.c
test_quota_compliance_udp_LDADD = \
 libgnunettransport.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/ats/libgnunetats.la \
 $(top_builddir)/src/nt/libgnunetnt.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettransporttesting.la
endif

test_quota_compliance_unix_SOURCES = \
 test_quota_compliance.c
test_quota_compliance_unix_LDADD = \
 libgnunettransport.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/ats/libgnunetats.la \
 $(top_builddir)/src/nt/libgnunetnt.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettransporttesting.la

test_quota_compliance_unix_asymmetric_SOURCES = \
 test_quota_compliance.c
test_quota_compliance_unix_asymmetric_LDADD = \
 libgnunettransport.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/ats/libgnunetats.la \
 $(top_builddir)/src/nt/libgnunetnt.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettransporttesting.la

test_quota_compliance_wlan_SOURCES = \
 test_quota_compliance.c
test_quota_compliance_wlan_LDADD = \
 libgnunettransport.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/ats/libgnunetats.la \
 $(top_builddir)/src/nt/libgnunetnt.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettransporttesting.la

test_quota_compliance_wlan_asymmetric_SOURCES = \
 test_quota_compliance.c
test_quota_compliance_wlan_asymmetric_LDADD = \
 libgnunettransport.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/ats/libgnunetats.la \
 $(top_builddir)/src/nt/libgnunetnt.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettransporttesting.la

test_quota_compliance_bluetooth_SOURCES = \
 test_quota_compliance.c
test_quota_compliance_bluetooth_LDADD = \
 libgnunettransport.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/ats/libgnunetats.la \
 $(top_builddir)/src/nt/libgnunetnt.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettransporttesting.la

test_quota_compliance_bluetooth_asymmetric_SOURCES = \
 test_quota_compliance.c
test_quota_compliance_bluetooth_asymmetric_LDADD = \
 libgnunettransport.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/ats/libgnunetats.la \
 $(top_builddir)/src/nt/libgnunetnt.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettransporttesting.la

test_transport_api_multi_SOURCES = \
 test_transport_api.c
test_transport_api_multi_LDADD = \
 libgnunettransport.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettransporttesting.la

test_transport_api_monitor_peers_SOURCES = \
 test_transport_api_monitor_peers.c
test_transport_api_monitor_peers_LDADD = \
 libgnunettransport.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettransporttesting.la

test_transport_api_slow_ats_SOURCES = \
 test_transport_api.c
test_transport_api_slow_ats_LDADD = \
 libgnunettransport.la \
 $(top_builddir)/src/hello/libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la  \
 libgnunettransporttesting.la


EXTRA_DIST = \
gnunet-transport-certificate-creation.in \
communicator-unix.conf \
test_plugin_hostkey \
test_plugin_hostkey.ecc \
test_delay \
template_cfg_peer1.conf\
template_cfg_peer2.conf\
test_plugin_transport_data.conf\
test_plugin_transport_data_udp.conf\
test_quota_compliance_data.conf\
test_quota_compliance_http_peer1.conf\
test_quota_compliance_http_peer2.conf\
test_quota_compliance_https_peer1.conf\
test_quota_compliance_https_peer2.conf\
test_quota_compliance_tcp_peer1.conf\
test_quota_compliance_tcp_peer2.conf\
test_quota_compliance_udp_peer1.conf\
test_quota_compliance_udp_peer2.conf\
test_quota_compliance_unix_peer1.conf\
test_quota_compliance_unix_peer2.conf\
test_quota_compliance_wlan_peer1.conf\
test_quota_compliance_wlan_peer2.conf\
test_quota_compliance_bluetooth_peer1.conf\
test_quota_compliance_bluetooth_peer2.conf\
test_quota_compliance_http_asymmetric_peer1.conf\
test_quota_compliance_http_asymmetric_peer2.conf\
test_quota_compliance_https_asymmetric_peer1.conf\
test_quota_compliance_https_asymmetric_peer2.conf\
test_quota_compliance_tcp_asymmetric_peer1.conf\
test_quota_compliance_tcp_asymmetric_peer2.conf\
test_quota_compliance_unix_asymmetric_peer1.conf\
test_quota_compliance_unix_asymmetric_peer2.conf\
test_quota_compliance_wlan_asymmetric_peer1.conf\
test_quota_compliance_wlan_asymmetric_peer2.conf\
test_quota_compliance_bluetooth_asymmetric_peer1.conf\
test_quota_compliance_bluetooth_asymmetric_peer2.conf\
test_transport_api_data.conf\
test_transport_api_blacklisting_tcp_peer1.conf \
test_transport_api_blacklisting_tcp_peer2.conf \
test_transport_api_http_peer1.conf\
test_transport_api_http_peer2.conf\
test_transport_api_https_peer1.conf\
test_transport_api_https_peer2.conf\
test_transport_api_limited_sockets_tcp_peer1.conf\
test_transport_api_limited_sockets_tcp_peer2.conf\
test_transport_api_timeout_tcp_peer1.conf\
test_transport_api_timeout_tcp_peer2.conf\
test_transport_api_multi_peer1.conf\
test_transport_api_multi_peer2.conf\
test_transport_api_restart_1peer_peer1.conf\
test_transport_api_restart_1peer_peer2.conf\
test_transport_api_reliability_http_peer1.conf\
test_transport_api_reliability_http_peer2.conf\
test_transport_api_reliability_https_peer1.conf\
test_transport_api_reliability_https_peer2.conf\
test_transport_api_reliability_tcp_nat_peer1.conf\
test_transport_api_reliability_tcp_nat_peer2.conf\
test_transport_api_reliability_tcp_peer1.conf\
test_transport_api_reliability_tcp_peer2.conf\
test_transport_api_reliability_wlan_peer1.conf\
test_transport_api_reliability_wlan_peer2.conf\
test_transport_api_reliability_bluetooth_peer1.conf\
test_transport_api_reliability_bluetooth_peer2.conf\
test_transport_api_manipulation_send_tcp_peer1.conf\
test_transport_api_manipulation_send_tcp_peer2.conf\
test_transport_api_manipulation_recv_tcp_peer1.conf\
test_transport_api_manipulation_recv_tcp_peer2.conf\
test_transport_api_manipulation_cfg_peer1.conf\
test_transport_api_manipulation_cfg_peer2.conf\
test_transport_api_restart_1peer_peer1.conf\
test_transport_api_restart_1peer_peer2.conf\
test_transport_api_restart_2peers_peer1.conf\
test_transport_api_restart_2peers_peer2.conf\
test_transport_api_tcp_nat_peer1.conf\
test_transport_api_tcp_nat_peer2.conf\
test_transport_api_tcp_peer1.conf\
test_transport_api_tcp_peer2.conf\
test_transport_api_udp_nat_peer1.conf\
test_transport_api_udp_nat_peer2.conf\
test_transport_api_udp_peer1.conf\
test_transport_api_udp_peer2.conf\
test_transport_api_timeout_udp_peer1.conf\
test_transport_api_timeout_udp_peer2.conf\
test_transport_api_unix_peer1.conf\
test_transport_api_unix_peer2.conf\
test_transport_api_unix_abstract_peer1.conf \
test_transport_api_unix_abstract_peer2.conf \
test_transport_api_timeout_unix_peer1.conf\
test_transport_api_timeout_unix_peer2.conf\
test_transport_api_timeout_wlan_peer1.conf \
test_transport_api_timeout_wlan_peer2.conf \
test_transport_api_timeout_bluetooth_peer1.conf\
test_transport_api_timeout_bluetooth_peer2.conf\
test_transport_api_reliability_udp_peer1.conf\
test_transport_api_reliability_udp_peer2.conf\
test_transport_api_reliability_http_xhr_peer1.conf\
test_transport_api_reliability_http_xhr_peer2.conf\
test_transport_api_reliability_https_xhr_peer1.conf\
test_transport_api_reliability_https_xhr_peer2.conf\
test_transport_api_reliability_unix_peer1.conf\
test_transport_api_reliability_unix_peer2.conf\
test_transport_api_reliability_wlan_peer1.conf\
test_transport_api_reliability_wlan_peer2.conf\
test_transport_api_unreliability_wlan_peer1.conf\
test_transport_api_unreliability_wlan_peer2.conf\
test_transport_api_reliability_bluetooth_peer1.conf\
test_transport_api_reliability_bluetooth_peer2.conf\
test_transport_api_wlan_peer1.conf\
test_transport_api_wlan_peer2.conf\
test_transport_api_bluetooth_peer1.conf\
test_transport_api_bluetooth_peer2.conf\
test_transport_api_monitor_peers_peer1.conf\
test_transport_api_monitor_peers_peer2.conf\
test_transport_api_monitor_validation_peer1.conf\
test_transport_api_monitor_validation_peer2.conf\
test_transport_defaults.conf\
test_transport_api_disconnect_tcp_peer1.conf\
test_transport_api_disconnect_tcp_peer2.conf\
test_transport_api_timeout_http_peer1.conf\
test_transport_api_timeout_http_peer2.conf\
test_transport_api_timeout_https_peer1.conf\
test_transport_api_timeout_https_peer2.conf\
test_transport_blacklisting_cfg_peer1.conf \
test_transport_blacklisting_cfg_peer2.conf \
test_transport_blacklisting_cfg_blp_peer1_full.conf\
test_transport_blacklisting_cfg_blp_peer1_plugin.conf \
test_transport_blacklisting_cfg_blp_peer2_full.conf\
test_transport_blacklisting_cfg_blp_peer2_plugin.conf \
test_transport_blacklisting_cfg_blp_peer1_multiple_plugins.conf \
test_transport_blacklisting_cfg_blp_peer2_multiple_plugins.conf \
test_transport_api_http_reverse_peer1.conf \
test_transport_api_http_reverse_peer2.conf \
perf_tcp_peer1.conf \
perf_tcp_peer2.conf \
test_transport_api_slow_ats_peer1.conf \
test_transport_api_slow_ats_peer2.conf \
  tcp_connection_legacy.c \
  tcp_server_mst_legacy.c \
  tcp_server_legacy.c \
  tcp_service_legacy.c \
test_communicator_unix_basic_peer1.conf \
test_communicator_unix_basic_peer2.conf \
test_communicator_tcp_basic_peer1.conf \
test_communicator_tcp_basic_peer2.conf \
test_communicator_udp_basic_peer1.conf \
test_communicator_udp_basic_peer2.conf \
test_communicator_tcp_rekey_peer1.conf \
test_communicator_tcp_rekey_peer2.conf \
test_communicator_udp_rekey_peer1.conf \
test_communicator_udp_rekey_peer2.conf \
test_communicator_udp_backchannel_peer1.conf \
test_communicator_udp_backchannel_peer2.conf
