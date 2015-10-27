# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

plugindir = $(libdir)/gnunet

libexecdir= $(pkglibdir)/libexec/

pkgcfgdir= $(pkgdatadir)/config.d/

dist_pkgcfg_DATA = \
  util.conf

pkgcfg_DATA = \
  resolver.conf

if MINGW
noinst_LTLIBRARIES = \
  libgnunetutilwin.la
libgnunetutilwin_la_SOURCES = \
  win.c \
  winproc.c
libgnunetutilwin_la_LDFLAGS = \
  -no-undefined -Wl,--export-all-symbols
libgnunetutilwin_la_LIBADD = \
  -lshell32 -liconv -lstdc++ \
  -lcomdlg32 -lgdi32 -liphlpapi
WINLIB = libgnunetutilwin.la
W32CAT = w32cat
W32CONSOLEHELPER = gnunet-helper-w32-console
endif

if !MINGW
 SERVER_CLIENT_UNIX = test_server_with_client_unix
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

w32cat_SOURCES = w32cat.c

gnunet_helper_w32_console_SOURCES = \
  gnunet-helper-w32-console.c \
  gnunet-helper-w32-console.h
gnunet_helper_w32_console_LDADD = \
  libgnunetutil.la

gnunet_config_diff_SOURCES = \
 gnunet-config-diff.c
gnunet_config_diff_LDADD = \
 libgnunetutil.la

test_common_logging_dummy_SOURCES = \
 test_common_logging_dummy.c
test_common_logging_dummy_LDADD = \
 libgnunetutil.la

libgnunetutil_la_SOURCES = \
  bandwidth.c \
  bio.c \
  client.c \
  client_manager.c \
  common_allocation.c \
  common_endian.c \
  common_logging.c \
  configuration.c \
  configuration_loader.c \
  connection.c \
  container_bloomfilter.c \
  container_heap.c \
  container_meta_data.c \
  container_multihashmap.c \
  container_multipeermap.c \
  container_multihashmap32.c \
  crypto_symmetric.c \
  crypto_crc.c \
  crypto_ecc.c \
  crypto_ecc_dlog.c \
  crypto_ecc_setup.c \
  crypto_hash.c \
  crypto_hash_file.c \
  crypto_hkdf.c \
  crypto_kdf.c \
  crypto_mpi.c \
  crypto_paillier.c \
  crypto_random.c \
  crypto_rsa.c \
  disk.c \
  disk_iterator.c \
  disk.h \
  getopt.c \
  getopt_helpers.c \
  helper.c \
  load.c \
  mq.c \
  network.c \
  os_installation.c \
  os_network.c \
  os_priority.c \
  peer.c \
  plugin.c \
  program.c \
  resolver_api.c resolver.h \
  scheduler.c \
  server.c \
  server_mst.c \
  server_nc.c \
  server_tc.c \
  service.c \
  signal.c \
  strings.c \
  time.c \
  socks.c \
  speedup.c speedup.h

libgnunetutil_la_LIBADD = \
  $(GCLIBADD) $(WINLIB) \
  $(LIBGCRYPT_LIBS) \
  $(LTLIBICONV) \
  $(LTLIBINTL) \
  -lltdl $(Z_LIBS) -lunistring $(XLIB)

libgnunetutil_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS) \
  -version-info 13:0:0


libgnunetutil_taler_wallet_la_SOURCES = \
  common_allocation.c \
  common_endian.c \
  common_logging.c \
  container_heap.c \
  container_multihashmap.c \
  container_multihashmap32.c \
  crypto_symmetric.c \
  crypto_crc.c \
  crypto_ecc.c \
  crypto_hash.c \
  crypto_hkdf.c \
  crypto_kdf.c \
  crypto_mpi.c \
  crypto_random.c \
  crypto_rsa.c \
  strings.c \
  time.c

libgnunetutil_taler_wallet_la_LIBADD = \
  $(LIBGCRYPT_LIBS) \
  -lunistring

libgnunetutil_taler_wallet_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS) \
  -version-info 0:0:0

if HAVE_TESTING
  GNUNET_ECC = gnunet-ecc
  GNUNET_SCRYPT = gnunet-scrypt
endif

if TALER_ONLY
lib_LTLIBRARIES = libgnunetutil_taler_wallet.la
else
lib_LTLIBRARIES = libgnunetutil.la

libexec_PROGRAMS = \
 gnunet-service-resolver \
 $(W32CONSOLEHELPER)

bin_SCRIPTS =\
 gnunet-qr

bin_PROGRAMS = \
 gnunet-resolver \
 gnunet-config \
 $(GNUNET_ECC) \
 $(GNUNET_SCRYPT) \
 gnunet-uri

noinst_PROGRAMS = \
 gnunet-config-diff \
 $(W32CAT) \
 test_common_logging_dummy


if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;
TESTS = $(check_PROGRAMS)
endif

endif


do_subst = $(SED) -e 's,[@]PYTHON[@],$(PYTHON),g'

gnunet-qr: gnunet-qr.py.in Makefile
	$(do_subst) < gnunet-qr.py.in > gnunet-qr
	chmod +x gnunet-qr

gnunet_service_resolver_SOURCES = \
 gnunet-service-resolver.c
gnunet_service_resolver_LDADD = \
  libgnunetutil.la \
  $(GN_LIBINTL)


gnunet_resolver_SOURCES = \
 gnunet-resolver.c
gnunet_resolver_LDADD = \
  libgnunetutil.la \
  $(GN_LIBINTL)


gnunet_ecc_SOURCES = \
 gnunet-ecc.c
gnunet_ecc_LDADD = \
  libgnunetutil.la \
  $(GN_LIBINTL) -lgcrypt

gnunet_scrypt_SOURCES = \
 gnunet-scrypt.c
gnunet_scrypt_LDADD = \
  libgnunetutil.la \
  $(GN_LIBINTL) -lgcrypt


gnunet_config_SOURCES = \
 gnunet-config.c
gnunet_config_LDADD = \
  libgnunetutil.la \
  $(GN_LIBINTL)


gnunet_uri_SOURCES = \
 gnunet-uri.c
gnunet_uri_LDADD = \
  libgnunetutil.la \
  $(GN_LIBINTL)

plugin_LTLIBRARIES = \
  libgnunet_plugin_test.la

libgnunet_plugin_test_la_SOURCES = \
  test_plugin_plug.c
libgnunet_plugin_test_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)

if HAVE_BENCHMARKS
 BENCHMARKS = \
  perf_crypto_hash \
  perf_crypto_ecc_dlog \
  perf_crypto_rsa \
  perf_crypto_paillier \
  perf_crypto_symmetric \
  perf_crypto_asymmetric \
  perf_malloc
endif

if HAVE_SSH_KEY
 SSH_USING_TESTS = test_socks.nc
endif

check_PROGRAMS = \
 test_bio \
 test_client.nc \
 $(SSH_USING_TESTS) \
 test_common_allocation \
 test_common_endian \
 test_common_logging \
 test_configuration \
 test_container_bloomfilter \
 test_container_meta_data \
 test_container_multihashmap \
 test_container_multihashmap32 \
 test_container_multipeermap \
 test_container_heap \
 test_crypto_symmetric \
 test_crypto_crc \
 test_crypto_ecdsa \
 test_crypto_eddsa \
 test_crypto_ecdhe \
 test_crypto_ecdh_eddsa \
 test_crypto_ecc_dlog \
 test_crypto_hash \
 test_crypto_hash_context \
 test_crypto_hkdf \
 test_crypto_paillier \
 test_crypto_random \
 test_crypto_rsa \
 test_disk \
 test_getopt \
 test_connection.nc \
 test_connection_addressing.nc \
 test_connection_receive_cancel.nc \
 test_connection_timeout.nc \
 test_connection_timeout_no_connect.nc \
 test_connection_transmit_cancel.nc \
 test_mq \
 test_mq_client.nc \
 test_os_network \
 test_peer \
 test_plugin \
 test_program \
 test_resolver_api.nc \
 test_scheduler \
 test_scheduler_delay \
 test_server.nc \
 test_server_disconnect.nc \
 test_server_with_client.nc \
 test_server_mst_interrupt.nc \
 $(SERVER_CLIENT_UNIX) \
 test_service \
 test_strings \
 test_strings_to_data \
 test_time \
 test_speedup \
 $(BENCHMARKS) \
 test_os_start_process \
 test_common_logging_runtime_loglevels


# Declare .nc (NO-CONCURRENCY) as a test extension so that we can impart
# sequential execution order for them
TEST_EXTENSIONS = .nc
test_connection.log: test_client.log
test_connection_addressing.log: test_connection.log
test_connection_timeout_no_connect.log: test_connection_addressing.log
test_connection_transmit_cancel.log: test_connection_timeout_no_connect.log
test_connection_receive_cancel.log: test_connection_transmit_cancel.log
test_connection_timeout.log: test_connection_receive_cancel.log
test_mq_client.log: test_connection_timeout.log
test_resolver_api.log: test_mq_client.log
test_server.log: test_resolver_api.log
test_server_disconnect.log: test_server.log
test_server_with_client.log: test_server_disconnect.log
test_server_mst_interrupt.log: test_server_with_client.log

test_bio_SOURCES = \
 test_bio.c
test_bio_LDADD = \
 libgnunetutil.la


test_os_start_process_SOURCES = \
 test_os_start_process.c
test_os_start_process_LDADD = \
 libgnunetutil.la
test_os_start_process_DEPENDENCIES = \
 libgnunetutil.la \
 $(WINCAT)

test_client_nc_SOURCES = \
 test_client.c
test_client_nc_LDADD = \
 libgnunetutil.la

test_socks_nc_SOURCES = \
 test_socks.c
test_socks_nc_LDADD = \
 libgnunetutil.la

test_common_allocation_SOURCES = \
 test_common_allocation.c
test_common_allocation_LDADD = \
 libgnunetutil.la

test_common_endian_SOURCES = \
 test_common_endian.c
test_common_endian_LDADD = \
 libgnunetutil.la

test_common_logging_SOURCES = \
 test_common_logging.c
test_common_logging_LDADD = \
 libgnunetutil.la

test_common_logging_runtime_loglevels_SOURCES = \
 test_common_logging_runtime_loglevels.c
test_common_logging_runtime_loglevels_LDADD = \
 libgnunetutil.la

test_configuration_SOURCES = \
 test_configuration.c
test_configuration_LDADD = \
 libgnunetutil.la

test_container_bloomfilter_SOURCES = \
 test_container_bloomfilter.c
test_container_bloomfilter_LDADD = \
 libgnunetutil.la

test_container_meta_data_SOURCES = \
 test_container_meta_data.c
test_container_meta_data_LDADD = \
 libgnunetutil.la -lextractor

test_container_multihashmap_SOURCES = \
 test_container_multihashmap.c
test_container_multihashmap_LDADD = \
 libgnunetutil.la

test_container_multihashmap32_SOURCES = \
 test_container_multihashmap32.c
test_container_multihashmap32_LDADD = \
 libgnunetutil.la

test_container_multipeermap_SOURCES = \
 test_container_multipeermap.c
test_container_multipeermap_LDADD = \
 libgnunetutil.la

test_container_heap_SOURCES = \
 test_container_heap.c
test_container_heap_LDADD = \
 libgnunetutil.la

test_crypto_symmetric_SOURCES = \
 test_crypto_symmetric.c
test_crypto_symmetric_LDADD = \
 libgnunetutil.la

test_crypto_crc_SOURCES = \
 test_crypto_crc.c
test_crypto_crc_LDADD = \
 libgnunetutil.la

test_crypto_ecdsa_SOURCES = \
 test_crypto_ecdsa.c
test_crypto_ecdsa_LDADD = \
 libgnunetutil.la \
 $(LIBGCRYPT_LIBS)

test_crypto_eddsa_SOURCES = \
 test_crypto_eddsa.c
test_crypto_eddsa_LDADD = \
 libgnunetutil.la \
 $(LIBGCRYPT_LIBS)

test_crypto_ecc_dlog_SOURCES = \
 test_crypto_ecc_dlog.c
test_crypto_ecc_dlog_LDADD = \
 libgnunetutil.la \
 $(LIBGCRYPT_LIBS)

test_crypto_ecdhe_SOURCES = \
 test_crypto_ecdhe.c
test_crypto_ecdhe_LDADD = \
 libgnunetutil.la \
 $(LIBGCRYPT_LIBS)

test_crypto_ecdh_eddsa_SOURCES = \
 test_crypto_ecdh_eddsa.c
test_crypto_ecdh_eddsa_LDADD = \
 libgnunetutil.la \
 $(LIBGCRYPT_LIBS)

test_crypto_hash_SOURCES = \
 test_crypto_hash.c
test_crypto_hash_LDADD = \
 libgnunetutil.la

test_crypto_hash_context_SOURCES = \
 test_crypto_hash_context.c
test_crypto_hash_context_LDADD = \
 libgnunetutil.la

test_crypto_hkdf_SOURCES = \
 test_crypto_hkdf.c
test_crypto_hkdf_LDADD = \
 libgnunetutil.la

test_crypto_paillier_SOURCES = \
 test_crypto_paillier.c
test_crypto_paillier_LDADD = \
 $(LIBGCRYPT_LIBS) \
 libgnunetutil.la

test_crypto_random_SOURCES = \
 test_crypto_random.c
test_crypto_random_LDADD = \
 libgnunetutil.la

test_crypto_rsa_SOURCES = \
 test_crypto_rsa.c
test_crypto_rsa_LDADD = \
 libgnunetutil.la

test_disk_SOURCES = \
 test_disk.c
test_disk_LDADD = \
 libgnunetutil.la

test_getopt_SOURCES = \
 test_getopt.c
test_getopt_LDADD = \
 libgnunetutil.la

test_connection_nc_SOURCES = \
 test_connection.c
test_connection_nc_LDADD = \
 libgnunetutil.la

test_connection_addressing_nc_SOURCES = \
 test_connection_addressing.c
test_connection_addressing_nc_LDADD = \
 libgnunetutil.la

test_connection_receive_cancel_nc_SOURCES = \
 test_connection_receive_cancel.c
test_connection_receive_cancel_nc_LDADD = \
 libgnunetutil.la

test_connection_timeout_nc_SOURCES = \
 test_connection_timeout.c
test_connection_timeout_nc_LDADD = \
 libgnunetutil.la

test_connection_timeout_no_connect_nc_SOURCES = \
 test_connection_timeout_no_connect.c
test_connection_timeout_no_connect_nc_LDADD = \
 libgnunetutil.la

test_connection_transmit_cancel_nc_SOURCES = \
 test_connection_transmit_cancel.c
test_connection_transmit_cancel_nc_LDADD = \
 libgnunetutil.la

test_mq_SOURCES = \
 test_mq.c
test_mq_LDADD = \
 libgnunetutil.la

test_mq_client_nc_SOURCES = \
 test_mq_client.c
test_mq_client_nc_LDADD = \
 libgnunetutil.la

test_os_network_SOURCES = \
 test_os_network.c
test_os_network_LDADD = \
 libgnunetutil.la

test_peer_SOURCES = \
 test_peer.c
test_peer_LDADD = \
 libgnunetutil.la -lgcrypt

test_plugin_SOURCES = \
 test_plugin.c
test_plugin_LDADD = \
 libgnunetutil.la

test_program_SOURCES = \
 test_program.c
test_program_LDADD = \
 libgnunetutil.la

test_resolver_api_nc_SOURCES = \
 test_resolver_api.c
test_resolver_api_nc_LDADD = \
 libgnunetutil.la

test_scheduler_SOURCES = \
 test_scheduler.c
test_scheduler_LDADD = \
 libgnunetutil.la

test_scheduler_delay_SOURCES = \
 test_scheduler_delay.c
test_scheduler_delay_LDADD = \
 libgnunetutil.la

test_server_mst_interrupt_nc_SOURCES = \
 test_server_mst_interrupt.c
test_server_mst_interrupt_nc_LDADD = \
 libgnunetutil.la

test_server_nc_SOURCES = \
 test_server.c
test_server_nc_LDADD = \
 libgnunetutil.la

test_server_disconnect_nc_SOURCES = \
 test_server_disconnect.c
test_server_disconnect_nc_LDADD = \
 libgnunetutil.la

test_server_with_client_nc_SOURCES = \
 test_server_with_client.c
test_server_with_client_nc_LDADD = \
 libgnunetutil.la

test_server_with_client_unix_SOURCES = \
 test_server_with_client_unix.c
test_server_with_client_unix_LDADD = \
 libgnunetutil.la


test_service_SOURCES = \
 test_service.c
test_service_LDADD = \
 libgnunetutil.la

test_strings_SOURCES = \
 test_strings.c
test_strings_LDADD = \
 libgnunetutil.la


test_strings_to_data_SOURCES = \
 test_strings_to_data.c
test_strings_to_data_LDADD = \
 libgnunetutil.la


test_time_SOURCES = \
 test_time.c
test_time_LDADD = \
 libgnunetutil.la

test_speedup_SOURCES = \
 test_speedup.c
test_speedup_LDADD = \
 libgnunetutil.la

perf_crypto_hash_SOURCES = \
 perf_crypto_hash.c
perf_crypto_hash_LDADD = \
 libgnunetutil.la

perf_crypto_ecc_dlog_SOURCES = \
 perf_crypto_ecc_dlog.c
perf_crypto_ecc_dlog_LDADD = \
 libgnunetutil.la \
 -lgcrypt

perf_crypto_rsa_SOURCES = \
 perf_crypto_rsa.c
perf_crypto_rsa_LDADD = \
 libgnunetutil.la

perf_crypto_symmetric_SOURCES = \
 perf_crypto_symmetric.c
perf_crypto_symmetric_LDADD = \
 libgnunetutil.la

perf_crypto_asymmetric_SOURCES = \
 perf_crypto_asymmetric.c
perf_crypto_asymmetric_LDADD = \
 libgnunetutil.la

perf_crypto_paillier_SOURCES = \
 perf_crypto_paillier.c
perf_crypto_paillier_LDADD = \
 libgnunetutil.la \
 -lgcrypt

perf_malloc_SOURCES = \
 perf_malloc.c
perf_malloc_LDADD = \
 libgnunetutil.la


EXTRA_DIST = \
  test_configuration_data.conf \
  test_program_data.conf \
  test_resolver_api_data.conf \
  test_service_data.conf \
  test_speedup_data.conf \
  gnunet-qr.py.in
