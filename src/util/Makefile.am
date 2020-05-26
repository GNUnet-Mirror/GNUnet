# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

plugindir = $(libdir)/gnunet

libexecdir= $(pkglibdir)/libexec/

pkgcfgdir= $(pkgdatadir)/config.d/

dist_pkgcfg_DATA = \
  util.conf

pkgcfg_DATA = \
  resolver.conf

TEST_CLIENT_UNIX_NC = test_client_unix.nc

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

if ENABLE_BENCHMARK
  BENCHMARK = benchmark.c benchmark.h
  PTHREAD = -lpthread
endif

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
  $(BENCHMARK) \
  bio.c \
  buffer.c \
  client.c \
  common_allocation.c \
  common_endian.c \
  common_logging.c \
  configuration.c \
  configuration_loader.c \
  consttime_memcmp.c \
  container_bloomfilter.c \
  container_heap.c \
  container_meta_data.c \
  container_multihashmap.c \
  container_multishortmap.c \
  container_multiuuidmap.c \
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
  crypto_pow.c \
  crypto_random.c \
  crypto_rsa.c \
  disk.c \
  disk.h \
  dnsparser.c \
  dnsstub.c \
  getopt.c \
  getopt_helpers.c \
  helper.c \
  load.c \
  mst.c \
  mq.c \
  nc.c \
  network.c \
  op.c \
  os_installation.c \
  os_network.c \
  os_priority.c \
  peer.c \
  plugin.c \
  program.c \
  regex.c \
  resolver_api.c resolver.h \
  scheduler.c \
  service.c \
  signal.c \
  strings.c \
  time.c \
  tun.c \
  speedup.c speedup.h \
  proc_compat.c

if HAVE_LIBATOMIC
if DARWIN
	LIBATOMIC=
else
  LIBATOMIC= -latomic
endif
else
  LIBATOMIC=
endif

if HAVE_LIBIDN
  LIBIDN= -lidn
else
  LIBIDN=
endif

if HAVE_LIBIDN2
  LIBIDN2= -lidn2
else
  LIBIDN2=
endif

libgnunetutil_la_LIBADD = \
  $(GCLIBADD) $(WINLIB) \
  $(LIBATOMIC) \
  $(LIBGCRYPT_LIBS) \
  $(LTLIBICONV) \
  $(LTLIBINTL) \
  -lltdl \
  $(LIBIDN) $(LIBIDN2) \
  $(Z_LIBS) \
  -lunistring \
  -lsodium \
  $(XLIB) \
  $(PTHREAD)

libgnunetutil_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS) \
  -version-info 13:2:0

if HAVE_TESTING
  GNUNET_ECC = gnunet-ecc
  GNUNET_SCRYPT = gnunet-scrypt
endif

lib_LTLIBRARIES = libgnunetutil.la

libexec_PROGRAMS = \
 gnunet-service-resolver \
 gnunet-timeout

bin_PROGRAMS = \
 gnunet-resolver \
 gnunet-config \
 gnunet-crypto-tvg \
 $(GNUNET_ECC) \
 $(GNUNET_SCRYPT) \
 gnunet-uri
if HAVE_ZBAR
bin_PROGRAMS += gnunet-qr
endif

noinst_PROGRAMS = \
 gnunet-config-diff \
 test_common_logging_dummy


if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
TESTS = $(check_PROGRAMS)
endif

gnunet_timeout_SOURCES = \
 gnunet-timeout.c

gnunet_service_resolver_SOURCES = \
 gnunet-service-resolver.c
gnunet_service_resolver_LDADD = \
  libgnunetutil.la \
  $(GN_LIBINTL)
if HAVE_GETADDRINFO_A
gnunet_service_resolver_LDADD += -lanl
endif


gnunet_resolver_SOURCES = \
 gnunet-resolver.c
gnunet_resolver_LDADD = \
  libgnunetutil.la \
  $(GN_LIBINTL)

gnunet_crypto_tvg_SOURCES = \
 gnunet-crypto-tvg.c
gnunet_crypto_tvg_LDADD = \
  libgnunetutil.la \
  $(GN_LIBINTL) -lgcrypt

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


gnunet_qr_SOURCES = \
  gnunet-qr.c
gnunet_qr_LDADD = \
  libgnunetutil.la \
  $(GN_LIBINTL)
gnunet_qr_LDFLAGS= -lzbar

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
  perf_malloc \
  perf_mq \
  perf_scheduler
endif

if HAVE_SSH_KEY
# SSH_USING_TESTS = test_socks.nc
endif

check_PROGRAMS = \
 test_bio \
 test_client.nc \
 $(TEST_CLIENT_UNIX_NC) \
 test_common_allocation \
 test_common_endian \
 test_common_logging \
 test_configuration \
 test_container_bloomfilter \
 test_container_dll \
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
 test_crypto_ecdh_ecdsa \
 test_crypto_ecc_dlog \
 test_crypto_hash \
 test_crypto_hash_context \
 test_crypto_hkdf \
 test_crypto_kdf \
 test_crypto_paillier \
 test_crypto_random \
 test_crypto_rsa \
 test_disk \
 test_getopt \
 test_hexcoder \
 test_mq \
 test_os_network \
 test_peer \
 test_plugin \
 test_program \
 test_regex \
 test_resolver_api.nc \
 test_scheduler \
 test_scheduler_delay \
 test_service \
 test_strings \
 test_strings_to_data \
 test_speedup \
 test_time \
 test_tun \
 $(BENCHMARKS) \
 test_os_start_process \
 test_common_logging_runtime_loglevels


# Declare .nc (NO-CONCURRENCY) as a test extension so that we can impart
# sequential execution order for them
TEST_EXTENSIONS = .nc
test_test_client_unix.log: test_client.log

test_bio_SOURCES = \
 test_bio.c
test_bio_LDADD = \
 libgnunetutil.la

test_hexcoder_SOURCES = \
 test_hexcoder.c
test_hexcoder_LDADD = \
 libgnunetutil.la

test_tun_SOURCES = \
 test_tun.c
test_tun_LDADD = \
 libgnunetutil.la

test_regex_SOURCES = \
 test_regex.c
test_regex_LDADD = \
 libgnunetutil.la

test_os_start_process_SOURCES = \
 test_os_start_process.c
test_os_start_process_LDADD = \
 libgnunetutil.la
test_os_start_process_DEPENDENCIES = \
 libgnunetutil.la

test_client_nc_SOURCES = \
 test_client.c
test_client_nc_LDADD = \
 libgnunetutil.la

test_client_unix_nc_SOURCES = \
 test_client.c
test_client_unix_nc_LDADD = \
 libgnunetutil.la

#test_socks_nc_SOURCES = \
# test_socks.c
#test_socks_nc_LDADD = \
# libgnunetutil.la

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

test_container_dll_SOURCES = \
 test_container_dll.c
test_container_dll_LDADD = \
 libgnunetutil.la

test_container_meta_data_SOURCES = \
 test_container_meta_data.c
test_container_meta_data_LDADD = \
 libgnunetutil.la

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

test_crypto_ecdh_ecdsa_SOURCES = \
 test_crypto_ecdh_ecdsa.c
test_crypto_ecdh_ecdsa_LDADD = \
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

test_crypto_kdf_SOURCES = \
 test_crypto_kdf.c
test_crypto_kdf_LDADD = \
 libgnunetutil.la -lgcrypt

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
 libgnunetutil.la -lgcrypt

test_disk_SOURCES = \
 test_disk.c
test_disk_LDADD = \
 libgnunetutil.la

test_getopt_SOURCES = \
 test_getopt.c
test_getopt_LDADD = \
 libgnunetutil.la

test_mq_SOURCES = \
 test_mq.c
test_mq_LDADD = \
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

perf_mq_SOURCES = \
 perf_mq.c
perf_mq_LDADD = \
 libgnunetutil.la

perf_scheduler_SOURCES = \
 perf_scheduler.c
perf_scheduler_LDADD = \
 libgnunetutil.la


EXTRA_DIST = \
  test_client_data.conf \
  test_client_unix.conf \
  test_configuration_data.conf \
  test_program_data.conf \
  test_resolver_api_data.conf \
  test_service_data.conf \
  test_speedup_data.conf
