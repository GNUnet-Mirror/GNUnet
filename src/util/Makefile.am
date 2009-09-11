INCLUDES = -I$(top_srcdir)/src/include

plugindir = $(libdir)/gnunet

if MINGW
 WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols -lole32 -lshell32 -luuid -liconv -lstdc++ -lcomdlg32 -lgdi32
 WINSRC = win.cc winproc.c
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

lib_LTLIBRARIES = libgnunetutil.la

libgnunetutil_la_SOURCES = \
  bio.c \
  client.c \
  common_allocation.c \
  common_endian.c \
  common_gettext.c \
  common_logging.c \
  configuration.c \
  connection.c \
  container_bloomfilter.c \
  container_meta_data.c \
  container_multihashmap.c \
  crypto_aes.c \
  crypto_crc.c \
  crypto_hash.c \
  crypto_ksk.c \
  crypto_random.c \
  crypto_rsa.c \
  disk.c \
  disk.h \
  getopt.c \
  getopt_helpers.c \
  network.c \
  os_installation.c \
  os_load.c \
  os_network.c \
  os_priority.c \
  plugin.c \
  program.c \
  pseudonym.c \
  scheduler.c \
  server.c \
  server_tc.c \
  service.c \
  signal.c \
  strings.c \
  time.c \
  $(WINSRC)


libgnunetutil_la_LIBADD = \
  $(GCLIBADD) \
  $(LIBGCRYPT_LIBS) \
  -lgmp -lltdl -lz -lextractor $(XLIB)

libgnunetutil_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS) $(WINFLAGS) \
  -version-info 4:0:0


plugin_LTLIBRARIES = \
  libgnunet_plugin_test.la

libgnunet_plugin_test_la_SOURCES = \
  test_plugin_plug.c
libgnunet_plugin_test_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)


check_PROGRAMS = \
 test_client \
 test_common_allocation \
 test_common_endian \
 test_common_logging \
 test_configuration \
 test_container_bloomfilter \
 test_container_meta_data \
 test_container_multihashmap \
 test_crypto_aes \
 test_crypto_aes_weak \
 test_crypto_crc \
 test_crypto_hash \
 test_crypto_ksk \
 test_crypto_random \
 test_crypto_rsa \
 test_disk \
 test_getopt \
 test_connection \
 test_connection_addressing \
 test_connection_receive_cancel \
 test_connection_timeout \
 test_connection_timeout_no_connect \
 test_connection_transmit_cancel \
 test_os_load \
 test_os_network \
 test_os_priority \
 test_plugin \
 test_program \
 test_pseudonym \
 test_scheduler \
 test_scheduler_delay \
 test_server \
 test_server_disconnect \
 test_server_with_client \
 test_service \
 test_strings \
 test_time \
 perf_crypto_hash

TESTS = $(check_PROGRAMS)

test_client_SOURCES = \
 test_client.c
test_client_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

test_common_allocation_SOURCES = \
 test_common_allocation.c
test_common_allocation_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

test_common_endian_SOURCES = \
 test_common_endian.c
test_common_endian_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

test_common_logging_SOURCES = \
 test_common_logging.c
test_common_logging_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

test_configuration_SOURCES = \
 test_configuration.c
test_configuration_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

test_container_bloomfilter_SOURCES = \
 test_container_bloomfilter.c
test_container_bloomfilter_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

test_container_meta_data_SOURCES = \
 test_container_meta_data.c
test_container_meta_data_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

test_container_multihashmap_SOURCES = \
 test_container_multihashmap.c
test_container_multihashmap_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

test_crypto_aes_SOURCES = \
 test_crypto_aes.c
test_crypto_aes_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

test_crypto_aes_weak_SOURCES = \
 test_crypto_aes_weak.c
test_crypto_aes_weak_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

test_crypto_crc_SOURCES = \
 test_crypto_crc.c
test_crypto_crc_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

test_crypto_hash_SOURCES = \
 test_crypto_hash.c
test_crypto_hash_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

test_crypto_ksk_SOURCES = \
 test_crypto_ksk.c
test_crypto_ksk_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

test_crypto_random_SOURCES = \
 test_crypto_random.c
test_crypto_random_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

test_crypto_rsa_SOURCES = \
 test_crypto_rsa.c
test_crypto_rsa_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

test_disk_SOURCES = \
 test_disk.c
test_disk_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

test_getopt_SOURCES = \
 test_getopt.c
test_getopt_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

test_connection_SOURCES = \
 test_connection.c
test_connection_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

test_connection_addressing_SOURCES = \
 test_connection_addressing.c
test_connection_addressing_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

test_connection_receive_cancel_SOURCES = \
 test_connection_receive_cancel.c
test_connection_receive_cancel_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

test_connection_timeout_SOURCES = \
 test_connection_timeout.c
test_connection_timeout_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

test_connection_timeout_no_connect_SOURCES = \
 test_connection_timeout_no_connect.c
test_connection_timeout_no_connect_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

test_connection_transmit_cancel_SOURCES = \
 test_connection_transmit_cancel.c
test_connection_transmit_cancel_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

test_os_load_SOURCES = \
 test_os_load.c
test_os_load_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

test_os_network_SOURCES = \
 test_os_network.c
test_os_network_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

test_os_priority_SOURCES = \
 test_os_priority.c
test_os_priority_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

test_plugin_SOURCES = \
 test_plugin.c
test_plugin_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

test_program_SOURCES = \
 test_program.c
test_program_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

test_pseudonym_SOURCES = \
 test_pseudonym.c
test_pseudonym_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

test_scheduler_SOURCES = \
 test_scheduler.c
test_scheduler_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

test_scheduler_delay_SOURCES = \
 test_scheduler_delay.c
test_scheduler_delay_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

test_server_SOURCES = \
 test_server.c
test_server_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

test_server_disconnect_SOURCES = \
 test_server_disconnect.c
test_server_disconnect_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

test_server_with_client_SOURCES = \
 test_server_with_client.c
test_server_with_client_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

test_service_SOURCES = \
 test_service.c
test_service_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

test_strings_SOURCES = \
 test_strings.c
test_strings_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

test_time_SOURCES = \
 test_time.c
test_time_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

perf_crypto_hash_SOURCES = \
 perf_crypto_hash.c
perf_crypto_hash_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  


EXTRA_DIST = \
  test_configuration_data.conf \
  test_container_meta_data_image.jpg \
  test_program_data.conf \
  test_pseudonym_data.conf \
  test_service_data.conf
