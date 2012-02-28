INCLUDES = -I$(top_srcdir)/src/include

if MINGW
 WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols 
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

pkgcfgdir= $(pkgdatadir)/config.d/

pkgcfg_DATA = \
  fs.conf

plugindir = $(libdir)/gnunet


lib_LTLIBRARIES = libgnunetfs.la

plugin_LTLIBRARIES = \
  libgnunet_plugin_block_fs.la 

noinst_LIBRARIES = libgnunetfstest.a

libgnunetfs_la_SOURCES = \
  fs_api.c fs_api.h fs.h \
  fs_directory.c \
  fs_dirmetascan.c \
  fs_download.c \
  fs_file_information.c \
  fs_getopt.c \
  fs_list_indexed.c \
  fs_publish.c \
  fs_publish_ksk.c \
  fs_misc.c \
  fs_namespace.c \
  fs_namespace_advertise.c \
  fs_search.c \
  fs_sharetree.c \
  fs_tree.c fs_tree.h \
  fs_unindex.c \
  fs_uri.c 

libgnunetfs_la_LIBADD = \
  $(top_builddir)/src/datastore/libgnunetdatastore.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL) $(XLIB) -lunistring -lextractor

libgnunetfs_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)  $(WINFLAGS) \
  -version-info 2:0:0


libgnunetfstest_a_SOURCES = \
  fs_test_lib.c fs_test_lib.h

libgnunetfstest_a_LIBADD = \
  $(top_builddir)/src/testing/libgnunettesting.la 

bin_PROGRAMS = \
  gnunet-directory \
  gnunet-download \
  gnunet-publish \
  gnunet-helper-fs-publish \
  gnunet-pseudonym \
  gnunet-search \
  gnunet-service-fs \
  gnunet-fs \
  gnunet-unindex 

bin_SCRIPTS = \
  gnunet-download-manager.scm

gnunet_directory_SOURCES = \
 gnunet-directory.c
gnunet_directory_LDADD = \
  $(top_builddir)/src/fs/libgnunetfs.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  -lextractor \
  $(GN_LIBINTL)
gnunet_directory_DEPENDENCIES = \
  libgnunetfs.la

gnunet_fs_SOURCES = \
 gnunet-fs.c
gnunet_fs_LDADD = \
  $(top_builddir)/src/fs/libgnunetfs.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  -lextractor \
  $(GN_LIBINTL)
gnunet_fs_DEPENDENCIES = \
  libgnunetfs.la

gnunet_download_SOURCES =  \
 gnunet-download.c         
gnunet_download_LDADD =  \
 $(top_builddir)/src/fs/libgnunetfs.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(GN_LIBINTL)
gnunet_download_DEPENDENCIES = \
  libgnunetfs.la

gnunet_publish_SOURCES =  \
 gnunet-publish.c         
gnunet_publish_LDADD =  \
 $(top_builddir)/src/fs/libgnunetfs.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 -lextractor \
 $(GN_LIBINTL)
gnunet_publish_DEPENDENCIES = \
  libgnunetfs.la

gnunet_helper_fs_publish_SOURCES =  \
 gnunet-helper-fs-publish.c 
gnunet_helper_fs_publish_LDADD =  \
 $(top_builddir)/src/util/libgnunetutil.la \
 -lextractor \
 $(GN_LIBINTL)
gnunet_helper_fs_publish_DEPENDENCIES = \
  libgnunetfs.la

gnunet_pseudonym_SOURCES = \
 gnunet-pseudonym.c
gnunet_pseudonym_LDADD = \
  $(top_builddir)/src/fs/libgnunetfs.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  -lextractor \
  $(GN_LIBINTL)
gnunet_pseudonym_DEPENDENCIES = \
  libgnunetfs.la

gnunet_search_SOURCES = \
 gnunet-search.c         
gnunet_search_LDADD = \
  $(top_builddir)/src/fs/libgnunetfs.la \
  $(top_builddir)/src/util/libgnunetutil.la \
 -lextractor \
  $(GN_LIBINTL)
gnunet_search_DEPENDENCIES = \
  libgnunetfs.la

gnunet_service_fs_SOURCES =  \
 gnunet-service-fs.c gnunet-service-fs.h \
 gnunet-service-fs_cp.c gnunet-service-fs_cp.h \
 gnunet-service-fs_indexing.c gnunet-service-fs_indexing.h \
 gnunet-service-fs_lc.c gnunet-service-fs_lc.h \
 gnunet-service-fs_pe.c gnunet-service-fs_pe.h \
 gnunet-service-fs_pr.c gnunet-service-fs_pr.h \
 gnunet-service-fs_push.c gnunet-service-fs_push.h \
 gnunet-service-fs_put.c gnunet-service-fs_put.h 
gnunet_service_fs_LDADD =  \
 $(top_builddir)/src/fs/libgnunetfs.la \
 $(top_builddir)/src/dht/libgnunetdht.la \
 $(top_builddir)/src/block/libgnunetblock.la \
 $(top_builddir)/src/datastore/libgnunetdatastore.la \
 $(top_builddir)/src/statistics/libgnunetstatistics.la \
 $(top_builddir)/src/ats/libgnunetats.la \
 $(top_builddir)/src/core/libgnunetcore.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(GN_LIBINTL) -lm
gnunet_service_fs_DEPENDENCIES = \
  libgnunetfs.la

gnunet_unindex_SOURCES = \
 gnunet-unindex.c         
gnunet_unindex_LDADD = \
  $(top_builddir)/src/fs/libgnunetfs.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)
gnunet_unindex_DEPENDENCIES = \
  libgnunetfs.la


libgnunet_plugin_block_fs_la_SOURCES = \
  plugin_block_fs.c
libgnunet_plugin_block_fs_la_LIBADD = \
  $(top_builddir)/src/block/libgnunetblock.la \
  $(top_builddir)/src/util/libgnunetutil.la 
libgnunet_plugin_block_fs_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)
libgnunet_plugin_block_fs_la_DEPENDENCIES = \
  $(top_builddir)/src/block/libgnunetblock.la



if HAVE_BENCHMARKS
 FS_BENCHMARKS = \
 perf_gnunet_service_fs_p2p \
 perf_gnunet_service_fs_p2p_dht \
 perf_gnunet_service_fs_p2p_index \
 perf_gnunet_service_fs_p2p_trust 
endif

check_PROGRAMS = \
 test_fs_directory \
 test_fs_download \
 test_fs_download_indexed \
 test_fs_download_persistence \
 test_fs_file_information \
 test_fs_getopt \
 test_fs_list_indexed \
 test_fs_namespace \
 test_fs_namespace_list_updateable \
 test_fs_publish \
 test_fs_publish_persistence \
 test_fs_search \
 test_fs_search_persistence \
 test_fs_start_stop \
 test_fs_test_lib \
 test_fs_unindex \
 test_fs_unindex_persistence \
 test_fs_uri \
 test_gnunet_service_fs_migration \
 test_gnunet_service_fs_p2p \
 $(FS_BENCHMARKS)


if HAVE_PYTHON_PEXPECT
check_SCRIPTS = \
 test_gnunet_fs_psd.py \
 test_gnunet_fs_rec.py \
 test_gnunet_fs_idx.py \
 test_gnunet_fs_ns.py 
endif


if ENABLE_TEST_RUN
TESTS = \
 test_fs_directory \
 test_fs_download \
 test_fs_download_indexed \
 test_fs_download_persistence \
 test_fs_file_information \
 test_fs_list_indexed \
 test_fs_namespace \
 test_fs_namespace_list_updateable \
 test_fs_publish \
 test_fs_publish_persistence \
 test_fs_search \
 test_fs_search_persistence \
 test_fs_start_stop \
 test_fs_unindex \
 test_fs_unindex_persistence \
 test_fs_uri \
 test_fs_test_lib \
 test_gnunet_service_fs_migration \
 test_gnunet_service_fs_p2p \
 perf_gnunet_service_fs_p2p \
 perf_gnunet_service_fs_p2p_index \
 perf_gnunet_service_fs_p2p_trust \
 $(check_SCRIPTS)  
endif




test_fs_directory_SOURCES = \
 test_fs_directory.c
test_fs_directory_LDADD = \
  -lextractor \
  $(top_builddir)/src/fs/libgnunetfs.la  \
  $(top_builddir)/src/util/libgnunetutil.la  

test_fs_download_SOURCES = \
 test_fs_download.c
test_fs_download_LDADD = \
  $(top_builddir)/src/fs/libgnunetfs.la  \
  $(top_builddir)/src/util/libgnunetutil.la  

test_fs_download_indexed_SOURCES = \
 test_fs_download_indexed.c
test_fs_download_indexed_LDADD = \
  $(top_builddir)/src/fs/libgnunetfs.la  \
  $(top_builddir)/src/util/libgnunetutil.la  

test_fs_download_persistence_SOURCES = \
 test_fs_download_persistence.c
test_fs_download_persistence_LDADD = \
  $(top_builddir)/src/fs/libgnunetfs.la  \
  $(top_builddir)/src/util/libgnunetutil.la  

test_fs_file_information_SOURCES = \
 test_fs_file_information.c
test_fs_file_information_LDADD = \
  -lextractor \
  $(top_builddir)/src/fs/libgnunetfs.la  \
  $(top_builddir)/src/util/libgnunetutil.la  

test_fs_getopt_SOURCES = \
 test_fs_getopt.c
test_fs_getopt_LDADD = \
  $(top_builddir)/src/fs/libgnunetfs.la  \
  $(top_builddir)/src/util/libgnunetutil.la  

test_fs_list_indexed_SOURCES = \
 test_fs_list_indexed.c
test_fs_list_indexed_LDADD = \
  $(top_builddir)/src/fs/libgnunetfs.la  \
  $(top_builddir)/src/util/libgnunetutil.la  

test_fs_namespace_SOURCES = \
 test_fs_namespace.c
test_fs_namespace_LDADD = \
  $(top_builddir)/src/fs/libgnunetfs.la  \
  $(top_builddir)/src/util/libgnunetutil.la  

test_fs_namespace_list_updateable_SOURCES = \
 test_fs_namespace_list_updateable.c
test_fs_namespace_list_updateable_LDADD = \
  $(top_builddir)/src/fs/libgnunetfs.la  \
  $(top_builddir)/src/util/libgnunetutil.la  

test_fs_publish_SOURCES = \
 test_fs_publish.c
test_fs_publish_LDADD = \
  $(top_builddir)/src/fs/libgnunetfs.la  \
  $(top_builddir)/src/util/libgnunetutil.la  

test_fs_publish_persistence_SOURCES = \
 test_fs_publish_persistence.c
test_fs_publish_persistence_LDADD = \
  $(top_builddir)/src/fs/libgnunetfs.la  \
  $(top_builddir)/src/util/libgnunetutil.la  

test_fs_search_SOURCES = \
 test_fs_search.c
test_fs_search_LDADD = $(top_builddir)/src/fs/libgnunetfs.la	\
  $(top_builddir)/src/util/libgnunetutil.la

test_fs_search_persistence_SOURCES = \
 test_fs_search_persistence.c
test_fs_search_persistence_LDADD = $(top_builddir)/src/fs/libgnunetfs.la	\
  $(top_builddir)/src/util/libgnunetutil.la

test_fs_start_stop_SOURCES = \
 test_fs_start_stop.c
test_fs_start_stop_LDADD = \
  $(top_builddir)/src/fs/libgnunetfs.la  \
  $(top_builddir)/src/util/libgnunetutil.la  

test_fs_unindex_SOURCES = \
 test_fs_unindex.c
test_fs_unindex_LDADD = \
  $(top_builddir)/src/fs/libgnunetfs.la  \
  $(top_builddir)/src/util/libgnunetutil.la  

test_fs_unindex_persistence_SOURCES = \
 test_fs_unindex_persistence.c
test_fs_unindex_persistence_LDADD = \
  $(top_builddir)/src/fs/libgnunetfs.la  \
  $(top_builddir)/src/util/libgnunetutil.la  

test_fs_uri_SOURCES = \
 test_fs_uri.c
test_fs_uri_LDADD = \
  $(top_builddir)/src/fs/libgnunetfs.la  \
  $(top_builddir)/src/util/libgnunetutil.la  

test_fs_test_lib_SOURCES = \
 test_fs_test_lib.c
test_fs_test_lib_LDADD = \
  $(top_builddir)/src/fs/libgnunetfstest.a \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/fs/libgnunetfs.la  \
  $(top_builddir)/src/util/libgnunetutil.la  

test_gnunet_service_fs_p2p_SOURCES = \
 test_gnunet_service_fs_p2p.c
test_gnunet_service_fs_p2p_LDADD = \
  $(top_builddir)/src/fs/libgnunetfstest.a \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/fs/libgnunetfs.la  \
  $(top_builddir)/src/util/libgnunetutil.la  

test_gnunet_service_fs_migration_SOURCES = \
 test_gnunet_service_fs_migration.c
test_gnunet_service_fs_migration_LDADD = \
  $(top_builddir)/src/fs/libgnunetfstest.a \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/fs/libgnunetfs.la  \
  $(top_builddir)/src/util/libgnunetutil.la  

perf_gnunet_service_fs_p2p_SOURCES = \
 perf_gnunet_service_fs_p2p.c
perf_gnunet_service_fs_p2p_LDADD = \
  $(top_builddir)/src/fs/libgnunetfstest.a \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/fs/libgnunetfs.la  \
  $(top_builddir)/src/util/libgnunetutil.la  

perf_gnunet_service_fs_p2p_index_SOURCES = \
 perf_gnunet_service_fs_p2p.c
perf_gnunet_service_fs_p2p_index_LDADD = \
  $(top_builddir)/src/fs/libgnunetfstest.a \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/fs/libgnunetfs.la  \
  $(top_builddir)/src/util/libgnunetutil.la  

perf_gnunet_service_fs_p2p_dht_SOURCES = \
 perf_gnunet_service_fs_p2p.c
perf_gnunet_service_fs_p2p_dht_LDADD = \
  $(top_builddir)/src/fs/libgnunetfstest.a \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/fs/libgnunetfs.la  \
  $(top_builddir)/src/util/libgnunetutil.la  

perf_gnunet_service_fs_p2p_trust_SOURCES = \
 perf_gnunet_service_fs_p2p_trust.c
perf_gnunet_service_fs_p2p_trust_LDADD = \
  $(top_builddir)/src/fs/libgnunetfstest.a \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/testing/libgnunettesting.la \
  $(top_builddir)/src/fs/libgnunetfs.la  \
  $(top_builddir)/src/util/libgnunetutil.la  


do_subst = $(SED) -e 's,[@]PYTHON[@],$(PYTHON),g'

test_gnunet_fs_psd.py: test_gnunet_fs_psd.py.in Makefile
	$(do_subst) < $(srcdir)/test_gnunet_fs_psd.py.in > test_gnunet_fs_psd.py
	chmod +x test_gnunet_fs_psd.py

test_gnunet_fs_rec.py: test_gnunet_fs_rec.py.in Makefile
	$(do_subst) < $(srcdir)/test_gnunet_fs_rec.py.in > test_gnunet_fs_rec.py
	chmod +x test_gnunet_fs_rec.py

test_gnunet_fs_ns.py: test_gnunet_fs_ns.py.in Makefile
	$(do_subst) < $(srcdir)/test_gnunet_fs_ns.py.in > test_gnunet_fs_ns.py
	chmod +x test_gnunet_fs_ns.py

test_gnunet_fs_idx.py: test_gnunet_fs_idx.py.in Makefile
	$(do_subst) < $(srcdir)/test_gnunet_fs_idx.py.in > test_gnunet_fs_idx.py
	chmod +x test_gnunet_fs_idx.py


EXTRA_DIST = \
  test_fs_defaults.conf \
  fs_test_lib_data.conf \
  test_fs_data.conf \
  test_fs_download_data.conf \
  test_fs_file_information_data.conf \
  fs_test_lib_data.conf \
  test_fs_list_indexed_data.conf \
  test_fs_namespace_data.conf \
  test_fs_publish_data.conf \
  test_fs_search_data.conf \
  test_fs_unindex_data.conf \
  test_fs_uri_data.conf \
  test_gnunet_service_fs_migration_data.conf \
  test_gnunet_fs_idx_data.conf \
  test_gnunet_fs_ns_data.conf \
  test_gnunet_fs_psd_data.conf \
  test_gnunet_fs_rec_data.conf \
  test_gnunet_fs_rec_data.tgz \
  test_gnunet_fs_psd.py.in \
  test_gnunet_fs_rec.py.in \
  test_gnunet_fs_ns.py.in \
  test_gnunet_fs_idx.py.in \
  $(bin_SCRIPTS) 

CLEANFILES = $(check_SCRIPTS)
