
INCLUDES = -I$(top_srcdir)/src/include

if MINGW
 WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols 
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif


lib_LTLIBRARIES = libgnunetfs.la

libgnunetfs_la_SOURCES = \
  fs.c \
  fs_collection.c \
  fs_directory.c \
  fs_download.c \
  fs_file_information.c \
  fs_getopt.c \
  fs_list_indexed.c \
  fs_publish.c \
  fs_namespace.c \
  fs_search.c \
  fs_tree.c fs_tree.h \
  fs_unindex.c \
  fs_uri.c 

libgnunetfs_la_LIBADD = \
  $(top_builddir)/src/datastore/libgnunetdatastore.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  -lextractor \
  $(GN_LIBINTL) $(XLIB)

libgnunetfs_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)  $(WINFLAGS) \
  -version-info 0:0:0


bin_PROGRAMS = \
  gnunet-directory \
  gnunet-download \
  gnunet-publish \
  gnunet-pseudonym \
  gnunet-search \
  gnunet-service-fs \
  gnunet-unindex 

gnunet_directory_SOURCES = \
 gnunet-directory.c
gnunet_directory_LDADD = \
  $(top_builddir)/src/fs/libgnunetfs.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)

gnunet_download_SOURCES =  \
 gnunet-download.c         
gnunet_download_LDADD =  \
 $(top_builddir)/src/fs/libgnunetfs.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(GN_LIBINTL)

gnunet_publish_SOURCES =  \
 gnunet-publish.c         
gnunet_publish_LDADD =  \
 $(top_builddir)/src/fs/libgnunetfs.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(GN_LIBINTL)

gnunet_pseudonym_SOURCES = \
 gnunet-pseudonym.c
gnunet_pseudonym_LDADD = \
  $(top_builddir)/src/fs/libgnunetfs.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)

gnunet_search_SOURCES = \
 gnunet-search.c         
gnunet_search_LDADD = \
  $(top_builddir)/src/fs/libgnunetfs.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)

gnunet_service_fs_SOURCES =  \
 gnunet-service-fs.c         
gnunet_service_fs_LDADD =  \
 $(top_builddir)/src/fs/libgnunetfs.la \
 $(top_builddir)/src/datastore/libgnunetdatastore.la \
 $(top_builddir)/src/core/libgnunetcore.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(GN_LIBINTL)

gnunet_unindex_SOURCES = \
 gnunet-unindex.c         
gnunet_unindex_LDADD = \
  $(top_builddir)/src/fs/libgnunetfs.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)




check_PROGRAMS = \
 test_fs_collection \
 test_fs_directory \
 test_fs_download \
 test_fs_file_information \
 test_fs_getopt \
 test_fs_list_indexed \
 test_fs_namespace \
 test_fs_publish \
 test_fs_search \
 test_fs_start_stop \
 test_fs_unindex \
 test_fs_uri

TESTS = \
 test_fs_directory \
 test_fs_download \ 
 test_fs_file_information \
 test_fs_search \
 test_fs_start_stop \
 test_fs_unindex \
 test_fs_uri
# $(check_PROGRAMS)

test_fs_collection_SOURCES = \
 test_fs_collection.c
test_fs_collection_LDADD = \
  $(top_builddir)/src/fs/libgnunetfs.la  \
  $(top_builddir)/src/util/libgnunetutil.la  

test_fs_directory_SOURCES = \
 test_fs_directory.c
test_fs_directory_LDADD = \
  $(top_builddir)/src/fs/libgnunetfs.la  \
  $(top_builddir)/src/util/libgnunetutil.la  

test_fs_download_SOURCES = \
 test_fs_download.c
test_fs_download_LDADD = \
  $(top_builddir)/src/fs/libgnunetfs.la  \
  $(top_builddir)/src/arm/libgnunetarm.la  \
  $(top_builddir)/src/util/libgnunetutil.la  

test_fs_file_information_SOURCES = \
 test_fs_file_information.c
test_fs_file_information_LDADD = \
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
  $(top_builddir)/src/arm/libgnunetarm.la  \
  $(top_builddir)/src/util/libgnunetutil.la  

test_fs_namespace_SOURCES = \
 test_fs_namespace.c
test_fs_namespace_LDADD = \
  $(top_builddir)/src/fs/libgnunetfs.la  \
  $(top_builddir)/src/arm/libgnunetarm.la  \
  $(top_builddir)/src/util/libgnunetutil.la  

test_fs_publish_SOURCES = \
 test_fs_publish.c
test_fs_publish_LDADD = \
  $(top_builddir)/src/fs/libgnunetfs.la  \
  $(top_builddir)/src/arm/libgnunetarm.la  \
  $(top_builddir)/src/util/libgnunetutil.la  

test_fs_search_SOURCES = \
 test_fs_search.c
test_fs_search_LDADD = $(top_builddir)/src/fs/libgnunetfs.la	\
  $(top_builddir)/src/arm/libgnunetarm.la			\
  $(top_builddir)/src/util/libgnunetutil.la

test_fs_start_stop_SOURCES = \
 test_fs_start_stop.c
test_fs_start_stop_LDADD = \
  $(top_builddir)/src/fs/libgnunetfs.la  \
  $(top_builddir)/src/arm/libgnunetarm.la  \
  $(top_builddir)/src/util/libgnunetutil.la  

test_fs_unindex_SOURCES = \
 test_fs_unindex.c
test_fs_unindex_LDADD = \
  $(top_builddir)/src/fs/libgnunetfs.la  \
  $(top_builddir)/src/arm/libgnunetarm.la  \
  $(top_builddir)/src/util/libgnunetutil.la  

test_fs_uri_SOURCES = \
 test_fs_uri.c
test_fs_uri_LDADD = \
  $(top_builddir)/src/fs/libgnunetfs.la  \
  $(top_builddir)/src/util/libgnunetutil.la  

EXTRA_DIST = \
  test_fs_data.conf \
  test_fs_collection_data.conf \
  test_fs_download_data.conf \
  test_fs_file_information_data.conf \
  test_fs_list_indexed_data.conf \
  test_fs_namespace_data.conf \
  test_fs_publish_data.conf \
  test_fs_search_data.conf \
  test_fs_unindex_data.conf \
  test_fs_uri_data.conf
