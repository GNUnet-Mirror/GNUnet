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
  fs_collection.c \
  fs_directory.c \
  fs_getopt.c \
  fs_uri.c 

libgnunetfs_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL) $(XLIB)

libgnunetfs_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)  $(WINFLAGS) \
  -version-info 0:0:0


#bin_PROGRAMS =  
# gnunet-directory 
# gnunet-download 
# gnunet-pseudonym 
# gnunet-search
# gnunet-share 
# gnunet-unindex 

#gnunet_directory_SOURCES = 
# gnunet-directory.c         
#gnunet_directory_LDADD = 
#  $(top_builddir)/src/fs/libgnunetfs.la 
#  $(top_builddir)/src/util/libgnunetutil.la 
#  $(GN_LIBINTL)


check_PROGRAMS = \
 test_fs_collection \
 test_fs_directory \
 test_fs_getopt \
 test_fs_uri

TESTS = $(check_PROGRAMS)

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

test_fs_getopt_SOURCES = \
 test_fs_getopt.c
test_fs_getopt_LDADD = \
  $(top_builddir)/src/fs/libgnunetfs.la  \
  $(top_builddir)/src/util/libgnunetutil.la  

test_fs_uri_SOURCES = \
 test_fs_uri.c
test_fs_uri_LDADD = \
  $(top_builddir)/src/fs/libgnunetfs.la  \
  $(top_builddir)/src/util/libgnunetutil.la  

EXTRA_DIST = \
  test_fs_uri_data.conf
