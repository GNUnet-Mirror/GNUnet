INCLUDES = -I$(top_srcdir)/src/include

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
endif


bin_PROGRAMS = \
 gnunet-daemon-hostlist

gnunet_daemon_hostlist_SOURCES = \
 gnunet-daemon-hostlist.c \
 hostlist-client.c hostlist-client.h \
 hostlist-server.c hostlist-server.h 

gnunet_daemon_hostlist_LDADD = \
  $(top_builddir)/src/core/libgnunetcore.la \
  $(top_builddir)/src/hello/libgnunethello.la \
  $(top_builddir)/src/peerinfo/libgnunetpeerinfo.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/transport/libgnunettransport.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  -lmicrohttpd \
  @LIBCURL@ \
  $(GN_LIBINTL)

gnunet_daemon_hostlist_CPPFLAGS = \
 @LIBCURL_CPPFLAGS@ 


