# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/


if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
endif

if HAVE_MHD
 HOSTLIST_SERVER_SOURCES = \
   gnunet-daemon-hostlist_server.c gnunet-daemon-hostlist_server.h
 GN_LIBMHD = -lmicrohttpd
endif

if HAVE_LIBGNURL
libexec_PROGRAMS = \
 gnunet-daemon-hostlist
LIB_GNURL=@LIBGNURL@
CPP_GNURL=@LIBGNURL_CPPFLAGS@
dist_pkgcfg_DATA = \
  hostlist.conf
else
if HAVE_LIBCURL
libexec_PROGRAMS = \
 gnunet-daemon-hostlist
LIB_GNURL=@LIBCURL@
CPP_GNURL=@LIBCURL_CPPFLAGS@
dist_pkgcfg_DATA = \
  hostlist.conf
endif
endif

gnunet_daemon_hostlist_SOURCES = \
 gnunet-daemon-hostlist.c gnunet-daemon-hostlist.h \
 gnunet-daemon-hostlist_client.c gnunet-daemon-hostlist_client.h \
 $(HOSTLIST_SERVER_SOURCES)

gnunet_daemon_hostlist_LDADD = \
  $(top_builddir)/src/core/libgnunetcore.la \
  $(top_builddir)/src/hello/libgnunethello.la \
  $(top_builddir)/src/peerinfo/libgnunetpeerinfo.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/transport/libgnunettransport.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBMHD) \
  $(LIB_GNURL) \
  $(GN_LIBINTL)

gnunet_daemon_hostlist_CPPFLAGS = \
 $(CPP_GNURL) \
 $(AM_CPPFLAGS)

if HAVE_LIBGNURL
check_PROGRAMS = \
 test_gnunet_daemon_hostlist \
 test_gnunet_daemon_hostlist_reconnect \
 test_gnunet_daemon_hostlist_learning

if HAVE_MHD
if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;
TESTS = \
 test_gnunet_daemon_hostlist \
 test_gnunet_daemon_hostlist_reconnect \
 test_gnunet_daemon_hostlist_learning
endif
endif
endif

test_gnunet_daemon_hostlist_SOURCES = \
 test_gnunet_daemon_hostlist.c
test_gnunet_daemon_hostlist_LDADD = \
  $(top_builddir)/src/transport/libgnunettransport.la \
  $(top_builddir)/src/util/libgnunetutil.la

test_gnunet_daemon_hostlist_reconnect_SOURCES = \
 test_gnunet_daemon_hostlist_reconnect.c
test_gnunet_daemon_hostlist_reconnect_LDADD = \
  $(top_builddir)/src/transport/libgnunettransport.la \
  $(top_builddir)/src/util/libgnunetutil.la

test_gnunet_daemon_hostlist_learning_SOURCES = \
 test_gnunet_daemon_hostlist_learning.c
test_gnunet_daemon_hostlist_learning_LDADD = \
  $(top_builddir)/src/transport/libgnunettransport.la \
  $(top_builddir)/src/core/libgnunetcore.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la

EXTRA_DIST = \
  test_hostlist_defaults.conf \
  test_gnunet_daemon_hostlist_data.conf \
  test_gnunet_daemon_hostlist_peer1.conf \
  test_gnunet_daemon_hostlist_peer2.conf \
  test_learning_adv_peer.conf \
  test_learning_learn_peer.conf \
  test_learning_learn_peer2.conf \
  learning_data.conf
