# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

libexecdir= $(pkglibdir)/libexec/

pkgcfgdir= $(pkgdatadir)/config.d/

pkgcfg_DATA = \
  nat-auto.conf

bin_PROGRAMS = \
 gnunet-nat-auto \
 gnunet-nat-server

libexec_PROGRAMS = \
 gnunet-service-nat-auto

gnunet_nat_server_SOURCES = \
 gnunet-nat-server.c nat-auto.h
gnunet_nat_server_LDADD = \
  $(top_builddir)/src/nat/libgnunetnat.la \
  $(top_builddir)/src/util/libgnunetutil.la

gnunet_nat_auto_SOURCES = \
  gnunet-nat-auto.c nat-auto.h
gnunet_nat_auto_LDADD = \
  libgnunetnatauto.la \
  $(top_builddir)/src/util/libgnunetutil.la


if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif

lib_LTLIBRARIES = \
  libgnunetnatauto.la

libgnunetnatauto_la_SOURCES = \
  nat_auto_api.c \
  nat_auto_api_test.c 
libgnunetnatauto_la_LIBADD = \
  $(top_builddir)/src/nat/libgnunetnatnew.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL) @EXT_LIBS@ 
libgnunetnatauto_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS) $(WINFLAGS) \
  -version-info 0:0:0

gnunet_service_nat_auto_SOURCES = \
 gnunet-service-nat-auto.c
gnunet_service_nat_auto_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/nat/libgnunetnatnew.la \
  $(LIBGCRYPT_LIBS) \
  -lgcrypt \
  $(GN_LIBINTL)

