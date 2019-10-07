# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

EXTRA_DIST = \
  test_abd_defaults.conf \
  test_abd_lookup.conf


if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
endif

pkgcfgdir = $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

plugindir = $(libdir)/gnunet

pkgcfg_DATA = \
  abd.conf


# /usr/lib - compiles a layer which can be used to be communicagte with the service
lib_LTLIBRARIES = \
  libgnunetabd.la

# /usr/lib/gnunet/libexec - Business logic . Separate process
libexec_PROGRAMS = \
  gnunet-service-abd

bin_PROGRAMS = \
  gnunet-abd

plugin_LTLIBRARIES = \
  libgnunet_plugin_gnsrecord_abd.la


gnunet_abd_SOURCES = \
 gnunet-abd.c
gnunet_abd_LDADD = \
  libgnunetabd.la \
  $(top_builddir)/src/util/libgnunetutil.la \
	$(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/identity/libgnunetidentity.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  $(GN_LIBINTL)


libgnunet_plugin_gnsrecord_abd_la_SOURCES = \
  plugin_gnsrecord_abd.c
libgnunet_plugin_gnsrecord_abd_la_LIBADD = \
	libgnunetabd.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(LTLIBINTL)
libgnunet_plugin_gnsrecord_abd_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)



gnunet_service_abd_SOURCES = \
 gnunet-service-abd.c
gnunet_service_abd_LDADD = \
	libgnunetabd.la \
  $(top_builddir)/src/util/libgnunetutil.la \
	$(top_builddir)/src/gns/libgnunetgns.la \
	$(top_builddir)/src/namestore/libgnunetnamestore.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(GN_LIBINTL)


libgnunetabd_la_SOURCES = \
 abd_api.c abd.h\
 abd_serialization.c \
 abd_serialization.h \
 delegate_misc.c \
 delegate_misc.h
libgnunetabd_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la $(XLIB)
libgnunetabd_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)



check_SCRIPTS = \
  test_abd_issue.sh \
	test_abd_verify_simple.sh \
	test_abd_verify.sh \
	test_abd_verify_and.sh

if ENABLE_TEST_RUN
if HAVE_SQLITE
 AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;
 TESTS = $(check_SCRIPTS)
endif
endif





