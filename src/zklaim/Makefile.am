# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

plugindir = $(libdir)/gnunet

libexecdir= $(pkglibdir)/libexec/

pkgcfgdir= $(pkgdatadir)/config.d/

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

pkgcfg_DATA = \
  zklaim.conf

plugin_LTLIBRARIES = \
  libgnunet_plugin_reclaim_attribute_zklaim.la \
	libgnunet_plugin_gnsrecord_zklaim.la

lib_LTLIBRARIES = \
	libgnunetzklaim.la

libexec_PROGRAMS = \
	gnunet-service-zklaim

libgnunet_plugin_gnsrecord_zklaim_la_SOURCES = \
  plugin_gnsrecord_zklaim.c
libgnunet_plugin_gnsrecord_zklaim_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(LTLIBINTL)
libgnunet_plugin_gnsrecord_zklaim_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)



libgnunetzklaim_la_SOURCES = \
  zklaim_api.c \
  zklaim_functions.c
libgnunetzklaim_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL) $(XLIB)
libgnunetzklaim_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)  $(WINFLAGS) \
  -version-info 0:0:0

gnunet_service_zklaim_SOURCES = \
 gnunet-service-zklaim.c
gnunet_service_zklaim_LDADD = \
  $(top_builddir)/src/gnsrecord/libgnunetgnsrecord.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/namestore/libgnunetnamestore.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/reclaim-attribute/libgnunetreclaimattribute.la \
  $(top_builddir)/src/reclaim/libgnunetreclaim.la \
  $(top_builddir)/src/gns/libgnunetgns.la \
  $(GCLIBADD)\
  $(LIBGCRYPT_LIBS) \
	-lzklaim \
  -lgcrypt \
  -lgmp \
  -lgmpxx \
  -lcrypto \
  -lprocps \
  -lstdc++ \
  -lm
  $(GN_LIBINTL)



libgnunet_plugin_reclaim_attribute_zklaim_la_SOURCES = \
  plugin_reclaim_attribute_zklaim.c
libgnunet_plugin_reclaim_attribute_zklaim_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(LTLIBINTL)
libgnunet_plugin_reclaim_attribute_zklaim_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)

test_zklaim_SOURCES = zklaim.c
test_zklaim_LDADD = \
  $(GCLIBADD)\
  $(LIBGCRYPT_LIBS) \
	-lzklaim \
  -lgcrypt \
  -lgmp \
  -lgmpxx \
  -lcrypto \
  -lprocps \
  -lstdc++ \
  -lm
test_zklaim_LDFLAGS = \
  $(GN_LIB_LDFLAGS)

gnunet_zklaim_SOURCES = gnunet-zklaim.c
gnunet_zklaim_LDADD = \
	$(top_builddir)/src/util/libgnunetutil.la \
	$(top_builddir)/src/identity/libgnunetidentity.la \
	libgnunetzklaim.la \
  $(GCLIBADD)\
  $(LIBGCRYPT_LIBS) \
	-lzklaim \
  -lgcrypt \
  -lgmp \
  -lgmpxx \
  -lcrypto \
  -lprocps \
  -lstdc++ \
  -lm
gnunet_zklaim_LDFLAGS = \
  $(GN_LIB_LDFLAGS)

bin_PROGRAMS = gnunet-zklaim
#lib_LTLIBRARIES = libgnunetzklaim.la
check_PROGRAMS = test_zklaim

if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
TESTS = $(check_PROGRAMS)
endif
