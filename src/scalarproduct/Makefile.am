AM_CPPFLAGS = -I$(top_srcdir)/src/include

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

pkgcfg_DATA = \
  scalarproduct.conf

if MINGW
 WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols
endif

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif

bin_PROGRAMS = \
 gnunet-scalarproduct

libexec_PROGRAMS = \
 gnunet-service-scalarproduct-alice \
 gnunet-service-scalarproduct-bob

lib_LTLIBRARIES = \
  libgnunetscalarproduct.la

gnunet_scalarproduct_SOURCES = \
  gnunet-scalarproduct.c
gnunet_scalarproduct_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  libgnunetscalarproduct.la \
  $(LIBGCRYPT_LIBS) \
  -lgcrypt \
  $(GN_LIBINTL)

gnunet_service_scalarproduct_alice_SOURCES = \
  gnunet-service-scalarproduct.h \
  gnunet-service-scalarproduct_alice.c
gnunet_service_scalarproduct_alice_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/cadet/libgnunetcadet.la \
  $(top_builddir)/src/set/libgnunetset.la \
  $(LIBGCRYPT_LIBS) \
  -lgcrypt \
  $(GN_LIBINTL)

gnunet_service_scalarproduct_bob_SOURCES = \
  gnunet-service-scalarproduct.h \
  gnunet-service-scalarproduct_bob.c gnunet-service-scalarproduct_bob.h
gnunet_service_scalarproduct_bob_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/cadet/libgnunetcadet.la \
  $(top_builddir)/src/set/libgnunetset.la \
  $(LIBGCRYPT_LIBS) \
  -lgcrypt \
  $(GN_LIBINTL)

libgnunetscalarproduct_la_SOURCES = \
  scalarproduct_api.c \
  scalarproduct.h
libgnunetscalarproduct_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(LIBGCRYPT_LIBS) \
  -lgcrypt \
  $(LTLIBINTL)
libgnunetscalarproduct_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)

EXTRA_DIST = \
  test_scalarproduct.conf \
  $(check_SCRIPTS)

check_SCRIPTS = \
  test_scalarproduct.sh \
  test_scalarproduct_negative.sh \
  test_scalarproduct_negativezero.sh

if ENABLE_TEST_RUN
  AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;
  TESTS = $(check_SCRIPTS)
endif
