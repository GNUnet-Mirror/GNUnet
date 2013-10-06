AM_CPPFLAGS = -I$(top_srcdir)/src/include

if MINGW
 WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

pkgcfg_DATA = \
  revocation.conf

bin_PROGRAMS = \
 gnunet-revocation


gnunet_revocation_SOURCES = \
 gnunet-revocation.c
gnunet_revocation_LDADD = \
  libgnunetrevocation.la \
  $(top_builddir)/src/identity/libgnunetidentity.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)

lib_LTLIBRARIES = libgnunetrevocation.la

libgnunetrevocation_la_SOURCES = \
  revocation_api.c revocation.h
libgnunetrevocation_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL) $(XLIB) -lgcrypt
libgnunetrevocation_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)  $(WINFLAGS) \
  -version-info 0:0:0

libexec_PROGRAMS = \
 gnunet-service-revocation


gnunet_service_revocation_SOURCES = \
 gnunet-service-revocation.c
gnunet_service_revocation_LDADD = \
  $(top_builddir)/src/revocation/libgnunetrevocation.la \
  $(top_builddir)/src/core/libgnunetcore.la \
  $(top_builddir)/src/set/libgnunetset.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  -lm \
  $(GN_LIBINTL)
gnunet_service_revocation_DEPENDENCIES = \
  libgnunetrevocation.la


EXTRA_DIST = test_revocation.conf

