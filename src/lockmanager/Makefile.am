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
  lockmanager.conf

bin_PROGRAMS = \
  gnunet-service-lockmanager

lib_LTLIBRARIES = \
  libgnunetlockmanager.la

gnunet_service_lockmanager_SOURCES = \
  gnunet-service-lockmanager.c \
  lockmanager.h
gnunet_service_lockmanager_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la
gnunet_service_lockmanager_DEPENDENCIES = \
  $(top_builddir)/src/util/libgnunetutil.la

libgnunetlockmanager_la_SOURCES = \
  lockmanager_api.c lockmanager.h
libgnunetlockmanager_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(XLIB)
libgnunetlockmanager_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS) $(WINFLAGS) \
  -version-info 0:0:0