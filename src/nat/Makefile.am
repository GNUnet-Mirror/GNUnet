SUBDIRS = miniupnp libnatpmp

INCLUDES = -I$(top_srcdir)/src/include

if MINGW
  WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols
endif

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif

lib_LTLIBRARIES = libgnunetnat.la

libgnunetnat_la_SOURCES = \
  upnp.c upnp.h \
  natpmp.c natpmp.h \
  nat.c nat.h

libgnunetnat_la_CFLAGS = \
 -I$(top_scrdir)/include

libgnunetnat_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/nat/miniupnp/libminiupnp.la \
  $(top_builddir)/src/nat/libnatpmp/libnatpmp.la \
  $(GN_LIBINTL) @EXT_LIBS@

libgnunetnat_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS) $(WINFLAGS) \
  -version-info 0:0:0

check_PROGRAMS = \
  test-nat

TESTS = $(check_PROGRAMS)

test_nat_SOURCES = \
  test_nat.c

test_nat_LDADD = \
 $(top_builddir)/src/nat/libgnunetnat.la \
 $(top_builddir)/src/util/libgnunetutil.la

