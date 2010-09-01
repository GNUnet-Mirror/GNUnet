SUBDIRS = .

INCLUDES = -I$(top_srcdir)/src/include

if MINGW
  WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols
endif

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif

if !MINGW

if HAVE_EXPERIMENTAL
lib_LTLIBRARIES = libgnunetnat.la
endif

libgnunetnat_la_SOURCES = \
  upnp.c upnp.h \
  natpmp.c natpmp.h \
  nat.c 

libgnunetnat_la_CFLAGS = \
 -I$(top_scrdir)/include

libgnunetnat_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL) @EXT_LIBS@ 

libgnunetnat_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS) $(WINFLAGS) \
  -version-info 0:0:0

if HAVE_EXPERIMENTAL
check_PROGRAMS = \
  test-nat
endif

if !DISABLE_TEST_RUN
TESTS = $(check_PROGRAMS)
endif

test_nat_SOURCES = \
  test_nat.c

test_nat_LDADD = \
 $(top_builddir)/src/nat/libgnunetnat.la \
 $(top_builddir)/src/util/libgnunetutil.la

endif
