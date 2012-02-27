INCLUDES = -I$(top_srcdir)/src/include

if MINGW
  WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

lib_LTLIBRARIES = libgnunettun.la

libgnunettun_la_SOURCES = \
  tun.c
libgnunettun_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la $(XLIB)
libgnunettun_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS) \
  -version-info 0:0:0


check_PROGRAMS = \
 test_tun


if ENABLE_TEST_RUN
TESTS = $(check_PROGRAMS)
endif

test_tun_SOURCES = \
 test_tun.c
test_tun_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 $(top_builddir)/src/tun/libgnunettun.la
