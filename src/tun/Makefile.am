AM_CPPFLAGS = -I$(top_srcdir)/src/include

if MINGW
  WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

lib_LTLIBRARIES = libgnunettun.la

libgnunettun_la_SOURCES = \
  tun.c \
  regex.c
libgnunettun_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la $(XLIB) \
 $(LTLIBINTL)
libgnunettun_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS) \
  -version-info 1:0:1


check_PROGRAMS = \
 test_tun \
 test_regex

if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;
TESTS = $(check_PROGRAMS)
endif

test_tun_SOURCES = \
 test_tun.c
test_tun_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettun.la


test_regex_SOURCES = \
 test_regex.c
test_regex_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la \
 libgnunettun.la
