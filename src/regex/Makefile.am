INCLUDES = -I$(top_srcdir)/src/include

if MINGW
  WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage
endif

lib_LTLIBRARIES = libgnunetregex.la

libgnunetregex_la_SOURCES = \
  regex.c regex.h
libgnunetregex_la_LIBADD = -lm \
 $(top_builddir)/src/util/libgnunetutil.la
libgnunetregex_la_LDFLAGS = \
 $(GN_LIB_LDFLAGS) \
  -version-info 0:0:0

check_PROGRAMS = \
 test_regex

if ENABLE_TEST_RUN
TESTS = $(check_PROGRAMS)
endif

test_regex_SOURCES = \
 test_regex.c
test_regex_LDADD = \
 $(top_builddir)/src/regex/libgnunetregex.la \
 $(top_builddir)/src/util/libgnunetutil.la

EXTRA_DIST = test_regex_data.conf
