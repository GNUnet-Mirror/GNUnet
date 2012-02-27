INCLUDES = -I$(top_srcdir)/src/include

if MINGW
  WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage
endif

lib_LTLIBRARIES = libgnunetfragmentation.la

libgnunetfragmentation_la_SOURCES = \
  fragmentation.c fragmentation.h \
  defragmentation.c 
libgnunetfragmentation_la_LIBADD = -lm \
 $(top_builddir)/src/statistics/libgnunetstatistics.la \
 $(top_builddir)/src/util/libgnunetutil.la  
libgnunetfragmentation_la_LDFLAGS = \
 $(GN_LIB_LDFLAGS) \
  -version-info 0:0:0

check_PROGRAMS = \
 test_fragmentation

if ENABLE_TEST_RUN
TESTS = $(check_PROGRAMS)
endif

test_fragmentation_SOURCES = \
 test_fragmentation.c
test_fragmentation_LDADD = \
 $(top_builddir)/src/fragmentation/libgnunetfragmentation.la \
 $(top_builddir)/src/util/libgnunetutil.la  

EXTRA_DIST = test_fragmentation_data.conf