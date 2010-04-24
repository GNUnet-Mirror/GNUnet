INCLUDES = -I$(top_srcdir)/src/include

if MINGW
  WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage
endif

lib_LTLIBRARIES = libgnunetblock.la

libgnunetblock_la_SOURCES = \
  block.c 
libgnunetblock_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la  

check_PROGRAMS = \
 test_block

#TESTS = $(check_PROGRAMS)

test_block_SOURCES = \
 test_block.c
test_block_LDADD = \
 $(top_builddir)/src/block/libgnunetblock.la \
 $(top_builddir)/src/util/libgnunetutil.la  

