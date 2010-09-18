INCLUDES = -I$(top_srcdir)/src/include

plugindir = $(libdir)/gnunet

if MINGW
  WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage
endif

lib_LTLIBRARIES = libgnunetblock.la

plugin_LTLIBRARIES = \
  libgnunet_plugin_block_fs.la \
  libgnunet_plugin_block_template.la 

libgnunet_plugin_block_fs_la_SOURCES = \
  plugin_block_fs.c
libgnunet_plugin_block_fs_la_LIBADD = \
  $(top_builddir)/src/block/libgnunetblock.la \
  $(top_builddir)/src/util/libgnunetutil.la 
libgnunet_plugin_block_fs_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)

libgnunet_plugin_block_template_la_SOURCES = \
  plugin_block_template.c
libgnunet_plugin_block_template_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la 
libgnunet_plugin_block_template_la_LDFLAGS = \
 $(GN_PLUGIN_LDFLAGS)


libgnunetblock_la_SOURCES = \
  block.c plugin_block.h
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

