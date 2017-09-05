  plugindir = $(libdir)/gnunet

  plugin_LTLIBRARIES = \
          libgnunet_plugin_block_ext.la
  libgnunet_plugin_block_ext_la_SOURCES = \
          plugin_block_ext.c
  libgnunet_plugin_block_ext_la_LIBADD = \
          $(prefix)/lib/libgnunethello.la \
          $(prefix)/lib/libgnunetblock.la \
          $(prefix)/lib/libgnunetutil.la
  libgnunet_plugin_block_ext_la_LDFLAGS = \
          $(GN_PLUGIN_LDFLAGS)
  libgnunet_plugin_block_ext_la_DEPENDENCIES = \
          $(prefix)/lib/libgnunetblock.la

