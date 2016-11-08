# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include
SUBDIRS  = doc m4 src po pkgconfig

if !TALER_ONLY
  SUBDIRS += contrib
endif

EXTRA_DIST = \
 ABOUT-NLS \
 config.rpath \
 install-sh \
 acinclude.m4

gnunetincludedir = $(includedir)/gnunet
gnunetinclude_HEADERS = gnunet_config.h

docdir = $(datadir)/doc/gnunet/
doc_DATA = COPYING README

ACLOCAL_AMFLAGS = -I m4

