# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

if DOCUMENTATION_ONLY
  SUBDIRS = doc
else
  SUBDIRS = m4 src po pkgconfig
if DOCUMENTATION
  SUBDIRS += doc
endif
endif

if !TALER_ONLY
  SUBDIRS += contrib
endif

EXTRA_DIST = \
 ABOUT-NLS \
 config.rpath \
 acinclude.m4 \
 README.1st

gnunetincludedir = $(includedir)/gnunet
gnunetinclude_HEADERS = gnunet_config.h

docdir = $(datadir)/doc/gnunet/
doc_DATA = COPYING README

ACLOCAL_AMFLAGS = -I m4
