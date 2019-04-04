# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

# only documentation (ALL of the documentation)
if DOCUMENTATION_ONLY
  SUBDIRS = doc
else
  SUBDIRS = m4 src po pkgconfig
endif

# documentation on / off switch (affects all of the documentation)
if DOCUMENTATION
  SUBDIRS += doc
endif
if HAVE_EXPERIMENTAL
  SUBDIRS += lint
endif

# only manpages, needs "doc" subdir
if INCLUDE_MANPAGES
  SUBDIRS += doc
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
