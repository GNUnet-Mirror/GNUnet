# This Makefile.am is in the public domain
if DOCUMENTATION
  SUBDIRS = doxygen handbook tutorial
endif

if !DOCUMENTATION
  SUBDIRS = doxygen
endif

if INCLUDE_MANPAGES
  SUBDIRS += man
endif

EXTRA_DIST =							\
	system_specific/outdated-and-old-installation-instructions.txt \
	system_specific/FROM_SOURCE
