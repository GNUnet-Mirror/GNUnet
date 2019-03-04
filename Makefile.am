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

# Check for bashisms in shell scripts
# Very verbose, need to exclude more files.
check-bashism:
	printf "Run checkbashism on all .sh files.\n"
	printf "Currently this expects checkbashism.pl at a fixed location."
	find . -type f ! -path '*/.*' ! -path '*/_*' -name '*.sh' -print0 | xargs -0 ~/src/scripts/src/checkbashisms.pl -f

check-python:
	printf "Running flake8 and 2to3 if detected.\n"
	$(top_srcdir)/contrib/scripts/lint-python.sh

check-man:
	printf "Running lint-man.sh in doc/man.\n"
	@cd $(top_srcdir)/doc/man ; $(top_srcdir)/../../contrib/scripts/lint-man.sh || true
