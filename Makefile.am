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

if HAVE_UNCRUSTIFY_BINARY
MCRUSTIFY = find $(top_srcdir) -type f -name '*.c' -or -name '*.h' -print0 | xargs -0 uncrustify -c $(top_srcdir)/contrib/uncrustify.cfg -q --replace --no-backup 2>&1 || true
else
MCRUSTIFY = echo "crustify: skipped"
endif

if HAVE_YAPF_BINARY
MYAPF = find $(top_srcdir) -type f -name '*.py' -or -name '*.py.in' -print0 | xargs -0 $(YAPF_BINARY) -i 2>&1 || true
else
MYAPF = echo "yapf: skipped"
endif

pretty:
	$(MCRUSTIFY)
	$(MYAPF)

lint: check-bashisms check-texinfo check-man check-python

check-bashisms:
if HAVE_CHECKBASHISMS
	printf "If checkbashisms.pl is in PATH, run checkbashism on all .sh files.\n"
	find '.' -type f ! -path '*/.*' ! -path '*/_*' -name '*.sh' -print0 | xargs -0 checkbashisms.pl -f 2>&1 | tee $(srcdir)/bashism.log || true
else
	printf "No checkbashisms in PATH, skipped"
endif

check-man:
	printf "Running lint-man.sh in doc/man.\n"
	@cd $(top_srcdir)/doc/man ; ../../contrib/scripts/lint/lint-man.sh || true

check-python:
	printf "Running flake8 and 2to3 if detected.\n"
	$(top_srcdir)/contrib/scripts/lint/lint-python.sh || true

# exception to add: ignore license files.
# exception to add: uref's can go above 79 chars.
check-texinfo:
	printf "Running basic texinfo linters\n"
	printf "...lines containing tabstops?\n" 2>&1 | tee $(top_srcdir)/doc/handbook/texinfo_handbook.log || true
	printf "...lines containing tabstops?\n" 2>&1 | tee $(top_srcdir)/doc/tutorial/texinfo_tutorial.log || true
	@cd $(top_srcdir)/doc/handbook ; find . -type f ! -path '*/.*' -name '*.texi' -print0 | xargs -0 awk '/\t/ {print FILENAME":"NR":"$$0}' > $(srcdir)/texinfo_handbook.log || true
	@cd $(top_srcdir)/doc/tutorial ; find . -type f ! -path '*/.*' -name '*.texi' -print0 | xargs -0 awk '/\t/ {print FILENAME":"NR":"$$0}' > $(srcdir)/texinfo_tutorial.log || true
	printf "...line length over 79 chars?\n" 2>&1 | tee $(top_srcdir)/doc/handbook/texinfo_handbook.log || true
	@cd $(top_srcdir)/doc/handbook ; find . -type f ! -path '*/.*' -name '*.texi' -print0 | xargs -0 awk 'length>79 {print FILENAME":"NR":"$$0}' > $(srcdir)/texinfo_handbook.log || true
	printf "...line length over 79 chars?\n" 2>&1 | tee $(top_srcdir)/doc/tutorial/texinfo_tutorial.log || true
	@cd $(top_srcdir)/doc/tutorial ; find . -type f ! -path '*/.*' -name '*.texi' -print0 | xargs -0 awk 'length>79 {print FILENAME":"NR":"$$0}' > $(srcdir)/texinfo_tutorial.log || true
	printf "...lines containing macros incompatible with old makeinfo?\n" 2>&1 | tee -a $(top_srcdir)/doc/handbook/texinfo_handbook.log || true
	@cd $(top_srcdir)/doc/handbook ; find . -type f ! -path '*/.*' -name '*.texi' -print0 | xargs -0 awk '/@geq\{\}/ {print FILENAME":"NR":"$$0}' >> $(srcdir)/texinfo_handbook.log || true
	printf "...lines containing macros incompatible with old makeinfo?\n" 2>&1 | tee -a $(top_srcdir)/doc/tutorial/texinfo_tutorial.log || true
	@cd $(top_srcdir)/doc/tutorial ; find . -type f ! -path '*/.*' -name '*.texi' -print0 | xargs -0 awk '/@geq\{\}/ {print FILENAME":"NR":"$$0}' >> $(srcdir)/texinfo_tutorial.log || true
	printf "...lines containing macros incompatible with texi2mdoc?\n" 2>&1 | tee -a $(top_srcdir)/doc/handbook/texinfo_handbook.log || true
	@cd $(top_srcdir)/doc/handbook ; find . -type f ! -path '*/.*' -name '*.texi' -print0 | xargs -0 awk '/@footnote\{/ {print FILENAME":"NR":"$$0}' >> $(srcdir)/texinfo_handbook.log || true
	printf "...lines containing macros incompatible with texi2mdoc?\n" 2>&1 | tee -a $(top_srcdir)/doc/tutorial/texinfo_tutorial.log || true
	@cd $(top_srcdir)/doc/tutorial ; find . -type f ! -path '*/.*' -name '*.texi' -print0 | xargs -0 awk '/@footnote\{/ {print FILENAME":"NR":"$$0}' >> $(srcdir)/texinfo_tutorial.log || true
	printf "...lines telling us what is left TODO or to fix?\n" 2>&1 | tee -a $(top_srcdir)/doc/handbook/texinfo_handbook.log || true
	@cd $(top_srcdir)/doc/handbook ; find . -type f ! -path '*/.*' -name '*.texi' -print0 | xargs -0 awk '/TODO/ {print FILENAME":"NR":"$$0}' >> $(srcdir)/texinfo_handbook.log || true
	@cd $(top_srcdir)/doc/handbook ; find . -type f ! -path '*/.*' -name '*.texi' -print0 | xargs -0 awk '/XXX/ {print FILENAME":"NR":"$$0}' >> $(srcdir)/texinfo_handbook.log || true
	printf "...lines telling us what is left TODO or to fix?\n" 2>&1 | tee -a $(top_srcdir)/doc/tutorial/texinfo_tutorial.log || true
	@cd $(top_srcdir)/doc/tutorial ; find . -type f ! -path '*/.*' -name '*.texi' -print0 | xargs -0 awk '/TODO/ {print FILENAME":"NR":"$$0}' >> $(srcdir)/texinfo_tutorial.log || true
	@cd $(top_srcdir)/doc/tutorial ; find . -type f ! -path '*/.*' -name '*.texi' -print0 | xargs -0 awk '/XXX/ {print FILENAME":"NR":"$$0}' >> $(srcdir)/texinfo_tutorial.log || true
