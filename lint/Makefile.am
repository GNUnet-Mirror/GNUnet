all: check-linters

do_subst = $(SED) -e 's,[@]PERL[@],$(PERL),g'

SUFFIXES = pl.in .pl

checkbashisms.pl: checkbashisms.pl.in Makefile
	$(do_subst) < $(srcdir)/checkbashisms.pl.in > checkbashisms.pl
	chmod +x checkbashisms.pl

CLEANFILES=	\
		checkbashisms.pl

noinst_SCRIPTS =		\
		$(CLEANFILES)

# Check for bashisms in shell scripts
# Very verbose, need to exclude more files.
check-bashism:
	printf "Run checkbashism on all .sh files.\n"
	printf "Currently this expects checkbashism.pl at a fixed location."
	find '..' -type f ! -path '*/.*' ! -path '*/_*' -name '*.sh' -print0 | xargs -0 $(srcdir)/checkbashisms.pl -f 2>&1 | tee $(srcdir)/bashism.log || true

check-python:
	printf "Running flake8 and 2to3 if detected.\n"
	$(top_srcdir)/contrib/scripts/lint-python.sh || true

check-man:
	printf "Running lint-man.sh in doc/man.\n"
	@cd $(top_srcdir)/doc/man ; ../../contrib/scripts/lint-man.sh || true

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

check-linters: check-bashism check-python check-man check-texinfo

EXTRA_DIST = \
  checkbashisms.pl.in
