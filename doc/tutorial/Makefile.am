# This Makefile.am is in the public domain
docdir = $(datadir)/doc/gnunet/

if ACTIVATE_TEXINFO4
# NOTE: While GNU makeinfo 6.5 supports --css-ref=URL,
# makeinfo 4.8 (in NetBSD 8.0, macOS, and maybe other
# base) does only support --css-include=FILE.
# The only difference is a shorter html output and
# in 6.5 the ability to use refs instead of include.
# We prefer not to break builds in this case, so
# we use the include version which is backwards compatible
# and upwards compatible, while the ref variant is neither.
AM_MAKEINFOHTMLFLAGS = --no-split --css-include=style.css --css-include=manual.css
else
# In the 5.x version they added `--split=chapters|sections` in
# addition to `--split=nodes`.
# Hold on to your hats: In version 6.5 this is already removed, ffs.
# GNU Texinfo, please be more consistent than 1 version in switches.
# This however is compatible to version 5.2. Thanks, I hate it.
# AM_MAKEINFOHTMLFLAGS = --split=sections --css-ref="../style.css" --css-ref="../manual.css"
AM_MAKEINFOHTMLFLAGS = --split --css-ref="../style.css" --css-ref="../manual.css"
endif

gnunet_tutorial_examples =					\
	examples/001.c							\
	examples/002.c							\
	examples/003.c							\
	examples/004.c							\
	examples/005.c							\
	examples/006.c							\
	examples/007.c							\
	examples/008.c							\
	examples/009.c							\
	examples/010.c							\
	examples/011.c							\
	examples/012.c							\
	examples/013.c							\
	examples/013.1.c						\
	examples/014.c							\
	examples/015.c							\
	examples/016.c							\
	examples/017.c							\
	examples/018.c							\
	examples/019.c							\
	examples/020.c							\
	examples/021.c							\
	examples/022.c							\
	examples/023.c							\
	examples/024.c							\
	examples/025.Makefile.am				\
	examples/026.c                          \
	examples/testbed_test.c

info_TEXINFOS = tutorial.texi

tutorial_TEXINFOS = \
	fdl-1.3.texi 						\
	gpl-3.0.texi						\
	agpl-3.0.texi						\
	version.texi

EXTRA_DIST = \
	$(tutorial_TEXINFOS)	\
	$(gnunet_tutorial_examples)	\
	htmlxref.cnf \
	run-gendocs.sh \
	docstyle.css \
    manual.css \
    reset.css \
    style.css


DISTCLEANFILES = \
    tutorial.cps \
	fdl-1.3.cps \
	agpl-3.0.cps \
	gpl-3.0.cps


CLEANFILES= \
    stamp-vti \
    version.texi \
    tutorial.t2p \
    $(DISTCLEANFILES)

doc-all-install:
	@mkdir -p $(DESTDIR)/$(docdir)
	@mkdir -p $(DESTDIR)/$(infoimagedir)
	@mkdir -p $(DESTDIR)/$(infodir)
	@install -m 0755 gnunet-tutorial.pdf $(DESTDIR)/$(docdir)
	@install -m 0755 gnunet-tutorial.info $(DESTDIR)/$(infodir)
	@install gnunet-tutorial.html $(DESTDIR)/$(docdir)

doc-gendoc-install:
	@mkdir -p $(DESTDIR)/$(docdir)
	@cp -r manual $(DESTDIR)/$(docdir)
