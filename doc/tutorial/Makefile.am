# This Makefile.am is in the public domain
docdir = $(datadir)/doc/gnunet/

#DOT_FILES = images/$(wildcard *.dot)

#DOT_VECTOR_GRAPHICS =						\
#	$(DOT_FILES:%.dot=%.eps)				\
#	$(DOT_FILES:%.dot=%.pdf)

# See ../handbook/Makefile.am comment!
AM_MAKEINFOHTMLFLAGS = --no-split --css-include=style.css --css-include=manual.css

#DOT_OPTIONS =							\
#	-Gratio=.9 -Gnodesep=.005 -Granksep=.00005		\
#	-Nfontsite=9 -Nheight=.1 -Nwidth=.1

# .dot.png:
# 	$(AM_V_DOT)$(DOT) -Tpng $(DOT_OPTIONS) < "$<" > "$(srcdir)/$@.tmp"; \
# 	mv "$(srcdir)/$@.tmp" "$(srcdir)/$@"

# .dot.pdf:
# 	$(AM_V_DOT)$(DOT) -Tpdf $(DOT_OPTIONS) < "$<" > "$(srcdir)/$@.tmp"; \
# 	mv "$(srcdir)/$@.tmp" "$(srcdir)/$@"

# .dot.eps:
# 	$(AM_V_DOT)$(DOT) -Teps $(DOT_OPTIONS) < "$<" > "$(srcdir)/$@.tmp"; \
# 	mv "$(srcdir)/$@.tmp" "$(srcdir)/$@"

# .png.eps:
# 	$(AM_V_GEN)convert "$<" "$@-tmp.eps"; \
# 	mv "$@-tmp.eps" "$@"

# pdf-local: $(DOT_FILES=%.dot=$(top_srcdir)/%.pdf)
# info-local: $(DOT_FILES=%.dot=$(top_srcdir)/%.png)
# ps-local: $(DOT_FILES=%.dot=$(top_srcdir)/%.eps)                \
# 	$(top_srcdir)/%D%/images/coreutils-size-map.eps
# dvi-local: ps-local


gnunet_tutorial_examples =						\
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
	examples/025.Makefile.am					\
	examples/026.c                                                  \
	examples/testbed_test.c

info_TEXINFOS = 						\
	gnunet-tutorial.texi

EXTRA_DIST =							\
	$(gnunet_tutorial_examples)				\
	htmlxref.cnf						\
	run-gendocs.sh						\
	docstyle.css                                            \
        manual.css                                              \
        reset.css                                               \
        style.css


DISTCLEANFILES = 						\
	gnunet-tutorial.cps					\
	fdl-1.3.cps

# XXX: is this sed invocation portable enough? otherwise try tr(1).
version.texi/replacement: version.texi/replacement/revert
	@sed "s/GPACKAGE_VERSION/$(PACKAGE_VERSION)/g" gversion.texi > gversion.texi.tmp
	@mv gversion.texi.tmp gversion.texi

version.texi/replacement/revert:
	@echo "@set VERSION GPACKAGE_VERSION" > gversion.texi
	@echo "@set EDITION GPACKAGE_VERSION" >> gversion.texi



# FIXME: rm *.html and *.pdf
#doc-clean:
#	@rm *.aux *.log *.toc *.cp *.cps

all: version.texi/replacement

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

#	@cp -r images $(DESTDIR)/$(infoimagedir)

dev-build: version.texi/replacement
	@makeinfo --pdf gnunet-c-tutorial.texi
	@makeinfo --html gnunet-c-tutorial.texi
	@makeinfo --no-split gnunet-c-tutorial.texi

# TODO: Add more to clean.
clean: version.texi/replacement/revert
	@rm -f gnunet-tutorial.pdf
	@rm -f gnunet-tutorial.info
	@rm -f gnunet-tutorial.html
	@rm -fr gnunet-tutorial.t2p

# CLEANFILES =						\
# 	gnunet.log					\
# 	gnunet-c-tutorial.log				\
# 	$(wildcard *.aux)				\
# 	$(wildcard *.toc)				\
# 	$(wildcard *.cp)				\
# 	$(wildcard *.cps)

#.PHONY: version.texi
# if HAVE_EXTENDED_DOCUMENTATION_BUILDING_PDF

# if HAVE_EXTENDED_DOCUMENTATION_BUILDING_HTML

# endif
# endif
# endif
