# This Makefile.am is in the public domain
docdir = $(datadir)/doc/gnunet/

infoimagedir = $(infodir)/images

#DOT_FILES = images/$(wildcard *.dot)

#DOT_VECTOR_GRAPHICS =								\
#	$(DOT_FILES:%.dot=%.eps)						\
#	$(DOT_FILES:%.dot=%.pdf)

# NOTE: While GNU makeinfo 6.5 supports --css-ref=URL,
# makeinfo 4.8 (in NetBSD 8.0, macOS, and maybe other
# base) does only support --css-include=FILE.
# The only difference is a shorter html output and
# in 6.5 the ability to use refs instead of include.
# We prefer not to break builds in this case, so
# we use the include version which is backwards compatible
# and upwards compatible, while the ref variant is neither.

AM_MAKEINFOHTMLFLAGS = --no-split --css-include=style.css --css-include=manual.css

dist_infoimage_DATA =                           		\
	images/gnunet-gtk-0-10-gns-a-done.png 			\
	images/gnunet-gtk-0-10-gns-a.png 			\
	images/daemon_lego_block.png 				\
	images/gnunet-gtk-0-10-gns.png 				\
	images/gnunet-0-10-peerinfo.png 			\
	images/gnunet-gtk-0-10-identity.png 			\
	images/gnunet-fs-gtk-0-10-star-tab.png 			\
	images/gnunet-gtk-0-10-download-area.png 		\
	images/gnunet-gtk-0-10-search-selected.png 		\
	images/gnunet-gtk-0-10-fs-menu.png 			\
	images/gnunet-gtk-0-10-traffic.png 			\
	images/gnunet-gtk-0-10-fs.png 				\
	images/gnunet-namestore-gtk-phone.png 			\
	images/gnunet-gtk-0-10-fs-publish-editing.png 		\
	images/gnunet-namestore-gtk-vpn.png 			\
	images/gnunet-gtk-0-10-fs-published.png 		\
	images/gnunet-setup-exit.png 				\
	images/gnunet-gtk-0-10-fs-publish.png 			\
	images/iceweasel-preferences.png 			\
	images/gnunet-gtk-0-10-fs-publish-select.png 		\
	images/iceweasel-proxy.png 				\
	images/gnunet-gtk-0-10-fs-publish-with-file_0.png 	\
	images/service_lego_block.png 				\
	images/gnunet-gtk-0-10-fs-publish-with-file.png 	\
	images/service_stack.png 				\
	images/gnunet-gtk-0-10-fs-search.png 			\
	images/gnunet-tutorial-service.png 			\
	images/gnunet-tutorial-system.png			\
	images/daemon_lego_block.svg  				\
	images/lego_stack.svg					\
	images/service_lego_block.svg				\
	images/structure.dot                                    \
	images/gns.dot	\
	images/gns.jpg

#	images/$(wildcard *.png)						\
#	images/$(wildcard *.svg)
#	$(DOT_FILES:%.dot=%.png)

#DOT_OPTIONS =									\
#	-Gratio=.9 -Gnodesep=.005 -Granksep=.00005				\
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


info_TEXINFOS = 						\
	gnunet.texi

gnunet_TEXINFOS = 						\
	chapters/developer.texi 				\
	chapters/keyconcepts.texi 				\
	chapters/preface.texi 				\
	chapters/philosophy.texi 				\
	chapters/installation.texi				\
	chapters/user.texi 					\
	chapters/vocabulary.texi				\
	chapters/configuration.texi				\
	chapters/contributing.texi				\
	fdl-1.3.texi 						\
	gpl-3.0.texi						\
	agpl-3.0.texi						\
	version.texi

EXTRA_DIST =							\
	$(gnunet_TEXINFOS)					\
	htmlxref.cnf						\
	gversion.texi                                           \
	run-gendocs.sh						\
	docstyle.css                                            \
        manual.css                                              \
        reset.css                                               \
        style.css


#	$(DOT_FILES)								\
#	$(DOT_VECTOR_GRAPHICS)

DISTCLEANFILES = 						\
	gnunet.cps						\
	chapters/developer.cps					\
	chapters/installation.cps				\
	chapter/philosophy.cps					\
	chapters/user.cps					\
	chapters/configuration.cps				\
	chapters/terminology.cps				\
	chapters/vocabulary.cps					\
	fdl-1.3.cps						\
	agpl-3.0.cps						\
	gpl-3.0.cps

# if HAVE_EXTENDED_DOCUMENTATION_BUILDING
daemon_lego_block.png: images/daemon_lego_block.svg
	convert images/daemon_lego_block.svg images/daemon_lego_block.png &&
	pngcrush images/daemon_lego_block.png images/daemon_lego_block.png

service_lego_block.png: images/service_lego_block.svg
	convert images/service_lego_block.svg images/service_lego_block.png &&
	pngcrush images/service_lego_block.png images/serivce_lego_block.png

lego_stack.png: images/lego_stack.svg
	convert images/lego_stack.svg images/lego_stack.png &&
	pngcrush images/lego_stack.png images/lego_stack.png

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
	@install -m 0755 gnunet.pdf $(DESTDIR)/$(docdir)
	@install -m 0755 gnunet.info $(DESTDIR)/$(infodir)
	@install gnunet.html $(DESTDIR)/$(docdir)

doc-gendoc-install:
	@mkdir -p $(DESTDIR)/$(docdir)
	@cp -r manual $(DESTDIR)/$(docdir)

#	@cp -r images $(DESTDIR)/$(infoimagedir)

dev-build: version.texi/replacement
	@makeinfo --pdf gnunet.texi
	@makeinfo --html gnunet.texi
	@makeinfo --no-split gnunet.texi

# TODO: Add more to clean.
clean: version.texi/replacement/revert
	@rm -f gnunet.pdf
	@rm -f gnunet.html
	@rm -f gnunet.info
	@rm -f gnunet.info-1
	@rm -f gnunet.info-2
	@rm -f gnunet.info-3
	@rm -fr gnunet.t2p
	@rm -fr gnunet-c-tutorial.t2p
	@rm -fr manual

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
