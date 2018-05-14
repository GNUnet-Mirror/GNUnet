# This Makefile.am is in the public domain
docdir = $(datadir)/doc/gnunet/

infoimagedir = $(infodir)/images

#DOT_FILES = images/$(wildcard *.dot)

#DOT_VECTOR_GRAPHICS =								\
#	$(DOT_FILES:%.dot=%.eps)						\
#	$(DOT_FILES:%.dot=%.pdf)

AM_MAKEINFOHTMLFLAGS = --no-split --css-ref=docstyle.css

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
	images/gns.dot

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


gnunet_tutorial_examples =					\
	tutorial-examples/001.c							\
	tutorial-examples/002.c							\
	tutorial-examples/003.c							\
	tutorial-examples/004.c							\
	tutorial-examples/005.c							\
	tutorial-examples/006.c							\
	tutorial-examples/007.c							\
	tutorial-examples/008.c							\
	tutorial-examples/009.c							\
	tutorial-examples/010.c							\
	tutorial-examples/011.c							\
	tutorial-examples/012.c							\
	tutorial-examples/013.c							\
	tutorial-examples/013.1.c							\
	tutorial-examples/014.c							\
	tutorial-examples/015.c							\
	tutorial-examples/016.c							\
	tutorial-examples/017.c							\
	tutorial-examples/018.c							\
	tutorial-examples/019.c							\
	tutorial-examples/020.c							\
	tutorial-examples/021.c							\
	tutorial-examples/022.c							\
	tutorial-examples/023.c							\
	tutorial-examples/024.c							\
	tutorial-examples/025.c							\
	tutorial-examples/026.c

info_TEXINFOS = 						\
	gnunet.texi						\
	gnunet-c-tutorial.texi

gnunet_TEXINFOS = 						\
	chapters/developer.texi 				\
	chapters/preface.texi 				\
	chapters/installation.texi 				\
	chapters/philosophy.texi 				\
	chapters/user.texi 					\
	chapters/vocabulary.texi				\
	chapters/configuration.texi				\
	chapters/contributing.texi				\
	fdl-1.3.texi 						\
	gpl-3.0.texi

EXTRA_DIST =							\
	$(gnunet_TEXINFOS)					\
	$(gnunet_tutorial_examples)				\
	htmlxref.cnf						\
	run-gendocs.sh						\
	docstyle.css


#	$(DOT_FILES)								\
#	$(DOT_VECTOR_GRAPHICS)

DISTCLEANFILES = 						\
	gnunet.cps						\
	gnunet-c-tutorial.cps					\
	chapters/developer.cps					\
	chapters/installation.cps				\
	chapter/philosophy.cps					\
	chapters/user.cps					\
	chapters/configuration.cps				\
	chapters/terminology.cps				\
	chapters/vocabulary.cps					\
	fdl-1.3.cps						\
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

# FIXME: The usage of 'date' strings causes a warning.
# version.texi:
# 	echo "@set UPDATED $(date +'%d %B %Y')" > $@
# 	echo "@set UPDATED-MONTH $(date +'%B %Y')" >> $@
# 	echo "@set EDITION $(PACKAGE_VERSION)" >> $@
# 	echo "@set VERSION $(PACKAGE_VERSION)" >> $@

# Workaround for makeinfo error. Whcih in turn introduces more
# date-related 'warnings'. Well.
version2.texi:
	echo "@set UPDATED $(date +'%d %B %Y')" > $@
	echo "@set UPDATED-MONTH $(date +'%B %Y')" >> $@
	echo "@set EDITION $(PACKAGE_VERSION)" >> $@
	echo "@set VERSION $(PACKAGE_VERSION)" >> $@

# FIXME: rm *.html and *.pdf
#doc-clean:
#	@rm *.aux *.log *.toc *.cp *.cps

doc-all-install:
	@mkdir -p $(DESTDIR)/$(docdir)
	@mkdir -p $(DESTDIR)/$(infoimagedir)
	@mkdir -p $(DESTDIR)/$(infodir)
	@install -m 0755 gnunet.pdf $(DESTDIR)/$(docdir)
	@install -m 0755 gnunet-c-tutorial.pdf $(DESTDIR)/$(docdir)
	@install -m 0755 gnunet-c-tutorial.info $(DESTDIR)/$(infodir)
	@install -m 0755 gnunet.info $(DESTDIR)/$(infodir)
	@install gnunet.html $(DESTDIR)/$(docdir)
	@install gnunet-c-tutorial.html $(DESTDIR)/$(docdir)

doc-gendoc-install:
	@mkdir -p $(DESTDIR)/$(docdir)
	@cp -r manual $(DESTDIR)/$(docdir)

#	@cp -r images $(DESTDIR)/$(infoimagedir)

dev-build: version.texi version2.texi
	@makeinfo --pdf gnunet.texi
	@makeinfo --pdf gnunet-c-tutorial.texi
	@makeinfo --html gnunet.texi
	@makeinfo --html gnunet-c-tutorial.texi
	@makeinfo --no-split gnunet.texi
	@makeinfo --no-split gnunet-c-tutorial.texi

# TODO: Add more to clean.
clean:
	@rm -f gnunet.pdf
	@rm -f gnunet.html
	@rm -f gnunet.info
	@rm -f gnunet.info-1
	@rm -f gnunet.info-2
	@rm -f gnunet.info-3
	@rm -f gnunet-c-tutorial.pdf
	@rm -f gnunet-c-tutorial.info
	@rm -f gnunet-c-tutorial.html
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
