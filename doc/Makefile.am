# This Makefile.am is in the public domain
SUBDIRS = man doxygen

docdir = $(datadir)/doc/gnunet/

infoimagedir = $(infodir)/images

dist_infoimage_DATA =                           		\
	images/gnunet-gtk-0-10-gns-a-done.png 			\
	images/gnunet-gtk-0-10-gns-a.png 			\
	images/daemon_lego_block.png 				\
	images/gnunet-gtk-0-10-gns.png 				\
	images/gnunet-0-10-peerinfo.png 			\
	images/gnunet-gtk-0-10-identity.png 			\
	images/gnunet-fs-gtk-0-10-star-tab.png 			\
	images/gnunet-gtk-0-10.png 				\
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
	images/service_lego_block.svg

gnunet_tutorial_examples =					\
	001.c							\
	002.c							\
	003.c							\
	004.c							\
	005.c							\
	006.c							\
	007.c							\
	008.c							\
	009.c							\
	010.c							\
	011.c							\
	012.c							\
	013.c							\
	014.c							\
	015.c							\
	016.c							\
	017.c							\
	018.c							\
	019.c							\
	020.c							\
	021.c							\
	022.c							\
	023.c							\
	024.c							\
	025.c							\
	026.c

info_TEXINFOS = \
	gnunet.texi

# It seems as if either we still have gnunet-c-tutorial markup issues
# or we have issues that can only occur in systems which are not using Guix
# or we have version incompabilities.
#	gnunet-c-tutorial.texi

gnunet_TEXINFOS = \
	chapters/developer.texi \
	chapters/installation.texi \
	chapters/philosophy.texi \
	chapters/user.texi \
	fdl-1.3.texi \
	gpl-3.0.texi

EXTRA_DIST = \
	$(gnunet_TEXINFOS) \
	$(gnunet_tutorial_examples) \
	outdated-and-old-installation-instructions.txt \
	gnunet-c-tutorial-v1.pdf \
	README.txt

daemon_lego_block.png: images/daemon_lego_block.svg
	convert images/daemon_lego_block.svg images/daemon_lego_block.png &&
	pngcrush images/daemon_lego_block.png images/daemon_lego_block.png

service_lego_block.png: images/service_lego_block.svg
	convert images/service_lego_block.svg images/service_lego_block.png &&
	pngcrush images/service_lego_block.png images/serivce_lego_block.png

lego_stack.png: images/lego_stack.svg
	convert images/lego_stack.svg images/lego_stack.png &&
	pngcrush images/lego_stack.png images/lego_stack.png

version.texi:
	echo "@set UPDATED $(date +'%d %B %Y')" > $@
	echo "@set UPDATED-MONTH $(date +'%B %Y')" >> $@
	echo "@set EDITION $(PACKAGE_VERSION)" >> $@
	echo "@set VERSION $(PACKAGE_VERSION)" >> $@ 

doc-pdf: version.texi
	@makeinfo --pdf --quiet gnunet.texi
doc-pdf-tutorial: version.texi
	@makeinfo --pdf --quiet gnunet-c-tutorial.texi

doc-html: version.texi
	@makeinfo --html gnunet.texi
doc-html-tutorial: version.texi
	@makeinfo --html gnunet-c-tutorial.texi

doc-info: version.texi
	@makeinfo --no-split gnunet.texi
doc-info-tutorial: version.texi
	@makeinfo --no-split gnunet-c-tutorial.texi

# FIXME: rm *.html and *.pdf
doc-clean:
	@rm *.aux *.log *.toc *.cp *.cps

doc-all: doc-pdf doc-html doc-info doc-pdf-tutorial doc-html-tutorial doc-info-tutorial

doc-pdf-noise: version.texi
	@makeinfo --pdf gnunet.texi
doc-pdf-tutorial-noise: version.texi
	@makeinfo --pdf gnunet-c-tutorial.texi

doc-html-noise: version.texi
	@makeinfo --html gnunet.texi
doc-html-tutorial-noise: version.texi
	@makeinfo --html gnunet-c-tutorial.texi

doc-info-noise: version.texi
	@makeinfo --no-split gnunet.texi
doc-info-tutorial-noise: version.texi
	@makeinfo --no-split gnunet-c-tutorial.texi

doc-all-give-me-the-noise: doc-pdf-noise doc-html-noise doc-info-noise doc-pdf-tutorial-noise doc-html-tutorial-noise doc-info-tutorial-noise

.PHONY: version.texi
