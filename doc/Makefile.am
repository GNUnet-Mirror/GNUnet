# This Makefile.am is in the public domain
SUBDIRS = man doxygen

docdir = $(datadir)/doc/gnunet/

infoimagedir = $(infodir)/images

dist_infoimage_DATA =                           		\
	%D%/images/gnunet-gtk-0-10-gns-a-done.png 		\
	%D%/images/gnunet-gtk-0-10-gns-a.png 			\
	%D%/images/daemon_lego_block.png 			\
	%D%/images/gnunet-gtk-0-10-gns.png 			\
	%D%/images/gnunet-0-10-peerinfo.png 			\
	%D%/images/gnunet-gtk-0-10-identity.png 		\
	%D%/images/gnunet-fs-gtk-0-10-star-tab.png 		\
	%D%/images/gnunet-gtk-0-10.png 				\
	%D%/images/gnunet-gtk-0-10-download-area.png 		\
	%D%/images/gnunet-gtk-0-10-search-selected.png 		\
	%D%/images/gnunet-gtk-0-10-fs-menu.png 			\
	%D%/images/gnunet-gtk-0-10-traffic.png 			\
	%D%/images/gnunet-gtk-0-10-fs.png 			\
	%D%/images/gnunet-namestore-gtk-phone.png 		\
	%D%/images/gnunet-gtk-0-10-fs-publish-editing.png 	\
	%D%/images/gnunet-namestore-gtk-vpn.png 		\
	%D%/images/gnunet-gtk-0-10-fs-published.png 		\
	%D%/images/gnunet-setup-exit.png 			\
	%D%/images/gnunet-gtk-0-10-fs-publish.png 		\
	%D%/images/iceweasel-preferences.png 			\
	%D%/images/gnunet-gtk-0-10-fs-publish-select.png 	\
	%D%/images/iceweasel-proxy.png 				\
	%D%/images/gnunet-gtk-0-10-fs-publish-with-file_0.png 	\
	%D%/images/service_lego_block.png 			\
	%D%/images/gnunet-gtk-0-10-fs-publish-with-file.png 	\
	%D%/images/service_stack.png 				\
	%D%/images/gnunet-gtk-0-10-fs-search.png 		\
	%D%/images/gnunet-tutorial-service.png 			\
	%D%/images/gnunet-tutorial-system.png

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
	gnunet.texi \
	gnunet-c-tutorial.texi

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
