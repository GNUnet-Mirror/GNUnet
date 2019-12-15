# This Makefile.am is in the public domain
docdir = $(datadir)/doc/gnunet/

infoimagedir = $(infodir)/images

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
AM_MAKEINFOHTMLFLAGS = --no-split --css-ref="../style.css" --css-ref="../manual.css"
endif

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
	version.texi                                           \
	run-gendocs.sh						\
	docstyle.css                                            \
        manual.css                                              \
        reset.css                                               \
        style.css


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

CLEANFILES= \
    stamp-vti \
    version.texi \
    $(DISTCLEANFILES)

clean-local: clean-local-check
.PHONY: clean-local-check
clean-local-check:
	rm -fr manual
	rm -fr gnunet.html
	rm -fr gnunet.t2p
	rm -fr gnunet-c-tutorial.t2p

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

# doc-all-install:
# 	@mkdir -p $(DESTDIR)/$(docdir)
# 	@mkdir -p $(DESTDIR)/$(infoimagedir)
# 	@mkdir -p $(DESTDIR)/$(infodir)
# 	@install -m 0755 gnunet.pdf $(DESTDIR)/$(docdir)
# 	@install -m 0755 gnunet.info $(DESTDIR)/$(infodir)
# 	@install gnunet.html $(DESTDIR)/$(docdir)

# doc-gendoc-install:
# 	@mkdir -p $(DESTDIR)/$(docdir)
# 	@cp -r manual $(DESTDIR)/$(docdir)
