# This Makefile.am is in the public domain

gnunet.conf.5: gnunet.conf.5.in Makefile
	$(AWK) -v bdir="$(bindir)" -v py="$(PYTHON)" -v awkay="$(AWK_BINARY)" -v pfx="$(prefix)" -v prl="$(PERL)" -v sysconfdirectory="$(sysconfdir)" -v pkgdatadirectory="$(pkgdatadir)" -f $(top_srcdir)/bin/dosubst.awk < $(srcdir)/gnunet.conf.5.in > $(srcdir)/gnunet.conf.5

CLEANFILES = gnunet.conf.5

if TEXI2MDOC_GENERATION
gnunet-tutorial.7: Makefile
	@texi2mdoc -I../tutorial:../tutorial/chapters ../tutorial/tutorial.texi > gnunet-tutorial.7

gnunet-documentation.7: Makefile
	@texi2mdoc -I../handbook:../handbook/chapters ../handbook/gnunet.texi > gnunet-documentation.7

CLEANFILES += gnunet-documentation.7 gnunet-tutorial.7
endif

if HAVE_EXPERIMENTAL
if HAVE_MANDOC
# After I went through the alternatives with the focus
# on staying as portable as possible to other make
# implementations, I have to face the fact after hours
# that this is the most portable way to achieve what
# I want and that the alternatives are depressing and
# nonfunctional.
produce_html.sh: produce_html.sh.in Makefile
	$(AWK) -v bdir="$(bindir)" -v py="$(PYTHON)" -v awkay="$(AWK_BINARY)" -v pfx="$(prefix)" -v prl="$(PERL)" -v sysconfdirectory="$(sysconfdir)" -v pkgdatadirectory="$(pkgdatadir)" -f $(top_srcdir)/bin/dosubst.awk < $(srcdir)/produce_html.sh.in > produce_html.sh
	@chmod +x produce_html.sh

CLEANFILES += produce_html.sh

.PHONY: man-html
man-html: produce_html.sh
	$(SH) $(srcdir)/produce_html.sh

htmldocdir = $(datadir)/doc/gnunet/manhtml/
.PHONY: man-html-install
man-html-install:
	@mkdir -p $(htmldocdir)
	@mv $(srcdir)/*.html $(htmldocdir)
man-html-uninstall:
	@rm $(htmldocdir)/*.html

CLEANFILES += *.html
endif
endif

man_MANS = \
  gnunet.conf.5 \
  gnunet-arm.1 \
  gnunet-ats.1 \
  gnunet-auto-share.1 \
  gnunet-bcd.1 \
  gnunet-bugreport.1 \
  gnunet-config.1 \
  gnunet-core.1 \
  gnunet-conversation.1 \
  gnunet-conversation-test.1 \
  gnunet-directory.1 \
  gnunet-dns2gns.1 \
  gnunet-datastore.1 \
  gnunet-download.1 \
  gnunet-ecc.1 \
  gnunet-fs.1 \
  gnunet-gns.1 \
  gnunet-gns-proxy.1 \
  gnunet-gns-proxy-setup-ca.1 \
  gnunet-identity.1 \
  gnunet-cadet.1 \
  gnunet-namecache.1 \
  gnunet-namestore.1 \
  gnunet-namestore-fcfsd.1 \
  gnunet-nat.1 \
  gnunet-nat-auto.1 \
  gnunet-nat-server.1 \
  gnunet-nse.1 \
  gnunet-peerinfo.1 \
  gnunet-publish.1 \
  gnunet-qr.1 \
  gnunet-reclaim.1 \
  gnunet-resolver.1 \
  gnunet-revocation.1 \
  gnunet-scalarproduct.1 \
  gnunet-scrypt.1 \
  gnunet-search.1 \
  gnunet-statistics.1 \
  gnunet-testbed-profiler.1 \
  gnunet-testing-run-service.1 \
  gnunet-timeout.1 \
  gnunet-transport.1 \
  gnunet-transport-certificate-creation.1 \
  gnunet-unindex.1 \
  gnunet-uri.1 \
  gnunet-vpn.1 \
  gnunet-zoneimport.1

if TEXI2MDOC_GENERATION
man_MANS += gnunet-tutorial.7 gnunet-documentation.7
endif

EXTRA_DIST = ${man_MANS} \
 gnunet.conf.5.in \
 produce_html.sh.in \
 README
