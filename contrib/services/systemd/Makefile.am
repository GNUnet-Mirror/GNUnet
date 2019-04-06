pkginitddir= $(pkgdatadir)/services/systemd

install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(pkginitdir)
	@$(NORMAL_INSTALL)
    $(INSTALL_DATA) gnunet.service $(DESTDIR)$(pkginitdir)
