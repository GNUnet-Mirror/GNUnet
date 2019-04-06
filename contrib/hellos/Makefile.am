# This Makefile.am is in the public domain

pkghellodir= $(pkgdatadir)/hellos

install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(pkghellodir)
	@$(NORMAL_INSTALL)
	for hello in $(srcdir)/hellos/*; do \
	  if test -f $$hello; then \
	    $(INSTALL_DATA) $$hello $(DESTDIR)$(pkghellodir)/ ; \
	  fi \
	done

dist-hook:
	if test -d $(srcdir)/hellos; then \
	  mkdir -p $(distdir)/hellos; \
	  for hello in $(srcdir)/hellos/*; do \
	    if test -f $$hello; then \
	      cp -p $$hello $(distdir)/hellos; \
	    fi \
	  done \
	fi
