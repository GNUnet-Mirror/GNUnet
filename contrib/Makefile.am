INCLUDES = -I$(top_srcdir)/src/include -I$(top_builddir)/src/include


noinst_PROGRAMS = \
 timeout_watchdog

if !MINGW
timeout_watchdog_SOURCES = \
 timeout_watchdog.c 
else
timeout_watchdog_SOURCES = \
 timeout_watchdog_w32.c
endif

noinst_SCRIPTS = \
 gnunet_pyexpect.py \
 gnunet_janitor.py

bin_SCRIPTS = \
 gnunet-gns-import.sh

dist_pkgdata_DATA = \
 gnunet-logo-color.png \
 testing_hostkeys.dat

EXTRA_DIST = \
 coverage.sh \
 hostlist.cgi \
 hostlist.php \
 report.sh \
 gnunet_pyexpect.py.in \
 gnunet_janitor.py.in \
 gnunet-gns-import.sh

do_subst = $(SED) -e 's,[@]PYTHON[@],$(PYTHON),g'

%.py: %.py.in Makefile
	$(do_subst) < $< > $@
	chmod +x $@

# init_gnunet_redhat \
# init_gnunet_ubuntu \
# visualize_stats.sh \
# gnmessage.sh \
# junkinsert.sh \
# junklookup.sh \
# namespacehelper.sh 


check_PROGRAMS = \
 test_gnunet_prefix

test_gnunet_prefix_SOURCES = \
 test_gnunet_prefix.c

test_gnunet_prefix_LDADD = \
  $(GCLIBADD) $(WINLIB) \
  $(LTLIBICONV) \
  -lltdl -lunistring $(XLIB) 

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

