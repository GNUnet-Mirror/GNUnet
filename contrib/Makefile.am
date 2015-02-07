# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include -I$(top_builddir)/src/include

tap32dir = $(pkgdatadir)/openvpn-tap32/tapw32/

tap64dir = $(pkgdatadir)/openvpn-tap32/tapw64/

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
 terminate.py \
 pydiffer.py \
 gnunet_pyexpect.py \
 gnunet_janitor.py

bin_SCRIPTS = \
 gnunet-gns-import.sh

dist_pkgdata_DATA = \
 gns-bcd.html \
 gns-bcd.tex \
 gnunet-logo.pdf \
 gnunet-logo-color.png \
 testing_hostkeys.ecc

if MINGW
tap32_DATA = \
 openvpn-tap32/tapw32/tap0901.sys \
 openvpn-tap32/tapw32/tap0901.cat \
 openvpn-tap32/tapw32/OemWin2k.inf

tap64_DATA = \
 openvpn-tap32/tapw64/tap0901.sys \
 openvpn-tap32/tapw64/tap0901.cat \
 openvpn-tap32/tapw64/OemWin2k.inf
endif

EXTRA_DIST = \
 no_forcestart.conf \
 no_autostart_above_core.conf \
 coverage.sh \
 report.sh \
 terminate.py.in \
 gnunet_pyexpect.py.in \
 gnunet_janitor.py.in \
 pydiffer.py.in \
 gnunet-gns-import.sh \
 openvpn-tap32/tapw32/tap0901.sys \
 openvpn-tap32/tapw32/tap0901.cat \
 openvpn-tap32/tapw32/OemWin2k.inf \
 openvpn-tap32/tapw64/tap0901.sys \
 openvpn-tap32/tapw64/tap0901.cat \
 openvpn-tap32/tapw64/OemWin2k.inf \
 openvpn-tap32/INSTALL \
 openvpn-tap32/tap32-signed-i386-2.1.zip \
 openvpn-tap32/tap32-source-2.1.zip

CLEANFILES = \
  $(noinst_SCRIPTS)

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

if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;
TESTS = $(check_PROGRAMS)
endif

test_gnunet_prefix_SOURCES = \
 test_gnunet_prefix.c

test_gnunet_prefix_CPPFLAGS = \
  $(LTDLINCL) $(AM_CPPFLAGS)

test_gnunet_prefix_LDADD = \
  $(GCLIBADD) $(WINLIB) \
  $(LTLIBICONV) \
  $(GN_LIBINTL) \
  $(LIBLTDL) -lunistring $(XLIB)

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

