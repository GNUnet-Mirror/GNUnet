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
 scripts/terminate.py \
 scripts/pydiffer.py \
 scripts/removetrailingwhitespace.py \
 scripts/gnunet_pyexpect.py \
 scripts/gnunet_janitor.py \
 scripts/gnunet-chk.py

dist_pkgdata_DATA = \
 gns/gns-bcd.html \
 gns/gns-bcd.tex \
 gns/def.tex \
 gns/gns-form-fields.xml \
 gns/gns-form.xslt \
 branding/logo/gnunet-logo.pdf \
 branding/logo/gnunet-logo-color.png \
 testing_hostkeys.ecc

if MINGW
tap32_DATA = \
 3rdparty/Windows/openvpn-tap32/tapw32/tap0901.sys \
 3rdparty/Windows/openvpn-tap32/tapw32/tap0901.cat \
 3rdparty/Windows/openvpn-tap32/tapw32/OemWin2k.inf

tap64_DATA = \
 3rdparty/Windows/openvpn-tap32/tapw64/tap0901.sys \
 3rdparty/Windows/openvpn-tap32/tapw64/tap0901.cat \
 3rdparty/Windows/openvpn-tap32/tapw64/OemWin2k.inf
endif

EXTRA_DIST = \
 conf/colorit/colorit.conf \
 conf/editors/eclipse/gnunet_codingstyle.xml \
 conf/gnunet/no_forcestart.conf \
 conf/gnunet/no_autostart_above_core.conf \
 conf/nss/nssswitch.conf \
 conf/wireshark/wireshark.lua \
 scripts/coverage.sh \
 scripts/terminate.py.in \
 scripts/gnunet_pyexpect.py.in \
 scripts/gnunet_janitor.py.in \
 scripts/gnunet-chk.py.in \
 scripts/removetrailingwhitespace.py.in \
 scripts/pydiffer.py.in \
 packages/nix/default.nix \
 packages/nix/gnunet-dev.nix \
 3rdparty/Windows/openvpn-tap32/tapw32/tap0901.sys \
 3rdparty/Windows/openvpn-tap32/tapw32/tap0901.cat \
 3rdparty/Windows/openvpn-tap32/tapw32/OemWin2k.inf \
 3rdparty/Windows/openvpn-tap32/tapw64/tap0901.sys \
 3rdparty/Windows/openvpn-tap32/tapw64/tap0901.cat \
 3rdparty/Windows/openvpn-tap32/tapw64/OemWin2k.inf \
 3rdparty/Windows/openvpn-tap32/INSTALL \
 3rdparty/Windows/openvpn-tap32/tap32-signed-i386-2.1.zip \
 3rdparty/Windows/openvpn-tap32/tap32-source-2.1.zip

CLEANFILES = \
  $(noinst_SCRIPTS)

do_subst = $(SED) -e 's,[@]PYTHON[@],$(PYTHON),g'

# Use SUFFIX Extension rules, they are more portable for every
# implementation of 'make'.
# You'll also run into the "'%' is a GNU make extension warning"
# if you use this:
#
#%.py: %.py.in Makefile
#	$(do_subst) < $< > $@
#	chmod +x $@
#
# instead of this:
SUFFIXES = .py.in .py

.py.in.py:
	$(do_subst) < $< > $@
	chmod +x $@

check_PROGRAMS = \
 test_gnunet_prefix

if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
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
	install scripts/gnunet-bugreport $(DESTDIR)$(bindir)/gnunet-bugreport

dist-hook:
	if test -d $(srcdir)/hellos; then \
	  mkdir -p $(distdir)/hellos; \
	  for hello in $(srcdir)/hellos/*; do \
	    if test -f $$hello; then \
	      cp -p $$hello $(distdir)/hellos; \
	    fi \
	  done \
	fi
