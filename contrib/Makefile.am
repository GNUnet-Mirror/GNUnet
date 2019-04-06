# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include -I$(top_builddir)/src/include

tap32dir = $(pkgdatadir)/openvpn-tap32/tapw32/

tap64dir = $(pkgdatadir)/openvpn-tap32/tapw64/

SUBDIRS = scripts hellos services

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

INITD_FILES = \
 services/openrc/gnunet.initd \
 services/systemd/gnunet.service

EXTRA_DIST = \
 conf/colorit/colorit.conf \
 conf/editors/eclipse/gnunet_codingstyle.xml \
 conf/gnunet/no_forcestart.conf \
 conf/gnunet/no_autostart_above_core.conf \
 conf/nss/nssswitch.conf \
 conf/wireshark/wireshark.lua \
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
 3rdparty/Windows/openvpn-tap32/tap32-source-2.1.zip \
 $(INITD_FILES)

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
