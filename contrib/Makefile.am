# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include -I$(top_builddir)/src/include

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

INITD_FILES = \
 services/openrc/gnunet.initd \
 services/systemd/gnunet.service

PACKAGES_FILES = \
    guix/guix-env-py2.scm \
    guix/guix-env-gillmann.scm \
    guix/notest-guix-env.scm \
    nix/gnunet-dev.nix \
    nix/default.nix \
    alpine/gnunet-gtk/APKBUILD \
    alpine/gnunet/APKBUILD \
    alpine/gnunet/gnunet-system-services.initd \
    alpine/gnunet/gnunet-system.conf \
    alpine/gnunet/gnunet-user-services.initd \
    alpine/gnunet/gnunet-user.conf \
    alpine/gnunet/gnunet.post-deinstall \
    alpine/gnunet/gnunet.post-install \
    alpine/gnunet/gnunet.pre-deinstall \
    alpine/gnunet/gnunet.pre-install \
    alpine/gnunet/gnunet.xsession \
    alpine/gnurl/APKBUILD

EXTRA_DIST = \
 conf/colorit/colorit.conf \
 conf/.style.yapf \
 conf/editors/eclipse/gnunet_codingstyle.xml \
 conf/gnunet/no_forcestart.conf \
 conf/gnunet/no_autostart_above_core.conf \
 conf/gnunet/gnunet-system.conf \
 conf/gnunet/gnunet-user.conf \
 conf/nss/nssswitch.conf \
 conf/wireshark/wireshark.lua \
 $(PACKAGES_FILES) \
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
