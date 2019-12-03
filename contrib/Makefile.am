# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include -I$(top_builddir)/src/include

SUBDIRS = scripts hellos services

include Makefile.inc

dist_pkgdata_DATA = \
 gns/gns-bcd.html \
 gns/gns-bcd.tex \
 gns/def.tex \
 gns/gns-form-fields.xml \
 gns/gns-form.xslt \
 branding/logo/gnunet-logo.pdf \
 branding/logo/gnunet-logo.png \
 branding/logo/gnunet-logo-color.png \
 testing_hostkeys.ecc \
 $(BUILDCOMMON_SHLIB_FILES)

INITD_FILES = \
 services/openrc/gnunet.initd \
 services/systemd/gnunet.service

PACKAGES_FILES = \
    packages/guix/guix-env-py2.scm \
    packages/guix/guix-env-gillmann.scm \
    packages/guix/notest-guix-env.scm \
    packages/homebrew/gnunet.rb \
    packages/nix/gnunet-dev.nix \
    packages/nix/default.nix \
    packages/alpine/gnunet-gtk/APKBUILD \
    packages/alpine/gnunet/APKBUILD \
    packages/alpine/gnunet/gnunet-system-services.initd \
    packages/alpine/gnunet/gnunet-system.conf \
    packages/alpine/gnunet/gnunet-user-services.initd \
    packages/alpine/gnunet/gnunet-user.conf \
    packages/alpine/gnunet/gnunet.post-install \
    packages/alpine/gnunet/gnunet.pre-deinstall \
    packages/alpine/gnunet/gnunet.pre-install \
    packages/alpine/gnunet/gnunet.xsession \
    packages/alpine/gnurl/APKBUILD

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
 $(INITD_FILES) \
 Makefile.inc \
 $(BUILD_COMMON_FILES)

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
