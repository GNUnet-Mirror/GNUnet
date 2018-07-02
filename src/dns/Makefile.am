# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

if MINGW
  WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
endif

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

plugindir = $(libdir)/gnunet

pkgcfg_DATA = \
  dns.conf

if LINUX
HIJACKBIN = gnunet-helper-dns
install-exec-hook:
	$(top_srcdir)/src/dns/install-dns-helper.sh $(DESTDIR)$(libexecdir) $(GNUNETDNS_GROUP) $(SUDO_BINARY) || true
else
install-exec-hook:
endif

lib_LTLIBRARIES = \
  libgnunetdns.la

libexec_PROGRAMS = \
  gnunet-service-dns $(HIJACKBIN)

noinst_PROGRAMS = \
  gnunet-dns-monitor \
  gnunet-dns-redirector \
  gnunet-zonewalk

plugin_LTLIBRARIES = \
  libgnunet_plugin_block_dns.la

if LINUX
check_SCRIPTS = \
 test_gnunet_dns.sh
endif

gnunet_helper_dns_SOURCES = \
 gnunet-helper-dns.c


gnunet_dns_monitor_SOURCES = \
 gnunet-dns-monitor.c
gnunet_dns_monitor_LDADD = \
  libgnunetdns.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)

gnunet_zonewalk_SOURCES = \
 gnunet-zonewalk.c
gnunet_zonewalk_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)

gnunet_dns_redirector_SOURCES = \
 gnunet-dns-redirector.c
gnunet_dns_redirector_LDADD = \
  libgnunetdns.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)

gnunet_service_dns_SOURCES = \
 gnunet-service-dns.c
gnunet_service_dns_LDADD = \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)

libgnunetdns_la_SOURCES = \
 dns_api.c dns.h
libgnunetdns_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la $(XLIB)
libgnunetdns_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS) \
  -version-info 0:0:0

libgnunet_plugin_block_dns_la_SOURCES = \
  plugin_block_dns.c
libgnunet_plugin_block_dns_la_LIBADD = \
  $(top_builddir)/src/block/libgnunetblockgroup.la \
  $(top_builddir)/src/util/libgnunetutil.la
libgnunet_plugin_block_dns_la_LDFLAGS = \
  $(top_builddir)/src/block/$(GN_PLUGIN_LDFLAGS)


if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
TESTS = $(check_PROGRAMS)  $(check_SCRIPTS)
endif

EXTRA_DIST = \
  $(check_SCRIPTS)


