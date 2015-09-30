# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

if MINGW
  WINFLAGS = -Wl,--no-undefined,--export-all-symbols
  EXITBIN = gnunet-helper-exit
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
endif

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

plugindir = $(libdir)/gnunet

dist_pkgcfg_DATA = \
  exit.conf

if LINUX
EXITBIN = gnunet-helper-exit
install-exec-hook:
	$(top_srcdir)/src/exit/install-exit-helper.sh $(DESTDIR)$(libexecdir) $(SUDO_BINARY) || true
else
install-exec-hook:
endif


libexec_PROGRAMS = \
  gnunet-daemon-exit \
  $(EXITBIN) 

if MINGW
  gnunet_helper_exit_LDFLAGS = \
    -no-undefined -Wl,--export-all-symbols 

  gnunet_helper_exit_LDADD = \
    -lsetupapi -lnewdev -lshell32 -liconv -lstdc++ \
    -lcomdlg32 -lgdi32 -liphlpapi

  gnunet_helper_exit_SOURCES = \
    gnunet-helper-exit-windows.c
else
  gnunet_helper_exit_SOURCES = \
   gnunet-helper-exit.c
endif
gnunet_daemon_exit_SOURCES = \
 gnunet-daemon-exit.c exit.h 
gnunet_daemon_exit_LDADD = \
  $(top_builddir)/src/dns/libgnunetdnsstub.la \
  $(top_builddir)/src/dht/libgnunetdht.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/tun/libgnunettun.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/cadet/libgnunetcadet.la \
  $(top_builddir)/src/regex/libgnunetregex.la \
  $(GN_LIBINTL)
