INCLUDES = -I$(top_srcdir)/src/include -I/usr/include/glib-2.0 -I/usr/include -I/usr/lib/x86_64-linux-gnu/glib-2.0/include/ -I/usr/include/libgtop-2.0/

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

pkgcfg_DATA = \
  sysmon.conf

if MINGW
 WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols 
endif

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif

libexec_PROGRAMS = \
 gnunet_daemon_sysmon

check_PROGRAMS = \
 test_glibtop
 
gnunet_daemon_sysmon_SOURCES = \
 gnunet-daemon-sysmon.c         
gnunet_daemon_sysmon_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(GN_LIBINTL)

test_glibtop_SOURCES = \
 test_glibtop.c      
test_glibtop_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  -lgtop-2.0 \
  $(GN_LIBINTL)


if ENABLE_TEST_RUN
TESTS = $(check_PROGRAMS)
endif
