INCLUDES = -I$(top_srcdir)/src/include

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

if HAVE_LIBGTOP
  GN_LIBTOP = -lgtop-2.0 -lglib-2.0
  GN_SYSMON_TEST_INIT = test_glibtop
  GN_SYSMON_TEST_PROCESS = test_glibtop_process
  GN_SYSMON_TEST_NETWORK = test_glibtop_network 
endif

pkgcfg_DATA = \
  sysmon.conf

if MINGW
 WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols 
endif

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif

libexec_PROGRAMS = \
 gnunet_service_sysmon

check_PROGRAMS = \
 $(GN_SYSMON_TEST_INIT) \
 $(GN_SYSMON_TEST_PROCESS) \
 $(GN_SYSMON_TEST_NETWORK)
 
gnunet_service_sysmon_SOURCES = \
 gnunet-service-sysmon.c         
gnunet_service_sysmon_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(GN_LIBTOP) \
  $(GN_LIBINTL)

if HAVE_GLIB2
test_glibtop_SOURCES = \
 test_glibtop.c      
test_glibtop_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(GN_LIBTOP) \
  $(GN_LIBINTL)

test_glibtop_process_SOURCES = \
 test_glibtop_process.c      
test_glibtop_process_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(GN_LIBTOP) \
  $(GN_LIBINTL)

test_glibtop_network_SOURCES = \
 test_glibtop_network.c      
test_glibtop_network_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(GN_LIBTOP) \
  $(GN_LIBINTL)
endif


if ENABLE_TEST_RUN
TESTS = $(check_PROGRAMS)
endif

EXTRA_DIST = \
sysmon-properties.conf
