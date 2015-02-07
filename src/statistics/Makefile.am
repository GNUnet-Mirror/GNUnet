# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

if MINGW
 WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols 
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

pkgcfg_DATA = \
  statistics.conf

lib_LTLIBRARIES = libgnunetstatistics.la

libgnunetstatistics_la_SOURCES = \
  statistics_api.c statistics.h
libgnunetstatistics_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL) $(XLIB)
libgnunetstatistics_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)  $(WINFLAGS) \
  -version-info 1:3:1

libexec_PROGRAMS = \
 gnunet-service-statistics

bin_PROGRAMS = \
 gnunet-statistics 

gnunet_statistics_SOURCES = \
 gnunet-statistics.c         
gnunet_statistics_LDADD = \
  libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)

gnunet_service_statistics_SOURCES = \
 gnunet-service-statistics.c         
gnunet_service_statistics_LDADD = \
  libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)

check_PROGRAMS = \
 test_statistics_api \
 test_statistics_api_loop \
 test_statistics_api_watch \
 test_statistics_api_watch_zero_value 

if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;
TESTS = $(check_PROGRAMS) $(check_SCRIPTS)
endif

test_statistics_api_SOURCES = \
 test_statistics_api.c
test_statistics_api_LDADD = \
  libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la  

test_statistics_api_loop_SOURCES = \
 test_statistics_api_loop.c
test_statistics_api_loop_LDADD = \
  libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la  

test_statistics_api_watch_SOURCES = \
 test_statistics_api_watch.c
test_statistics_api_watch_LDADD = \
  libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la  

test_statistics_api_watch_zero_value_SOURCES = \
 test_statistics_api_watch_zero_value.c
test_statistics_api_watch_zero_value_LDADD = \
  libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la  

if HAVE_PYTHON
check_SCRIPTS = \
  test_gnunet_statistics.py
endif

do_subst = $(SED) -e 's,[@]PYTHON[@],$(PYTHON),g'

%.py: %.py.in Makefile
	$(do_subst) < $(srcdir)/$< > $@
	chmod +x $@

test_gnunet_statistics.py: test_gnunet_statistics.py.in Makefile
	$(do_subst) < $(srcdir)/test_gnunet_statistics.py.in > test_gnunet_statistics.py
	chmod +x test_gnunet_statistics.py

EXTRA_DIST = \
  test_statistics_api_data.conf \
  test_gnunet_statistics.py.in


