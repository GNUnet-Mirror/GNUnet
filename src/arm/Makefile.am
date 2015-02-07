# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

pkgcfg_DATA = \
  arm.conf

if MINGW
 WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols 
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

lib_LTLIBRARIES = libgnunetarm.la

libgnunetarm_la_SOURCES = \
  arm_api.c arm_monitor_api.c arm.h
libgnunetarm_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL) $(XLIB)
libgnunetarm_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS)  $(WINFLAGS) \
  -version-info 1:3:0


bin_PROGRAMS = \
 gnunet-arm

noinst_PROGRAMS = \
 mockup-service

libexec_PROGRAMS = \
 gnunet-service-arm

gnunet_arm_SOURCES = \
 gnunet-arm.c         
gnunet_arm_LDADD = \
  libgnunetarm.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)

gnunet_service_arm_SOURCES = \
 gnunet-service-arm.c 
gnunet_service_arm_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)

mockup_service_SOURCES = \
  mockup-service.c
 mockup_service_LDADD = \
 $(top_builddir)/src/util/libgnunetutil.la  


check_PROGRAMS = \
 test_arm_api \
 test_exponential_backoff \
 test_gnunet_service_arm

if HAVE_PYTHON
check_SCRIPTS = \
 test_gnunet_arm.py
endif

if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;
TESTS = $(check_PROGRAMS)  $(check_SCRIPTS)
endif

test_arm_api_SOURCES = \
 test_arm_api.c
test_arm_api_LDADD = \
  libgnunetarm.la \
  $(top_builddir)/src/util/libgnunetutil.la  

test_exponential_backoff_SOURCES = \
 test_exponential_backoff.c
test_exponential_backoff_LDADD = \
  libgnunetarm.la \
  $(top_builddir)/src/util/libgnunetutil.la

test_gnunet_service_arm_SOURCES = \
 test_gnunet_service_arm.c
 test_gnunet_service_arm_LDADD = \
  libgnunetarm.la \
  $(top_builddir)/src/util/libgnunetutil.la  

do_subst = $(SED) -e 's,[@]PYTHON[@],$(PYTHON),g'

%.py: %.py.in Makefile
	$(do_subst) < $(srcdir)/$< > $@
	chmod +x $@

test_gnunet_arm.py: test_gnunet_arm.py.in Makefile
	$(do_subst) < $(srcdir)/test_gnunet_arm.py.in > test_gnunet_arm.py
	chmod +x test_gnunet_arm.py

EXTRA_DIST = \
  test_arm_api_data.conf \
  test_gnunet_arm.py.in 
