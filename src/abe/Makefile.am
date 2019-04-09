# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

plugindir = $(libdir)/gnunet

libexecdir= $(pkglibdir)/libexec/

pkgcfgdir= $(pkgdatadir)/config.d/

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

libgnunetabe_la_SOURCES = abe.c 

libgnunetabe_la_LIBADD = \
  $(GCLIBADD)\
  $(LIBGCRYPT_LIBS) \
  $(LTLIBICONV) \
  $(LTLIBINTL) \
	$(ABE_LIBADD) \
	$(top_builddir)/src/util/libgnunetutil.la \
	-lgmp \
	-lgabe \
	-lpbc \
	-lglib-2.0 \
  -lltdl $(Z_LIBS) -lunistring $(XLIB)

libgnunetabe_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS) \
  -version-info 1:0:0

lib_LTLIBRARIES = libgnunetabe.la

if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
TESTS = $(check_PROGRAMS)
endif

check_PROGRAMS = test_cpabe 

test_cpabe_SOURCES = \
 test_cpabe.c
test_cpabe_LDADD = \
 libgnunetabe.la \
 $(top_builddir)/src/util/libgnunetutil.la
check_PROGRAMS += \
 test_cpabe
