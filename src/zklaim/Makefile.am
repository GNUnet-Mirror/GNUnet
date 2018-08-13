# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

plugindir = $(libdir)/gnunet

libexecdir= $(pkglibdir)/libexec/

pkgcfgdir= $(pkgdatadir)/config.d/

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif


libgnunetzklaim_la_SOURCES = zklaim.c
libgnunetzklaim_la_LIBADD = \
  $(GCLIBADD)\
  $(LIBGCRYPT_LIBS) \
	-lzklaim \
  -lgcrypt \
  -lgmp \
  -lgmpxx \
  -lcrypto \
  -lprocps \
  -lstdc++ \
  -lm
libgnunetzklaim_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS) \
  -version-info 1:0:0

lib_LTLIBRARIES = libgnunetzklaim.la

if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
TESTS = $(check_PROGRAMS)
endif

#check_PROGRAMS = test_cpabe 

#test_cpabe_SOURCES = \
# test_cpabe.c
#test_cpabe_LDADD = \
# libgnunetabe.la \
# $(top_builddir)/src/util/libgnunetutil.la
#check_PROGRAMS += \
# test_cpabe
