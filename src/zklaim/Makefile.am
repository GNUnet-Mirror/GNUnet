# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

plugindir = $(libdir)/gnunet

libexecdir= $(pkglibdir)/libexec/

pkgcfgdir= $(pkgdatadir)/config.d/

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif


gnunet_zklaim_SOURCES = zklaim.c
gnunet_zklaim_LDADD = \
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
gnunet_zklaim_LDFLAGS = \
  $(GN_LIB_LDFLAGS)

#lib_LTLIBRARIES = libgnunetzklaim.la
bin_PROGRAMS = gnunet-zklaim

if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
TESTS = $(check_PROGRAMS)
endif
