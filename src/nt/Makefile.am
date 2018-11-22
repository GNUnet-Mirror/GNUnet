# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

if MINGW
  WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage
endif

lib_LTLIBRARIES = libgnunetnt.la

libgnunetnt_la_SOURCES = \
  nt.c

libgnunetnt_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la
libgnunetnt_la_LDFLAGS = \
 $(GN_LIB_LDFLAGS) \
  -version-info 0:0:0

#if ENABLE_TEST_RUN
#TESTS = \
# test_nt
#endif

#check_PROGRAMS= \
# test_nt
#
#test_nt_SOURCES = \
#  test_nt.c
#test_nt_LDADD = \
#  libgnunetnt.la \
#  $(top_builddir)/src/util/libgnunetutil.la  \
#   $(XLIB)
