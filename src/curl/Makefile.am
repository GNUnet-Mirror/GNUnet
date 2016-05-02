# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

lib_LTLIBRARIES = \
  libgnunetcurl.la

libgnunetcurl_la_LDFLAGS = \
  -version-info 0:0:0 \
  -no-undefined
libgnunetcurl_la_SOURCES = \
  curl.c \
  curl_reschedule.c
libgnunetcurl_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  -ljansson \
  -lcurl \
  $(XLIB)

#check_PROGRAMS = \
#  test_curl

#TESTS = \
#  $(check_PROGRAMS)

#test_curl_SOURCES = \
#  test_curl.c
#test_curl_LDADD = \
#  libgnunetcurl.la \
#  $(top_builddir)/src/util/libgnunetutil.la \
#  -ljansson -lcurl
