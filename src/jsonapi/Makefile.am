# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

lib_LTLIBRARIES = \
  libgnunetjsonapi.la

libgnunetjsonapi_la_LDFLAGS = \
  -version-info 0:0:0 \
  -no-undefined
libgnunetjsonapi_la_SOURCES = \
  jsonapi.c 
libgnunetjsonapi_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
	$(top_builddir)/src/json/libgnunetjson.la \
  -ljansson \
  $(XLIB)

#check_PROGRAMS = \
#  test_json

#TESTS = \
#  $(check_PROGRAMS)

#test_json_SOURCES = \
#  test_json.c
#test_json_LDADD = \
#  libgnunetjson.la \
#  $(top_builddir)/src/util/libgnunetutil.la \
#  -ljansson
