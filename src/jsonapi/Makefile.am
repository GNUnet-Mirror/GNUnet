# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

lib_LTLIBRARIES = \
  libgnunetjsonapi.la \
	libgnunetjsonapiutils.la

libgnunetjsonapiutils_la_LDFLAGS = \
	-version-info 0:0:0 \
	-no-undefined
libgnunetjsonapiutils_la_SOURCES = \
	jsonapi.c
libgnunetjsonapiutils_la_LIBADD = \
	$(top_builddir)/src/util/libgnunetutil.la \
	$(top_builddir)/src/jsonapi/libgnunetjsonapi.la \
	$(top_builddir)/src/rest/libgnunetrest.la \
  $(XLIB)

libgnunetjsonapi_la_LDFLAGS = \
  -version-info 0:0:0 \
  -no-undefined
libgnunetjsonapi_la_SOURCES = \
	jsonapi_document.c \
	jsonapi_resource.c \
	jsonapi_error.c \
	jsonapi_relationship.c
libgnunetjsonapi_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
	$(top_builddir)/src/json/libgnunetjson.la \
  -ljansson \
  $(XLIB)

check_PROGRAMS = \
  test_jsonapi

TESTS = \
  $(check_PROGRAMS)

test_jsonapi_SOURCES = \
  test_jsonapi.c
test_jsonapi_LDADD = \
  libgnunetjsonapi.la \
  $(top_builddir)/src/json/libgnunetjson.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  -ljansson
