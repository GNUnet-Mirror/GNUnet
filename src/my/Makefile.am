# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

if MINGW
  WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage
endif

if HAVE_MYSQL
lib_LTLIBRARIES = libgnunetmy.la
endif

libgnunetmy_la_SOURCES = \
  my.c \
  my_query_helper.c \
  my_result_helper.c

libgnunetmy_la_LIBADD = $(MYSQL_LDFLAGS) -lmysqlclient \
 $(top_builddir)/src/mysql/libgnunetmysql.la \
 $(top_builddir)/src/util/libgnunetutil.la
libgnunetmy_la_LDFLAGS = \
 $(GN_LIB_LDFLAGS) \
  -version-info 0:0:0

TESTS = \
 test_my

check_PROGRAMS= \
 test_my

test_my_SOURCES = \
  test_my.c
test_my_LDADD = \
  libgnunetmy.la \
  $(top_builddir)/src/util/libgnunetutil.la  \
  -lmysqlclient $(XLIB)

