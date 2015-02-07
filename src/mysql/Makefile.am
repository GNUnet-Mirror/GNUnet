# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

if MINGW
  WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage
endif

if HAVE_MYSQL
lib_LTLIBRARIES = libgnunetmysql.la
endif

libgnunetmysql_la_SOURCES = \
  mysql.c
libgnunetmysql_la_LIBADD = $(MYSQL_LDFLAGS) -lmysqlclient \
 $(top_builddir)/src/util/libgnunetutil.la
libgnunetmysql_la_LDFLAGS = \
 $(GN_LIB_LDFLAGS) \
  -version-info 0:0:0
