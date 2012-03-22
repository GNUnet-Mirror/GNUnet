INCLUDES = -I$(top_srcdir)/src/include

if MINGW
  WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage
endif

lib_LTLIBRARIES = libgnunetpostgres.la

libgnunetpostgres_la_SOURCES = \
  postgres.c
libgnunetpostgres_la_LIBADD = -lpq \
 $(top_builddir)/src/util/libgnunetutil.la  
libgnunetpostgres_la_LDFLAGS = \
 $(GN_LIB_LDFLAGS) \
  -version-info 0:0:0

