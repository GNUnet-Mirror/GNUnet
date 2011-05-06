INCLUDES = -I$(top_srcdir)/src/include

if MINGW
  WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols
endif

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif

lib_LTLIBRARIES = libgnunetnat.la

libgnunetnat_la_SOURCES = \
  upnp.c upnp.h \
  upnp-commands.c upnp-commands.h \
  upnp-discover.c upnp-discover.h \
  upnp-igd-parse.c upnp-igd-parse.h \
  upnp-minixml.c upnp-minixml.h \
  upnp-reply-parse.c upnp-reply-parse.h bsdqueue.h \
  nat.c nat.h \
  natpmp.h 

libgnunetnat_la_CFLAGS = \
 -DDEBUG_UPNP -g -O0

libgnunetnat_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  @LIBCURL@ \
  $(GN_LIBINTL) @EXT_LIBS@ 

libgnunetnat_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS) $(WINFLAGS) \
  -version-info 0:0:0		

check_PROGRAMS = \
  test-nat

if !DISABLE_TEST_RUN
TESTS = $(check_PROGRAMS)
endif

test_nat_SOURCES = \
  test_nat.c

test_nat_LDADD = \
 $(top_builddir)/src/nat/libgnunetnat.la \
 $(top_builddir)/src/util/libgnunetutil.la \
 @LIBCURL@
