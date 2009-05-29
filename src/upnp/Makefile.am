INCLUDES = -I$(top_srcdir)/src/include

if MINGW
  WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols
endif

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif

lib_LTLIBRARIES = libgnunetupnp.la

libgnunetupnp_la_SOURCES = \
  upnp.c upnp.h \
  upnp_ip.c upnp_ip.h \
  upnp_util.c upnp_util.h \
  upnp_xmlnode.c upnp_xmlnode.h 
libgnunetupnp_la_CFLAGS = \
 -I$(top_scrdir)/include \
 @LIBCURL_CPPFLAGS@ @XML_CPPFLAGS@
libgnunetupnp_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL) @EXT_LIBS@ @XML_LIBS@ @LIBCURL@
libgnunetupnp_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS) $(WINFLAGS) \
  -version-info 0:0:0


bin_PROGRAMS = \
 gnunet-upnp \
 gnunet-service-upnp

gnunet_upnp_SOURCES = \
 gnunet-upnp.c         
gnunet_upnp_LDADD = \
  $(top_builddir)/src/upnp/libgnunetupnp.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)

gnunet_service_upnp_SOURCES = \
 gnunet-service-upnp.c 
gnunet_service_upnp_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)


check_PROGRAMS = \ 
 test_upnp

TESTS = $(check_PROGRAMS)

test_upnp_SOURCES = \
 test_upnp.c
test_upnp_LDADD = \
 $(top_builddir)/src/transport/libgnunetupnp.la \
 $(top_builddir)/src/util/libgnunetutil.la  


# EXTRA_DIST = test_upnp_data.conf 
