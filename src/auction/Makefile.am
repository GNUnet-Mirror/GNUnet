# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

dist_pkgcfg_DATA = \
  auction.conf

if MINGW
 WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols
endif

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif

# use bin_PROGRAMS for gnunet-auction wrapper script

libexec_PROGRAMS = \
 gnunet-auction-create \
 gnunet-auction-info \
 gnunet-auction-join \
 gnunet-service-auction

gnunet_auction_create_SOURCES = \
 gnunet-auction-create.c
gnunet_auction_create_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)

gnunet_auction_info_SOURCES = \
 gnunet-auction-info.c
gnunet_auction_info_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)

gnunet_auction_join_SOURCES = \
 gnunet-auction-join.c
gnunet_auction_join_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)

gnunet_service_auction_SOURCES = \
 gnunet-service-auction.c
gnunet_service_auction_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)


check_PROGRAMS = \
 test_auction_api

if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;
TESTS = $(check_PROGRAMS)
endif

test_auction_api_SOURCES = \
 test_auction_api.c
test_auction_api_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la
