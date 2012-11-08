INCLUDES = -I$(top_srcdir)/src/include

pkgcfgdir= $(pkgdatadir)/config.d/

libexecdir= $(pkglibdir)/libexec/

pkgcfg_DATA = \
  consensus.conf

if MINGW
 WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols 
endif

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif

#bin_PROGRAMS = \
# gnunet-consensus 

libexec_PROGRAMS = \
 gnunet-service-consensus

#gnunet_consensus_SOURCES = \
# gnunet-consensus.c         
#gnunet_consensus_LDADD = \
#  $(top_builddir)/src/util/libgnunetutil.la \
#  $(GN_LIBINTL)

gnunet_service_consensus_SOURCES = \
 gnunet-service-consensus.cc
gnunet_service_consensus_LDADD = \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL) 


#check_PROGRAMS = \
# test_consensus_api

#if ENABLE_TEST_RUN
#TESTS = $(check_PROGRAMS)
#endif
#
#test_consensus_api_SOURCES = \
# test_consensus_api.c
#test_consensus_api_LDADD = \
#  $(top_builddir)/src/util/libgnunetutil.la  

