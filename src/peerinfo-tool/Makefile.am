INCLUDES = -I$(top_srcdir)/src/include

if MINGW
 WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols -lole32 -lshell32 -luuid -liconv -lstdc++ -lcomdlg32 -lgdi32
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

bin_PROGRAMS = \
 gnunet-peerinfo 

gnunet_peerinfo_SOURCES = \
 gnunet-peerinfo.c         
gnunet_peerinfo_LDADD = \
  $(top_builddir)/src/peerinfo/libgnunetpeerinfo.la \
  $(top_builddir)/src/transport/libgnunettransport.la \
  $(top_builddir)/src/util/libgnunetutil.la 


#check_SCRIPTS = \
#  test_gnunet_peerinfo.sh
