INCLUDES = -I$(top_srcdir)/src/include

if MINGW
 WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols -lole32 -lshell32 -liconv -lstdc++ -lcomdlg32 -lgdi32
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

bin_PROGRAMS = \
 gnunet-peerinfo 

gnunet_peerinfo_SOURCES = \
 gnunet-peerinfo.c \
 gnunet-peerinfo_plugins.c gnunet-peerinfo_plugins.h

gnunet_peerinfo_LDADD = \
  $(top_builddir)/src/peerinfo/libgnunetpeerinfo.la \
  $(top_builddir)/src/transport/libgnunettransport.la \
  $(top_builddir)/src/hello/libgnunethello.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la 

if HAVE_PYTHON_PEXPECT
check_SCRIPTS = \
 test_gnunet_peerinfo.py 
endif

if ENABLE_TEST_RUN
TESTS = $(check_SCRIPTS)
endif

do_subst = $(SED) -e 's,[@]PYTHON[@],$(PYTHON),g'

test_gnunet_peerinfo.py: test_gnunet_peerinfo.py.in Makefile
	$(do_subst) < $(srcdir)/test_gnunet_peerinfo.py.in > test_gnunet_peerinfo.py
	chmod +x test_gnunet_peerinfo.py

EXTRA_DIST = \
  test_gnunet_peerinfo.py.in \
  test_gnunet_peerinfo_data.conf

CLEANFILES = $(check_SCRIPTS)
