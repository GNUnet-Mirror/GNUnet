INCLUDES = -I$(top_srcdir)/src/include

if MINGW
  WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
endif

if LINUX
VPNBIN = gnunet-vpn-helper
install-exec-hook:
	chown root $(bindir)/gnunet-vpn-helper || true
	chmod u+s $(bindir)/gnunet-vpn-helper || true
else
install-exec-hook:
endif


bin_PROGRAMS = \
 gnunet-daemon-vpn $(VPNBIN)


gnunet_vpn_helper_SOURCES = \
 gnunet-vpn-helper.c \
 gnunet-vpn-helper-p.h \
 tun.h tun.c

# debug.c  debug.h \
# packet.h packet.c \
# pretty-print.c  pretty-print.h \
# tcp.c  tcp.h \
# test.c \
# tun.c  tun.h \
# udp.c udp.h

gnunet_daemon_vpn_SOURCES = \
 gnunet-daemon-vpn.c
gnunet_daemon_vpn_LDADD = \
  $(top_builddir)/src/core/libgnunetcore.la \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(GN_LIBINTL)


#check_PROGRAMS = \
# test_XXX

#TESTS = \
# test_transport_api_tcp 


#test_transport_api_tcp_SOURCES = \
# test_transport_api.c
#test_transport_api_tcp_LDADD = \
# $(top_builddir)/src/transport/libgnunettransport.la \
# $(top_builddir)/src/util/libgnunetutil.la  

#EXTRA_DIST = test_transport_api_data.conf 
