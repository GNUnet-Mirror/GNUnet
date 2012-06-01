INCLUDES = -I$(top_srcdir)/src/include

if MINGW
 WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols 
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

#bin_PROGRAMS = \
# connection_watchdog

noinst_PROGRAMS = connection_watchdog

noinst_SCRIPTS = \
 gnunet_testing.py \
 gnunet_pyexpect.py \
 test_integration_connection_values_tcp.py \
 test_integration_connection_values_tcp_udp.py \
 test_integration_connection_values_tcp_udp_http.py

if HAVE_PYTHON_PEXPECT
check_SCRIPTS = \
 test_integration_bootstrap_and_connect.py \
 test_integration_bootstrap_and_connect_and_disconnect.py \
 test_integration_bootstrap_and_connect_and_disconnect_nat.py \
 test_integration_restart.py \
 test_integration_clique.py \
 test_integration_clique_nat.py \
 test_integration_connect_on_restart.py
endif
# test_integration_disconnect.py 

check_PROGRAMS = \
	test_connection_stability


if ENABLE_TEST_RUN
TESTS = \
 $(check_SCRIPTS)  
endif

connection_watchdog_SOURCE = \
 connection_watchdog.c      
connection_watchdog_LDADD = \
  $(top_builddir)/src/statistics/libgnunetstatistics.la \
  $(top_builddir)/src/core/libgnunetcore.la \
  $(top_builddir)/src/transport/libgnunettransport.la \
  $(top_builddir)/src/util/libgnunetutil.la

do_subst = $(SED) -e 's,[@]PYTHON[@],$(PYTHON),g'

%.py: %.py.in Makefile
	$(do_subst) < $(srcdir)/$< > $@
	chmod +x $@

gnunet_testing.py: gnunet_testing.py.in Makefile
	$(do_subst) < $(srcdir)/gnunet_testing.py.in > gnunet_testing.py
	chmod +x gnunet_testing.py	

gnunet_pyexpect.py: gnunet_pyexpect.py.in Makefile
	$(do_subst) < $(srcdir)/gnunet_pyexpect.py.in > gnunet_pyexpect.py
	chmod +x gnunet_pyexpect.py	

test_integration_bootstrap_and_connect.py: test_integration_bootstrap_and_connect.py.in Makefile
	$(do_subst) < $(srcdir)/test_integration_bootstrap_and_connect.py.in > test_integration_bootstrap_and_connect.py
	chmod +x test_integration_bootstrap_and_connect.py

test_integration_bootstrap_and_connect_and_disconnect.py: test_integration_bootstrap_and_connect_and_disconnect.py.in Makefile
	$(do_subst) < $(srcdir)/test_integration_bootstrap_and_connect_and_disconnect.py.in > test_integration_bootstrap_and_connect_and_disconnect.py
	chmod +x test_integration_bootstrap_and_connect_and_disconnect.py

test_integration_bootstrap_and_connect_and_disconnect_nat.py: test_integration_bootstrap_and_connect_and_disconnect_nat.py.in Makefile
	$(do_subst) < $(srcdir)/test_integration_bootstrap_and_connect_and_disconnect_nat.py.in > test_integration_bootstrap_and_connect_and_disconnect_nat.py
	chmod +x test_integration_bootstrap_and_connect_and_disconnect_nat.py


test_integration_disconnect.py: test_integration_disconnect.py.in Makefile
	$(do_subst) < $(srcdir)/test_integration_disconnect.py.in > test_integration_disconnect.py
	chmod +x test_integration_disconnect.py

#test_integration_disconnect_nat.py: test_integration_disconnect_nat.py.in Makefile
#	$(do_subst) < $(srcdir)/test_integration_disconnect_nat.py.in > test_integration_disconnect_nat.py
#	chmod +x test_integration_disconnect_nat.py

test_integration_restart.py: test_integration_restart.py.in Makefile
	$(do_subst) < $(srcdir)/test_integration_restart.py.in > test_integration_restart.py
	chmod +x test_integration_restart.py	

test_integration_clique.py: test_integration_clique.py.in Makefile
	$(do_subst) < $(srcdir)/test_integration_clique.py.in > test_integration_clique.py
	chmod +x test_integration_clique.py	

test_integration_clique_nat.py: test_integration_clique_nat.py.in Makefile
	$(do_subst) < $(srcdir)/test_integration_clique_nat.py.in > test_integration_clique_nat.py
	chmod +x test_integration_clique_nat.py	

test_integration_connect_on_restart.py: test_integration_connect_on_restart.py.in Makefile
	$(do_subst) < $(srcdir)/test_integration_connect_on_restart.py.in > test_integration_connect_on_restart.py
	chmod +x test_integration_connect_on_restart.py		

test_integration_connection_values_tcp.py: test_integration_connection_values_tcp.py.in Makefile
	$(do_subst) < $(srcdir)/test_integration_connection_values_tcp.py.in > test_integration_connection_values_tcp.py
	chmod +x test_integration_connection_values_tcp.py		

test_integration_connection_values_tcp_udp.py: test_integration_connection_values_tcp_udp.py.in Makefile
	$(do_subst) < $(srcdir)/test_integration_connection_values_tcp_udp.py.in > test_integration_connection_values_tcp_udp.py
	chmod +x test_integration_connection_values_tcp_udp.py		

test_integration_connection_values_tcp_udp_http.py: test_integration_connection_values_tcp_udp_http.py.in Makefile
	$(do_subst) < $(srcdir)/test_integration_connection_values_tcp_udp_http.py.in > test_integration_connection_values_tcp_udp_http.py
	chmod +x test_integration_connection_values_tcp_udp_http.py		

test_connection_stability_SOURCES = \
 test_connection_stability.c
test_connection_stability_LDADD = \
 $(top_builddir)/src/testing/libgnunettesting.la \
 $(top_builddir)/src/util/libgnunetutil.la  


EXTRA_DIST = \
   gnunet_testing.py.in \
   gnunet_pyexpect.py.in \
   test_integration_connection_values_tcp.py.in \
   test_integration_connection_values_tcp_udp.py.in \
   test_integration_connection_values_tcp_udp_http.py.in \
   test_integration_bootstrap_and_connect.py.in \
   test_integration_bootstrap_and_connect_and_disconnect.py.in \
   test_integration_bootstrap_and_connect_and_disconnect_nat.py.in \
   test_integration_connect_on_restart.py.in \
   test_integration_disconnect.py.in \
   test_integration_restart.py.in \
   test_integration_clique.py.in \
   test_integration_clique_nat.py.in \
   confs/c_bootstrap_server.conf \
   confs/c_nat_client.conf \
   confs/c_no_nat_client_2.conf \
   confs/c_no_nat_client.conf \
   confs/c_normal_client_tcp.conf \
   confs/c_normal_client_tcp_udp.conf \
   confs/c_normal_client_tcp_udp_http.conf \
   confs/c_no_nat_client_http.conf \
   confs/c_no_nat_client_http_2.conf\
   confs/c_no_nat_client_http.conf \
   confs/c_no_nat_client_http_2.conf \
   confs/c_no_nat_client_unix.conf \
   confs/c_no_nat_client_unix_2.conf \
   test_connection_stability.conf \
   hostkeys/0000-hostkey \
   hostkeys/0001-hostkey \
   hostkeys/0002-hostkey \
   hostkeys/0003-hostkey \
   hostkeys/0004-hostkey \
   hostkeys/0005-hostkey \
   hostkeys/0006-hostkey \
   hostkeys/0007-hostkey \
   hostkeys/0008-hostkey \
   hostkeys/0009-hostkey 
#   test_integration_disconnect_nat.py 

CLEANFILES = \
	$(check_SCRIPTS) \
	gnunet_testing.py
