INCLUDES = -I$(top_srcdir)/src/include

if MINGW
 WINFLAGS = -Wl,--no-undefined -Wl,--export-all-symbols 
endif

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

bin_PROGRAMS =

check_PROGRAMS =

noinst_SCRIPTS = \
 gnunet_testing.py \
 gnunet_pyexpect.py

if HAVE_PYTHON_PEXPECT
check_SCRIPTS = \
 test_integration_bootstrap_and_connect.py \
 test_integration_bootstrap_and_connect_and_disconnect.py \
 test_integration_bootstrap_and_connect_and_disconnect_nat.py \
 test_integration_restart.py \
 test_integration_clique.py \
 test_integration_clique_nat.py
endif
# test_integration_disconnect.py 


if ENABLE_TEST_RUN
TESTS = \
 $(check_SCRIPTS)  
endif

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


EXTRA_DIST = \
   gnunet_testing.py.in \
   gnunet_pyexpect.py.in \
   test_integration_bootstrap_and_connect.py.in \
   test_integration_bootstrap_and_connect_and_disconnect.py.in \
   test_integration_bootstrap_and_connect_and_disconnect_nat.py.in \
   test_integration_disconnect.py.in \
   test_integration_restart.py.in \
   test_integration_clique.py.in \
   test_integration_clique_nat.py.in \
   confs/c_bootstrap_server.conf \
   confs/c_nat_client.conf \
   confs/c_no_nat_client_2.conf \
   confs/c_no_nat_client.conf \
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
