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
 gnunet_testing.py

if HAVE_PYTHON_PEXPECT
check_SCRIPTS = \
 test_integration_bootstrap_and_connect.py \
 test_integration_disconnect.py \
 test_integration_restart.py \
 test_integration_clique.py \
 test_integration_clique_nat.py
endif


if ENABLE_TEST_RUN
TESTS = \
 $(check_SCRIPTS)  
endif

do_subst = $(SED) -e 's,[@]PYTHON[@],$(PYTHON),g'

%.py: %.py.in Makefile
	$(do_subst) < $(srcdir)/$< > $@
	chmod +x $@

test_integration_bootstrap_and_connect.py: test_integration_bootstrap_and_connect.py.in Makefile
	$(do_subst) < $(srcdir)/test_integration_bootstrap_and_connect.py.in > test_integration_bootstrap_and_connect.py
	chmod +x test_integration_bootstrap_and_connect.py

test_integration_disconnect.py: test_integration_disconnect.py.in Makefile
	$(do_subst) < $(srcdir)/test_integration_disconnect.py.in > test_integration_disconnect.py
	chmod +x test_integration_disconnect.py

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
   test_integration_bootstrap_and_connect.py.in \
   test_integration_disconnect.py.in \
   test_integration_restart.py.in \ 
   test_integration_clique.py.in \
   test_integration_clique_nat.py.in

CLEANFILES = \
	$(check_SCRIPTS) \
	gnunet_testing.py
