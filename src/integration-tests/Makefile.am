# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

noinst_SCRIPTS = \
 gnunet_testing.py \
 gnunet_pyexpect.py

if HAVE_PYTHON
check_SCRIPTS = \
  test_integration_bootstrap_and_connect.py \
  test_integration_disconnect.py \
  test_integration_disconnect_nat.py \
  test_integration_reconnect.py \
  test_integration_reconnect_nat.py
#  test_integration_clique.py
endif


if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
if HAVE_LIBGNURL
TESTS = \
 $(check_SCRIPTS)
else
if HAVE_LIBCURL
TESTS = \
 $(check_SCRIPTS)
endif
endif
endif

SUFFIXES = .py.in .py
.py.in.py:
	$(AWK) -v bdir="$(bindir)" -v py="$(PYTHON)" -v awkay="$(AWK_BINARY)" -v pfx="$(prefix)" -v prl="$(PERL)" -v sysconfdirectory="$(sysconfdir)" -v pkgdatadirectory="$(pkgdatadir)" -f $(top_srcdir)/bin/dosubst.awk < $(srcdir)/$< > $@
	chmod +x $@

gnunet_testing.py: gnunet_testing.py.in Makefile
	$(AWK) -v bdir="$(bindir)" -v py="$(PYTHON)" -v awkay="$(AWK_BINARY)" -v pfx="$(prefix)" -v prl="$(PERL)" -v sysconfdirectory="$(sysconfdir)" -v pkgdatadirectory="$(pkgdatadir)" -f $(top_srcdir)/bin/dosubst.awk < $(srcdir)/gnunet_testing.py.in > gnunet_testing.py
	chmod +x gnunet_testing.py

gnunet_pyexpect.py: gnunet_pyexpect.py.in Makefile
	$(AWK) -v bdir="$(bindir)" -v py="$(PYTHON)" -v awkay="$(AWK_BINARY)" -v pfx="$(prefix)" -v prl="$(PERL)" -v sysconfdirectory="$(sysconfdir)" -v pkgdatadirectory="$(pkgdatadir)" -f $(top_srcdir)/bin/dosubst.awk < $(srcdir)/gnunet_pyexpect.py.in > gnunet_pyexpect.py
	chmod +x gnunet_pyexpect.py

test_integration_bootstrap_and_connect.py: test_integration_bootstrap_and_connect.py.in Makefile
	$(AWK) -v bdir="$(bindir)" -v py="$(PYTHON)" -v awkay="$(AWK_BINARY)" -v pfx="$(prefix)" -v prl="$(PERL)" -v sysconfdirectory="$(sysconfdir)" -v pkgdatadirectory="$(pkgdatadir)" -f $(top_srcdir)/bin/dosubst.awk < $(srcdir)/test_integration_bootstrap_and_connect.py.in > test_integration_bootstrap_and_connect.py
	chmod +x test_integration_bootstrap_and_connect.py

test_integration_disconnect.py: test_integration_disconnect.py.in Makefile
	$(AWK) -v bdir="$(bindir)" -v py="$(PYTHON)" -v awkay="$(AWK_BINARY)" -v pfx="$(prefix)" -v prl="$(PERL)" -v sysconfdirectory="$(sysconfdir)" -v pkgdatadirectory="$(pkgdatadir)" -f $(top_srcdir)/bin/dosubst.awk < $(srcdir)/test_integration_disconnect.py.in > test_integration_disconnect.py
	chmod +x test_integration_disconnect.py

test_integration_disconnect_nat.py: test_integration_disconnect_nat.py.in Makefile
	$(AWK) -v bdir="$(bindir)" -v py="$(PYTHON)" -v awkay="$(AWK_BINARY)" -v pfx="$(prefix)" -v prl="$(PERL)" -v sysconfdirectory="$(sysconfdir)" -v pkgdatadirectory="$(pkgdatadir)" -f $(top_srcdir)/bin/dosubst.awk < $(srcdir)/test_integration_disconnect_nat.py.in > test_integration_disconnect_nat.py
	chmod +x test_integration_disconnect_nat.py

test_integration_reconnect.py: test_integration_reconnect.py.in Makefile
	$(AWK) -v bdir="$(bindir)" -v py="$(PYTHON)" -v awkay="$(AWK_BINARY)" -v pfx="$(prefix)" -v prl="$(PERL)" -v sysconfdirectory="$(sysconfdir)" -v pkgdatadirectory="$(pkgdatadir)" -f $(top_srcdir)/bin/dosubst.awk < $(srcdir)/test_integration_reconnect.py.in > test_integration_reconnect.py
	chmod +x test_integration_reconnect.py

test_integration_reconnect_nat.py: test_integration_reconnect_nat.py.in Makefile
	$(AWK) -v bdir="$(bindir)" -v py="$(PYTHON)" -v awkay="$(AWK_BINARY)" -v pfx="$(prefix)" -v prl="$(PERL)" -v sysconfdirectory="$(sysconfdir)" -v pkgdatadirectory="$(pkgdatadir)" -f $(top_srcdir)/bin/dosubst.awk < $(srcdir)/test_integration_reconnect_nat.py.in > test_integration_reconnect_nat.py
	chmod +x test_integration_reconnect_nat.py

test_integration_clique.py: test_integration_clique.py.in Makefile
	$(AWK) -v bdir="$(bindir)" -v py="$(PYTHON)" -v awkay="$(AWK_BINARY)" -v pfx="$(prefix)" -v prl="$(PERL)" -v sysconfdirectory="$(sysconfdir)" -v pkgdatadirectory="$(pkgdatadir)" -f $(top_srcdir)/bin/dosubst.awk < $(srcdir)/test_integration_clique.py.in > test_integration_clique.py
	chmod +x test_integration_clique.py


EXTRA_DIST = \
   gnunet_testing.py.in \
   gnunet_pyexpect.py.in \
   test_integration_bootstrap_and_connect.py.in \
   test_integration_disconnect.py.in \
   test_integration_disconnect_nat.py.in \
   test_integration_reconnect.py.in \
   test_integration_reconnect_nat.py.in \
   test_integration_clique.py.in \
   confs/test_defaults.conf \
   confs/c_bootstrap_server.conf \
   confs/c_nat_client.conf \
   confs/c_no_nat_client_2.conf \
   confs/c_no_nat_client.conf \
   hostkeys/c_bootstrap_server \
   hostkeys/c_no_nat_client \
   hostkeys/c_no_nat_client_2 \
   hostkeys/c_nat_client

CLEANFILES = \
	$(check_SCRIPTS) \
	gnunet_pyexpect.py \
	gnunet_testing.py
