INCLUDES = -I$(top_srcdir)/src/include -I$(top_builddir)/src/include


if !MINGW
noinst_PROGRAMS = \
 timeout_watchdog

timeout_watchdog_SOURCES = \
 timeout_watchdog.c 
endif

noinst_SCRIPTS = \
 gnunet_pyexpect.py \
 gnunet_janitor.py

dist_pkgdata_DATA = \
 gnunet-logo-color.png 

EXTRA_DIST = \
 coverage.sh \
 hostlist.cgi \
 hostlist.php \
 report.sh \
 testing_hostkeys.dat \
 gnunet_pyexpect.py.in \
 gnunet_janitor.py.in

do_subst = $(SED) -e 's,[@]PYTHON[@],$(PYTHON),g'

%.py: %.py.in Makefile
	$(do_subst) < $< > $@
	chmod +x $@

# init_gnunet_redhat \
# init_gnunet_ubuntu \
# visualize_stats.sh \
# gnmessage.sh \
# junkinsert.sh \
# junklookup.sh \
# namespacehelper.sh 


check_PROGRAMS = \
 test_gnunet_prefix

test_gnunet_prefix_SOURCES = \
 test_gnunet_prefix.c
