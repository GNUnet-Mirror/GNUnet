if !MINGW
noinst_PROGRAMS = \
 timeout_watchdog

timeout_watchdog_SOURCES = \
 timeout_watchdog.c 
endif

noinst_SCRIPTS = \
 gnunet_pyexpect.py

dist_pkgdata_DATA = \
 gnunet-logo-color.png \
 defaults.conf

EXTRA_DIST = \
 coverage.sh \
 hostlist.cgi \
 hostlist.php \
 report.sh \
 __init__.py \
 gnunet_pyexpect.py.in

do_subst = $(SED) -e 's,[@]PYTHON[@],$(PYTHON),g'

gnunet_pyexpect.py: gnunet_pyexpect.py.in Makefile
	$(do_subst) < $(srcdir)/gnunet_pyexpect.py.in > gnunet_pyexpect.py
	chmod +x gnunet_pyexpect.py
	chmod +x __init__.py


# init_gnunet_redhat \
# init_gnunet_ubuntu \
# visualize_stats.sh \
# gnmessage.sh \
# junkinsert.sh \
# junklookup.sh \
# namespacehelper.sh 

