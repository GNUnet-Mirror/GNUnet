# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include -I$(top_builddir)/src/include

SUBDIRS = gnunet-logread gnunet-download-manager

noinst_SCRIPTS = \
 terminate.py \
 pydiffer.py \
 removetrailingwhitespace.py \
 gnunet_pyexpect.py \
 gnunet_janitor.py \
 gnunet-chk.py

bin_SCRIPTS = \
 gnunet-bugreport

EXTRA_DIST = \
 coverage.sh \
 terminate.py.in \
 gnunet_pyexpect.py.in \
 gnunet_janitor.py.in \
 gnunet-chk.py.in \
 $(SCRIPTS) \
 removetrailingwhitespace.py.in \
 pydiffer.py.in

CLEANFILES = \
  $(noinst_SCRIPTS)

do_subst = $(SED) -e 's,[@]PYTHON[@],$(PYTHON),g'

# Use SUFFIX Extension rules, they are more portable for every
# implementation of 'make'.
# You'll also run into the "'%' is a GNU make extension warning"
# if you use this:
#
#%.py: %.py.in Makefile
#	$(do_subst) < $< > $@
#	chmod +x $@
#
# instead of this:
SUFFIXES = .py.in .py

.py.in.py:
	$(do_subst) < $< > $@
	chmod +x $@
