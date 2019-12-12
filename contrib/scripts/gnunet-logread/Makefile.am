# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include -I$(top_builddir)/src/include

SUFFIXES = .in

gnunet-logread: gnunet-logread.in Makefile
	$(AWK) -v prl="$(PERL)" -v pfx="$(prefix)" -f $(top_srcdir)/bin/dosubst.awk < $(srcdir)/gnunet-logread.in > gnunet-logread
	chmod +x gnunet-logread

gnunet-logread-ipc-sdedit: gnunet-logread-ipc-sdedit.in Makefile
	$(AWK) -v prl="$(PERL)" -f $(top_srcdir)/bin/dosubst.awk < $(srcdir)/gnunet-logread-ipc-sdedit.in > gnunet-logread-ipc-sdedit
	chmod +x gnunet-logread-ipc-sdedit

CLEANFILES=	\
		gnunet-logread \
		gnunet-logread-ipc-sdedit

if GNUNET_LOGREAD
if HAVE_PERL
bin_SCRIPTS = \
		gnunet-logread-ipc \
		$(CLEANFILES)
else
noinst_SCRIPTS =		\
		gnunet-logread-ipc \
		$(CLEANFILES)
endif
endif

EXTRA_DIST = \
  gnunet-logread.in \
  gnunet-logread-ipc-sdedit.in \
  gnunet-logread-ipc
