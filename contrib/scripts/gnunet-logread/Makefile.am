# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include -I$(top_builddir)/src/include

do_subst = $(SED) -e 's,[@]PERL[@],$(PERL),g'

SUFFIXES = .in

gnunet-logread: gnunet-logread.in Makefile
	$(do_subst) < $(srcdir)/gnunet-logread.in > gnunet-logread
	chmod +x gnunet-logread

gnunet-logread-ipc-sdedit: gnunet-logread-ipc-sdedit.in Makefile
	$(do_subst) < $(srcdir)/gnunet-logread-ipc-sdedit.in > gnunet-logread-ipc-sdedit
	chmod +x gnunet-logread-ipc-sdedit

CLEANFILES=	\
		gnunet-logread \
		gnunet-logread-ipc-sdedit

noinst_SCRIPTS =		\
		$(CLEANFILES) \
		gnunet-logread-ipc

EXTRA_DIST = \
  gnunet-logread.in \
  gnunet-logread-ipc-sdedit.in \
  gnunet-logread-ipc
