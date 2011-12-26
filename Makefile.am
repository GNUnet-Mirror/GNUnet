INCLUDES = -I$(top_srcdir)/src/include
SUBDIRS  = contrib doc m4 src po pkgconfig

EXTRA_DIST = \
 ABOUT-NLS \
 config.rpath \
 install-sh \
 acinclude.m4

gnunetincludedir = $(includedir)/gnunet
gnunetinclude_HEADERS = gnunet_config.h

docdir = $(datadir)/doc/gnunet/
doc_DATA = COPYING

ACLOCAL_AMFLAGS = -I m4

ChangeLog:
	if test -f $(top_srcdir)/.svn/entries; then \
		svn log -v --xml -r HEAD:18409 | \
			xsltproc --stringparam ignore-message-starting "-" \
				 --stringparam strip-prefix "gnunet" \
				 --stringparam include-rev "yes" $(top_srcdir)/contrib/svn2cl.xsl - > $@; \
	fi

dist: ChangeLog

.PHONY: ChangeLog

