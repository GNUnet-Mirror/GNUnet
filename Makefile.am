INCLUDES = -I$(top_srcdir)/src/include
SUBDIRS  = contrib doc m4 src po pkgconfig

EXTRA_DIST = \
 ABOUT-NLS \
 config.rpath \
 install-sh \
 HACKING \
 acinclude.m4

gnunetincludedir = $(includedir)/gnunet
gnunetinclude_HEADERS = gnunet_config.h

ACLOCAL_AMFLAGS = -I m4

ChangeLog:
	if test -f $(top_srcdir)/.svn/entries; then \
		svn log -v --xml -r HEAD:18264 | \
			xsltproc --stringparam strip-prefix "-" \
				 --stringparam include-rev "yes" $(top_srcdir)/contrib/svn2cl.xsl - > $@; \
	fi
