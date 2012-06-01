# $Id$
#
# This file taken and modified from nss-gns.
#
# nss-gns is free software; you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation; either version 2 of the
# License, or (at your option) any later version.
#
# nss-gns is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with nss-gns; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
# USA.

EXTRA_DIST = map-file

AM_LDFLAGS=-avoid-version -module -export-dynamic

if HAVE_SUDO
nssdir = /lib/
else
nssdir = $(libdir)
endif

LIBTOOL = $(SUDO_BINARY) $(SHELL) $(top_builddir)/libtool

if !MINGW
nss_LTLIBRARIES = \
	libnss_gns.la \
	libnss_gns4.la \
	libnss_gns6.la
endif

sources = nss_gns_query.h nss_gns_query.c

# GNU Libc
libnss_gns_la_SOURCES= $(sources) nss_gns.c
libnss_gns_la_CFLAGS=$(AM_CFLAGS) -D_GNU_SOURCE
libnss_gns_la_LDFLAGS=$(AM_LDFLAGS) -shrext .so.2 -Wl,-version-script=$(srcdir)/map-file

libnss_gns4_la_SOURCES=$(libnss_gns_la_SOURCES)
libnss_gns4_la_CFLAGS=$(libnss_gns_la_CFLAGS) -DNSS_IPV4_ONLY=1
libnss_gns4_la_LDFLAGS=$(libnss_gns_la_LDFLAGS)

libnss_gns6_la_SOURCES=$(libnss_gns_la_SOURCES)
libnss_gns6_la_CFLAGS=$(libnss_gns_la_CFLAGS) -DNSS_IPV6_ONLY=1
libnss_gns6_la_LDFLAGS=$(libnss_gns_la_LDFLAGS)

install-data-hook:
	$(SUDO_BINARY) $(SHELL) $(top_builddir)/libtool --finish $(nssdir)
	$(SUDO_BINARY) rm -f $(nssdir)/libnss_gns.la $(nssdir)/libnss_gns4.la $(nssdir)/libnss_gns6.la 

uninstall-hook:
	$(SUDO_BINARY) rm -f $(nssdir)/libnss_gns.so.2 $(nssdir)/libnss_gns4.so.2 $(nssdir)/libnss_gns6.so.2 
