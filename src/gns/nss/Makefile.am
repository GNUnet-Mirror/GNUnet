# This Makefile.am is in the public domain
# $Id$
#
# This file taken and modified from nss-gns.
#
# nss-gns is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 3 of the
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

EXTRA_DIST = map-file \
  install-nss-plugin.sh \
  uninstall-nss-plugin.sh

AM_LDFLAGS=-avoid-version -module -export-dynamic

nssdir = $(NSS_DIR)

LIBTOOL = $(SUDO_BINARY) $(SHELL) $(top_builddir)/libtool

if !MINGW
if INSTALL_NSS
nss_LTLIBRARIES = \
	libnss_gns.la \
	libnss_gns4.la \
	libnss_gns6.la
endif
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

if INSTALL_NSS
if !MINGW
install-data-hook:
	$(top_srcdir)/src/gns/nss/install-nss-plugin.sh $(SHELL) $(top_builddir) $(nssdir) $(SUDO_BINARY)

uninstall-hook:
	$(top_srcdir)/src/gns/nss/uninstall-nss-plugin.sh $(SHELL) $(top_builddir) "rm -f $(nssdir)/libnss_gns.so.2" $(SUDO_BINARY)
	$(top_srcdir)/src/gns/nss/uninstall-nss-plugin.sh $(SHELL) $(top_builddir) "rm -f $(nssdir)/libnss_gns4.so.2" $(SUDO_BINARY)
	$(top_srcdir)/src/gns/nss/uninstall-nss-plugin.sh $(SHELL) $(top_builddir) "rm -f $(nssdir)/libnss_gns6.so.2" $(SUDO_BINARY)
endif
endif