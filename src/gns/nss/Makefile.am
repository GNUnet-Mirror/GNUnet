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
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301
# USA.

EXTRA_DIST = map-file

AM_LDFLAGS=-avoid-version -module -export-dynamic

nssdir = $(libdir)/gnunet/nss

nss_LTLIBRARIES = \
	libnss_gns.la \
	libnss_gns4.la \
	libnss_gns6.la

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
