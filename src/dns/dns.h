/*
      This file is part of GNUnet
      (C) 2010, 2011, 2012 Christian Grothoff (and other contributing authors)

      GNUnet is free software; you can redistribute it and/or modify
      it under the terms of the GNU General Public License as published
      by the Free Software Foundation; either version 2, or (at your
      option) any later version.

      GNUnet is distributed in the hope that it will be useful, but
      WITHOUT ANY WARRANTY; without even the implied warranty of
      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
      General Public License for more details.

      You should have received a copy of the GNU General Public License
      along with GNUnet; see the file COPYING.  If not, write to the
      Free Software Foundation, Inc., 59 Temple Place - Suite 330,
      Boston, MA 02111-1307, USA.
 */

/**
 * @file dns/dns.h
 * @brief IPC messages between DNS API and DNS service
 * @author Philipp Toelke
 * @author Christian Grothoff
 */
#ifndef DNS_H
#define DNS_H

GNUNET_NETWORK_STRUCT_BEGIN

struct query_packet
{
  struct GNUNET_MessageHeader hdr;

        /**
	 * The IP-Address this query was originally sent to
	 */
  char orig_to[16];
        /**
	 * The IP-Address this query was originally sent from
	 */
  char orig_from[16];
  char addrlen;
        /**
	 * The UDP-Port this query was originally sent from
	 */
  uint16_t src_port GNUNET_PACKED;

  unsigned char data[1];        /* The DNS-Packet */
};
GNUNET_NETWORK_STRUCT_END

#endif
