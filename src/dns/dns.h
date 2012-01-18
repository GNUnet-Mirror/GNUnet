/*
      This file is part of GNUnet
      (C) 2012 Christian Grothoff (and other contributing authors)

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
 * @author Christian Grothoff
 */
#ifndef DNS_NEW_H
#define DNS_NEW_H

GNUNET_NETWORK_STRUCT_BEGIN


/**
 * Message from client to DNS service to register itself.
 */
struct GNUNET_DNS_Register
{
  /**
    * Header of type GNUNET_MESSAGE_TYPE_DNS_CLIENT_INIT
   */
  struct GNUNET_MessageHeader header;

  /**
   * NBO encoding of 'enum GNUNET_DNS_Flags' for the client.
   */
  uint32_t flags;
};


/**
 * Message from DNS service to client: please handle a request.
 */
struct GNUNET_DNS_Request
{
  /**
    * Header of type GNUNET_MESSAGE_TYPE_DNS_CLIENT_REQUEST
   */
  struct GNUNET_MessageHeader header;

  /**
   * Always zero.
   */
  uint32_t reserved GNUNET_PACKED;
  
  /**
   * Unique request ID.
   */
  uint64_t request_id GNUNET_PACKED;

  /* followed by original DNS request (without UDP header) */

};


/**
 * Message from client to DNS service: here is my reply.
 */
struct GNUNET_DNS_Response
{
  /**
   * Header of type GNUNET_MESSAGE_TYPE_DNS_CLIENT_RESPONSE
   */
  struct GNUNET_MessageHeader header;

  /**
   * Zero to drop, 1 for no change (no payload), 2 for update (message has payload).
   */
  uint32_t drop_flag GNUNET_PACKED;
  
  /**
   * Unique request ID.
   */
  uint64_t request_id GNUNET_PACKED;

  /* followed by original DNS request (without UDP header) */

};


GNUNET_NETWORK_STRUCT_END

#endif
