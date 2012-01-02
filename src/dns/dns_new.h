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
 * @file dns/dns_new.h
 * @brief IPC messages between DNS API and DNS service
 * @author Christian Grothoff
 */
#ifndef DNS_NEW_H
#define DNS_NEW_H

GNUNET_NETWORK_STRUCT_BEGIN

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
   * A DNS type (GNUNET_DNS_TYPE_*)
   */
  uint16_t dns_type GNUNET_PACKED;
  
  /**
   * A DNS class (usually 1).
   */
  uint16_t dns_class GNUNET_PACKED;

  /**
   * Unique request ID.
   */
  uint64_t request_id GNUNET_PACKED;

  /**
   * TTL if rdata is present, otherwise 0.
   */
  uint32_t dns_ttl GNUNET_PACKED;

  /**
   * Number of bytes of rdata that follow at the end.
   */
  uint16_t rdata_length GNUNET_PACKED;

  /**
   * Number of bytes of the name that follow right now (including 0-termination).
   */
  uint16_t name_length GNUNET_PACKED;
  
  /* followed by char name[name_length] */

  /* followed by char rdata[rdata_length] */

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
   * TTL if rdata is present, otherwise 0.
   */
  uint32_t dns_ttl GNUNET_PACKED;

  /**
   * Unique request ID, matches the original request.
   */
  uint64_t request_id GNUNET_PACKED;

  /**
   * 1 to drop request, 0 to forward if there is no response
   * or to answer if there is a response.
   */
  uint16_t drop_flag GNUNET_PACKED;

  /**
   * Number of bytes of rdata that follow at the end.
   */
  uint16_t rdata_length GNUNET_PACKED;

  /* followed by char rdata[rdata_length] */

};


GNUNET_NETWORK_STRUCT_END

#endif
