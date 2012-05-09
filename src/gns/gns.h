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

#include "gnunet_gns_service.h"

/**
 * @file gns/gns.h
 * @brief IPC messages between GNS API and GNS service
 * @author Martin Schanzenbach
 */
#ifndef GNS_H
#define GNS_H

#define GNUNET_GNS_TLD "gnunet"
#define GNUNET_GNS_TLD_ZKEY "zkey"
#define GNUNET_GNS_DHT_MAX_UPDATE_INTERVAL 3600

#define MAX_DNS_LABEL_LENGTH 63
#define MAX_DNS_NAME_LENGTH 253

GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Message from client to GNS service to lookup records.
 */
struct GNUNET_GNS_ClientLookupMessage
{
  /**
    * Header of type GNUNET_MESSAGE_TYPE_GNS_CLIENT_LOOKUP
   */
  struct GNUNET_MessageHeader header;

  /**
   * Unique identifier for this request (for key collisions).
   */
  uint32_t id GNUNET_PACKED;

  /**
   * Should we look up in the default zone?
   */
  uint32_t use_default_zone GNUNET_PACKED;

  /**
   * If use_default_zone is empty this zone is used for lookup
   */
  struct GNUNET_CRYPTO_ShortHashCode zone;

  /**
   * the type of record to look up
   */
  enum GNUNET_GNS_RecordType type;

  /* Followed by the name to look up */
};


/**
 * Message from GNS service to client: new results.
 */
struct GNUNET_GNS_ClientLookupResultMessage
{
  /**
    * Header of type GNUNET_MESSAGE_TYPE_GNS_CLIENT_RESULT
   */
  struct GNUNET_MessageHeader header;

  /**
   * Unique identifier for this request (for key collisions).
   */
  uint32_t id GNUNET_PACKED;

  /**
   * The number of records contained in response
   */  
  uint32_t rd_count;

  // FIXME: what format has a GNS_Record?
  /* followed by rd_count GNUNET_NAMESTORE_RecordData structs*/

};

/**
 * Message from client to GNS service to shorten names.
 */
struct GNUNET_GNS_ClientShortenMessage
{
  /**
    * Header of type GNUNET_MESSAGE_TYPE_GNS_CLIENT_SHORTEN
   */
  struct GNUNET_MessageHeader header;

  /**
   * Unique identifier for this request
   */
  uint32_t id GNUNET_PACKED;

  /**
   * Should we look up in the default zone?
   */
  uint32_t use_default_zone GNUNET_PACKED;

  /**
   * If use_default_zone is empty this zone is used for lookup
   */
  struct GNUNET_CRYPTO_ShortHashCode zone;

  /* Followed by the name to shorten up */
};


/**
 * Message from GNS service to client: shorten result.
 */
struct GNUNET_GNS_ClientShortenResultMessage
{
  /**
    * Header of type GNUNET_MESSAGE_TYPE_GNS_CLIENT_SHORTEN_RESULT
   */
  struct GNUNET_MessageHeader header;

  /**
   * Unique identifier for this request (for key collisions).
   */
  uint32_t id GNUNET_PACKED;

  /* followed by the shortened name or '\0' for no result*/

};

/**
 * Message from client to GNS service to lookup an authority of a name.
 */
struct GNUNET_GNS_ClientGetAuthMessage
{
  /**
    * Header of type GNUNET_MESSAGE_TYPE_GNS_CLIENT_GET_AUTH
   */
  struct GNUNET_MessageHeader header;

  /**
   * Unique identifier for this request
   */
  uint32_t id GNUNET_PACKED;

  /* Followed by the name to get authority for */
};


/**
 * Message from GNS service to client: authority result.
 */
struct GNUNET_GNS_ClientGetAuthResultMessage
{
  /**
    * Header of type GNUNET_MESSAGE_TYPE_GNS_CLIENT_GET_AUTH_RESULT
   */
  struct GNUNET_MessageHeader header;

  /**
   * Unique identifier for this request (for key collisions).
   */
  uint32_t id GNUNET_PACKED;

  /* followed by the authority part of the name or '\0' for no result*/

};
GNUNET_NETWORK_STRUCT_END

#endif
