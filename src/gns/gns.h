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
 * @file gns/gns.h
 * @brief IPC messages between GNS API and GNS service
 * @author Martin Schanzenbach
 */
#ifndef GNS_H
#define GNS_H

#include "gnunet_gns_service.h"

/**
 * Name of the GADS TLD.
 */
#define GNUNET_GNS_TLD "gads"

/**
 * Name of the zone key TLD.
 */
#define GNUNET_GNS_TLD_ZKEY "zkey"

/**
 * TLD name used to indicate relative names.
 */
#define GNUNET_GNS_TLD_PLUS "+"


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
   * If use_default_zone is empty this zone is used for lookup
   */
  struct GNUNET_CRYPTO_ShortHashCode zone;

  /**
   * Only check cached results
   */
  uint32_t only_cached GNUNET_PACKED;

  /**
   * Should we look up in the given zone, instead of the default zone?
   */
  uint32_t have_zone GNUNET_PACKED;

  /**
   * Is a shorten key attached?
   */
  uint32_t have_key GNUNET_PACKED;

  /**
   * the type of record to look up
   */
  /* enum GNUNET_GNS_RecordType */ uint32_t type;
  
  /**
   * The key for shorten, if 'have_key' is set 
   */
  struct GNUNET_CRYPTO_EccPrivateKey shorten_key;

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
   * If use_default_zone is empty this zone is used for lookup
   */
  struct GNUNET_CRYPTO_ShortHashCode zone;

  /**
   * Shorten zone
   */
  struct GNUNET_CRYPTO_ShortHashCode shorten_zone;

  /**
   * Private zone
   */
  struct GNUNET_CRYPTO_ShortHashCode private_zone;

  /**
   * Should we look up in the default zone?
   */
  uint32_t use_default_zone GNUNET_PACKED;
  
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
