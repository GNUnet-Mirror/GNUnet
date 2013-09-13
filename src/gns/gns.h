/*
      This file is part of GNUnet
      (C) 2012-2013 Christian Grothoff (and other contributing authors)

      GNUnet is free software; you can redistribute it and/or modify
      it under the terms of the GNU General Public License as published
      by the Free Software Foundation; either version 3, or (at your
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
 * Name of the GNS TLD.
 */
#define GNUNET_GNS_TLD "gnu"

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
   * Zone that is to be used for lookup
   */
  struct GNUNET_CRYPTO_EccPublicSignKey zone;

  /**
   * Only check cached results
   */
  int16_t only_cached GNUNET_PACKED;

  /**
   * Is a shorten key attached?
   */
  int16_t have_key GNUNET_PACKED;

  /**
   * the type of record to look up
   */
  int32_t type;
  
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


GNUNET_NETWORK_STRUCT_END

#endif
