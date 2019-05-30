/*
      This file is part of GNUnet
      Copyright (C) 2012-2013 GNUnet e.V.

      GNUnet is free software: you can redistribute it and/or modify it
      under the terms of the GNU Affero General Public License as published
      by the Free Software Foundation, either version 3 of the License,
      or (at your option) any later version.

      GNUnet is distributed in the hope that it will be useful, but
      WITHOUT ANY WARRANTY; without even the implied warranty of
      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
      Affero General Public License for more details.
     
      You should have received a copy of the GNU Affero General Public License
      along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
 */
/**
 * @file gns/gns.h
 * @brief IPC messages between GNS API and GNS service
 * @author Martin Schanzenbach
 */
#ifndef GNS_H
#define GNS_H

#include "gnunet_gns_service.h"


GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Message from client to GNS service to lookup records.
 */
struct LookupMessage
{
  /**
   * Header of type #GNUNET_MESSAGE_TYPE_GNS_LOOKUP
   */
  struct GNUNET_MessageHeader header;

  /**
   * Unique identifier for this request (for key collisions).
   */
  uint32_t id GNUNET_PACKED;

  /**
   * Zone that is to be used for lookup
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey zone;

  /**
   * Local options for where to look for results
   * (an `enum GNUNET_GNS_LocalOptions` in NBO).
   */
  int16_t options GNUNET_PACKED;

  /**
   * Always 0.
   */
  int16_t reserved GNUNET_PACKED;

  /**
   * the type of record to look up
   */
  int32_t type GNUNET_PACKED;

  /* Followed by the zero-terminated name to look up */
};


/**
 * Message from GNS service to client: new results.
 */
struct LookupResultMessage
{
  /**
    * Header of type #GNUNET_MESSAGE_TYPE_GNS_LOOKUP_RESULT
   */
  struct GNUNET_MessageHeader header;

  /**
   * Unique identifier for this request (for key collisions).
   */
  uint32_t id GNUNET_PACKED;

  /**
   * The number of records contained in response
   */
  uint32_t rd_count GNUNET_PACKED;

  /* followed by rd_count GNUNET_GNSRECORD_Data structs*/

};


GNUNET_NETWORK_STRUCT_END

#endif
