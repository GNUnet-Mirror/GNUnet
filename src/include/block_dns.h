/*
     This file is part of GNUnet.
     Copyright (C) 2013 GNUnet e.V.

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
*/

/**
 * @author Christian Grothoff
 *
 * @file
 * DNS network structs
 *
 * @defgroup block-dns  DNS Service network protocol definitions
 * @{
 */
#ifndef BLOCK_DNS_H
#define BLOCK_DNS_H

#include "gnunet_util_lib.h"

GNUNET_NETWORK_STRUCT_BEGIN

/**
 * This is the structure describing an DNS exit service.
 */
struct GNUNET_DNS_Advertisement
{
  /**
   * Signature of the peer affirming that it is offering the service.
   */
  struct GNUNET_CRYPTO_EddsaSignature signature;

  /**
   * Beginning of signed portion of the record, signs everything until
   * the end of the struct.
   */
  struct GNUNET_CRYPTO_EccSignaturePurpose purpose;

  /**
   * When does this signature expire?
   */
  struct GNUNET_TIME_AbsoluteNBO expiration_time;

  /**
   * The peer providing this service
   */
  struct GNUNET_PeerIdentity peer;

};
GNUNET_NETWORK_STRUCT_END

#endif

/** @} */  /* end of group */
