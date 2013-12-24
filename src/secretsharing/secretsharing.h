/*
     This file is part of GNUnet.
     (C) 2013 Christian Grothoff (and other contributing authors)

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
 * @author Florian Dold
 * @file secretsharing/secretsharing.h
 * @brief messages used for the secretsharing api
 */
#ifndef SECRETSHARING_H
#define SECRETSHARING_H

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_time_lib.h"
#include "gnunet_secretsharing_service.h"


GNUNET_NETWORK_STRUCT_BEGIN


struct GNUNET_SECRETSHARING_CreateMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_SECRETSHARING_CLIENT_GENERATE
   */
  struct GNUNET_MessageHeader header;

  /**
   * Session ID, will be used for consensus.
   */
  struct GNUNET_HashCode session_id GNUNET_PACKED;

  /**
   * Deadline for the establishment of the crypto system.
   */
  struct GNUNET_TIME_AbsoluteNBO deadline;

  /**
   * Mininum number of cooperating peers to decrypt a
   * value.
   */
  uint16_t threshold GNUNET_PACKED;

  /**
   * Number of peers at the end of this message.
   */
  uint16_t num_peers GNUNET_PACKED;

  /* struct GNUNET_PeerIdentity[num_peers]; */
};


struct GNUNET_SECRETSHARING_SecretReadyMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_SECRETSHARING_CLIENT_SECRET_READY
   */
  struct GNUNET_MessageHeader header;

  /**
   * Secret share in network byte order.
   */
  unsigned char secret[GNUNET_SECRETSHARING_KEY_BITS / 8];

  /**
   * Secret share in network byte order.
   */
  struct GNUNET_SECRETSHARING_PublicKey public_key;

  /**
   * Number of peers at the end of this message.
   * Includes peers that are part of the established
   * threshold crypto system.
   */
  uint16_t num_secret_peers GNUNET_PACKED;

  /* struct GNUNET_PeerIdentity[num_peers]; */
};


struct GNUNET_SECRETSHARING_DecryptRequestMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_SECRETSHARING_CLIENT_DECRYPT_REQUEST
   */
  struct GNUNET_MessageHeader header;

  /**
   * Ciphertext to request decryption for.
   */
  unsigned char ciphertext[GNUNET_SECRETSHARING_KEY_BITS / 8];

  /**
   * Number of peers at the end of this message.
   * Includes peers that are part of the established
   * threshold crypto system.
   */
  uint16_t num_secret_peers GNUNET_PACKED;

  /* struct GNUNET_PeerIdentity[num_peers]; */
};


struct GNUNET_SECRETSHARING_DecryptResponseMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_SECRETSHARING_CLIENT_DECRYPT_RESPONSE
   */
  struct GNUNET_MessageHeader header;

  /**
   * Ciphertext to request decryption for.
   */
  unsigned char plaintext[GNUNET_SECRETSHARING_KEY_BITS / 8];
};


GNUNET_NETWORK_STRUCT_END

#endif
