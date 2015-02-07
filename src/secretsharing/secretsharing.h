/*
     This file is part of GNUnet.
     Copyright (C) 2013 Christian Grothoff (and other contributing authors)

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
#include "gnunet_util_lib.h"
#include "gnunet_time_lib.h"
#include "gnunet_common.h"
#include "gnunet_secretsharing_service.h"


GNUNET_NETWORK_STRUCT_BEGIN

struct GNUNET_SECRETSHARING_FieldElement
{
  /**
   * Value of an element in &lt;elgamal_g&gt;.
   */
  unsigned char bits[GNUNET_SECRETSHARING_ELGAMAL_BITS / 8];
};


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
   * Start time for communication with the other peers.
   */
  struct GNUNET_TIME_AbsoluteNBO start;

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



struct GNUNET_SECRETSHARING_ShareHeaderNBO
{
  /**
   * Threshold for the key this share belongs to.
   */
  uint16_t threshold;

  /**
   * Peers that have the share.
   */
  uint16_t num_peers;

  /**
   * Index of our peer in the list.
   */
  uint16_t my_peer;

  /**
   * Public key. Must correspond to the product of
   * the homomorphic share commitments.
   */
  struct GNUNET_SECRETSHARING_PublicKey public_key;

  /**
   * Share of 'my_peer'
   */
  struct GNUNET_SECRETSHARING_FieldElement my_share;
};


/**
 * Notify the client that then threshold secret has been
 * established.
 */
struct GNUNET_SECRETSHARING_SecretReadyMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_SECRETSHARING_CLIENT_SECRET_READY
   */
  struct GNUNET_MessageHeader header;

  /* rest: the serialized share */

};


struct GNUNET_SECRETSHARING_DecryptRequestMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_SECRETSHARING_CLIENT_DECRYPT_REQUEST
   */
  struct GNUNET_MessageHeader header;

  /**
   * Until when should the decryption start?
   */
  struct GNUNET_TIME_AbsoluteNBO start;

  /**
   * Until when should the decryption be finished?
   */
  struct GNUNET_TIME_AbsoluteNBO deadline;

  /**
   * Ciphertext we want to decrypt.
   */
  struct GNUNET_SECRETSHARING_Ciphertext ciphertext;

  /* the share with payload */
};


struct GNUNET_SECRETSHARING_DecryptResponseMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_SECRETSHARING_CLIENT_DECRYPT_DONE
   */
  struct GNUNET_MessageHeader header;

  /**
   * Zero if decryption failed, non-zero if decryption succeeded.
   * If the decryption failed, plaintext is also zero.
   */
  uint32_t success;

  /**
   * Decrypted plaintext.
   */
  struct GNUNET_SECRETSHARING_FieldElement plaintext;
};


GNUNET_NETWORK_STRUCT_END


/**
 * A share, with all values in in host byte order.
 */
struct GNUNET_SECRETSHARING_Share
{
  /**
   * Threshold for the key this share belongs to.
   */
  uint16_t threshold;

  /**
   * Peers that have the share.
   */
  uint16_t num_peers;

  /**
   * Index of our peer in the list.
   */
  uint16_t my_peer;

  /**
   * Public key.  Computed from the
   * exponentiated coefficients.
   */
  struct GNUNET_SECRETSHARING_PublicKey public_key;

  /**
   * Share of 'my_peer'
   */
  struct GNUNET_SECRETSHARING_FieldElement my_share;

  /**
   * Peer identities (includes 'my_peer')
   */
  struct GNUNET_PeerIdentity *peers;

  /*
   * For each peer, store elgamal_g to the peer's
   * share.
   */
  struct GNUNET_SECRETSHARING_FieldElement *sigmas;

  /*
   * Original indices of peers from the DKG round.
   */
  uint16_t *original_indices;
};


#endif
