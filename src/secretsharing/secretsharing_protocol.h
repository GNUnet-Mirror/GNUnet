/*
      This file is part of GNUnet
      (C) 2012 Christian Grothoff (and other contributing authors)

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
 * @file secretsharing/secretsharing_protocol.h
 * @brief p2p message definitions for secretsharing
 * @author Florian Dold
 */

#ifndef GNUNET_SECRETSHARING_PROTOCOL_H
#define GNUNET_SECRETSHARING_PROTOCOL_H

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_protocols.h"
#include "secretsharing.h"

/**
 * Bit length used for the Paillier crypto system.
 */
#define PAILLIER_BITS 2048

GNUNET_NETWORK_STRUCT_BEGIN


/**
 * Public key for the Paillier crypto system.
 */
struct PaillierPublicKey
{
  /**
   * Network order representation of the
   * n-component.
   */
  uint32_t n[PAILLIER_BITS / 8 / sizeof (uint32_t)];
};


/**
 * Consensus element data used in the first round of key generation.
 */
struct GNUNET_SECRETSHARING_KeygenCommitData
{
  /**
   * Signature over the rest of the message.
   */
  struct GNUNET_CRYPTO_EddsaSignature signature;
  /**
   * Signature purpose for signing the keygen commit data.
   */
  struct GNUNET_CRYPTO_EccSignaturePurpose purpose;
  /**
   * Peer that inserts this element.
   */
  struct GNUNET_PeerIdentity peer;
  /**
   * Ephemeral paillier public key used by 'peer' for
   * this session.
   */
  struct PaillierPublicKey pubkey GNUNET_PACKED;
  /**
   * Commitment of 'peer' to his presecret.
   */
  struct GNUNET_HashCode commitment GNUNET_PACKED;
};


struct GNUNET_SECRETSHARING_KeygenRevealData
{
  /**
   * Signature over rest of the message.
   */
  struct GNUNET_CRYPTO_EddsaSignature signature;
  /*
   * Signature purpose for signing the keygen commit data.
   */
  struct GNUNET_CRYPTO_EccSignaturePurpose purpose;
  /**
   * Peer that inserts this element.
   */
  struct GNUNET_PeerIdentity peer;

  /* values follow */
};


/**
 * Data of then element put in consensus
 * for decrypting a value.
 */
struct GNUNET_SECRETSHARING_DecryptData
{
  /*
   * Signature over rest of the message.
   */
  struct GNUNET_CRYPTO_EddsaSignature signature;
  /*
   * Signature purpose for signing the keygen commit data.
   */
  struct GNUNET_CRYPTO_EccSignaturePurpose purpose;
  /**
   * Ciphertext we want to decrypt.
   */
  struct GNUNET_SECRETSHARING_Ciphertext ciphertext;
  /**
   * Peer that inserts this element.
   */
  struct GNUNET_PeerIdentity peer;
  /**
   * Partial decryption, computed as c_1^{s_i}
   */
  struct GNUNET_SECRETSHARING_FieldElement partial_decryption;
  /**
   * Commitment for the non-interactive zero knowledge proof.
   * g^\beta, with \beta < q
   */
  struct GNUNET_SECRETSHARING_FieldElement nizk_commit1;
  /**
   * Commitment for the non-interactive zero knowledge proof.
   * c_1^\beta, with \beta < q
   */
  struct GNUNET_SECRETSHARING_FieldElement nizk_commit2;
  /**
   * Reponse to the challenge computed from the protocol transcript.
   * r = \beta + challenge \cdot share_i
   */
  struct GNUNET_SECRETSHARING_FieldElement nizk_response;
};

GNUNET_NETWORK_STRUCT_END

#endif
