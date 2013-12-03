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

/**
 * Bit length used for the Paillier crypto system.
 */
#define PAILLIER_BITS 2048

/**
 * Big endian representation of the prime field order used
 * for ElGamal.
 */
#define ELGAMAL_Q_DATA {0x00 /* FIXME */};


GNUNET_NETWORK_STRUCT_BEGIN


/**
 * Public key for the Paillier crypto system.
 */
struct PaillierPublicKey
{
  /**
   * Network order representation of the
   * g-component.
   */
  uint32_t g[PAILLIER_BITS / 8 / sizeof (uint32_t)];

  /**
   * Network order representation of the
   * g-component.
   */
  uint32_t mu[PAILLIER_BITS / 8 / sizeof (uint32_t)];
};


/**
 * Consensus element data used in the first round of key generation.
 */
struct GNUNET_SECRETSHARING_KeygenCommitData
{
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
  /**
   * Signature over the previous values.
   */
  struct GNUNET_CRYPTO_EddsaSignature signature;
};

GNUNET_NETWORK_STRUCT_END

#endif
