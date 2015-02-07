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
 * @author Christian Grothoff
 * @file revocation/revocation.h
 * @brief messages for key revocation
 */
#ifndef REVOCATION_H
#define REVOCATION_H

#include "gnunet_util_lib.h"

GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Query key revocation status.
 */
struct QueryMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_REVOCATION_QUERY
   */
  struct GNUNET_MessageHeader header;

  /**
   * For alignment.
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * Key to check.
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey key;

};


/**
 * Key revocation response.
 */
struct QueryResponseMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_REVOCATION_QUERY_RESPONSE
   */
  struct GNUNET_MessageHeader header;

  /**
   * #GNUNET_NO if revoked, #GNUNET_YES if valid.
   */
  uint32_t is_valid GNUNET_PACKED;

};


/**
 * Revoke key.  These messages are exchanged between peers (during
 * flooding) but also sent by the client to the service.  When the
 * client sends it to the service, the message is answered by a
 * #GNUNET_MESSAGE_TYPE_REVOCATION_REVOKE_RESPONSE (which is just
 * in a `struct GNUNET_MessageHeader`.
 */
struct RevokeMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_REVOCATION_REVOKE
   */
  struct GNUNET_MessageHeader header;

  /**
   * For alignment.
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * Number that causes a hash collision with the @e public_key.
   */
  uint64_t proof_of_work GNUNET_PACKED;

  /**
   * Signature confirming revocation.
   */
  struct GNUNET_CRYPTO_EcdsaSignature signature;

  /**
   * Must have purpose #GNUNET_SIGNATURE_PURPOSE_REVOCATION,
   * size expands over the public key.
   */
  struct GNUNET_CRYPTO_EccSignaturePurpose purpose;

  /**
   * Key to revoke.
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey public_key;

};


/**
 * Key revocation response.
 */
struct RevocationResponseMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_REVOCATION_REVOKE_RESPONSE
   */
  struct GNUNET_MessageHeader header;

  /**
   * #GNUNET_NO if revoked, #GNUNET_YES if valid.
   */
  uint32_t is_valid GNUNET_PACKED;

};


GNUNET_NETWORK_STRUCT_END



#endif
