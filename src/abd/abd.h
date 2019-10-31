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
 * @file abd/abd.h
 * @brief IPC messages between ABD API and ABD service
 * @author Martin Schanzenbach
 */
#ifndef ABD_H
#define ABD_H

#include "gnunet_abd_service.h"

GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Message from client to Credential service to collect credentials.
 */
struct CollectMessage
{
  /**
   * Header of type #GNUNET_MESSAGE_TYPE_ABD_VERIFY
   */
  struct GNUNET_MessageHeader header;

  /**
   * Subject public key
   */
  struct GNUNET_CRYPTO_EcdsaPrivateKey subject_key;

  /**
   * Trust anchor
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey issuer_key;

  /**
   * Length of the issuer attribute
   */
  uint16_t issuer_attribute_len;

  /**
   * Direction of the resolution algo
   */
  uint16_t resolution_algo;

  /**
   * Unique identifier for this request (for key collisions).
   */
  uint32_t id GNUNET_PACKED;

  /* Followed by the zero-terminated attribute */
};


/**
 * Message from client to Credential service to verify attributes.
 */
struct VerifyMessage
{
  /**
   * Header of type #GNUNET_MESSAGE_TYPE_ABD_VERIFY
   */
  struct GNUNET_MessageHeader header;

  /**
   * Subject public key
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey subject_key;

  /**
   * Trust anchor
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey issuer_key;

  /**
   * Number of delegates
   */
  uint32_t d_count;

  /**
   * Length of the issuer attribute
   */
  uint16_t issuer_attribute_len;

  /**
   * Direction of the resolution algo
   */
  uint16_t resolution_algo;

  /**
   * Unique identifier for this request (for key collisions).
   */
  uint32_t id GNUNET_PACKED;

  /* Followed by the zero-terminated attribute and credentials to look up */
};


/**
 * Message from ABD service to client: new results.
 */
struct DelegationChainResultMessage
{
  /**
    * Header of type #GNUNET_MESSAGE_TYPE_ABD_VERIFY_RESULT
   */
  struct GNUNET_MessageHeader header;

  /**
   * Unique identifier for this request (for key collisions).
   */
  uint32_t id GNUNET_PACKED;

  /**
   * Indicates if credential has been found at all
   */
  uint32_t del_found GNUNET_PACKED;

  /**
   * The number of delegations in the response
   */
  uint32_t d_count GNUNET_PACKED;

  /**
   * The number of credentials in the response
   */
  uint32_t c_count GNUNET_PACKED;

  /* followed by ad_count GNUNET_ABD_RecordData structs*/
};

/**
 * Message from ABD service to client: new results.
 */
struct DelegationChainIntermediateMessage
{
  /**
    * Header of type #GNUNET_MESSAGE_TYPE_ABD_INTERMEDIATE_RESULT
   */
  struct GNUNET_MessageHeader header;

  /**
   * Unique identifier for this request (for key collisions).
   */
  uint32_t id GNUNET_PACKED;

  uint16_t is_bw GNUNET_PACKED;

  uint32_t size GNUNET_PACKED;
};

struct DelegationRecordData
{
  /**
   * Subject key
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey subject_key;

  /**
   * Subject attributes
   */
  uint32_t subject_attribute_len GNUNET_PACKED;
};


struct ChainEntry
{
  /**
   * Issuer key
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey issuer_key;

  /**
   * Subject key
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey subject_key;

  /**
   * Issuer attributes
   */
  uint32_t issuer_attribute_len GNUNET_PACKED;

  /**
   * Subject attributes
   */
  uint32_t subject_attribute_len GNUNET_PACKED;
};


struct CredentialEntry
{

  /**
   * The signature for this credential by the issuer
   */
  struct GNUNET_CRYPTO_EcdsaSignature signature;

  /**
   * Signature meta
   */
  struct GNUNET_CRYPTO_EccSignaturePurpose purpose;

  /**
   * Public key of the issuer
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey issuer_key;

  /**
   * Public key of the subject this credential was issued to
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey subject_key;

  /**
   * Expiration time of this credential
   */
  uint64_t expiration GNUNET_PACKED;

  /**
   * Issuer attribute length
   */
  uint32_t issuer_attribute_len;

  /**
   * Followed by the attribute string
   */
};

struct DelegateEntry
{

  /**
   * The signature for this credential by the issuer
   */
  struct GNUNET_CRYPTO_EcdsaSignature signature;

  /**
   * Signature meta
   */
  struct GNUNET_CRYPTO_EccSignaturePurpose purpose;

  /**
   * Public key of the issuer
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey issuer_key;

  /**
   * Public key of the subject this credential was issued to
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey subject_key;

  /**
   * Expiration time of this credential
   */
  uint64_t expiration GNUNET_PACKED;

  /**
   * Issuer subject attribute length
   */
  uint32_t issuer_attribute_len;

  /**
   * Issuer attribute length
   */
  uint32_t subject_attribute_len;

  /**
   * Followed by the subject attribute string
   */
};


GNUNET_NETWORK_STRUCT_END

#endif
