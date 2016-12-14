/*
      This file is part of GNUnet
      Copyright (C) 2012-2013 GNUnet e.V.

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
      Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
      Boston, MA 02110-1301, USA.
 */
/**
 * @file credential/credential.h
 * @brief IPC messages between CREDENTIAL API and CREDENTIAL service
 * @author Adnan Husain 
 */
#ifndef CREDENTIAL_H
#define CREDENTIAL_H

#include "gnunet_credential_service.h"

GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Message from client to Credential service to verify attributes.
 */
struct VerifyMessage
{
  /**
   * Header of type #GNUNET_MESSAGE_TYPE_CREDENTIAL_VERIFY
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
   * Length of the issuer attribute
   */
  uint16_t issuer_attribute_len;

  /**
   * Length of the subject attribute
   */
  uint16_t subject_attribute_len;

  /**
   * Unique identifier for this request (for key collisions).
   */
  uint32_t id GNUNET_PACKED;

  /* Followed by the zero-terminated attributes to look up */

};


/**
 * Message from CREDENTIAL service to client: new results.
 */
struct VerifyResultMessage
{
  /**
    * Header of type #GNUNET_MESSAGE_TYPE_CREDENTIAL_VERIFY_RESULT
   */
  struct GNUNET_MessageHeader header;

  /**
   * Unique identifier for this request (for key collisions).
   */
  uint32_t id GNUNET_PACKED;
  
  /**
   * Indicates if credential has been found at all
   */
  uint32_t cred_found GNUNET_PACKED;

  /**
   * The number of delegations in the response
   */
  uint32_t d_count GNUNET_PACKED;

  /**
   * The number of credentials in the response
   */
  uint32_t c_count GNUNET_PACKED;

  /* followed by ad_count GNUNET_CREDENTIAL_RecordData structs*/

};


GNUNET_NETWORK_STRUCT_END

#endif

