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
 * @author Martin Schanzenbach
 * @file zklaim/zklaim.h
 *
 * @brief Common type definitions for the zklaim
 *        service and API.
 */
#ifndef ZKLAIM_API_H
#define ZKLAIM_API_H

#include "gnunet_common.h"


GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Answer from service to client about last operation;
 * GET_DEFAULT maybe answered with this message on failure;
 * CREATE and RENAME will always be answered with this message.
 */
struct ContextMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_ZKLAIM_RESULT_CTX
   */
  struct GNUNET_MessageHeader header;

  /**
   * Length if the serialized context.
   */
  uint32_t ctx_len GNUNET_PACKED;

  /* followed by 0-terminated error message (on error) */

};



/**
 * Answer from service to client about last operation;
 * GET_DEFAULT maybe answered with this message on failure;
 * CREATE and RENAME will always be answered with this message.
 */
struct ResultCodeMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_ZKLAIM_RESULT_CODE
   */
  struct GNUNET_MessageHeader header;

  /**
   * Status code for the last operation, in NBO.
   * (currently not used).
   */
  uint32_t result_code GNUNET_PACKED;

  /* followed by 0-terminated error message (on error) */

};

/**
 * Client requests issue of a credential.  Service
 * will respond with a context.
 */
struct LookupMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_ZKLAIM_LOOKUP_CTX
   */
  struct GNUNET_MessageHeader header;

  /**
   * Number of bytes in name string including 0-termination, in NBO.
   */
  uint16_t name_len GNUNET_PACKED;

  /**
   * Always zero.
   */
  uint16_t reserved GNUNET_PACKED;

  /**
   * The private key
   */
  struct GNUNET_CRYPTO_EcdsaPrivateKey private_key;

  /* followed by 0-terminated identity name */

};


/**
 * Client requests creation of an identity.  Service
 * will respond with a result code.
 */
struct CreateRequestMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_ZKLAIM_CREATE
   */
  struct GNUNET_MessageHeader header;

  /**
   * Number of bytes in name string including 0-termination, in NBO.
   */
  uint16_t name_len GNUNET_PACKED;

  /**
   * Number of bytes in attributes string including 0-termination, in NBO.
   */
  uint16_t attrs_len GNUNET_PACKED;

  /**
   * Always zero.
   */
  uint16_t reserved GNUNET_PACKED;

  /**
   * The private key
   */
  struct GNUNET_CRYPTO_EcdsaPrivateKey private_key;

  /* followed by 0-terminated identity name */

};

GNUNET_NETWORK_STRUCT_END

#endif
