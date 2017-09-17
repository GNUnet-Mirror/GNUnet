/*
     This file is part of GNUnet.
     Copyright (C) 2016 GNUnet e.V.

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public Liceidentity as published
     by the Free Software Foundation; either version 3, or (at your
     option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     General Public Liceidentity for more details.

     You should have received a copy of the GNU General Public Liceidentity
     along with GNUnet; see the file COPYING.  If not, write to the
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/

/**
 * @author Martin Schanzenbach
 * @file identity-provider/identity_provider.h
 *
 * @brief Common type definitions for the identity provider
 *        service and API.
 */
#ifndef IDENTITY_PROVIDER_H
#define IDENTITY_PROVIDER_H

#include "gnunet_common.h"


GNUNET_NETWORK_STRUCT_BEGIN

/**
 * The token
 */
struct GNUNET_IDENTITY_PROVIDER_Token
{
  /**
   * The JWT representation of the identity token
   */
  char *data;
};

/**
 * The ticket DEPRECATED
 */
struct GNUNET_IDENTITY_PROVIDER_Ticket
{
  /**
   * The Base64 representation of the ticket
   */
  char *data;
};

/**
 * Answer from service to client after issue operation
 */
struct IssueResultMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_IDENTITY_RESULT_CODE
   */
  struct GNUNET_MessageHeader header;

  /**
   * Unique identifier for this request (for key collisions).
   */
  uint32_t id GNUNET_PACKED;

  /* followed by 0-terminated label,ticket,token */

};


/**
 * Ticket exchange message.
 */
struct ExchangeResultMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_IDENTITY_UPDATE
   */
  struct GNUNET_MessageHeader header;

  /**
   * Unique identifier for this request (for key collisions).
   */
  uint32_t id GNUNET_PACKED;

  /**
   * Nonce found in ticket. NBO
   * 0 on error.
   */
  uint64_t ticket_nonce GNUNET_PACKED;

  /* followed by 0-terminated token */

};



/**
 * Client requests IdP to issue token.
 */
struct IssueMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_IDENTITY_GET_DEFAULT
   */
  struct GNUNET_MessageHeader header;

  /**
   * Unique identifier for this request (for key collisions).
   */
  uint32_t id GNUNET_PACKED;


  /**
   * Issuer identity private key
   */
  struct GNUNET_CRYPTO_EcdsaPrivateKey iss_key;

  /**
   * Audience public key
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey aud_key;

  /**
   * Nonce
   */
  uint64_t nonce;

  /**
   * Length of scopes
   */
  uint64_t scope_len;

  /**
   * Expiration of token in NBO.
   */
  struct GNUNET_TIME_AbsoluteNBO expiration;


  /* followed by 0-terminated comma-separated scope list */

};


/**
 * Use to exchange a ticket for a token
 */
struct ExchangeMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_IDENTITY_SET_DEFAULT
   */
  struct GNUNET_MessageHeader header;

  /**
   * Unique identifier for this request (for key collisions).
   */
  uint32_t id GNUNET_PACKED;

  /**
   * Audience identity private key
   */
  struct GNUNET_CRYPTO_EcdsaPrivateKey aud_privkey;

  /* followed by 0-terminated ticket string */

};

/**
 * Use to store an identity attribute
 */
struct AttributeStoreMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_IDENTITY_SET_DEFAULT
   */
  struct GNUNET_MessageHeader header;

  /**
   * Unique identifier for this request (for key collisions).
   */
  uint32_t id GNUNET_PACKED;

  /**
   * The length of the attribute
   */
  uint32_t attr_len GNUNET_PACKED;

  /**
   * Identity
   */
  struct GNUNET_CRYPTO_EcdsaPrivateKey identity;

  /* followed by the serialized attribute */

};

/**
 * Attribute store response message
 */
struct AttributeStoreResponseMessage
{
  /**
   * Message header
   */
  struct GNUNET_MessageHeader header;
  
  /**
   * Unique identifier for this request (for key collisions).
   */
  uint32_t id GNUNET_PACKED;

  /**
   * #GNUNET_SYSERR on failure, #GNUNET_OK on success
   */
  int32_t op_result GNUNET_PACKED;

};

/**
 * Attribute is returned from the idp.
 */
struct AttributeResultMessage
{
  /**
   * Message header
   */
  struct GNUNET_MessageHeader header;

   /**
   * Unique identifier for this request (for key collisions).
   */
  uint32_t id GNUNET_PACKED;

  /**
   * Length of serialized attribute data
   */
  uint16_t attr_len GNUNET_PACKED;

  /**
   * always zero (for alignment)
   */
  uint16_t reserved GNUNET_PACKED;

  /**
   * The public key of the identity.
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey identity;

  /* followed by:
   * serialized attribute data
   */
};


/**
 * Start a attribute iteration for the given identity
 */
struct AttributeIterationStartMessage
{
  /**
   * Message
   */
  struct GNUNET_MessageHeader header;

  /**
   * Unique identifier for this request (for key collisions).
   */
  uint32_t id GNUNET_PACKED;

  /**
   * Identity.
   */
  struct GNUNET_CRYPTO_EcdsaPrivateKey identity;

};


/**
 * Ask for next result of attribute iteration for the given operation
 */
struct AttributeIterationNextMessage
{
  /**
   * Type will be #GNUNET_MESSAGE_TYPE_IDENTITY_PROVIDER_ATTRIBUTE_ITERATION_NEXT
   */
  struct GNUNET_MessageHeader header;

  /**
   * Unique identifier for this request (for key collisions).
   */
  uint32_t id GNUNET_PACKED;

};


/**
 * Stop attribute iteration for the given operation
 */
struct AttributeIterationStopMessage
{
  /**
   * Type will be #GNUNET_MESSAGE_TYPE_IDENTITY_PROVIDER_ATTRIBUTE_ITERATION_STOP
   */
  struct GNUNET_MessageHeader header;

  /**
   * Unique identifier for this request (for key collisions).
   */
  uint32_t id GNUNET_PACKED;

};

/**
 * Ticket issue message
 */
struct TicketIssueMessage
{
  /**
   * Type will be #GNUNET_MESSAGE_TYPE_IDENTITY_PROVIDER_TICKET_ISSUE
   */
  struct GNUNET_MessageHeader header;

  /**
   * Unique identifier for this request (for key collisions).
   */
  uint32_t id GNUNET_PACKED;

  /**
   * Identity.
   */
  struct GNUNET_CRYPTO_EcdsaPrivateKey identity;

  /**
   * Requesting party.
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey rp;

  /**
   * length of serialized attribute list
   */
  uint32_t attr_len GNUNET_PACKED;

  //Followed by a serialized attribute list
};

/**
 * Ticket result message
 */
struct TicketResultMessage
{
  /**
   * Type will be #GNUNET_MESSAGE_TYPE_IDENTITY_PROVIDER_TICKET_RESULT
   */
  struct GNUNET_MessageHeader header;

  /**
   * Unique identifier for this request (for key collisions).
   */
  uint32_t id GNUNET_PACKED;

};

/**
 * Ticket consume message
 */
struct ConsumeTicketMessage
{
  /**
   * Type will be #GNUNET_MESSAGE_TYPE_IDENTITY_PROVIDER_TICKET_ISSUE
   */
  struct GNUNET_MessageHeader header;

  /**
   * Unique identifier for this request (for key collisions).
   */
  uint32_t id GNUNET_PACKED;

  /**
   * Identity.
   */
  struct GNUNET_CRYPTO_EcdsaPrivateKey identity;

  //Followed by a serialized ticket
};


GNUNET_NETWORK_STRUCT_END

#endif
