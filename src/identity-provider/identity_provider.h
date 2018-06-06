/*
     This file is part of GNUnet.
     Copyright (C) 2016 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.
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
   * The expiration interval of the attribute
   */
  uint64_t exp GNUNET_PACKED;

  /**
   * Identity
   */
  struct GNUNET_CRYPTO_EcdsaPrivateKey identity;

  /* followed by the serialized attribute */

};

/**
 * Attribute store response message
 */
struct AttributeStoreResultMessage
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
 * Start a ticket iteration for the given identity
 */
struct TicketIterationStartMessage
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
  struct GNUNET_CRYPTO_EcdsaPublicKey identity;

  /**
   * Identity is audience or issuer
   */
  uint32_t is_audience GNUNET_PACKED;
};


/**
 * Ask for next result of ticket iteration for the given operation
 */
struct TicketIterationNextMessage
{
  /**
   * Type will be #GNUNET_MESSAGE_TYPE_IDENTITY_PROVIDER_TICKET_ITERATION_NEXT
   */
  struct GNUNET_MessageHeader header;

  /**
   * Unique identifier for this request (for key collisions).
   */
  uint32_t id GNUNET_PACKED;

};


/**
 * Stop ticket iteration for the given operation
 */
struct TicketIterationStopMessage
{
  /**
   * Type will be #GNUNET_MESSAGE_TYPE_IDENTITY_PROVIDER_TICKET_ITERATION_STOP
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
struct IssueTicketMessage
{
  /**
   * Type will be #GNUNET_MESSAGE_TYPE_IDENTITY_PROVIDER_ISSUE_TICKET
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
 * Ticket revoke message
 */
struct RevokeTicketMessage
{
  /**
   * Type will be #GNUNET_MESSAGE_TYPE_IDENTITY_PROVIDER_REVOKE_TICKET
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
   * length of serialized attribute list
   */
  uint32_t attrs_len GNUNET_PACKED;

  //Followed by a ticket and serialized attribute list
};

/**
 * Ticket revoke message
 */
struct RevokeTicketResultMessage
{
  /**
   * Type will be #GNUNET_MESSAGE_TYPE_IDENTITY_PROVIDER_REVOKE_TICKET_RESULT
   */
  struct GNUNET_MessageHeader header;

  /**
   * Unique identifier for this request (for key collisions).
   */
  uint32_t id GNUNET_PACKED;

  /**
   * Revocation result
   */
  uint32_t success GNUNET_PACKED;
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
   * Type will be #GNUNET_MESSAGE_TYPE_IDENTITY_PROVIDER_CONSUME_TICKET
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

/**
 * Attribute list is returned from the idp.
 */
struct ConsumeTicketResultMessage
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
  uint16_t attrs_len GNUNET_PACKED;

  /**
   * always zero (for alignment)
   */
  uint16_t reserved GNUNET_PACKED;

  /**
   * The public key of the identity.
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey identity;

  /* followed by:
   * serialized attributes data
   */
};



GNUNET_NETWORK_STRUCT_END

#endif
