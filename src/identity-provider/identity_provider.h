/*
     This file is part of GNUnet.
     Copyright (C) 2016 Christian Grothoff (and other contributing authors)

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
 * The ticket
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
struct GNUNET_IDENTITY_PROVIDER_IssueResultMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_IDENTITY_RESULT_CODE
   */
  struct GNUNET_MessageHeader header;

  /* followed by 0-terminated ticket */

};


/**
 * Ticket exchange message.
 */
struct GNUNET_IDENTITY_PROVIDER_ExchangeResultMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_IDENTITY_UPDATE
   */
  struct GNUNET_MessageHeader header;

  /**
   * Number of bytes in token string including 0-termination, in NBO;
   * 0 on error.
   */
  uint16_t name_len GNUNET_PACKED;

  /* followed by 0-terminated token */

};



/**
 * Client requests IdP to issue token.
 */
struct GNUNET_IDENTITY_PROVIDER_IssueMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_IDENTITY_GET_DEFAULT
   */
  struct GNUNET_MessageHeader header;

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
   * Expiration of token in NBO.
   */
  struct GNUNET_TIME_AbsoluteNBO expiration;


  /* followed by 0-terminated comma-separated scope list */

};


/**
 * Use to exchange a ticket for a token
 */
struct GNUNET_IDENTITY_PROVIDER_ExchangeMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_IDENTITY_SET_DEFAULT
   */
  struct GNUNET_MessageHeader header;
  
  /**
   * Audience identity private key
   */
  struct GNUNET_CRYPTO_EcdsaPrivateKey aud_privkey;

  /* followed by 0-terminated ticket string */

};


GNUNET_NETWORK_STRUCT_END

#endif
