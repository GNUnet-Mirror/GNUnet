/*
     This file is part of GNUnet.
     Copyright (C) 2013 Christian Grothoff (and other contributing authors)

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
     Free Software Foundation, Inc., 59 Temple Place - Suite 330,
     Boston, MA 02111-1307, USA.
*/

/**
 * @author Christian Grothoff
 * @file identity/identity.h
 *
 * @brief Common type definitions for the identity
 *        service and API.
 */
#ifndef IDENTITY_H
#define IDENTITY_H

#include "gnunet_common.h"


GNUNET_NETWORK_STRUCT_BEGIN


/**
 * Answer from service to client about last operation;
 * GET_DEFAULT maybe answered with this message on failure;
 * CREATE and RENAME will always be answered with this message.
 */
struct GNUNET_IDENTITY_ResultCodeMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_IDENTITY_RESULT_CODE
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
 * Service informs client about status of a pseudonym.
 */
struct GNUNET_IDENTITY_UpdateMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_IDENTITY_UPDATE
   */
  struct GNUNET_MessageHeader header;

  /**
   * Number of bytes in ego name string including 0-termination, in NBO;
   * 0 if the ego was deleted.
   */
  uint16_t name_len GNUNET_PACKED;

  /**
   * Usually #GNUNET_NO, #GNUNET_YES to signal end of list.
   */
  uint16_t end_of_list GNUNET_PACKED;

  /**
   * The private key
   */
  struct GNUNET_CRYPTO_EcdsaPrivateKey private_key;

  /* followed by 0-terminated ego name */

};



/**
 * Client requests knowledge about default identity for
 * a subsystem from identity service.
 */
struct GNUNET_IDENTITY_GetDefaultMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_IDENTITY_GET_DEFAULT
   */
  struct GNUNET_MessageHeader header;

  /**
   * Number of bytes in service name string including 0-termination, in NBO.
   */
  uint16_t name_len GNUNET_PACKED;

  /**
   * Always zero.
   */
  uint16_t reserved GNUNET_PACKED;


  /* followed by 0-terminated service name */

};


/**
 * Used from service to client as a result to the GET_DEFAULT
 * message, used from client to service to SET_DEFAULT.
 */
struct GNUNET_IDENTITY_SetDefaultMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_IDENTITY_SET_DEFAULT
   */
  struct GNUNET_MessageHeader header;

  /**
   * Number of bytes in service name string including 0-termination, in NBO.
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

  /* followed by 0-terminated service name */

};


/**
 * Client requests creation of an identity.  Service
 * will respond with a result code.
 */
struct GNUNET_IDENTITY_CreateRequestMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_IDENTITY_CREATE
   */
  struct GNUNET_MessageHeader header;

  /**
   * Number of bytes in identity name string including 0-termination, in NBO.
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
 * Client requests renaming of an identity.  Service
 * will respond with a result code.
 */
struct GNUNET_IDENTITY_RenameMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_IDENTITY_RENAME
   */
  struct GNUNET_MessageHeader header;

  /**
   * Number of characters in the old name including 0-termination, in NBO.
   */
  uint16_t old_name_len GNUNET_PACKED;

  /**
   * Number of characters in the new name including 0-termination, in NBO.
   */
  uint16_t new_name_len GNUNET_PACKED;

  /* followed by 0-terminated old name */
  /* followed by 0-terminated new name */
};


/**
 * Client requests deletion of an identity.  Service
 * will respond with a result code.
 */
struct GNUNET_IDENTITY_DeleteMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_IDENTITY_DELETE
   */
  struct GNUNET_MessageHeader header;

  /**
   * Number of characters in the name including 0-termination, in NBO.
   */
  uint16_t name_len GNUNET_PACKED;

  /**
   * Always zero.
   */
  uint16_t reserved GNUNET_PACKED;

  /* followed by 0-terminated name */

};



GNUNET_NETWORK_STRUCT_END

#endif
