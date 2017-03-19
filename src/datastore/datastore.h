/*
     This file is part of GNUnet
     Copyright (C) 2004, 2005, 2006, 2007, 2009 GNUnet e.V.

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
 * @file datastore/datastore.h
 * @brief structs for communication between datastore service and API
 * @author Christian Grothoff
 */

#ifndef DATASTORE_H
#define DATASTORE_H


#include "gnunet_util_lib.h"

GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Message from datastore service informing client about
 * the current size of the datastore.
 */
struct ReserveMessage
{
  /**
   * Type is GNUNET_MESSAGE_TYPE_DATASTORE_RESERVE.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Number of items to reserve.
   */
  uint32_t entries GNUNET_PACKED;

  /**
   * Number of bytes to reserve.
   */
  uint64_t amount GNUNET_PACKED;
};


/**
 * Message from datastore service informing client about
 * the success or failure of a requested operation.
 * This header is optionally followed by a variable-size,
 * 0-terminated error message.
 */
struct StatusMessage
{
  /**
   * Type is GNUNET_MESSAGE_TYPE_DATASTORE_STATUS.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Status code, -1 for errors.
   */
  int32_t status GNUNET_PACKED;

  /**
   * Minimum expiration time required for content to be stored
   * by the datacache at this time, zero for unknown or no limit.
   */
  struct GNUNET_TIME_AbsoluteNBO min_expiration;

};


/**
 * Message from datastore client informing service that
 * the remainder of the reserved bytes can now be released
 * for other requests.
 */
struct ReleaseReserveMessage
{
  /**
   * Type is GNUNET_MESSAGE_TYPE_DATASTORE_RELEASE_RESERVE.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Reservation id.
   */
  int32_t rid GNUNET_PACKED;

};


/**
 * Message to the datastore service asking about specific
 * content.
 */
struct GetKeyMessage
{
  /**
   * Type is #GNUNET_MESSAGE_TYPE_DATASTORE_GET_KEY.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Desired content type.  (actually an enum GNUNET_BLOCK_Type)
   */
  uint32_t type GNUNET_PACKED;

  /**
   * UID at which to start the search
   */
  uint64_t next_uid GNUNET_PACKED;

  /**
   * If true return a random result
   */
  uint32_t random GNUNET_PACKED;

  /**
   * Desired key.
   */
  struct GNUNET_HashCode key;

};


/**
 * Message to the datastore service asking about specific
 * content.
 */
struct GetMessage
{
  /**
   * Type is #GNUNET_MESSAGE_TYPE_DATASTORE_GET.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Desired content type.  (actually an enum GNUNET_BLOCK_Type)
   */
  uint32_t type GNUNET_PACKED;

  /**
   * UID at which to start the search
   */
  uint64_t next_uid GNUNET_PACKED;

  /**
   * If true return a random result
   */
  uint32_t random GNUNET_PACKED;

};


/**
 * Message to the datastore service asking about zero
 * anonymity content.
 */
struct GetZeroAnonymityMessage
{
  /**
   * Type is GNUNET_MESSAGE_TYPE_DATASTORE_GET_ZERO_ANONYMITY.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Desired content type (actually an enum GNUNET_BLOCK_Type)
   */
  uint32_t type GNUNET_PACKED;

  /**
   * UID at which to start the search
   */
  uint64_t next_uid GNUNET_PACKED;

};


/**
 * Message transmitting content from or to the datastore
 * service.
 */
struct DataMessage
{
  /**
   * Type is either GNUNET_MESSAGE_TYPE_DATASTORE_PUT,
   * GNUNET_MESSAGE_TYPE_DATASTORE_REMOVE or
   * GNUNET_MESSAGE_TYPE_DATASTORE_DATA.  Depending on the message
   * type, some fields may simply have values of zero.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Reservation ID to use; use zero for none.
   */
  uint32_t rid GNUNET_PACKED;

  /**
   * Number of bytes in the item (NBO).
   */
  uint32_t size GNUNET_PACKED;

  /**
   * Type of the item (NBO), zero for remove,  (actually an enum GNUNET_BLOCK_Type)
   */
  uint32_t type GNUNET_PACKED;

  /**
   * Priority of the item (NBO), zero for remove.
   */
  uint32_t priority GNUNET_PACKED;

  /**
   * Desired anonymity level (NBO), zero for remove.
   */
  uint32_t anonymity GNUNET_PACKED;

  /**
   * Desired replication level. 0 from service to API.
   */
  uint32_t replication GNUNET_PACKED;

  /**
   * For alignment.
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * Unique ID for the content (can be used for UPDATE);
   * can be zero for remove (which indicates that
   * the datastore should use whatever UID matches
   * the key and content).
   */
  uint64_t uid;

  /**
   * Expiration time (NBO); zero for remove.
   */
  struct GNUNET_TIME_AbsoluteNBO expiration;

  /**
   * Key under which the item can be found.
   */
  struct GNUNET_HashCode key;

};
GNUNET_NETWORK_STRUCT_END



#endif
