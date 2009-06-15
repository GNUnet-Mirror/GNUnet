/*
     This file is part of GNUnet
     (C) 2004, 2005, 2006, 2007, 2009 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
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
 * @file datastore/datastore.hc
 * @brief structs for communication between datastore service and API
 * @author Christian Grothoff
 */

#ifndef DATASTORE_H
#define DATASTORE_H

#include "gnunet_util_lib.h"

/**
 * Message from datastore service informing client about
 * the current size of the datastore.
 */
struct SizeMessage
{
  /**
   * Type is GNUNET_MESSAGE_TYPE_DATASTORE_SIZE.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Always zero.
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * Size of the datastore in bytes.
   */
  uint64_t size GNUNET_PACKED;
};


/**
 * Message to the datastore service asking about specific
 * content.
 */
struct GetMessage
{
  /**
   * Type is GNUNET_MESSAGE_TYPE_DATASTORE_GET.  Size
   * can either be "sizeof(struct GetMessage)" or 
   * "sizeof(struct GetMessage) - sizeof(GNUNET_HashCode)"!
   */
  struct GNUNET_MessageHeader header;

  /**
   * Desired content type.
   */
  uint32_t type GNUNET_PACKED;

  /**
   * Desired key (optional).  Check the "size" of the
   * header to see if the key is actually present.
   */
  GNUNET_HashCode key GNUNET_PACKED;

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
   * Always zero.
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * Number of bytes in the item (NBO).
   */
  uint32_t size GNUNET_PACKED;

  /**
   * Type of the item (NBO), zero for remove.
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
   * Expiration time (NBO); zero for remove.
   */
  struct GNUNET_TIME_AbsoluteNBO expiration;

  /**
   * Key under which the item can be found.
   */
  GNUNET_HashCode key GNUNET_PACKED;

};




#endif
