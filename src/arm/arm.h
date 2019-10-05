/*
     This file is part of GNUnet.
     Copyright (C) 2009 GNUnet e.V.

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
 * @author Christian Grothoff
 * @file arm/arm.h
 */
#ifndef ARM_H
#define ARM_H

#include "gnunet_common.h"

/**
 * This option will turn on the DEBUG loglevel for
 * all processes controlled by this ARM!
 */
#define DEBUG_ARM GNUNET_EXTRA_LOGGING

GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Status update from ARM to client.
 */
struct GNUNET_ARM_StatusMessage
{
  /**
   * Reply to client, of type is #GNUNET_MESSAGE_TYPE_ARM_STATUS.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Status from the 'enum GNUNET_ARM_ServiceStatus'
   */
  uint32_t status;

  /* followed by a 0-terminated service name */
};

struct GNUNET_ARM_Message
{
  /**
   * Reply to client, type is #GNUNET_MESSAGE_TYPE_ARM_RESULT or
   * #GNUNET_MESSAGE_TYPE_ARM_LIST_RESULT.
   * OR
   * Request from client, type is #GNUNET_MESSAGE_TYPE_ARM_START or
   * #GNUNET_MESSAGE_TYPE_ARM_STOP.
   */
  struct GNUNET_MessageHeader header;

  /**
   * For alignment.
   */
  uint32_t reserved;

  /**
   * ID of a request that is being replied to.
   * OR
   * ID of a request that is being sent.
   */
  uint64_t request_id;

  /* For requests - followed by a 0-terminated service name */
};


/**
 * Reply from ARM to client.
 */
struct GNUNET_ARM_ResultMessage
{
  /**
   * Reply to client, of type is #GNUNET_MESSAGE_TYPE_ARM_RESULT, with an ID.
   */
  struct GNUNET_ARM_Message arm_msg;

  /**
   * Result from the `enum GNUNET_ARM_Result`
   */
  uint32_t result;
};

struct GNUNET_ARM_ServiceInfoMessage
{
  /**
   * String pool index for the service's name.
   */
  uint16_t name_index;

  /**
   * String pool index for the service's binary.
   */
  uint16_t binary_index;

  /**
   * Last process exit status.
   */
  int16_t last_exit_status;

  /**
   * Padding.
   */
  uint16_t padding;

  /**
   * Status from the 'enum GNUNET_ARM_ServiceStatus'
   */
  uint32_t status;

  /**
   * Time when the sevice will be restarted, if applicable
   * to the current status.
   */
  struct GNUNET_TIME_AbsoluteNBO restart_at;

  /**
   * Time when the sevice was first started, if applicable.
   */
  struct GNUNET_TIME_AbsoluteNBO last_started_at;
};

/**
 * Reply from ARM to client for the
 * #GNUNET_MESSAGE_TYPE_ARM_LIST request followed by count
 * '\0' terminated strings. header->size contains the
 * total size (including all strings).
 */
struct GNUNET_ARM_ListResultMessage
{
  /**
   * Reply to client, of type is #GNUNET_MESSAGE_TYPE_ARM_LIST_RESULT,
   * with an ID.
   */
  struct GNUNET_ARM_Message arm_msg;

  /**
   * Number of 'struct GNUNET_ARM_ServiceInfoMessage' that
   * are at the end of this message.
   */
  uint16_t count;

  /* struct GNUNET_ARM_ServiceInfoMessage[count]; */
  /* pool of 0-terminated strings */
};

GNUNET_NETWORK_STRUCT_END

#endif
