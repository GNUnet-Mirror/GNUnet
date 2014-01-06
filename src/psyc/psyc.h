/*
 * This file is part of GNUnet
 * (C) 2013 Christian Grothoff (and other contributing authors)
 *
 * GNUnet is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 3, or (at your
 * option) any later version.
 *
 * GNUnet is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNUnet; see the file COPYING.  If not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

/**
 * @file psyc/psyc.h
 * @brief Common type definitions for the PSYC service and API.
 * @author Gabor X Toth
 */

#ifndef PSYC_H
#define PSYC_H

#include "gnunet_common.h"


enum MessageState
{
  MSG_STATE_START = 0,
  MSG_STATE_HEADER = 1,
  MSG_STATE_METHOD = 2,
  MSG_STATE_MODIFIER = 3,
  MSG_STATE_MOD_CONT = 4,
  MSG_STATE_DATA = 5,
  MSG_STATE_END = 6,
  MSG_STATE_CANCEL = 7,
};


GNUNET_NETWORK_STRUCT_BEGIN

/**** service -> library ****/

/**
 * Answer from service to client about last operation.
 */
struct OperationResult
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_PSYCSTORE_RESULT_CODE
   */
  struct GNUNET_MessageHeader header;

  /**
   * Operation ID.
   */
  uint32_t op_id GNUNET_PACKED;

  /**
   * Status code for the operation.
   */
  int64_t result_code GNUNET_PACKED;

  /* followed by NUL-terminated error message (on error) */
};


struct CountersResult
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_PSYC_RESULT_COUNTERS
   */
  struct GNUNET_MessageHeader header;

  /**
   * Status code for the operation.
   */
  int32_t result_code GNUNET_PACKED;

  uint64_t max_message_id;
};


#if REMOVE
/**
 * Transmit acknowledgment.
 *
 * Sent after the last GNUNET_PSYC_MessageModifier and after each
 * GNUNET_PSYC_MessageData.
 *
 * This message acknowledges previously received messages and asks for the next
 * fragment of data.
 */
struct TransmitAck
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_PSYC_TRANSMIT_ACK
   */
  struct GNUNET_MessageHeader header;

  /**
   * Buffer space available for the next data fragment.
   */
  uint16_t buf_avail;
};
#endif


/**** library -> service ****/


struct MasterStartRequest
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_PSYC_MASTER_START
   */
  struct GNUNET_MessageHeader header;

  struct GNUNET_CRYPTO_EddsaPrivateKey channel_key;

  uint32_t policy GNUNET_PACKED;
};


struct SlaveJoinRequest
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_PSYC_SLAVE_JOIN
   */
  struct GNUNET_MessageHeader header;

  uint32_t relay_count GNUNET_PACKED;

  struct GNUNET_CRYPTO_EddsaPublicKey channel_key;

  struct GNUNET_CRYPTO_EddsaPrivateKey slave_key;

  struct GNUNET_PeerIdentity origin;

  /* Followed by struct GNUNET_PeerIdentity relays[relay_count] */
};


struct ChannelSlaveAdd
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_PSYC_CHANNEL_SLAVE_ADD
   */
  struct GNUNET_MessageHeader header;

  uint32_t reserved;

  struct GNUNET_CRYPTO_EddsaPublicKey *slave_key;

  uint64_t announced_at;

  uint64_t effective_since;
};


struct ChannelSlaveRemove
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_PSYC_CHANNEL_SLAVE_RM
   */
  struct GNUNET_MessageHeader header;

  uint32_t reserved;

  struct GNUNET_CRYPTO_EddsaPublicKey *slave_key;

  uint64_t announced_at;
};


struct StoryRequest
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_PSYC_CHANNEL_STORY_REQUEST
   */
  struct GNUNET_MessageHeader header;

  uint64_t op_id;

  uint64_t start_message_id;

  uint64_t end_message_id;
};


struct StateQuery
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_PSYC_CHANNEL_STATE_QUERY
   */
  struct GNUNET_MessageHeader header;

  uint64_t op_id;

  /* Followed by NUL-terminated name. */
};


struct StateResult
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_PSYC_CHANNEL_STATE_RESULT
   */
  struct GNUNET_MessageHeader header;

  /**
   * Size of name, including NUL terminator.
   */
  uint16_t name_size GNUNET_PACKED;

  /**
   * OR'd StateOpFlags
   */
  uint8_t flags;

  /* Followed by NUL-terminated name, then the value. */
};


GNUNET_NETWORK_STRUCT_END

#endif
