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

#include "platform.h"
#include "gnunet_psyc_service.h"


int
GNUNET_PSYC_check_message_parts (uint16_t data_size, const char *data,
                                 uint16_t *first_ptype, uint16_t *last_ptype);

void
GNUNET_PSYC_log_message (enum GNUNET_ErrorType kind,
                         const struct GNUNET_MessageHeader *msg);


enum MessageState
{
  MSG_STATE_START    = 0,
  MSG_STATE_HEADER   = 1,
  MSG_STATE_METHOD   = 2,
  MSG_STATE_MODIFIER = 3,
  MSG_STATE_MOD_CONT = 4,
  MSG_STATE_DATA     = 5,
  MSG_STATE_END      = 6,
  MSG_STATE_CANCEL   = 7,
  MSG_STATE_ERROR    = 8,
};


enum MessageFragmentState
{
  MSG_FRAG_STATE_START    = 0,
  MSG_FRAG_STATE_HEADER   = 1,
  MSG_FRAG_STATE_DATA     = 2,
  MSG_FRAG_STATE_END      = 3,
  MSG_FRAG_STATE_CANCEL   = 4,
  MSG_FRAG_STATE_DROP     = 5,
};


GNUNET_NETWORK_STRUCT_BEGIN


/**** library -> service ****/


struct MasterStartRequest
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_PSYC_MASTER_START
   */
  struct GNUNET_MessageHeader header;

  uint32_t policy GNUNET_PACKED;

  struct GNUNET_CRYPTO_EddsaPrivateKey channel_key;
};


struct SlaveJoinRequest
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_PSYC_SLAVE_JOIN
   */
  struct GNUNET_MessageHeader header;

  uint32_t relay_count GNUNET_PACKED;

  struct GNUNET_CRYPTO_EddsaPublicKey channel_key;

  struct GNUNET_CRYPTO_EcdsaPrivateKey slave_key;

  struct GNUNET_PeerIdentity origin;

  /* Followed by struct GNUNET_PeerIdentity relays[relay_count] */

  /* Followed by struct GNUNET_MessageHeader join_msg */
};


struct ChannelSlaveAddRequest
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_PSYC_CHANNEL_SLAVE_ADD
   */
  struct GNUNET_MessageHeader header;

  uint32_t reserved;

  struct GNUNET_CRYPTO_EcdsaPublicKey *slave_key;

  uint64_t announced_at;

  uint64_t effective_since;
};


struct ChannelSlaveRemoveRequest
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_PSYC_CHANNEL_SLAVE_RM
   */
  struct GNUNET_MessageHeader header;

  uint32_t reserved;

  struct GNUNET_CRYPTO_EcdsaPublicKey *slave_key;

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


struct StateRequest
{
  /**
   * Types:
   * - GNUNET_MESSAGE_TYPE_PSYC_CHANNEL_STATE_GET
   * - GNUNET_MESSAGE_TYPE_PSYC_CHANNEL_STATE_GET_PREFIX
   */
  struct GNUNET_MessageHeader header;

  /**
   * ID for this operation.
   */
  uint64_t op_id;

  /* Followed by NUL-terminated name. */
};


/**** service -> library ****/


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

  /**
   * Last message ID sent to the channel.
   */
  uint64_t max_message_id;
};


/**
 * Answer from service to client about last operation.
 */
struct OperationResult
{
  /**
   * Types:
   * - GNUNET_MESSAGE_TYPE_PSYC_RESULT_CODE
   * - GNUNET_MESSAGE_TYPE_PSYC_CHANNEL_STORY_RESULT
   * - GNUNET_MESSAGE_TYPE_PSYC_CHANNEL_STATE_RESULT
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

  /* Followed by:
   * - on error: NUL-terminated error message
   * - on success: one of the following message types
   *
   *   For a STORY_RESULT:
   *   - GNUNET_MESSAGE_TYPE_PSYC_MESSAGE
   *
   *   For a STATE_RESULT, one of:
   *   - GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_MODIFIER
   *   - GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_MOD_CONT
   *   - GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_END
   */
};

GNUNET_NETWORK_STRUCT_END

#endif
