/*
 * This file is part of GNUnet
 * Copyright (C) 2013 Christian Grothoff (and other contributing authors)
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
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

/**
 * @file psycstore/psycstore.h
 * @brief Common type definitions for the PSYCstore service and API.
 * @author Gabor X Toth
 */

#ifndef GNUNET_PSYCSTORE_H
#define GNUNET_PSYCSTORE_H

#include "gnunet_common.h"


GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Answer from service to client about last operation.
 */
struct OperationResult
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_PSYCSTORE_RESULT_CODE
   */
  struct GNUNET_MessageHeader header;

  uint32_t reserved GNUNET_PACKED;

  /**
   * Operation ID.
   */
  uint64_t op_id GNUNET_PACKED;

  /**
   * Status code for the operation.
   */
  uint64_t result_code GNUNET_PACKED;

  /* followed by 0-terminated error message (on error) */

};


/**
 * Answer from service to client about master counters.
 *
 * @see GNUNET_PSYCSTORE_counters_get()
 */
struct CountersResult
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_PSYCSTORE_RESULT_COUNTERS
   */
  struct GNUNET_MessageHeader header;

  /**
   * Status code for the operation:
   * #GNUNET_OK: success, counter values are returned.
   * #GNUNET_NO: no message has been sent to the channel yet.
   * #GNUNET_SYSERR: an error occurred.
   */
  uint32_t result_code GNUNET_PACKED;

  /**
   * Operation ID.
   */
  uint64_t op_id GNUNET_PACKED;

  uint64_t max_fragment_id GNUNET_PACKED;

  uint64_t max_message_id GNUNET_PACKED;

  uint64_t max_group_generation GNUNET_PACKED;

  uint64_t max_state_message_id GNUNET_PACKED;
};


/**
 * Answer from service to client containing a message fragment.
 */
struct FragmentResult
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_PSYCSTORE_RESULT_CODE
   */
  struct GNUNET_MessageHeader header;

  uint32_t psycstore_flags GNUNET_PACKED;

  /**
   * Operation ID.
   */
  uint64_t op_id GNUNET_PACKED;

  /* Followed by GNUNET_MULTICAST_MessageHeader */
};


/**
 * Answer from service to client containing a state variable.
 */
struct StateResult
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_PSYCSTORE_RESULT_CODE
   */
  struct GNUNET_MessageHeader header;

  uint16_t name_size GNUNET_PACKED;

  uint16_t reserved GNUNET_PACKED;

  /**
   * Operation ID.
   */
  uint64_t op_id GNUNET_PACKED;

  /* Followed by name and value */
};


/**
 * Generic operation request.
 */
struct OperationRequest
{
  struct GNUNET_MessageHeader header;

  uint32_t reserved GNUNET_PACKED;

  /**
   * Operation ID.
   */
  uint64_t op_id GNUNET_PACKED;

  struct GNUNET_CRYPTO_EddsaPublicKey channel_key;
};


/**
 * @see GNUNET_PSYCSTORE_membership_store()
 */
struct MembershipStoreRequest
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_PSYCSTORE_MEMBERSHIP_STORE
   */
  struct GNUNET_MessageHeader header;

  uint32_t reserved GNUNET_PACKED;

  /**
   * Operation ID.
   */
  uint64_t op_id GNUNET_PACKED;

  /**
   * Channel's public key.
   */
  struct GNUNET_CRYPTO_EddsaPublicKey channel_key;

  /**
   * Slave's public key.
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey slave_key;

  uint64_t announced_at GNUNET_PACKED;
  uint64_t effective_since GNUNET_PACKED;
  uint64_t group_generation GNUNET_PACKED;
  uint8_t did_join;
};


/**
 * @see GNUNET_PSYCSTORE_membership_test()
 */
struct MembershipTestRequest
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_PSYCSTORE_MEMBERSHIP_TEST
   */
  struct GNUNET_MessageHeader header;

  uint32_t reserved GNUNET_PACKED;

  /**
   * Operation ID.
   */
  uint64_t op_id GNUNET_PACKED;

  /**
   * Channel's public key.
   */
  struct GNUNET_CRYPTO_EddsaPublicKey channel_key;

  /**
   * Slave's public key.
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey slave_key;

  uint64_t message_id GNUNET_PACKED;

  uint64_t group_generation GNUNET_PACKED;
};


/**
 * @see GNUNET_PSYCSTORE_fragment_store()
 */
struct FragmentStoreRequest
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_PSYCSTORE_FRAGMENT_STORE
   */
  struct GNUNET_MessageHeader header;

  /**
   * enum GNUNET_PSYCSTORE_MessageFlags
   */
  uint32_t psycstore_flags GNUNET_PACKED;

  /**
   * Channel's public key.
   */
  struct GNUNET_CRYPTO_EddsaPublicKey channel_key;

  /**
   * Operation ID.
   */
  uint64_t op_id;

  /* Followed by fragment */
};


/**
 * @see GNUNET_PSYCSTORE_fragment_get()
 */
struct FragmentGetRequest
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_PSYCSTORE_FRAGMENT_GET
   */
  struct GNUNET_MessageHeader header;

  uint32_t reserved GNUNET_PACKED;

  /**
   * Operation ID.
   */
  uint64_t op_id GNUNET_PACKED;

  /**
   * Channel's public key.
   */
  struct GNUNET_CRYPTO_EddsaPublicKey channel_key;

  /**
   * Slave's public key.
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey slave_key;

  /**
   * First fragment ID to request.
   */
  uint64_t first_fragment_id GNUNET_PACKED;

  /**
   * Last fragment ID to request.
   */
  uint64_t last_fragment_id GNUNET_PACKED;

  /**
   * Maximum number of fragments to retrieve.
   */
  uint64_t fragment_limit GNUNET_PACKED;

  /**
   * Do membership test with @a slave_key before returning fragment?
   * #GNUNET_YES or #GNUNET_NO
   */
  uint8_t do_membership_test;
};


/**
 * @see GNUNET_PSYCSTORE_message_get()
 */
struct MessageGetRequest
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_PSYCSTORE_MESSAGE_GET
   */
  struct GNUNET_MessageHeader header;

  uint32_t reserved GNUNET_PACKED;

  /**
   * Operation ID.
   */
  uint64_t op_id GNUNET_PACKED;

  /**
   * Channel's public key.
   */
  struct GNUNET_CRYPTO_EddsaPublicKey channel_key;

  /**
   * Slave's public key.
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey slave_key;

  /**
   * First message ID to request.
   */
  uint64_t first_message_id GNUNET_PACKED;

  /**
   * Last message ID to request.
   */
  uint64_t last_message_id GNUNET_PACKED;

  /**
   * Maximum number of messages to retrieve.
   */
  uint64_t message_limit GNUNET_PACKED;

  /**
   * Do membership test with @a slave_key before returning fragment?
   * #GNUNET_YES or #GNUNET_NO
   */
  uint8_t do_membership_test;
};


/**
 * @see GNUNET_PSYCSTORE_message_get_fragment()
 */
struct MessageGetFragmentRequest
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_PSYCSTORE_MESSAGE_FRAGMENT_GET
   */
  struct GNUNET_MessageHeader header;

  uint32_t reserved GNUNET_PACKED;

  /**
   * Operation ID.
   */
  uint64_t op_id GNUNET_PACKED;

  /**
   * Channel's public key.
   */
  struct GNUNET_CRYPTO_EddsaPublicKey channel_key;

  /**
   * Slave's public key.
   */
  struct GNUNET_CRYPTO_EcdsaPublicKey slave_key;

  /**
   * Requested message ID.
   */
  uint64_t message_id GNUNET_PACKED;

  /**
   * Requested fragment offset.
   */
  uint64_t fragment_offset GNUNET_PACKED;

  /**
   * Do membership test with @a slave_key before returning fragment?
   * #GNUNET_YES or #GNUNET_NO
   */
  uint8_t do_membership_test;
};


/**
 * @see GNUNET_PSYCSTORE_state_hash_update()
 */
struct StateHashUpdateRequest
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_PSYCSTORE_STATE_HASH_UPDATE
   */
  struct GNUNET_MessageHeader header;

  uint32_t reserved GNUNET_PACKED;

  /**
   * Operation ID.
   */
  uint64_t op_id GNUNET_PACKED;

  /**
   * Channel's public key.
   */
  struct GNUNET_CRYPTO_EddsaPublicKey channel_key;

  struct GNUNET_HashCode hash;
};


enum StateOpFlags
{
  STATE_OP_FIRST = 1 << 0,
  STATE_OP_LAST = 1 << 1
};


/**
 * @see GNUNET_PSYCSTORE_state_modify()
 */
struct StateModifyRequest
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_PSYCSTORE_STATE_MODIFY
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

  /**
   * enum GNUNET_ENV_Operator
   */
  uint8_t oper;

  /**
   * Operation ID.
   */
  uint64_t op_id GNUNET_PACKED;

  /**
   * Channel's public key.
   */
  struct GNUNET_CRYPTO_EddsaPublicKey channel_key;

  uint64_t message_id GNUNET_PACKED;

  uint64_t state_delta GNUNET_PACKED;

  /* Followed by NUL-terminated name, then the value. */
};


/**
 * @see GNUNET_PSYCSTORE_state_sync()
 */
struct StateSyncRequest
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_PSYCSTORE_STATE_SYNC
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

  uint8_t reserved;

  uint64_t message_id GNUNET_PACKED;

  /**
   * Operation ID.
   */
  uint64_t op_id GNUNET_PACKED;

  /**
   * Channel's public key.
   */
  struct GNUNET_CRYPTO_EddsaPublicKey channel_key;

  /* Followed by NUL-terminated name, then the value. */
};


GNUNET_NETWORK_STRUCT_END

#endif
