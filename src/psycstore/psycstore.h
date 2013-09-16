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
 * @file psycstore/psycstore.h
 * @brief Common type definitions for the PSYCstore service and API.
 * @author Gabor X Toth
 */

#ifndef PSYCSTORE_H
#define PSYCSTORE_H

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

  /**
   * Status code for the operation.
   */
  int64_t result_code GNUNET_PACKED;

  uint32_t op_id GNUNET_PACKED;

  /* followed by 0-terminated error message (on error) */

};


/**
 * Answer from service to client about master counters.
 *
 * @see GNUNET_PSYCSTORE_counters_get_master()
 */
struct MasterCountersResult
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_PSYCSTORE_RESULT_COUNTERS_MASTER
   */
  struct GNUNET_MessageHeader header;

  uint64_t fragment_id GNUNET_PACKED;

  uint64_t message_id GNUNET_PACKED;

  uint64_t group_generation GNUNET_PACKED;

  /**
   * Status code for the operation.
   */
  int64_t result_code GNUNET_PACKED;

  uint32_t op_id GNUNET_PACKED;

};


/**
 * Answer from service to client about slave counters.
 *
 * @see GNUNET_PSYCSTORE_counters_get_slave()
 */
struct SlaveCountersResult
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_PSYCSTORE_RESULT_COUNTERS_SLAVE
   */
  struct GNUNET_MessageHeader header;

  uint64_t max_known_msg_id GNUNET_PACKED;

  /**
   * Status code for the operation.
   */
  int64_t result_code GNUNET_PACKED;

  uint32_t op_id GNUNET_PACKED;

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

  uint32_t op_id GNUNET_PACKED;

  uint32_t psycstore_flags GNUNET_PACKED;

  /* followed by GNUNET_MULTICAST_MessageHeader */

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

  uint32_t op_id GNUNET_PACKED;

  uint16_t name_size  GNUNET_PACKED;

  /* followed by name and value */
};


/**
 * Generic operation request.
 */
struct OperationRequest
{
  struct GNUNET_MessageHeader header;

  struct GNUNET_CRYPTO_EccPublicSignKey channel_key;

  uint32_t op_id GNUNET_PACKED;
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

  /**
   * Channel's public key.
   */
  struct GNUNET_CRYPTO_EccPublicSignKey channel_key;

  /**
   * Slave's public key.
   */
  struct GNUNET_CRYPTO_EccPublicSignKey slave_key;

  int did_join;
  uint64_t announced_at;
  uint64_t effective_since;
  uint64_t group_generation;

  uint32_t op_id GNUNET_PACKED;
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

  /**
   * Channel's public key.
   */
  struct GNUNET_CRYPTO_EccPublicSignKey channel_key;

  /**
   * Slave's public key.
   */
  struct GNUNET_CRYPTO_EccPublicSignKey slave_key;

  uint64_t message_id GNUNET_PACKED;

  uint64_t group_generation GNUNET_PACKED;

  uint32_t op_id GNUNET_PACKED;
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
   * Channel's public key.
   */
  struct GNUNET_CRYPTO_EccPublicSignKey channel_key;

  uint32_t psycstore_flags GNUNET_PACKED;

  uint32_t op_id GNUNET_PACKED;
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

  /**
   * Channel's public key.
   */
  struct GNUNET_CRYPTO_EccPublicSignKey channel_key;

  uint64_t fragment_id;

  uint32_t op_id GNUNET_PACKED;
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

  /**
   * Channel's public key.
   */
  struct GNUNET_CRYPTO_EccPublicSignKey channel_key;

  uint64_t message_id;

  uint32_t op_id GNUNET_PACKED;
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

  /**
   * Channel's public key.
   */
  struct GNUNET_CRYPTO_EccPublicSignKey channel_key;

  uint64_t message_id;

  uint64_t fragment_offset;

  uint32_t op_id GNUNET_PACKED;
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

  /**
   * Channel's public key.
   */
  struct GNUNET_CRYPTO_EccPublicSignKey channel_key;

  struct GNUNET_HashCode hash;

  uint32_t op_id GNUNET_PACKED;
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
   * Channel's public key.
   */
  struct GNUNET_CRYPTO_EccPublicSignKey channel_key;

  uint64_t message_id GNUNET_PACKED;

  uint64_t state_delta GNUNET_PACKED;

  uint32_t op_id GNUNET_PACKED;

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
   * Channel's public key.
   */
  struct GNUNET_CRYPTO_EccPublicSignKey channel_key;

  uint64_t message_id GNUNET_PACKED;

  uint32_t op_id GNUNET_PACKED;

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
