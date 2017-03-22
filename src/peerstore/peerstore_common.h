/*
      This file is part of GNUnet
      Copyright (C) 2013-2016 GNUnet e.V.

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
 * @file peerstore/peerstore_common.h
 * @brief Helper peerstore functions
 * @author Omar Tarabai
 */
#include "platform.h"
#include "peerstore.h"

/**
 * Creates a hash of the given key combination
 *
 */
void
PEERSTORE_hash_key (const char *sub_system,
                    const struct GNUNET_PeerIdentity *peer,
                    const char *key,
                    struct GNUNET_HashCode *ret);


/**
 * Creates a MQ envelope for a single record
 *
 * @param sub_system sub system string
 * @param peer Peer identity (can be NULL)
 * @param key record key string (can be NULL)
 * @param value record value BLOB (can be NULL)
 * @param value_size record value size in bytes (set to 0 if value is NULL)
 * @param expiry time after which the record expires
 * @param options options specific to the storage operation
 * @param msg_type message type to be set in header
 * @return pointer to record message struct
 */
struct GNUNET_MQ_Envelope *
PEERSTORE_create_record_mq_envelope (const char *sub_system,
                                     const struct GNUNET_PeerIdentity *peer,
                                     const char *key,
                                     const void *value,
                                     size_t value_size,
                                     struct GNUNET_TIME_Absolute expiry,
                                     enum GNUNET_PEERSTORE_StoreOption options,
                                     uint16_t msg_type);


/**
 * Parses a message carrying a record
 *
 * @param srm the actual message
 * @return Pointer to record or NULL on error
 */
struct GNUNET_PEERSTORE_Record *
PEERSTORE_parse_record_message (const struct StoreRecordMessage *srm);


/**
 * Free any memory allocated for this record
 *
 * @param record
 */
void
PEERSTORE_destroy_record (struct GNUNET_PEERSTORE_Record *record);

/* end of peerstore_common.h */
