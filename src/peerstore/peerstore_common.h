/*
      This file is part of GNUnet
      (C)

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
      Free Software Foundation, Inc., 59 Temple Place - Suite 330,
      Boston, MA 02111-1307, USA.
 */

/**
 * @file peerstore/peerstore_common.h
 * @brief Helper peerstore functions
 * @author Omar Tarabai
 */

#include "peerstore.h"

/**
 * PEERSTORE single record
 */
struct GNUNET_PEERSTORE_Record
{

  /**
   * Responsible sub system string
   */
  char *sub_system;

  /**
   * Peer Identity
   */
  struct GNUNET_PeerIdentity *peer;

  /**
   * Record key string
   */
  char *key;

  /**
   * Record value BLOB
   */
  void *value;

  /**
   * Size of value BLOB
   */
  size_t value_size;

  /**
   * Expiry time of record
   */
  struct GNUNET_TIME_Absolute expiry;

};

/**
 * Creates a record message ready to be sent
 *
 * @param sub_system sub system string
 * @param peer Peer identity (can be NULL)
 * @param key record key string (can be NULL)
 * @param value record value BLOB (can be NULL)
 * @param value_size record value size in bytes (set to 0 if value is NULL)
 * @param expiry time after which the record expires
 * @param msg_type message type to be set in header
 * @return pointer to record message struct
 */
struct StoreRecordMessage *
PEERSTORE_create_record_message(const char *sub_system,
    const struct GNUNET_PeerIdentity *peer,
    const char *key,
    const void *value,
    size_t value_size,
    struct GNUNET_TIME_Absolute expiry,
    uint16_t msg_type);

/**
 * Parses a message carrying a record
 *
 * @param message the actual message
 * @return Pointer to record or NULL if error
 */
struct GNUNET_PEERSTORE_Record *
PEERSTORE_parse_record_message(const struct GNUNET_MessageHeader *message);
