/*
      This file is part of GNUnet
      Copyright (C) 2012-2013 GNUnet e.V.

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
 * @file peerstore/peerstore_common.c
 * @brief Helper peerstore functions
 * @author Omar Tarabai
 */

#include "peerstore_common.h"

/**
 * Creates a hash of the given key combination
 *
 */
void
PEERSTORE_hash_key (const char *sub_system,
                    const struct GNUNET_PeerIdentity *peer,
                    const char *key,
                    struct GNUNET_HashCode *ret)
{
  size_t sssize;
  size_t psize;
  size_t ksize;
  size_t totalsize;
  void *block;
  void *blockptr;

  sssize = strlen (sub_system) + 1;
  psize = sizeof (struct GNUNET_PeerIdentity);
  ksize = strlen (key) + 1;
  totalsize = sssize + psize + ksize;
  block = GNUNET_malloc (totalsize);
  blockptr = block;
  GNUNET_memcpy (blockptr, sub_system, sssize);
  blockptr += sssize;
  GNUNET_memcpy (blockptr, peer, psize);
  blockptr += psize;
  GNUNET_memcpy (blockptr, key, ksize);
  GNUNET_CRYPTO_hash (block, totalsize, ret);
  GNUNET_free (block);
}


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
                                     uint16_t msg_type)
{
  struct StoreRecordMessage *srm;
  struct GNUNET_MQ_Envelope *ev;
  size_t ss_size;
  size_t key_size;
  size_t msg_size;
  void *dummy;

  GNUNET_assert (NULL != sub_system);
  ss_size = strlen (sub_system) + 1;
  if (NULL == key)
    key_size = 0;
  else
    key_size = strlen (key) + 1;
  msg_size = ss_size + key_size + value_size;
  ev = GNUNET_MQ_msg_extra (srm, msg_size, msg_type);
  srm->key_size = htons (key_size);
  srm->expiry = GNUNET_TIME_absolute_hton (expiry);
  if (NULL == peer)
    srm->peer_set = htons (GNUNET_NO);
  else
  {
    srm->peer_set = htons (GNUNET_YES);
    srm->peer = *peer;
  }
  srm->sub_system_size = htons (ss_size);
  srm->value_size = htons (value_size);
  srm->options = htonl (options);
  dummy = &srm[1];
  GNUNET_memcpy (dummy, sub_system, ss_size);
  dummy += ss_size;
  GNUNET_memcpy (dummy, key, key_size);
  dummy += key_size;
  GNUNET_memcpy (dummy, value, value_size);
  return ev;
}


/**
 * Parses a message carrying a record
 *
 * @param srm the actual message
 * @return Pointer to record or NULL if error
 */
struct GNUNET_PEERSTORE_Record *
PEERSTORE_parse_record_message (const struct StoreRecordMessage *srm)
{
  struct GNUNET_PEERSTORE_Record *record;
  uint16_t req_size;
  uint16_t ss_size;
  uint16_t key_size;
  uint16_t value_size;
  char *dummy;

  req_size = ntohs (srm->header.size) - sizeof (*srm);
  ss_size = ntohs (srm->sub_system_size);
  key_size = ntohs (srm->key_size);
  value_size = ntohs (srm->value_size);
  if (ss_size + key_size + value_size != req_size)
  {
    GNUNET_break (0);
    return NULL;
  }
  record = GNUNET_new (struct GNUNET_PEERSTORE_Record);
  if (GNUNET_YES == ntohs (srm->peer_set))
  {
    record->peer = srm->peer;
  }
  record->expiry = GNUNET_TIME_absolute_ntoh (srm->expiry);
  dummy = (char *) &srm[1];
  if (ss_size > 0)
  {
    record->sub_system = GNUNET_strdup (dummy);
    dummy += ss_size;
  }
  if (key_size > 0)
  {
    record->key = GNUNET_strdup (dummy);
    dummy += key_size;
  }
  if (value_size > 0)
  {
    record->value = GNUNET_malloc (value_size);
    GNUNET_memcpy (record->value,
                   dummy,
                   value_size);
  }
  record->value_size = value_size;
  return record;
}


/**
 * Free any memory allocated for this record
 *
 * @param record
 */
void
PEERSTORE_destroy_record (struct GNUNET_PEERSTORE_Record *record)
{
  if (NULL != record->sub_system)
    GNUNET_free (record->sub_system);
  if (NULL != record->key)
    GNUNET_free (record->key);
  if (NULL != record->value)
  {
    GNUNET_free (record->value);
    record->value = 0;
  }
  GNUNET_free (record);
}
