/*
      This file is part of GNUnet
      (C) 2012-2013 Christian Grothoff (and other contributing authors)

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
 * @file peerstore/peerstore.h
 * @brief IPC messages
 * @author Omar Tarabai
 */

#ifndef PEERSTORE_H_
#define PEERSTORE_H_

#include "gnunet_peerstore_service.h"


GNUNET_NETWORK_STRUCT_BEGIN
/**
 * Message carrying a PEERSTORE record message
 */
    struct StoreRecordMessage
{

  /**
   * GNUnet message header
   */
  struct GNUNET_MessageHeader header;

  /**
   * #GNUNET_YES if peer id value set, #GNUNET_NO otherwise
   */
  uint16_t peer_set;

  /**
   * Peer Identity
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * Size of the sub_system string
   * Allocated at position 0 after this struct
   */
  size_t sub_system_size;

  /**
   * Size of the key string
   * Allocated at position 1 after this struct
   */
  size_t key_size;

  /**
   * Size of value blob
   * Allocated at position 2 after this struct
   */
  size_t value_size;

  /**
   * Expiry time of entry
   */
  struct GNUNET_TIME_Absolute expiry;

  /**
   * Options, needed only in case of a
   * store operation
   */
  enum GNUNET_PEERSTORE_StoreOption options;

};

/**
 * Message carrying record key hash
 */
struct StoreKeyHashMessage
{

  /**
   * GNUnet message header
   */
  struct GNUNET_MessageHeader header;

  /**
   * Hash of a record key
   */
  struct GNUNET_HashCode keyhash;

};

GNUNET_NETWORK_STRUCT_END
#endif
