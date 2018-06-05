/*
     This file is part of GNUnet.
     Copyright (C) 2012, 2017 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.
*/

/**
 * @file fs/gnunet-service-fs_cadet.h
 * @brief non-anonymous file-transfer
 * @author Christian Grothoff
 */
#ifndef GNUNET_SERVICE_FS_CADET_H
#define GNUNET_SERVICE_FS_CADET_H

/**
 * Handle for a request that is going out via cadet API.
 */
struct GSF_CadetRequest;


/**
 * Function called with a reply from the cadet.
 *
 * @param cls closure
 * @param type type of the block, ANY on error
 * @param expiration expiration time for the block
 * @param data_size number of bytes in @a data, 0 on error
 * @param data reply block data, NULL on error
 */
typedef void
(*GSF_CadetReplyProcessor)(void *cls,
                           enum GNUNET_BLOCK_Type type,
                           struct GNUNET_TIME_Absolute expiration,
                           size_t data_size,
                           const void *data);


/**
 * Look for a block by directly contacting a particular peer.
 *
 * @param target peer that should have the block
 * @param query hash to query for the block
 * @param type desired type for the block
 * @param proc function to call with result
 * @param proc_cls closure for @a proc
 * @return handle to cancel the operation
 */
struct GSF_CadetRequest *
GSF_cadet_query (const struct GNUNET_PeerIdentity *target,
                 const struct GNUNET_HashCode *query,
                 enum GNUNET_BLOCK_Type type,
                 GSF_CadetReplyProcessor proc,
                 void *proc_cls);

/**
 * Function called on each active cadets to shut them down.
 *
 * @param cls NULL
 * @param key target peer, unused
 * @param value the `struct CadetHandle` to destroy
 * @return #GNUNET_YES (continue to iterate)
 */
int
GSF_cadet_release_clients (void *cls,
                           const struct GNUNET_PeerIdentity *key,
                           void *value);


/**
 * Cancel an active request; must not be called after 'proc'
 * was calld.
 *
 * @param sr request to cancel
 */
void
GSF_cadet_query_cancel (struct GSF_CadetRequest *sr);


/**
 * Initialize subsystem for non-anonymous file-sharing.
 */
void
GSF_cadet_start_server (void);


/**
 * Shutdown subsystem for non-anonymous file-sharing.
 */
void
GSF_cadet_stop_server (void);

/**
 * Cadet channel for creating outbound channels.
 */
extern struct GNUNET_CADET_Handle *cadet_handle;

/**
 * Map from peer identities to 'struct CadetHandles' with cadet
 * channels to those peers.
 */
extern struct GNUNET_CONTAINER_MultiPeerMap *cadet_map;


GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Query from one peer, asking the other for CHK-data.
 */
struct CadetQueryMessage
{

  /**
   * Type is GNUNET_MESSAGE_TYPE_FS_CADET_QUERY.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Block type must be DBLOCK or IBLOCK.
   */
  uint32_t type GNUNET_PACKED;

  /**
   * Query hash from CHK (hash of encrypted block).
   */
  struct GNUNET_HashCode query;

};


/**
 * Reply to a CadetQueryMessage.
 */
struct CadetReplyMessage
{

  /**
   * Type is GNUNET_MESSAGE_TYPE_FS_CADET_REPLY.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Block type must be DBLOCK or IBLOCK.
   */
  uint32_t type GNUNET_PACKED;

  /**
   * Expiration time for the block.
   */
  struct GNUNET_TIME_AbsoluteNBO expiration;

  /* followed by the encrypted block */

};

GNUNET_NETWORK_STRUCT_END


#endif
