/*
     This file is part of GNUnet.
     Copyright (C) 2012 Christian Grothoff (and other contributing authors)

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
 * @param data_size number of bytes in 'data', 0 on error
 * @param data reply block data, NULL on error
 */
typedef void (*GSF_CadetReplyProcessor)(void *cls,
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
 * @param proc_cls closure for 'proc'
 * @return handle to cancel the operation
 */
struct GSF_CadetRequest *
GSF_cadet_query (const struct GNUNET_PeerIdentity *target,
		  const struct GNUNET_HashCode *query,
		  enum GNUNET_BLOCK_Type type,
		  GSF_CadetReplyProcessor proc, void *proc_cls);


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
 * Initialize subsystem for non-anonymous file-sharing.
 */
void
GSF_cadet_start_client (void);


/**
 * Shutdown subsystem for non-anonymous file-sharing.
 */
void
GSF_cadet_stop_client (void);


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
