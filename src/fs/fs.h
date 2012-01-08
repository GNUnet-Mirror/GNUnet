/*
     This file is part of GNUnet.
     (C) 2003, 2004, 2005, 2006, 2007, 2008, 2009 Christian Grothoff (and other contributing authors)

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
 * @file fs/fs.h
 * @brief definitions for the entire fs module
 * @author Igor Wronsky, Christian Grothoff
 */
#ifndef FS_H
#define FS_H

#include "gnunet_constants.h"
#include "gnunet_datastore_service.h"
#include "gnunet_dht_service.h"
#include "gnunet_fs_service.h"
#include "gnunet_block_lib.h"
#include "block_fs.h"


/**
 * Size of the individual blocks used for file-sharing.
 */
#define DBLOCK_SIZE (32*1024)

/**
 * Blocksize to use when hashing files for indexing (blocksize for IO,
 * not for the DBlocks).  Larger blocksizes can be more efficient but
 * will be more disruptive as far as the scheduler is concerned.
 */
#define HASHING_BLOCKSIZE (1024 * 128)


/**
 * @brief content hash key
 */
struct ContentHashKey
{
  /**
   * Hash of the original content, used for encryption.
   */
  GNUNET_HashCode key;

  /**
   * Hash of the encrypted content, used for querying.
   */
  GNUNET_HashCode query;
};


GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Message sent from a GNUnet (fs) publishing activity to the
 * gnunet-fs-service to initiate indexing of a file.  The service is
 * supposed to check if the specified file is available and has the
 * same cryptographic hash.  It should then respond with either a
 * confirmation or a denial.
 *
 * On OSes where this works, it is considered acceptable if the
 * service only checks that the path, device and inode match (it can
 * then be assumed that the hash will also match without actually
 * computing it; this is an optimization that should be safe given
 * that the client is not our adversary).
 */
struct IndexStartMessage
{

  /**
   * Message type will be GNUNET_MESSAGE_TYPE_FS_INDEX_START.
   */
  struct GNUNET_MessageHeader header;

  /**
   * For alignment.
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * ID of device containing the file, as seen by the client.  This
   * device ID is obtained using a call like "statvfs" (and converting
   * the "f_fsid" field to a 32-bit big-endian number).  Use 0 if the
   * OS does not support this, in which case the service must do a
   * full hash recomputation.
   */
  uint64_t device GNUNET_PACKED;

  /**
   * Inode of the file on the given device, as seen by the client
   * ("st_ino" field from "struct stat").  Use 0 if the OS does not
   * support this, in which case the service must do a full hash
   * recomputation.
   */
  uint64_t inode GNUNET_PACKED;

  /**
   * Hash of the file that we would like to index.
   */
  GNUNET_HashCode file_id;

  /* this is followed by a 0-terminated
   * filename of a file with the hash
   * "file_id" as seen by the client */

};


/**
 * Message send by FS service in response to a request
 * asking for a list of all indexed files.
 */
struct IndexInfoMessage
{
  /**
   * Message type will be
   * GNUNET_MESSAGE_TYPE_FS_INDEX_LIST_ENTRY.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Always zero.
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * Hash of the indexed file.
   */
  GNUNET_HashCode file_id;

  /* this is followed by a 0-terminated
   * filename of a file with the hash
   * "file_id" as seen by the client */

};


/**
 * Message sent from a GNUnet (fs) unindexing activity to the
 * gnunet-service-fs to indicate that a file will be unindexed.  The
 * service is supposed to remove the file from the list of indexed
 * files and response with a confirmation message (even if the file
 * was already not on the list).
 */
struct UnindexMessage
{

  /**
   * Message type will be
   * GNUNET_MESSAGE_TYPE_FS_UNINDEX.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Always zero.
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * Hash of the file that we will unindex.
   */
  GNUNET_HashCode file_id;

};


/**
 * No options.
 */
#define SEARCH_MESSAGE_OPTION_NONE 0

/**
 * Only search the local datastore (no network)
 */
#define SEARCH_MESSAGE_OPTION_LOOPBACK_ONLY 1

/**
 * Request is too large to fit in 64k format.  The list of
 * already-known search results will be continued in another message
 * for the same type/query/target and additional already-known results
 * following this one).
 */
#define SEARCH_MESSAGE_OPTION_CONTINUED 2


/**
 * Message sent from a GNUnet (fs) search activity to the
 * gnunet-service-fs to start a search.
 */
struct SearchMessage
{

  /**
   * Message type will be
   * GNUNET_MESSAGE_TYPE_FS_START_SEARCH.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Bitmask with options.  Zero for no options, one for
   * loopback-only, two for 'to be continued' (with a second search
   * message for the same type/query/target and additional
   * already-known results following this one).  See
   * SEARCH_MESSAGE_OPTION_ defines.
   *
   * Other bits are currently not defined.
   */
  uint32_t options GNUNET_PACKED;

  /**
   * Type of the content that we're looking for.
   */
  uint32_t type GNUNET_PACKED;

  /**
   * Desired anonymity level, big-endian.
   */
  uint32_t anonymity_level GNUNET_PACKED;

  /**
   * If the request is for a DBLOCK or IBLOCK, this is the identity of
   * the peer that is known to have a response.  Set to all-zeros if
   * such a target is not known (note that even if OUR anonymity
   * level is >0 we may happen to know the responder's identity;
   * nevertheless, we should probably not use it for a DHT-lookup
   * or similar blunt actions in order to avoid exposing ourselves).
   * <p>
   * If the request is for an SBLOCK, this is the identity of the
   * pseudonym to which the SBLOCK belongs.
   * <p>
   * If the request is for a KBLOCK, "target" must be all zeros.
   */
  GNUNET_HashCode target;

  /**
   * Hash of the keyword (aka query) for KBLOCKs; Hash of
   * the CHK-encoded block for DBLOCKS and IBLOCKS (aka query)
   * and hash of the identifier XORed with the target for
   * SBLOCKS (aka query).
   */
  GNUNET_HashCode query;

  /* this is followed by the hash codes of already-known
   * results (which should hence be excluded from what
   * the service returns); naturally, this only applies
   * to queries that can have multiple results, such as
   * those for KBLOCKS (KSK) and SBLOCKS (SKS) */
};


/**
 * Response from FS service with a result for a previous FS search.
 * Note that queries for DBLOCKS and IBLOCKS that have received a
 * single response are considered done.  This message is transmitted
 * between peers.
 */
struct PutMessage
{

  /**
   * Message type will be GNUNET_MESSAGE_TYPE_FS_PUT.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Type of the block (in big endian).  Should never be zero.
   */
  uint32_t type GNUNET_PACKED;

  /**
   * When does this result expire?
   */
  struct GNUNET_TIME_AbsoluteNBO expiration;

  /* this is followed by the actual encrypted content */

};

/**
 * Response from FS service with a result for a previous FS search.
 * Note that queries for DBLOCKS and IBLOCKS that have received a
 * single response are considered done.  This message is transmitted
 * between the service and a client.
 */
struct ClientPutMessage
{

  /**
   * Message type will be GNUNET_MESSAGE_TYPE_FS_PUT.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Type of the block (in big endian).  Should never be zero.
   */
  uint32_t type GNUNET_PACKED;

  /**
   * When does this result expire?
   */
  struct GNUNET_TIME_AbsoluteNBO expiration;

  /**
   * When was the last time we've tried to download this block?
   * (FOREVER if unknown/not relevant)
   */
  struct GNUNET_TIME_AbsoluteNBO last_transmission;

  /* this is followed by the actual encrypted content */

};
GNUNET_NETWORK_STRUCT_END


#endif

/* end of fs.h */
