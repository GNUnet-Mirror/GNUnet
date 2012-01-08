/*
     This file is part of GNUnet.
     (C) 2009, 2010, 2011 Christian Grothoff (and other contributing authors)

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
 * @file fs/gnunet-service-fs_pr.h
 * @brief API to handle pending requests
 * @author Christian Grothoff
 */
#ifndef GNUNET_SERVICE_FS_PR_H
#define GNUNET_SERVICE_FS_PR_H

#include "gnunet-service-fs.h"


/**
 * Options for pending requests (bits to be ORed).
 */
enum GSF_PendingRequestOptions
{

  /**
   * No special options (P2P-default).
   */
  GSF_PRO_DEFAULTS = 0,

    /**
     * Request must only be processed locally.
     */
  GSF_PRO_LOCAL_ONLY = 1,

    /**
     * Request must only be forwarded (no routing)
     */
  GSF_PRO_FORWARD_ONLY = 2,

    /**
     * Request persists indefinitely (no expiration).
     */
  GSF_PRO_REQUEST_NEVER_EXPIRES = 4,

    /**
     * Request is allowed to refresh bloomfilter and change mingle value.
     */
  GSF_PRO_BLOOMFILTER_FULL_REFRESH = 8,

    /**
     * Request priority is allowed to be exceeded.
     */
  GSF_PRO_PRIORITY_UNLIMITED = 16,

    /**
     * Option mask for typical local requests.
     */
  GSF_PRO_LOCAL_REQUEST =
      (GSF_PRO_BLOOMFILTER_FULL_REFRESH | GSF_PRO_PRIORITY_UNLIMITED | GSF_PRO_REQUEST_NEVER_EXPIRES)
};


/**
 * Public data (in the sense of not encapsulated within
 * 'gnunet-service-fs_pr', not in the sense of network-wide
 * known) associated with each pending request.
 */
struct GSF_PendingRequestData
{

  /**
   * Primary query hash for this request.
   */
  GNUNET_HashCode query;

  /**
   * Namespace to query, only set if the type is SBLOCK.
   */
  GNUNET_HashCode namespace;

  /**
   * Identity of a peer hosting the content, only set if
   * 'has_target' is GNUNET_YES.
   */
  struct GNUNET_PeerIdentity target;

  /**
   * Fields for the plan module to track a DLL with the request.
   */
  struct GSF_RequestPlanReference *rpr_head;

  /**
   * Fields for the plan module to track a DLL with the request.
   */
  struct GSF_RequestPlanReference *rpr_tail;

  /**
   * Current TTL for the request.
   */
  struct GNUNET_TIME_Absolute ttl;

  /**
   * When did we start with the request.
   */
  struct GNUNET_TIME_Absolute start_time;

  /**
   * Desired anonymity level.
   */
  uint32_t anonymity_level;

  /**
   * Priority that this request (still) has for us.
   */
  uint32_t priority;

  /**
   * Priority that this request (originally) had for us.
   */
  uint32_t original_priority;

  /**
   * Options for the request.
   */
  enum GSF_PendingRequestOptions options;

  /**
   * Type of the requested block.
   */
  enum GNUNET_BLOCK_Type type;

  /**
   * Number of results we have found for this request so far.
   */
  unsigned int results_found;

  /**
   * Is the 'target' value set to a valid peer identity?
   */
  int has_target;

  /**
   * Has this request been started yet (local/p2p operations)?  Or are
   * we still constructing it?
   */
  int has_started;

};


/**
 * Handle a reply to a pending request.  Also called if a request
 * expires (then with data == NULL).  The handler may be called
 * many times (depending on the request type), but will not be
 * called during or after a call to GSF_pending_request_cancel
 * and will also not be called anymore after a call signalling
 * expiration.
 *
 * @param cls user-specified closure
 * @param eval evaluation of the result
 * @param pr handle to the original pending request
 * @param reply_anonymity_level anonymity level for the reply, UINT32_MAX for "unknown"
 * @param expiration when does 'data' expire?
 * @param last_transmission the last time we've tried to get this block (FOREVER if unknown)
 * @param type type of the block
 * @param data response data, NULL on request expiration
 * @param data_len number of bytes in data
 */
typedef void (*GSF_PendingRequestReplyHandler) (void *cls,
                                                enum
                                                GNUNET_BLOCK_EvaluationResult
                                                eval,
                                                struct GSF_PendingRequest * pr,
                                                uint32_t reply_anonymity_level,
                                                struct GNUNET_TIME_Absolute
                                                expiration,
                                                struct GNUNET_TIME_Absolute
                                                last_transmission,
                                                enum GNUNET_BLOCK_Type type,
                                                const void *data,
                                                size_t data_len);


/**
 * Create a new pending request.
 *
 * @param options request options
 * @param type type of the block that is being requested
 * @param query key for the lookup
 * @param namespace namespace to lookup, NULL for no namespace
 * @param target preferred target for the request, NULL for none
 * @param bf_data raw data for bloom filter for known replies, can be NULL
 * @param bf_size number of bytes in bf_data
 * @param mingle mingle value for bf
 * @param anonymity_level desired anonymity level
 * @param priority maximum outgoing cummulative request priority to use
 * @param ttl current time-to-live for the request
 * @param sender_pid peer ID to use for the sender when forwarding, 0 for none;
 *                   reference counter is taken over by this function
 * @param origin_pid peer ID of origin of query (do not loop back)
 * @param replies_seen hash codes of known local replies
 * @param replies_seen_count size of the 'replies_seen' array
 * @param rh handle to call when we get a reply
 * @param rh_cls closure for rh
 * @return handle for the new pending request
 */
struct GSF_PendingRequest *
GSF_pending_request_create_ (enum GSF_PendingRequestOptions options,
                             enum GNUNET_BLOCK_Type type,
                             const GNUNET_HashCode * query,
                             const GNUNET_HashCode * namespace,
                             const struct GNUNET_PeerIdentity *target,
                             const char *bf_data, size_t bf_size,
                             uint32_t mingle, uint32_t anonymity_level,
                             uint32_t priority, int32_t ttl,
                             GNUNET_PEER_Id sender_pid,
                             GNUNET_PEER_Id origin_pid,
                             const GNUNET_HashCode * replies_seen,
                             unsigned int replies_seen_count,
                             GSF_PendingRequestReplyHandler rh, void *rh_cls);


/**
 * Update a given pending request with additional replies
 * that have been seen.
 *
 * @param pr request to update
 * @param replies_seen hash codes of replies that we've seen
 * @param replies_seen_count size of the replies_seen array
 */
void
GSF_pending_request_update_ (struct GSF_PendingRequest *pr,
                             const GNUNET_HashCode * replies_seen,
                             unsigned int replies_seen_count);


/**
 * Obtain the public data associated with a pending request
 *
 * @param pr pending request
 * @return associated public data
 */
struct GSF_PendingRequestData *
GSF_pending_request_get_data_ (struct GSF_PendingRequest *pr);


/**
 * Test if two pending requests are compatible (would generate
 * the same query modulo filters and should thus be processed
 * jointly).
 *
 * @param pra a pending request
 * @param prb another pending request
 * @return GNUNET_OK if the requests are compatible
 */
int
GSF_pending_request_is_compatible_ (struct GSF_PendingRequest *pra,
                                    struct GSF_PendingRequest *prb);


/**
 * Generate the message corresponding to the given pending request for
 * transmission to other peers (or at least determine its size).
 *
 * @param pr request to generate the message for
 * @param buf_size number of bytes available in buf
 * @param buf where to copy the message (can be NULL)
 * @return number of bytes needed (if buf_size too small) or used
 */
size_t
GSF_pending_request_get_message_ (struct GSF_PendingRequest *pr,
                                  size_t buf_size, void *buf);


/**
 * Explicitly cancel a pending request.
 *
 * @param pr request to cancel
 * @param full_cleanup fully purge the request
 */
void
GSF_pending_request_cancel_ (struct GSF_PendingRequest *pr, int full_cleanup);


/**
 * Signature of function called on each request.
 * (Note: 'subtype' of GNUNET_CONTAINER_HashMapIterator).
 *
 * @param cls closure
 * @param key query for the request
 * @param pr handle to the pending request
 * @return GNUNET_YES to continue to iterate
 */
typedef int (*GSF_PendingRequestIterator) (void *cls,
                                           const GNUNET_HashCode * key,
                                           struct GSF_PendingRequest * pr);


/**
 * Iterate over all pending requests.
 *
 * @param it function to call for each request
 * @param cls closure for it
 */
void
GSF_iterate_pending_requests_ (GSF_PendingRequestIterator it, void *cls);


/**
 * Handle P2P "CONTENT" message.  Checks that the message is
 * well-formed and then checks if there are any pending requests for
 * this content and possibly passes it on (to local clients or other
 * peers).  Does NOT perform migration (content caching at this peer).
 *
 * @param cp the other peer involved (sender or receiver, NULL
 *        for loopback messages where we are both sender and receiver)
 * @param message the actual message
 * @return GNUNET_OK if the message was well-formed,
 *         GNUNET_SYSERR if the message was malformed (close connection,
 *         do not cache under any circumstances)
 */
int
GSF_handle_p2p_content_ (struct GSF_ConnectedPeer *cp,
                         const struct GNUNET_MessageHeader *message);


/**
 * Consider looking up the data in the DHT (anonymity-level permitting).
 *
 * @param pr the pending request to process
 */
void
GSF_dht_lookup_ (struct GSF_PendingRequest *pr);


/**
 * Function to be called after we're done processing
 * replies from the local lookup.
 *
 * @param cls closure
 * @param pr the pending request we were processing
 * @param result final datastore lookup result
 */
typedef void (*GSF_LocalLookupContinuation) (void *cls,
                                             struct GSF_PendingRequest * pr,
                                             enum GNUNET_BLOCK_EvaluationResult
                                             result);


/**
 * Look up the request in the local datastore.
 *
 * @param pr the pending request to process
 * @param cont function to call at the end
 * @param cont_cls closure for cont
 */
void
GSF_local_lookup_ (struct GSF_PendingRequest *pr,
                   GSF_LocalLookupContinuation cont, void *cont_cls);


/**
 * Is the given target a legitimate peer for forwarding the given request?
 *
 * @param pr request
 * @param target
 * @return GNUNET_YES if this request could be forwarded to the given peer
 */
int
GSF_pending_request_test_target_ (struct GSF_PendingRequest *pr,
                                  const struct GNUNET_PeerIdentity *target);



/**
 * Setup the subsystem.
 */
void
GSF_pending_request_init_ (void);


/**
 * Shutdown the subsystem.
 */
void
GSF_pending_request_done_ (void);


#endif
/* end of gnunet-service-fs_pr.h */
