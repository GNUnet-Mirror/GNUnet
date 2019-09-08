/*
     This file is part of GNUnet.
     Copyright (C) 2009-2013 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
 */

/**
 * @file fs/gnunet-service-fs_pr.c
 * @brief API to handle pending requests
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_load_lib.h"
#include "gnunet-service-fs.h"
#include "gnunet-service-fs_cp.h"
#include "gnunet-service-fs_indexing.h"
#include "gnunet-service-fs_pe.h"
#include "gnunet-service-fs_pr.h"
#include "gnunet-service-fs_cadet.h"


/**
 * Desired replication level for GETs.
 */
#define DHT_GET_REPLICATION 5

/**
 * Maximum size of the datastore queue for P2P operations.  Needs to
 * be large enough to queue #MAX_QUEUE_PER_PEER operations for roughly
 * the number of active (connected) peers.
 */
#define MAX_DATASTORE_QUEUE (16 * MAX_QUEUE_PER_PEER)

/**
 * Bandwidth value of a 0-priority content (must be fairly high
 * compared to query since content is typically significantly larger
 * -- and more valueable since it can take many queries to get one
 * piece of content).
 */
#define CONTENT_BANDWIDTH_VALUE 800

/**
 * Hard limit on the number of results we may get from the datastore per query.
 */
#define MAX_RESULTS (100 * 1024)

/**
 * Collect an instane number of statistics?  May cause excessive IPC.
 */
#define INSANE_STATISTICS GNUNET_NO

/**
 * If obtaining a block via cadet fails, how often do we retry it before
 * giving up for good (and sticking to non-anonymous transfer)?
 */
#define CADET_RETRY_MAX 3


/**
 * An active request.
 */
struct GSF_PendingRequest {
  /**
   * Public data for the request.
   */
  struct GSF_PendingRequestData public_data;

  /**
   * Function to call if we encounter a reply.
   */
  GSF_PendingRequestReplyHandler rh;

  /**
   * Closure for @e rh
   */
  void *rh_cls;

  /**
   * Array of hash codes of replies we've already seen.
   */
  struct GNUNET_HashCode *replies_seen;

  /**
   * Block group for filtering replies we've already seen.
   */
  struct GNUNET_BLOCK_Group *bg;

  /**
   * Entry for this pending request in the expiration heap, or NULL.
   */
  struct GNUNET_CONTAINER_HeapNode *hnode;

  /**
   * Datastore queue entry for this request (or NULL for none).
   */
  struct GNUNET_DATASTORE_QueueEntry *qe;

  /**
   * DHT request handle for this request (or NULL for none).
   */
  struct GNUNET_DHT_GetHandle *gh;

  /**
   * Cadet request handle for this request (or NULL for none).
   */
  struct GSF_CadetRequest *cadet_request;

  /**
   * Function to call upon completion of the local get
   * request, or NULL for none.
   */
  GSF_LocalLookupContinuation llc_cont;

  /**
   * Closure for @e llc_cont.
   */
  void *llc_cont_cls;

  /**
   * Last result from the local datastore lookup evaluation.
   */
  enum GNUNET_BLOCK_EvaluationResult local_result;

  /**
   * Identity of the peer that we should use for the 'sender'
   * (recipient of the response) when forwarding (0 for none).
   */
  GNUNET_PEER_Id sender_pid;

  /**
   * Identity of the peer that we should never forward this query
   * to since it originated this query (0 for none).
   */
  GNUNET_PEER_Id origin_pid;

  /**
   * Time we started the last datastore lookup.
   */
  struct GNUNET_TIME_Absolute qe_start;

  /**
   * Task that warns us if the local datastore lookup takes too long.
   */
  struct GNUNET_SCHEDULER_Task *warn_task;

  /**
   * Do we have a first UID yet?
   */
  bool have_first_uid;

  /**
   * Have we seen a NULL result yet?
   */
  bool seen_null;

  /**
   * Unique ID of the first result from the local datastore;
   * used to terminate the loop.
   */
  uint64_t first_uid;

  /**
   * Result count.
   */
  size_t result_count;

  /**
   * How often have we retried this request via 'cadet'?
   * (used to bound overall retries).
   */
  unsigned int cadet_retry_count;

  /**
   * Number of valid entries in the 'replies_seen' array.
   */
  unsigned int replies_seen_count;

  /**
   * Length of the 'replies_seen' array.
   */
  unsigned int replies_seen_size;
};


/**
 * All pending requests, ordered by the query.  Entries
 * are of type 'struct GSF_PendingRequest*'.
 */
static struct GNUNET_CONTAINER_MultiHashMap *pr_map;


/**
 * Datastore 'PUT' load tracking.
 */
static struct GNUNET_LOAD_Value *datastore_put_load;


/**
 * Are we allowed to migrate content to this peer.
 */
static int active_to_migration;


/**
 * Heap with the request that will expire next at the top.  Contains
 * pointers of type "struct PendingRequest*"; these will *also* be
 * aliased from the "requests_by_peer" data structures and the
 * "requests_by_query" table.  Note that requests from our clients
 * don't expire and are thus NOT in the "requests_by_expiration"
 * (or the "requests_by_peer" tables).
 */
static struct GNUNET_CONTAINER_Heap *requests_by_expiration_heap;


/**
 * Maximum number of requests (from other peers, overall) that we're
 * willing to have pending at any given point in time.  Can be changed
 * via the configuration file (32k is just the default).
 */
static unsigned long long max_pending_requests = (32 * 1024);


/**
 * Recalculate our bloom filter for filtering replies.  This function
 * will create a new bloom filter from scratch, so it should only be
 * called if we have no bloomfilter at all (and hence can create a
 * fresh one of minimal size without problems) OR if our peer is the
 * initiator (in which case we may resize to larger than mimimum size).
 *
 * @param type type of the request
 * @param pr request for which the BF is to be recomputed
 */
static void
refresh_bloomfilter(enum GNUNET_BLOCK_Type type, struct GSF_PendingRequest *pr)
{
  if (NULL != pr->bg)
    {
      GNUNET_BLOCK_group_destroy(pr->bg);
      pr->bg = NULL;
    }
  if (GNUNET_BLOCK_TYPE_FS_UBLOCK != type)
    return; /* no need */
  pr->bg =
    GNUNET_BLOCK_group_create(GSF_block_ctx,
                              type,
                              GNUNET_CRYPTO_random_u32(GNUNET_CRYPTO_QUALITY_WEAK,
                                                       UINT32_MAX),
                              NULL,
                              0,
                              "seen-set-size",
                              pr->replies_seen_count,
                              NULL);
  if (NULL == pr->bg)
    return;
  GNUNET_break(GNUNET_OK ==
               GNUNET_BLOCK_group_set_seen(pr->bg,
                                           pr->replies_seen,
                                           pr->replies_seen_count));
}


/**
 * Create a new pending request.
 *
 * @param options request options
 * @param type type of the block that is being requested
 * @param query key for the lookup
 * @param target preferred target for the request, NULL for none
 * @param bf_data raw data for bloom filter for known replies, can be NULL
 * @param bf_size number of bytes in @a bf_data
 * @param mingle mingle value for bf
 * @param anonymity_level desired anonymity level
 * @param priority maximum outgoing cummulative request priority to use
 * @param ttl current time-to-live for the request
 * @param sender_pid peer ID to use for the sender when forwarding, 0 for none
 * @param origin_pid peer ID of origin of query (do not loop back)
 * @param replies_seen hash codes of known local replies
 * @param replies_seen_count size of the @a replies_seen array
 * @param rh handle to call when we get a reply
 * @param rh_cls closure for @a rh
 * @return handle for the new pending request
 */
struct GSF_PendingRequest *
GSF_pending_request_create_(enum GSF_PendingRequestOptions options,
                            enum GNUNET_BLOCK_Type type,
                            const struct GNUNET_HashCode *query,
                            const struct GNUNET_PeerIdentity *target,
                            const char *bf_data,
                            size_t bf_size,
                            uint32_t mingle,
                            uint32_t anonymity_level,
                            uint32_t priority,
                            int32_t ttl,
                            GNUNET_PEER_Id sender_pid,
                            GNUNET_PEER_Id origin_pid,
                            const struct GNUNET_HashCode *replies_seen,
                            unsigned int replies_seen_count,
                            GSF_PendingRequestReplyHandler rh,
                            void *rh_cls)
{
  struct GSF_PendingRequest *pr;
  struct GSF_PendingRequest *dpr;
  size_t extra;
  struct GNUNET_HashCode *eptr;

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "Creating request handle for `%s' of type %d\n",
             GNUNET_h2s(query),
             type);
#if INSANE_STATISTICS
  GNUNET_STATISTICS_update(GSF_stats,
                           gettext_noop("# Pending requests created"),
                           1,
                           GNUNET_NO);
#endif
  extra = 0;
  if (NULL != target)
    extra += sizeof(struct GNUNET_PeerIdentity);
  pr = GNUNET_malloc(sizeof(struct GSF_PendingRequest) + extra);
  pr->public_data.query = *query;
  eptr = (struct GNUNET_HashCode *)&pr[1];
  if (NULL != target)
    {
      pr->public_data.target = (struct GNUNET_PeerIdentity *)eptr;
      GNUNET_memcpy(eptr, target, sizeof(struct GNUNET_PeerIdentity));
    }
  pr->public_data.anonymity_level = anonymity_level;
  pr->public_data.priority = priority;
  pr->public_data.original_priority = priority;
  pr->public_data.options = options;
  pr->public_data.type = type;
  pr->public_data.start_time = GNUNET_TIME_absolute_get();
  pr->sender_pid = sender_pid;
  pr->origin_pid = origin_pid;
  pr->rh = rh;
  pr->rh_cls = rh_cls;
  GNUNET_assert((sender_pid != 0) || (0 == (options & GSF_PRO_FORWARD_ONLY)));
  if (ttl >= 0)
    pr->public_data.ttl = GNUNET_TIME_relative_to_absolute(
      GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, (uint32_t)ttl));
  else
    pr->public_data.ttl = GNUNET_TIME_absolute_subtract(
      pr->public_data.start_time,
      GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS,
                                    (uint32_t)(-ttl)));
  if (replies_seen_count > 0)
    {
      pr->replies_seen_size = replies_seen_count;
      pr->replies_seen =
        GNUNET_new_array(pr->replies_seen_size, struct GNUNET_HashCode);
      GNUNET_memcpy(pr->replies_seen,
                    replies_seen,
                    replies_seen_count * sizeof(struct GNUNET_HashCode));
      pr->replies_seen_count = replies_seen_count;
    }
  if ((NULL != bf_data) &&
      (GNUNET_BLOCK_TYPE_FS_UBLOCK == pr->public_data.type))
    {
      pr->bg = GNUNET_BLOCK_group_create(GSF_block_ctx,
                                         pr->public_data.type,
                                         mingle,
                                         bf_data,
                                         bf_size,
                                         "seen-set-size",
                                         0,
                                         NULL);
    }
  else if ((replies_seen_count > 0) &&
           (0 != (options & GSF_PRO_BLOOMFILTER_FULL_REFRESH)))
    {
      refresh_bloomfilter(pr->public_data.type, pr);
    }
  GNUNET_CONTAINER_multihashmap_put(pr_map,
                                    &pr->public_data.query,
                                    pr,
                                    GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
  if (0 == (options & GSF_PRO_REQUEST_NEVER_EXPIRES))
    {
      pr->hnode = GNUNET_CONTAINER_heap_insert(requests_by_expiration_heap,
                                               pr,
                                               pr->public_data.ttl.abs_value_us);
      /* make sure we don't track too many requests */
      while (GNUNET_CONTAINER_heap_get_size(requests_by_expiration_heap) >
             max_pending_requests)
        {
          dpr = GNUNET_CONTAINER_heap_peek(requests_by_expiration_heap);
          GNUNET_assert(NULL != dpr);
          if (pr == dpr)
            break; /* let the request live briefly... */
          if (NULL != dpr->rh)
            dpr->rh(dpr->rh_cls,
                    GNUNET_BLOCK_EVALUATION_REQUEST_VALID,
                    dpr,
                    UINT32_MAX,
                    GNUNET_TIME_UNIT_FOREVER_ABS,
                    GNUNET_TIME_UNIT_FOREVER_ABS,
                    GNUNET_BLOCK_TYPE_ANY,
                    NULL,
                    0);
          GSF_pending_request_cancel_(dpr, GNUNET_YES);
        }
    }
  GNUNET_STATISTICS_update(GSF_stats,
                           gettext_noop("# Pending requests active"),
                           1,
                           GNUNET_NO);
  return pr;
}

/**
 * Obtain the public data associated with a pending request
 *
 * @param pr pending request
 * @return associated public data
 */
struct GSF_PendingRequestData *
GSF_pending_request_get_data_(struct GSF_PendingRequest *pr)
{
  return &pr->public_data;
}


/**
 * Test if two pending requests are compatible (would generate
 * the same query modulo filters and should thus be processed
 * jointly).
 *
 * @param pra a pending request
 * @param prb another pending request
 * @return #GNUNET_OK if the requests are compatible
 */
int
GSF_pending_request_is_compatible_(struct GSF_PendingRequest *pra,
                                   struct GSF_PendingRequest *prb)
{
  if ((pra->public_data.type != prb->public_data.type) ||
      (0 != memcmp(&pra->public_data.query,
                   &prb->public_data.query,
                   sizeof(struct GNUNET_HashCode))))
    return GNUNET_NO;
  return GNUNET_OK;
}


/**
 * Update a given pending request with additional replies
 * that have been seen.
 *
 * @param pr request to update
 * @param replies_seen hash codes of replies that we've seen
 * @param replies_seen_count size of the replies_seen array
 */
void
GSF_pending_request_update_(struct GSF_PendingRequest *pr,
                            const struct GNUNET_HashCode *replies_seen,
                            unsigned int replies_seen_count)
{
  if (replies_seen_count + pr->replies_seen_count < pr->replies_seen_count)
    return; /* integer overflow */
  if (0 != (pr->public_data.options & GSF_PRO_BLOOMFILTER_FULL_REFRESH))
    {
      /* we're responsible for the BF, full refresh */
      if (replies_seen_count + pr->replies_seen_count > pr->replies_seen_size)
        GNUNET_array_grow(pr->replies_seen,
                          pr->replies_seen_size,
                          replies_seen_count + pr->replies_seen_count);
      GNUNET_memcpy(&pr->replies_seen[pr->replies_seen_count],
                    replies_seen,
                    sizeof(struct GNUNET_HashCode) * replies_seen_count);
      pr->replies_seen_count += replies_seen_count;
      refresh_bloomfilter(pr->public_data.type, pr);
    }
  else
    {
      if (NULL == pr->bg)
        {
          /* we're not the initiator, but the initiator did not give us
           * any bloom-filter, so we need to create one on-the-fly */
          refresh_bloomfilter(pr->public_data.type, pr);
        }
      else
        {
          GNUNET_break(GNUNET_OK ==
                       GNUNET_BLOCK_group_set_seen(pr->bg,
                                                   replies_seen,
                                                   pr->replies_seen_count));
        }
    }
  if (NULL != pr->gh)
    GNUNET_DHT_get_filter_known_results(pr->gh,
                                        replies_seen_count,
                                        replies_seen);
}


/**
 * Generate the message corresponding to the given pending request for
 * transmission to other peers.
 *
 * @param pr request to generate the message for
 * @return envelope with the request message
 */
struct GNUNET_MQ_Envelope *
GSF_pending_request_get_message_(struct GSF_PendingRequest *pr)
{
  struct GNUNET_MQ_Envelope *env;
  struct GetMessage *gm;
  struct GNUNET_PeerIdentity *ext;
  unsigned int k;
  uint32_t bm;
  uint32_t prio;
  size_t bf_size;
  struct GNUNET_TIME_Absolute now;
  int64_t ttl;
  int do_route;
  void *bf_data;
  uint32_t bf_nonce;

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "Building request message for `%s' of type %d\n",
             GNUNET_h2s(&pr->public_data.query),
             pr->public_data.type);
  k = 0;
  bm = 0;
  do_route = (0 == (pr->public_data.options & GSF_PRO_FORWARD_ONLY));
  if ((!do_route) && (pr->sender_pid == 0))
    {
      GNUNET_break(0);
      do_route = GNUNET_YES;
    }
  if (!do_route)
    {
      bm |= GET_MESSAGE_BIT_RETURN_TO;
      k++;
    }
  if (NULL != pr->public_data.target)
    {
      bm |= GET_MESSAGE_BIT_TRANSMIT_TO;
      k++;
    }
  if (GNUNET_OK !=
      GNUNET_BLOCK_group_serialize(pr->bg, &bf_nonce, &bf_data, &bf_size))
    {
      bf_size = 0;
      bf_data = NULL;
    }
  env = GNUNET_MQ_msg_extra(gm,
                            bf_size + k * sizeof(struct GNUNET_PeerIdentity),
                            GNUNET_MESSAGE_TYPE_FS_GET);
  gm->type = htonl(pr->public_data.type);
  if (do_route)
    prio = GNUNET_CRYPTO_random_u32(GNUNET_CRYPTO_QUALITY_WEAK,
                                    pr->public_data.priority + 1);
  else
    prio = 0;
  pr->public_data.priority -= prio;
  pr->public_data.num_transmissions++;
  pr->public_data.respect_offered += prio;
  gm->priority = htonl(prio);
  now = GNUNET_TIME_absolute_get();
  ttl = (int64_t)(pr->public_data.ttl.abs_value_us - now.abs_value_us);
  gm->ttl = htonl(ttl / 1000LL / 1000LL);
  gm->filter_mutator = htonl(bf_nonce);
  gm->hash_bitmap = htonl(bm);
  gm->query = pr->public_data.query;
  ext = (struct GNUNET_PeerIdentity *)&gm[1];
  k = 0;
  if (!do_route)
    GNUNET_PEER_resolve(pr->sender_pid, &ext[k++]);
  if (NULL != pr->public_data.target)
    ext[k++] = *pr->public_data.target;
  GNUNET_memcpy(&ext[k], bf_data, bf_size);
  GNUNET_free_non_null(bf_data);
  return env;
}


/**
 * Iterator to free pending requests.
 *
 * @param cls closure, unused
 * @param key current key code
 * @param value value in the hash map (pending request)
 * @return #GNUNET_YES (we should continue to iterate)
 */
static int
clean_request(void *cls, const struct GNUNET_HashCode *key, void *value)
{
  struct GSF_PendingRequest *pr = value;
  GSF_LocalLookupContinuation cont;

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "Cleaning up pending request for `%s'.\n",
             GNUNET_h2s(key));
  if (NULL != pr->cadet_request)
    {
      pr->cadet_retry_count = CADET_RETRY_MAX;
      GSF_cadet_query_cancel(pr->cadet_request);
      pr->cadet_request = NULL;
    }
  if (NULL != (cont = pr->llc_cont))
    {
      pr->llc_cont = NULL;
      cont(pr->llc_cont_cls, pr, pr->local_result);
    }
  GSF_plan_notify_request_done_(pr);
  GNUNET_free_non_null(pr->replies_seen);
  GNUNET_BLOCK_group_destroy(pr->bg);
  pr->bg = NULL;
  GNUNET_PEER_change_rc(pr->sender_pid, -1);
  pr->sender_pid = 0;
  GNUNET_PEER_change_rc(pr->origin_pid, -1);
  pr->origin_pid = 0;
  if (NULL != pr->hnode)
    {
      GNUNET_CONTAINER_heap_remove_node(pr->hnode);
      pr->hnode = NULL;
    }
  if (NULL != pr->qe)
    {
      GNUNET_DATASTORE_cancel(pr->qe);
      pr->qe = NULL;
    }
  if (NULL != pr->gh)
    {
      GNUNET_DHT_get_stop(pr->gh);
      pr->gh = NULL;
    }
  if (NULL != pr->warn_task)
    {
      GNUNET_SCHEDULER_cancel(pr->warn_task);
      pr->warn_task = NULL;
    }
  GNUNET_assert(
    GNUNET_OK ==
    GNUNET_CONTAINER_multihashmap_remove(pr_map, &pr->public_data.query, pr));
  GNUNET_STATISTICS_update(GSF_stats,
                           gettext_noop("# Pending requests active"),
                           -1,
                           GNUNET_NO);
  GNUNET_free(pr);
  return GNUNET_YES;
}


/**
 * Explicitly cancel a pending request.
 *
 * @param pr request to cancel
 * @param full_cleanup fully purge the request
 */
void
GSF_pending_request_cancel_(struct GSF_PendingRequest *pr, int full_cleanup)
{
  GSF_LocalLookupContinuation cont;

  if (NULL == pr_map)
    return; /* already cleaned up! */
  if (GNUNET_NO == full_cleanup)
    {
      /* make request inactive (we're no longer interested in more results),
       * but do NOT remove from our data-structures, we still need it there
       * to prevent the request from looping */
      pr->rh = NULL;
      if (NULL != pr->cadet_request)
        {
          pr->cadet_retry_count = CADET_RETRY_MAX;
          GSF_cadet_query_cancel(pr->cadet_request);
          pr->cadet_request = NULL;
        }
      if (NULL != (cont = pr->llc_cont))
        {
          pr->llc_cont = NULL;
          cont(pr->llc_cont_cls, pr, pr->local_result);
        }
      GSF_plan_notify_request_done_(pr);
      if (NULL != pr->qe)
        {
          GNUNET_DATASTORE_cancel(pr->qe);
          pr->qe = NULL;
        }
      if (NULL != pr->gh)
        {
          GNUNET_DHT_get_stop(pr->gh);
          pr->gh = NULL;
        }
      if (NULL != pr->warn_task)
        {
          GNUNET_SCHEDULER_cancel(pr->warn_task);
          pr->warn_task = NULL;
        }
      return;
    }
  GNUNET_assert(GNUNET_YES ==
                clean_request(NULL, &pr->public_data.query, pr));
}


/**
 * Iterate over all pending requests.
 *
 * @param it function to call for each request
 * @param cls closure for @a it
 */
void
GSF_iterate_pending_requests_(GSF_PendingRequestIterator it, void *cls)
{
  GNUNET_CONTAINER_multihashmap_iterate(
    pr_map,
    (GNUNET_CONTAINER_MulitHashMapIteratorCallback)it,
    cls);
}


/**
 * Closure for process_reply() function.
 */
struct ProcessReplyClosure {
  /**
   * The data for the reply.
   */
  const void *data;

  /**
   * Who gave us this reply? NULL for local host (or DHT)
   */
  struct GSF_ConnectedPeer *sender;

  /**
   * When the reply expires.
   */
  struct GNUNET_TIME_Absolute expiration;

  /**
   * Size of data.
   */
  size_t size;

  /**
   * Type of the block.
   */
  enum GNUNET_BLOCK_Type type;

  /**
   * Control flags for evaluation.
   */
  enum GNUNET_BLOCK_EvaluationOptions eo;

  /**
   * How much was this reply worth to us?
   */
  uint32_t priority;

  /**
   * Anonymity requirements for this reply.
   */
  uint32_t anonymity_level;

  /**
   * Evaluation result (returned).
   */
  enum GNUNET_BLOCK_EvaluationResult eval;

  /**
   * Did we find a matching request?
   */
  int request_found;
};


/**
 * Update the performance data for the sender (if any) since
 * the sender successfully answered one of our queries.
 *
 * @param prq information about the sender
 * @param pr request that was satisfied
 */
static void
update_request_performance_data(struct ProcessReplyClosure *prq,
                                struct GSF_PendingRequest *pr)
{
  if (prq->sender == NULL)
    return;
  GSF_peer_update_performance_(prq->sender,
                               pr->public_data.start_time,
                               prq->priority);
}


/**
 * We have received a reply; handle it!
 *
 * @param cls response (a `struct ProcessReplyClosure`)
 * @param key our query
 * @param value value in the hash map (info about the query)
 * @return #GNUNET_YES (we should continue to iterate)
 */
static int
process_reply(void *cls, const struct GNUNET_HashCode *key, void *value)
{
  struct ProcessReplyClosure *prq = cls;
  struct GSF_PendingRequest *pr = value;
  struct GNUNET_HashCode chash;
  struct GNUNET_TIME_Absolute last_transmission;

  if (NULL == pr->rh)
    return GNUNET_YES;
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "Matched result (type %u) for query `%s' with pending request\n",
             (unsigned int)prq->type,
             GNUNET_h2s(key));
  GNUNET_STATISTICS_update(GSF_stats,
                           gettext_noop("# replies received and matched"),
                           1,
                           GNUNET_NO);
  prq->eval = GNUNET_BLOCK_evaluate(GSF_block_ctx,
                                    prq->type,
                                    pr->bg,
                                    prq->eo,
                                    key,
                                    NULL,
                                    0,
                                    prq->data,
                                    prq->size);
  switch (prq->eval)
    {
    case GNUNET_BLOCK_EVALUATION_OK_MORE:
      update_request_performance_data(prq, pr);
      break;

    case GNUNET_BLOCK_EVALUATION_OK_LAST:
      /* short cut: stop processing early, no BF-update, etc. */
      update_request_performance_data(prq, pr);
      GNUNET_LOAD_update(GSF_rt_entry_lifetime,
                         GNUNET_TIME_absolute_get_duration(
                           pr->public_data.start_time)
                         .rel_value_us);
      if (GNUNET_YES !=
          GSF_request_plan_reference_get_last_transmission_(pr->public_data
                                                            .pr_head,
                                                            prq->sender,
                                                            &last_transmission))
        last_transmission.abs_value_us =
          GNUNET_TIME_UNIT_FOREVER_ABS.abs_value_us;
      /* pass on to other peers / local clients */
      pr->rh(pr->rh_cls,
             prq->eval,
             pr,
             prq->anonymity_level,
             prq->expiration,
             last_transmission,
             prq->type,
             prq->data,
             prq->size);
      return GNUNET_YES;

    case GNUNET_BLOCK_EVALUATION_OK_DUPLICATE:
#if INSANE_STATISTICS
      GNUNET_STATISTICS_update(GSF_stats,
                               gettext_noop(
                                 "# duplicate replies discarded (bloomfilter)"),
                               1,
                               GNUNET_NO);
#endif
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Duplicate response, discarding.\n");
      return GNUNET_YES; /* duplicate */

    case GNUNET_BLOCK_EVALUATION_RESULT_IRRELEVANT:
      GNUNET_STATISTICS_update(GSF_stats,
                               gettext_noop("# irrelevant replies discarded"),
                               1,
                               GNUNET_NO);
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Irrelevant response, ignoring.\n");
      return GNUNET_YES;

    case GNUNET_BLOCK_EVALUATION_RESULT_INVALID:
      return GNUNET_YES; /* wrong namespace */

    case GNUNET_BLOCK_EVALUATION_REQUEST_VALID:
      GNUNET_break(0);
      return GNUNET_YES;

    case GNUNET_BLOCK_EVALUATION_REQUEST_INVALID:
      GNUNET_break(0);
      return GNUNET_YES;

    case GNUNET_BLOCK_EVALUATION_TYPE_NOT_SUPPORTED:
      GNUNET_log(GNUNET_ERROR_TYPE_ERROR,
                 _("Unsupported block type %u\n"),
                 prq->type);
      return GNUNET_NO;
    }
  /* update bloomfilter */
  GNUNET_CRYPTO_hash(prq->data, prq->size, &chash);
  GSF_pending_request_update_(pr, &chash, 1);
  if (NULL == prq->sender)
    {
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
                 "Found result for query `%s' in local datastore\n",
                 GNUNET_h2s(key));
      GNUNET_STATISTICS_update(GSF_stats,
                               gettext_noop("# results found locally"),
                               1,
                               GNUNET_NO);
    }
  else
    {
      GSF_dht_lookup_(pr);
    }
  prq->priority += pr->public_data.original_priority;
  pr->public_data.priority = 0;
  pr->public_data.original_priority = 0;
  pr->public_data.results_found++;
  prq->request_found = GNUNET_YES;
  /* finally, pass on to other peer / local client */
  if (!GSF_request_plan_reference_get_last_transmission_(pr->public_data
                                                         .pr_head,
                                                         prq->sender,
                                                         &last_transmission))
    last_transmission.abs_value_us = GNUNET_TIME_UNIT_FOREVER_ABS.abs_value_us;
  pr->rh(pr->rh_cls,
         prq->eval,
         pr,
         prq->anonymity_level,
         prq->expiration,
         last_transmission,
         prq->type,
         prq->data,
         prq->size);
  return GNUNET_YES;
}


/**
 * Context for put_migration_continuation().
 */
struct PutMigrationContext {
  /**
   * Start time for the operation.
   */
  struct GNUNET_TIME_Absolute start;

  /**
   * Request origin.
   */
  struct GNUNET_PeerIdentity origin;

  /**
   * #GNUNET_YES if we had a matching request for this block,
   * #GNUNET_NO if not.
   */
  int requested;
};


/**
 * Continuation called to notify client about result of the
 * operation.
 *
 * @param cls closure
 * @param success #GNUNET_SYSERR on failure
 * @param min_expiration minimum expiration time required for content to be stored
 * @param msg NULL on success, otherwise an error message
 */
static void
put_migration_continuation(void *cls,
                           int success,
                           struct GNUNET_TIME_Absolute min_expiration,
                           const char *msg)
{
  struct PutMigrationContext *pmc = cls;
  struct GSF_ConnectedPeer *cp;
  struct GNUNET_TIME_Relative mig_pause;
  struct GSF_PeerPerformanceData *ppd;

  if (NULL != datastore_put_load)
    {
      if (GNUNET_SYSERR != success)
        {
          GNUNET_LOAD_update(datastore_put_load,
                             GNUNET_TIME_absolute_get_duration(pmc->start)
                             .rel_value_us);
        }
      else
        {
          /* on queue failure / timeout, increase the put load dramatically */
          GNUNET_LOAD_update(datastore_put_load,
                             GNUNET_TIME_UNIT_MINUTES.rel_value_us);
        }
    }
  cp = GSF_peer_get_(&pmc->origin);
  if (GNUNET_OK == success)
    {
      if (NULL != cp)
        {
          ppd = GSF_get_peer_performance_data_(cp);
          ppd->migration_delay.rel_value_us /= 2;
        }
      GNUNET_free(pmc);
      return;
    }
  if ((GNUNET_NO == success) && (GNUNET_NO == pmc->requested) && (NULL != cp))
    {
      ppd = GSF_get_peer_performance_data_(cp);
      if (min_expiration.abs_value_us > 0)
        {
          GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
                     "Asking to stop migration for %s because datastore is full\n",
                     GNUNET_STRINGS_relative_time_to_string(
                       GNUNET_TIME_absolute_get_remaining(min_expiration),
                       GNUNET_YES));
          GSF_block_peer_migration_(cp, min_expiration);
        }
      else
        {
          ppd->migration_delay = GNUNET_TIME_relative_max(GNUNET_TIME_UNIT_SECONDS,
                                                          ppd->migration_delay);
          ppd->migration_delay =
            GNUNET_TIME_relative_min(GNUNET_TIME_UNIT_HOURS, ppd->migration_delay);
          mig_pause.rel_value_us =
            GNUNET_CRYPTO_random_u64(GNUNET_CRYPTO_QUALITY_WEAK,
                                     ppd->migration_delay.rel_value_us);
          ppd->migration_delay =
            GNUNET_TIME_relative_saturating_multiply(ppd->migration_delay, 2);
          GNUNET_log(
            GNUNET_ERROR_TYPE_DEBUG,
            "Replicated content already exists locally, asking to stop migration for %s\n",
            GNUNET_STRINGS_relative_time_to_string(mig_pause, GNUNET_YES));
          GSF_block_peer_migration_(cp,
                                    GNUNET_TIME_relative_to_absolute(mig_pause));
        }
    }
  GNUNET_free(pmc);
  GNUNET_STATISTICS_update(GSF_stats,
                           gettext_noop("# Datastore `PUT' failures"),
                           1,
                           GNUNET_NO);
}


/**
 * Test if the DATABASE (PUT) load on this peer is too high
 * to even consider processing the query at
 * all.
 *
 * @param priority the priority of the item
 * @return #GNUNET_YES if the load is too high to do anything (load high)
 *         #GNUNET_NO to process normally (load normal or low)
 */
static int
test_put_load_too_high(uint32_t priority)
{
  double ld;

  if (NULL == datastore_put_load)
    return GNUNET_NO;
  if (GNUNET_LOAD_get_average(datastore_put_load) < 50)
    return GNUNET_NO; /* very fast */
  ld = GNUNET_LOAD_get_load(datastore_put_load);
  if (ld < 2.0 * (1 + priority))
    return GNUNET_NO;
  GNUNET_STATISTICS_update(GSF_stats,
                           gettext_noop(
                             "# storage requests dropped due to high load"),
                           1,
                           GNUNET_NO);
  return GNUNET_YES;
}


/**
 * Iterator called on each result obtained for a DHT
 * operation that expects a reply
 *
 * @param cls closure
 * @param exp when will this value expire
 * @param key key of the result
 * @param get_path peers on reply path (or NULL if not recorded)
 * @param get_path_length number of entries in @a get_path
 * @param put_path peers on the PUT path (or NULL if not recorded)
 * @param put_path_length number of entries in @a get_path
 * @param type type of the result
 * @param size number of bytes in @a data
 * @param data pointer to the result data
 */
static void
handle_dht_reply(void *cls,
                 struct GNUNET_TIME_Absolute exp,
                 const struct GNUNET_HashCode *key,
                 const struct GNUNET_PeerIdentity *get_path,
                 unsigned int get_path_length,
                 const struct GNUNET_PeerIdentity *put_path,
                 unsigned int put_path_length,
                 enum GNUNET_BLOCK_Type type,
                 size_t size,
                 const void *data)
{
  struct GSF_PendingRequest *pr = cls;
  struct ProcessReplyClosure prq;
  struct PutMigrationContext *pmc;

  GNUNET_STATISTICS_update(GSF_stats,
                           gettext_noop("# Replies received from DHT"),
                           1,
                           GNUNET_NO);
  memset(&prq, 0, sizeof(prq));
  prq.data = data;
  prq.expiration = exp;
  /* do not allow migrated content to live longer than 1 year */
  prq.expiration = GNUNET_TIME_absolute_min(GNUNET_TIME_relative_to_absolute(
                                              GNUNET_TIME_UNIT_YEARS),
                                            prq.expiration);
  prq.size = size;
  prq.type = type;
  prq.eo = GNUNET_BLOCK_EO_NONE;
  process_reply(&prq, key, pr);
  if ((GNUNET_YES == active_to_migration) &&
      (GNUNET_NO == test_put_load_too_high(prq.priority)))
    {
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
                 "Replicating result for query `%s' with priority %u\n",
                 GNUNET_h2s(key),
                 prq.priority);
      pmc = GNUNET_new(struct PutMigrationContext);
      pmc->start = GNUNET_TIME_absolute_get();
      pmc->requested = GNUNET_YES;
      if (NULL == GNUNET_DATASTORE_put(GSF_dsh,
                                       0,
                                       key,
                                       size,
                                       data,
                                       type,
                                       prq.priority,
                                       1 /* anonymity */,
                                       0 /* replication */,
                                       exp,
                                       1 + prq.priority,
                                       MAX_DATASTORE_QUEUE,
                                       &put_migration_continuation,
                                       pmc))
        {
          put_migration_continuation(pmc,
                                     GNUNET_SYSERR,
                                     GNUNET_TIME_UNIT_ZERO_ABS,
                                     NULL);
        }
    }
}


/**
 * Consider looking up the data in the DHT (anonymity-level permitting).
 *
 * @param pr the pending request to process
 */
void
GSF_dht_lookup_(struct GSF_PendingRequest *pr)
{
  const void *xquery;
  size_t xquery_size;
  struct GNUNET_PeerIdentity pi;
  char buf[sizeof(struct GNUNET_HashCode) * 2] GNUNET_ALIGN;

  if (0 != pr->public_data.anonymity_level)
    return;
  if (NULL != pr->gh)
    {
      GNUNET_DHT_get_stop(pr->gh);
      pr->gh = NULL;
    }
  xquery = NULL;
  xquery_size = 0;
  if (0 != (pr->public_data.options & GSF_PRO_FORWARD_ONLY))
    {
      GNUNET_assert(0 != pr->sender_pid);
      GNUNET_PEER_resolve(pr->sender_pid, &pi);
      GNUNET_memcpy(&buf[xquery_size], &pi, sizeof(struct GNUNET_PeerIdentity));
      xquery_size += sizeof(struct GNUNET_PeerIdentity);
    }
  pr->gh = GNUNET_DHT_get_start(GSF_dht,
                                pr->public_data.type,
                                &pr->public_data.query,
                                DHT_GET_REPLICATION,
                                GNUNET_DHT_RO_DEMULTIPLEX_EVERYWHERE,
                                xquery,
                                xquery_size,
                                &handle_dht_reply,
                                pr);
  if ((NULL != pr->gh) && (0 != pr->replies_seen_count))
    GNUNET_DHT_get_filter_known_results(pr->gh,
                                        pr->replies_seen_count,
                                        pr->replies_seen);
}


/**
 * Function called with a reply from the cadet.
 *
 * @param cls the pending request struct
 * @param type type of the block, ANY on error
 * @param expiration expiration time for the block
 * @param data_size number of bytes in @a data, 0 on error
 * @param data reply block data, NULL on error
 */
static void
cadet_reply_proc(void *cls,
                 enum GNUNET_BLOCK_Type type,
                 struct GNUNET_TIME_Absolute expiration,
                 size_t data_size,
                 const void *data)
{
  struct GSF_PendingRequest *pr = cls;
  struct ProcessReplyClosure prq;
  struct GNUNET_HashCode query;

  pr->cadet_request = NULL;
  if (GNUNET_BLOCK_TYPE_ANY == type)
    {
      GNUNET_break(NULL == data);
      GNUNET_break(0 == data_size);
      pr->cadet_retry_count++;
      if (pr->cadet_retry_count >= CADET_RETRY_MAX)
        return; /* give up on cadet */
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Error retrieiving block via cadet\n");
      /* retry -- without delay, as this is non-anonymous
         and cadet/cadet connect will take some time anyway */
      pr->cadet_request = GSF_cadet_query(pr->public_data.target,
                                          &pr->public_data.query,
                                          pr->public_data.type,
                                          &cadet_reply_proc,
                                          pr);
      return;
    }
  if (GNUNET_YES !=
      GNUNET_BLOCK_get_key(GSF_block_ctx, type, data, data_size, &query))
    {
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
                 "Failed to derive key for block of type %d\n",
                 (int)type);
      GNUNET_break_op(0);
      return;
    }
  GNUNET_STATISTICS_update(GSF_stats,
                           gettext_noop("# Replies received from CADET"),
                           1,
                           GNUNET_NO);
  memset(&prq, 0, sizeof(prq));
  prq.data = data;
  prq.expiration = expiration;
  /* do not allow migrated content to live longer than 1 year */
  prq.expiration = GNUNET_TIME_absolute_min(GNUNET_TIME_relative_to_absolute(
                                              GNUNET_TIME_UNIT_YEARS),
                                            prq.expiration);
  prq.size = data_size;
  prq.type = type;
  prq.eo = GNUNET_BLOCK_EO_NONE;
  process_reply(&prq, &query, pr);
}


/**
 * Consider downloading via cadet (if possible)
 *
 * @param pr the pending request to process
 */
void
GSF_cadet_lookup_(struct GSF_PendingRequest *pr)
{
  if (0 != pr->public_data.anonymity_level)
    return;
  if (0 == pr->public_data.target)
    {
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
                 "Cannot do cadet-based download, target peer not known\n");
      return;
    }
  if (NULL != pr->cadet_request)
    return;
  pr->cadet_request = GSF_cadet_query(pr->public_data.target,
                                      &pr->public_data.query,
                                      pr->public_data.type,
                                      &cadet_reply_proc,
                                      pr);
}


/**
 * Task that issues a warning if the datastore lookup takes too long.
 *
 * @param cls the `struct GSF_PendingRequest`
 */
static void
warn_delay_task(void *cls)
{
  struct GSF_PendingRequest *pr = cls;

  GNUNET_log(GNUNET_ERROR_TYPE_WARNING | GNUNET_ERROR_TYPE_BULK,
             _("Datastore lookup already took %s!\n"),
             GNUNET_STRINGS_relative_time_to_string(
               GNUNET_TIME_absolute_get_duration(pr->qe_start),
               GNUNET_YES));
  pr->warn_task = GNUNET_SCHEDULER_add_delayed(GNUNET_TIME_UNIT_MINUTES,
                                               &warn_delay_task,
                                               pr);
}


/**
 * Task that issues a warning if the datastore lookup takes too long.
 *
 * @param cls the `struct GSF_PendingRequest`
 */
static void
odc_warn_delay_task(void *cls)
{
  struct GSF_PendingRequest *pr = cls;

  GNUNET_log(GNUNET_ERROR_TYPE_WARNING,
             _("On-demand lookup already took %s!\n"),
             GNUNET_STRINGS_relative_time_to_string(
               GNUNET_TIME_absolute_get_duration(pr->qe_start),
               GNUNET_YES));
  pr->warn_task = GNUNET_SCHEDULER_add_delayed(GNUNET_TIME_UNIT_MINUTES,
                                               &odc_warn_delay_task,
                                               pr);
}


/* Call our continuation (if we have any) */
static void
call_continuation(struct GSF_PendingRequest *pr)
{
  GSF_LocalLookupContinuation cont = pr->llc_cont;

  GNUNET_assert(NULL == pr->qe);
  if (NULL != pr->warn_task)
    {
      GNUNET_SCHEDULER_cancel(pr->warn_task);
      pr->warn_task = NULL;
    }
  if (NULL == cont)
    return; /* no continuation */
  pr->llc_cont = NULL;
  if (0 != (GSF_PRO_LOCAL_ONLY & pr->public_data.options))
    {
      if (GNUNET_BLOCK_EVALUATION_OK_LAST != pr->local_result)
        {
          /* Signal that we are done and that there won't be any
             additional results to allow client to clean up state. */
          pr->rh(pr->rh_cls,
                 GNUNET_BLOCK_EVALUATION_OK_LAST,
                 pr,
                 UINT32_MAX,
                 GNUNET_TIME_UNIT_ZERO_ABS,
                 GNUNET_TIME_UNIT_FOREVER_ABS,
                 GNUNET_BLOCK_TYPE_ANY,
                 NULL,
                 0);
        }
      /* Finally, call our continuation to signal that we are
         done with local processing of this request; i.e. to
         start reading again from the client. */
      cont(pr->llc_cont_cls, NULL, GNUNET_BLOCK_EVALUATION_OK_LAST);
      return;
    }

  cont(pr->llc_cont_cls, pr, pr->local_result);
}


/* Update stats and call continuation */
static void
no_more_local_results(struct GSF_PendingRequest *pr)
{
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG | GNUNET_ERROR_TYPE_BULK,
             "No further local responses available.\n");
#if INSANE_STATISTICS
  if ((GNUNET_BLOCK_TYPE_FS_DBLOCK == pr->public_data.type) ||
      (GNUNET_BLOCK_TYPE_FS_IBLOCK == pr->public_data.type))
    GNUNET_STATISTICS_update(GSF_stats,
                             gettext_noop(
                               "# requested DBLOCK or IBLOCK not found"),
                             1,
                             GNUNET_NO);
#endif
  call_continuation(pr);
}


/* forward declaration */
static void
process_local_reply(void *cls,
                    const struct GNUNET_HashCode *key,
                    size_t size,
                    const void *data,
                    enum GNUNET_BLOCK_Type type,
                    uint32_t priority,
                    uint32_t anonymity,
                    uint32_t replication,
                    struct GNUNET_TIME_Absolute expiration,
                    uint64_t uid);


/* Start a local query */
static void
start_local_query(struct GSF_PendingRequest *pr,
                  uint64_t next_uid,
                  bool random)
{
  pr->qe_start = GNUNET_TIME_absolute_get();
  pr->warn_task = GNUNET_SCHEDULER_add_delayed(GNUNET_TIME_UNIT_MINUTES,
                                               &warn_delay_task,
                                               pr);
  pr->qe = GNUNET_DATASTORE_get_key(GSF_dsh,
                                    next_uid,
                                    random,
                                    &pr->public_data.query,
                                    pr->public_data.type ==
                                    GNUNET_BLOCK_TYPE_FS_DBLOCK
                                    ? GNUNET_BLOCK_TYPE_ANY
                                    : pr->public_data.type,
                                    (0 != (GSF_PRO_PRIORITY_UNLIMITED &
                                           pr->public_data.options))
                                    ? UINT_MAX
                                    : 1
                                    /* queue priority */,
                                    (0 != (GSF_PRO_PRIORITY_UNLIMITED &
                                           pr->public_data.options))
                                    ? UINT_MAX
                                    : GSF_datastore_queue_size
                                    /* max queue size */,
                                    &process_local_reply,
                                    pr);
  if (NULL != pr->qe)
    return;
  GNUNET_log(
    GNUNET_ERROR_TYPE_DEBUG,
    "ERROR Requesting `%s' of type %d with next_uid %llu from datastore.\n",
    GNUNET_h2s(&pr->public_data.query),
    pr->public_data.type,
    (unsigned long long)next_uid);
  GNUNET_STATISTICS_update(GSF_stats,
                           gettext_noop(
                             "# Datastore lookups concluded (error queueing)"),
                           1,
                           GNUNET_NO);
  call_continuation(pr);
}


/**
 * We're processing (local) results for a search request
 * from another peer.  Pass applicable results to the
 * peer and if we are done either clean up (operation
 * complete) or forward to other peers (more results possible).
 *
 * @param cls our closure (`struct GSF_PendingRequest *`)
 * @param key key for the content
 * @param size number of bytes in @a data
 * @param data content stored
 * @param type type of the content
 * @param priority priority of the content
 * @param anonymity anonymity-level for the content
 * @param replication replication-level for the content
 * @param expiration expiration time for the content
 * @param uid unique identifier for the datum;
 *        maybe 0 if no unique identifier is available
 */
static void
process_local_reply(void *cls,
                    const struct GNUNET_HashCode *key,
                    size_t size,
                    const void *data,
                    enum GNUNET_BLOCK_Type type,
                    uint32_t priority,
                    uint32_t anonymity,
                    uint32_t replication,
                    struct GNUNET_TIME_Absolute expiration,
                    uint64_t uid)
{
  struct GSF_PendingRequest *pr = cls;
  struct ProcessReplyClosure prq;
  struct GNUNET_HashCode query;
  unsigned int old_rf;

  GNUNET_SCHEDULER_cancel(pr->warn_task);
  pr->warn_task = NULL;
  if (NULL == pr->qe)
    goto called_from_on_demand;
  pr->qe = NULL;
  if (
    (NULL == key) && pr->seen_null &&
    !pr->have_first_uid)  /* We have hit the end for the 2nd time with no results */
    {
      /* No results */
#if INSANE_STATISTICS
      GNUNET_STATISTICS_update(GSF_stats,
                               gettext_noop(
                                 "# Datastore lookups concluded (no results)"),
                               1,
                               GNUNET_NO);
#endif
      no_more_local_results(pr);
      return;
    }
  if (((NULL == key) &&
       pr->seen_null) || /* We have hit the end for the 2nd time OR */
      (pr->seen_null && pr->have_first_uid &&
       (uid >= pr->first_uid))) /* We have hit the end and past first UID */
    {
      /* Seen all results */
      GNUNET_STATISTICS_update(GSF_stats,
                               gettext_noop(
                                 "# Datastore lookups concluded (seen all)"),
                               1,
                               GNUNET_NO);
      no_more_local_results(pr);
      return;
    }
  if (NULL == key)
    {
      GNUNET_assert(!pr->seen_null);
      pr->seen_null = true;
      start_local_query(pr, 0 /* next_uid */, false /* random */);
      return;
    }
  if (!pr->have_first_uid)
    {
      pr->first_uid = uid;
      pr->have_first_uid = true;
    }
  pr->result_count++;
  if (pr->result_count > MAX_RESULTS)
    {
      GNUNET_STATISTICS_update(
        GSF_stats,
        gettext_noop("# Datastore lookups aborted (more than MAX_RESULTS)"),
        1,
        GNUNET_NO);
      no_more_local_results(pr);
      return;
    }
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "Received reply for `%s' of type %d with UID %llu from datastore.\n",
             GNUNET_h2s(key),
             type,
             (unsigned long long)uid);
  if (GNUNET_BLOCK_TYPE_FS_ONDEMAND == type)
    {
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
                 "Found ONDEMAND block, performing on-demand encoding\n");
      GNUNET_STATISTICS_update(GSF_stats,
                               gettext_noop(
                                 "# on-demand blocks matched requests"),
                               1,
                               GNUNET_NO);
      pr->qe_start = GNUNET_TIME_absolute_get();
      pr->warn_task = GNUNET_SCHEDULER_add_delayed(GNUNET_TIME_UNIT_MINUTES,
                                                   &odc_warn_delay_task,
                                                   pr);
      if (GNUNET_OK == GNUNET_FS_handle_on_demand_block(key,
                                                        size,
                                                        data,
                                                        type,
                                                        priority,
                                                        anonymity,
                                                        replication,
                                                        expiration,
                                                        uid,
                                                        &process_local_reply,
                                                        pr))
        {
          GNUNET_STATISTICS_update(GSF_stats,
                                   gettext_noop(
                                     "# on-demand lookups performed successfully"),
                                   1,
                                   GNUNET_NO);
          return; /* we're done */
        }
      GNUNET_STATISTICS_update(GSF_stats,
                               gettext_noop("# on-demand lookups failed"),
                               1,
                               GNUNET_NO);
      GNUNET_SCHEDULER_cancel(pr->warn_task);
      start_local_query(pr, uid + 1 /* next_uid */, false /* random */);
      return;
    }
called_from_on_demand:
  old_rf = pr->public_data.results_found;
  memset(&prq, 0, sizeof(prq));
  prq.data = data;
  prq.expiration = expiration;
  prq.size = size;
  if (GNUNET_OK !=
      GNUNET_BLOCK_get_key(GSF_block_ctx, type, data, size, &query))
    {
      GNUNET_break(0);
      GNUNET_DATASTORE_remove(GSF_dsh,
                              key,
                              size,
                              data,
                              UINT_MAX,
                              UINT_MAX,
                              NULL,
                              NULL);
      start_local_query(pr, uid + 1 /* next_uid */, false /* random */);
      return;
    }
  prq.type = type;
  prq.priority = priority;
  prq.request_found = GNUNET_NO;
  prq.anonymity_level = anonymity;
  if ((0 == old_rf) && (0 == pr->public_data.results_found))
    GSF_update_datastore_delay_(pr->public_data.start_time);
  prq.eo = GNUNET_BLOCK_EO_LOCAL_SKIP_CRYPTO;
  process_reply(&prq, key, pr);
  pr->local_result = prq.eval;
  if (GNUNET_BLOCK_EVALUATION_OK_LAST == prq.eval)
    {
      GNUNET_STATISTICS_update(
        GSF_stats,
        gettext_noop("# Datastore lookups concluded (found last result)"),
        1,
        GNUNET_NO);
      call_continuation(pr);
      return;
    }
  if ((0 == (GSF_PRO_PRIORITY_UNLIMITED & pr->public_data.options)) &&
      ((GNUNET_YES == GSF_test_get_load_too_high_(0)) ||
       (pr->public_data.results_found > 5 + 2 * pr->public_data.priority)))
    {
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Load too high, done with request\n");
      GNUNET_STATISTICS_update(GSF_stats,
                               gettext_noop(
                                 "# Datastore lookups concluded (load too high)"),
                               1,
                               GNUNET_NO);
      call_continuation(pr);
      return;
    }
  start_local_query(pr, uid + 1 /* next_uid */, false /* random */);
}


/**
 * Is the given target a legitimate peer for forwarding the given request?
 *
 * @param pr request
 * @param target
 * @return #GNUNET_YES if this request could be forwarded to the given peer
 */
int
GSF_pending_request_test_target_(struct GSF_PendingRequest *pr,
                                 const struct GNUNET_PeerIdentity *target)
{
  struct GNUNET_PeerIdentity pi;

  if (0 == pr->origin_pid)
    return GNUNET_YES;
  GNUNET_PEER_resolve(pr->origin_pid, &pi);
  return (0 == memcmp(&pi, target, sizeof(struct GNUNET_PeerIdentity)))
         ? GNUNET_NO
         : GNUNET_YES;
}


/**
 * Look up the request in the local datastore.
 *
 * @param pr the pending request to process
 * @param cont function to call at the end
 * @param cont_cls closure for @a cont
 */
void
GSF_local_lookup_(struct GSF_PendingRequest *pr,
                  GSF_LocalLookupContinuation cont,
                  void *cont_cls)
{
  GNUNET_assert(NULL == pr->gh);
  GNUNET_assert(NULL == pr->cadet_request);
  GNUNET_assert(NULL == pr->llc_cont);
  pr->llc_cont = cont;
  pr->llc_cont_cls = cont_cls;
#if INSANE_STATISTICS
  GNUNET_STATISTICS_update(GSF_stats,
                           gettext_noop("# Datastore lookups initiated"),
                           1,
                           GNUNET_NO);
#endif
  start_local_query(pr, 0 /* next_uid */, true /* random */);
}


/**
 * Handle P2P "CONTENT" message.  Checks that the message is
 * well-formed and then checks if there are any pending requests for
 * this content and possibly passes it on (to local clients or other
 * peers).  Does NOT perform migration (content caching at this peer).
 *
 * @param cls the other peer involved
 * @param put the actual message
 */
void
handle_p2p_put(void *cls, const struct PutMessage *put)
{
  struct GSF_ConnectedPeer *cp = cls;
  uint16_t msize;
  size_t dsize;
  enum GNUNET_BLOCK_Type type;
  struct GNUNET_TIME_Absolute expiration;
  struct GNUNET_HashCode query;
  struct ProcessReplyClosure prq;
  struct GNUNET_TIME_Relative block_time;
  double putl;
  struct PutMigrationContext *pmc;

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "Received P2P PUT from %s\n",
             GNUNET_i2s(GSF_get_peer_performance_data_(cp)->peer));
  GSF_cover_content_count++;
  msize = ntohs(put->header.size);
  dsize = msize - sizeof(struct PutMessage);
  type = ntohl(put->type);
  expiration = GNUNET_TIME_absolute_ntoh(put->expiration);
  /* do not allow migrated content to live longer than 1 year */
  expiration = GNUNET_TIME_absolute_min(GNUNET_TIME_relative_to_absolute(
                                          GNUNET_TIME_UNIT_YEARS),
                                        expiration);
  if (GNUNET_OK !=
      GNUNET_BLOCK_get_key(GSF_block_ctx, type, &put[1], dsize, &query))
    {
      GNUNET_break_op(0);
      return;
    }
  GNUNET_STATISTICS_update(GSF_stats,
                           gettext_noop("# GAP PUT messages received"),
                           1,
                           GNUNET_NO);
  /* now, lookup 'query' */
  prq.data = (const void *)&put[1];
  prq.sender = cp;
  prq.size = dsize;
  prq.type = type;
  prq.expiration = expiration;
  prq.priority = 0;
  prq.anonymity_level = UINT32_MAX;
  prq.request_found = GNUNET_NO;
  prq.eo = GNUNET_BLOCK_EO_NONE;
  GNUNET_CONTAINER_multihashmap_get_multiple(pr_map,
                                             &query,
                                             &process_reply,
                                             &prq);
  if (NULL != cp)
    {
      GSF_connected_peer_change_preference_(cp,
                                            CONTENT_BANDWIDTH_VALUE +
                                            1000 * prq.priority);
      GSF_get_peer_performance_data_(cp)->respect += prq.priority;
    }
  if ((GNUNET_YES == active_to_migration) && (NULL != cp) &&
      (GNUNET_NO == test_put_load_too_high(prq.priority)))
    {
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
                 "Replicating result for query `%s' with priority %u\n",
                 GNUNET_h2s(&query),
                 prq.priority);
      pmc = GNUNET_new(struct PutMigrationContext);
      pmc->start = GNUNET_TIME_absolute_get();
      pmc->requested = prq.request_found;
      GNUNET_assert(0 != GSF_get_peer_performance_data_(cp)->pid);
      GNUNET_PEER_resolve(GSF_get_peer_performance_data_(cp)->pid,
                          &pmc->origin);
      if (NULL == GNUNET_DATASTORE_put(GSF_dsh,
                                       0,
                                       &query,
                                       dsize,
                                       &put[1],
                                       type,
                                       prq.priority,
                                       1 /* anonymity */,
                                       0 /* replication */,
                                       expiration,
                                       1 + prq.priority,
                                       MAX_DATASTORE_QUEUE,
                                       &put_migration_continuation,
                                       pmc))
        {
          put_migration_continuation(pmc,
                                     GNUNET_SYSERR,
                                     GNUNET_TIME_UNIT_ZERO_ABS,
                                     NULL);
        }
    }
  else if (NULL != cp)
    {
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
                 "Choosing not to keep content `%s' (%d/%d)\n",
                 GNUNET_h2s(&query),
                 active_to_migration,
                 test_put_load_too_high(prq.priority));
    }
  putl = GNUNET_LOAD_get_load(datastore_put_load);
  if ((NULL != cp) && (GNUNET_NO == prq.request_found) &&
      ((GNUNET_YES != active_to_migration) ||
       (putl > 2.5 * (1 + prq.priority))))
    {
      if (GNUNET_YES != active_to_migration)
        putl = 1.0 + GNUNET_CRYPTO_random_u32(GNUNET_CRYPTO_QUALITY_WEAK, 5);
      block_time = GNUNET_TIME_relative_multiply(
        GNUNET_TIME_UNIT_MILLISECONDS,
        5000 + GNUNET_CRYPTO_random_u32(GNUNET_CRYPTO_QUALITY_WEAK,
                                        (unsigned int)(60000 * putl * putl)));
      GNUNET_log(
        GNUNET_ERROR_TYPE_DEBUG,
        "Asking to stop migration for %s because of load %f and events %d/%d\n",
        GNUNET_STRINGS_relative_time_to_string(block_time, GNUNET_YES),
        putl,
        active_to_migration,
        (GNUNET_NO == prq.request_found));
      GSF_block_peer_migration_(cp,
                                GNUNET_TIME_relative_to_absolute(block_time));
    }
}


/**
 * Check if the given request is still active.
 *
 * @param pr pending request
 * @return #GNUNET_YES if the request is still active
 */
int
GSF_pending_request_test_active_(struct GSF_PendingRequest *pr)
{
  return (NULL != pr->rh) ? GNUNET_YES : GNUNET_NO;
}


/**
 * Setup the subsystem.
 */
void
GSF_pending_request_init_()
{
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number(GSF_cfg,
                                            "fs",
                                            "MAX_PENDING_REQUESTS",
                                            &max_pending_requests))
    {
      GNUNET_log_config_missing(GNUNET_ERROR_TYPE_INFO,
                                "fs",
                                "MAX_PENDING_REQUESTS");
    }
  active_to_migration =
    GNUNET_CONFIGURATION_get_value_yesno(GSF_cfg, "FS", "CONTENT_CACHING");
  datastore_put_load = GNUNET_LOAD_value_init(DATASTORE_LOAD_AUTODECLINE);
  pr_map = GNUNET_CONTAINER_multihashmap_create(32 * 1024, GNUNET_YES);
  requests_by_expiration_heap =
    GNUNET_CONTAINER_heap_create(GNUNET_CONTAINER_HEAP_ORDER_MIN);
}


/**
 * Shutdown the subsystem.
 */
void
GSF_pending_request_done_()
{
  GNUNET_CONTAINER_multihashmap_iterate(pr_map, &clean_request, NULL);
  GNUNET_CONTAINER_multihashmap_destroy(pr_map);
  pr_map = NULL;
  GNUNET_CONTAINER_heap_destroy(requests_by_expiration_heap);
  requests_by_expiration_heap = NULL;
  GNUNET_LOAD_value_free(datastore_put_load);
  datastore_put_load = NULL;
}


/* end of gnunet-service-fs_pr.c */
