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
 * @file fs/gnunet-service-fs_pr.c
 * @brief API to handle pending requests
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet-service-fs_pr.h"


/**
 * An active request.
 */
struct GSF_PendingRequest
{
  /**
   * Public data for the request.
   */ 
  struct GSF_PendingRequestData public_data;

  /**
   * Function to call if we encounter a reply.
   */
  GSF_PendingRequestReplyHandler rh;

  /**
   * Closure for 'rh'
   */
  void *rh_cls;

  /**
   * Array of hash codes of replies we've already seen.
   */
  GNUNET_HashCode *replies_seen;

  /**
   * Bloomfilter masking replies we've already seen.
   */
  struct GNUNET_CONTAINER_BloomFilter *bf;

  /**
   * Number of valid entries in the 'replies_seen' array.
   */
  unsigned int replies_seen_count;

  /**
   * Length of the 'replies_seen' array.
   */
  unsigned int replies_seen_size;

  /**
   * Mingle value we currently use for the bf.
   */
  int32_t mingle;
			    
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
 * How many bytes should a bloomfilter be if we have already seen
 * entry_count responses?  Note that BLOOMFILTER_K gives us the number
 * of bits set per entry.  Furthermore, we should not re-size the
 * filter too often (to keep it cheap).
 *
 * Since other peers will also add entries but not resize the filter,
 * we should generally pick a slightly larger size than what the
 * strict math would suggest.
 *
 * @return must be a power of two and smaller or equal to 2^15.
 */
static size_t
compute_bloomfilter_size (unsigned int entry_count)
{
  size_t size;
  unsigned int ideal = (entry_count * BLOOMFILTER_K) / 4;
  uint16_t max = 1 << 15;

  if (entry_count > max)
    return max;
  size = 8;
  while ((size < max) && (size < ideal))
    size *= 2;
  if (size > max)
    return max;
  return size;
}


/**
 * Recalculate our bloom filter for filtering replies.  This function
 * will create a new bloom filter from scratch, so it should only be
 * called if we have no bloomfilter at all (and hence can create a
 * fresh one of minimal size without problems) OR if our peer is the
 * initiator (in which case we may resize to larger than mimimum size).
 *
 * @param pr request for which the BF is to be recomputed
 * @return GNUNET_YES if a refresh actually happened
 */
static int
refresh_bloomfilter (struct GSF_PendingRequest *pr)
{
  unsigned int i;
  size_t nsize;
  GNUNET_HashCode mhash;

  nsize = compute_bloomfilter_size (pr->replies_seen_off);
  if ( (bf != NULL) &&
       (nsize == GNUNET_CONTAINER_bloomfilter_get_size (pr->bf)) )
    return GNUNET_NO; /* size not changed */
  if (pr->bf != NULL)
    GNUNET_CONTAINER_bloomfilter_free (pr->bf);
  pr->mingle = (int32_t) GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, 
						   UINT32_MAX);
  pr->bf = GNUNET_CONTAINER_bloomfilter_init (NULL, 
					      nsize,
					      BLOOMFILTER_K);
  for (i=0;i<pr->replies_seen_count;i++)
    {
      GNUNET_BLOCK_mingle_hash (&pr->replies_seen[i],
				pr->mingle,
				&mhash);
      GNUNET_CONTAINER_bloomfilter_add (pr->bf, &mhash);
    }
  return GNUNET_YES;
}


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
 * @param replies_seen hash codes of known local replies
 * @param replies_seen_count size of the 'replies_seen' array
 * @param rh handle to call when we get a reply
 * @param rh_cls closure for rh
 * @return handle for the new pending request
 */
struct GSF_PendingRequest *
GSF_pending_request_create_ (enum GSF_PendingRequestOptions options,
			     enum GNUNET_BLOCK_Type type,
			     const GNUNET_HashCode *query,
			     const GNUNET_HashCode *namespace,
			     const struct GNUNET_PeerIdentity *target,
			     const char *bf_data,
			     size_t bf_size,
			     int32_t mingle,
			     uint32_t anonymity_level,
			     uint32_t priority,
			     int32_t ttl,
			     const GNUNET_HashCode *replies_seen,
			     unsigned int replies_seen_count,
			     GSF_PendingRequestReplyHandler rh,
			     void *rh_cls)
{
  struct GSF_PendingRequest *pr;

  
  pr = GNUNET_malloc (sizeof (struct GSF_PendingRequest));
  pr->public_data.query = *query;
  if (GNUNET_BLOCK_TYPE_SBLOCK == type)
    {
      GNUNET_assert (NULL != namespace);
      pr->public_data.namespace = *namespace;
    }
  if (NULL != target)
    {
      pr->public_data.target = *target;
      pr->has_target = GNUNET_YES;
    }
  pr->public_data.anonymity_level = anonymity_data;
  pr->public_data.priority = priority;
  pr->public_data.options = options;
  pr->public_data.type = type;  
  pr->public_data.start_time = GNUNET_TIME_absolute_get ();
  pr->rh = rh;
  pr->rh_cls = rh_cls;
  if (ttl >= 0)
    pr->ttl = GNUNET_TIME_relative_to_absolute (GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS,
									       (uint32_t) ttl));
  else
    pr->ttl = GNUNET_TIME_absolute_subtract (pr->public_data.start_time,
					     GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS,
									    (uint32_t) (- ttl)));
  if (replies_seen_count > 0)
    {
      pr->replies_seen_size = replies_seen_count;
      pr->replies_seen = GNUNET_malloc (sizeof (GNUNET_HashCode) * pr->replies_seen_size);
      memcpy (pr->replies_seen,
	      replies_seen,
	      replies_seen_count * sizeof (struct GNUNET_HashCode));
      pr->replies_seen_count = replies_seen_count;
    }
  if (NULL != bf_data)    
    {
      pr->bf = GNUNET_CONTAINER_bloomfilter_init (bf_data,
						  bf_size,
						  BLOOMFILTER_K);
      pr->mingle = mingle;
    }
  else if ( (replies_seen_count > 0) &&
	    (0 != (options & GSF_PRO_BLOOMFILTER_FULL_REFRESH)) )
    {
      GNUNET_assert (GNUNET_YES == refresh_bloomfilter (pr));
    }
  GNUNET_CONTAINER_multihashmap_put (pr_map,
				     query,
				     pr,
				     GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
  // FIXME: if not a local query, we also need to track the
  // total number of external queries we currently have and
  // bound it => need an additional heap!

  pr->hnode = GNUNET_CONTAINER_heap_insert (requests_by_expiration_heap,
					    pr,
					    pr->start_time.abs_value + pr->ttl);



  /* make sure we don't track too many requests */
  if (GNUNET_CONTAINER_heap_get_size (requests_by_expiration_heap) > max_pending_requests)
    {
      pr = GNUNET_CONTAINER_heap_peek (requests_by_expiration_heap);
      GNUNET_assert (pr != NULL);
      destroy_pending_request (pr);
    }


  return pr;
}


/**
 * Obtain the public data associated with a pending request
 * 
 * @param pr pending request
 * @return associated public data
 */
struct GSF_PendingRequestData *
GSF_pending_request_get_data_ (struct GSF_PendingRequest *pr)
{
  return &pr->public_data;
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
GSF_pending_request_update_ (struct GSF_PendingRequest *pr,
			     const GNUNET_HashCode *replies_seen,
			     unsigned int replies_seen_count)
{
  unsigned int i;
  GNUNET_HashCode mhash;

  if (replies_seen_count + pr->replies_seen_count < pr->replies_seen_count)
    return; /* integer overflow */
  if (0 != (options & GSF_PRO_BLOOMFILTER_FULL_REFRESH))
    {
      /* we're responsible for the BF, full refresh */
      if (replies_seen_count + pr->replies_seen_count > pr->replies_seen_size)
	GNUNET_array_grow (pr->replies_seen,
			   pr->replies_seen_size,
			   replies_seen_count + pr->replies_seen_count);
      memcpy (&pr->replies_seen[pr->replies_seen_count],
	      replies_seen,
	      sizeof (GNUNET_HashCode) * replies_seen_count);
      pr->replies_seen_count += replies_seen;
      if (GNUNET_NO == refresh_bloomfilter (pr))
	{
	  /* bf not recalculated, simply extend it with new bits */
	  for (i=0;i<pr->replies_seen_count;i++)
	    {
	      GNUNET_BLOCK_mingle_hash (&replies_seen[i],
					pr->mingle,
					&mhash);
	      GNUNET_CONTAINER_bloomfilter_add (pr->bf, &mhash);
	    }
	}
    }
  else
    {
      if (NULL == pr->bf)
	{
	  /* we're not the initiator, but the initiator did not give us
	     any bloom-filter, so we need to create one on-the-fly */
	  pr->mingle = (int32_t) GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, 
							   UINT32_MAX);
	  pr->bf = GNUNET_CONTAINER_bloomfilter_init (compute_bloomfilter_size (replies_seen_count),
						      pr->mingle,
						      BLOOMFILTER_K);
	}
      for (i=0;i<pr->replies_seen_count;i++)
	{
	  GNUNET_BLOCK_mingle_hash (&replies_seen[i],
				    pr->mingle,
				    &mhash);
	  GNUNET_CONTAINER_bloomfilter_add (pr->bf, &mhash);
	}
    }
}


/**
 * Generate the message corresponding to the given pending request for
 * transmission to other peers (or at least determine its size).
 *
 * @param pr request to generate the message for
 * @param do_route are we routing the reply
 * @param buf_size number of bytes available in buf
 * @param buf where to copy the message (can be NULL)
 * @return number of bytes needed (if > buf_size) or used
 */
size_t
GSF_pending_request_get_message_ (struct GSF_PendingRequest *pr,
				  int do_route,
				  size_t buf_size,
				  void *buf)
{
  struct PendingMessage *pm;
  char lbuf[GNUNET_SERVER_MAX_MESSAGE_SIZE];
  struct GetMessage *gm;
  GNUNET_HashCode *ext;
  size_t msize;
  unsigned int k;
  int no_route;
  uint32_t bm;
  uint32_t prio;
  size_t bf_size;

  k = 0;
  bm = 0;
  if (GNUNET_YES != do_route)
    {
      bm |= GET_MESSAGE_BIT_RETURN_TO;
      k++;      
    }
  if (GNUNET_BLOCK_TYPE_SBLOCK == pr->type)
    {
      bm |= GET_MESSAGE_BIT_SKS_NAMESPACE;
      k++;
    }
  if (GNUNET_YES == pr->has_target)
    {
      bm |= GET_MESSAGE_BIT_TRANSMIT_TO;
      k++;
    }
  bf_size = GNUNET_CONTAINER_bloomfilter_get_size (pr->bf);
  msize = sizeof (struct GetMessage) + bf_size + k * sizeof(GNUNET_HashCode);
  GNUNET_assert (msize < GNUNET_SERVER_MAX_MESSAGE_SIZE);
  if (buf_size < msize)
    return msize;  
  gm = (struct GetMessage*) lbuf;
  gm->header.type = htons (GNUNET_MESSAGE_TYPE_FS_GET);
  gm->header.size = htons (msize);
  gm->type = htonl (pr->type);
  if (GNUNET_YES == do_route)
    prio = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
				     pr->public_data.priority + 1);
  else
    prio = 0;
  pr->public_data.priority -= prio;
  gm->priority = htonl (prio);
  gm->ttl = htonl (pr->ttl);
  gm->filter_mutator = htonl(pr->mingle); 
  gm->hash_bitmap = htonl (bm);
  gm->query = pr->query;
  ext = (GNUNET_HashCode*) &gm[1];
  k = 0;
  if (GNUNET_YES != do_route)
    GNUNET_PEER_resolve (pr->cp->pid, (struct GNUNET_PeerIdentity*) &ext[k++]);
  if (GNUNET_BLOCK_TYPE_SBLOCK == pr->type)
    memcpy (&ext[k++], pr->namespace, sizeof (GNUNET_HashCode));
  if (GNUNET_YES == pr->has_target)
    GNUNET_PEER_resolve (pr->target_pid, (struct GNUNET_PeerIdentity*) &ext[k++]);
  if (pr->bf != NULL)
    GNUNET_CONTAINER_bloomfilter_get_raw_data (pr->bf,
					       (char*) &ext[k],
					       bf_size);
  memcpy (buf, gm, msize);
  return msize;
}


/**
 * Iterator to free pending requests.
 *
 * @param cls closure, unused
 * @param key current key code
 * @param value value in the hash map (pending request)
 * @return GNUNET_YES (we should continue to iterate)
 */
static int 
clean_request (void *cls,
	       const GNUNET_HashCode * key,
	       void *value)
{
  struct GSF_PendingRequest *pr = value;
  
  GNUNET_free_non_null (pr->replies_seen);
  if (NULL != pr->bf)
    GNUNET_CONTAINER_bloomfilter_free (pr->bf);
  GNUNET_free (pr);
  return GNUNET_YES;
}


/**
 * Explicitly cancel a pending request.
 *
 * @param pr request to cancel
 */
void
GSF_pending_request_cancel_ (struct GSF_PendingRequest *pr)
{
  GNUNET_assert (GNUNET_OK ==
		 GNUNET_CONTAINER_multihashmap_remove (pr_map,
						       &pr->public_data.query,
						       pr));
  GNUNET_assert (GNUNET_YES ==
		 clean_request (NULL, &pr->public_data.query, pr));  
}


/**
 * Iterate over all pending requests.
 *
 * @param it function to call for each request
 * @param cls closure for it
 */
void
GSF_iterate_pending_pr_map_ (GSF_PendingRequestIterator it,
			     void *cls)
{
  GNUNET_CONTAINER_multihashmap_iterate (pr_map,
					 (GNUNET_CONTAINER_HashMapIterator) it,
					 cls);
}




/**
 * Closure for "process_reply" function.
 */
struct ProcessReplyClosure
{
  /**
   * The data for the reply.
   */
  const void *data;

  /**
   * Who gave us this reply? NULL for local host (or DHT)
   */
  struct ConnectedPeer *sender;

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
   * Did we finish processing the associated request?
   */ 
  int finished;

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
update_request_performance_data (struct ProcessReplyClosure *prq,
				 struct GSF_PendingRequest *pr)
{
  unsigned int i;
  struct GNUNET_TIME_Relative cur_delay;

  if (prq->sender == NULL)
    return;      
  /* FIXME: adapt code to new API... */
  for (i=0;i<pr->used_targets_off;i++)
    if (pr->used_targets[i].pid == prq->sender->pid)
      break;
  if (i < pr->used_targets_off)
    {
      cur_delay = GNUNET_TIME_absolute_get_duration (pr->used_targets[i].last_request_time);      
      prq->sender->avg_delay.rel_value
	= (prq->sender->avg_delay.rel_value * 
	   (RUNAVG_DELAY_N - 1) + cur_delay.rel_value) / RUNAVG_DELAY_N; 
      prq->sender->avg_priority
	= (prq->sender->avg_priority * 
	   (RUNAVG_DELAY_N - 1) + pr->priority) / (double) RUNAVG_DELAY_N;
    }
  if (pr->cp != NULL)
    {
      GNUNET_PEER_change_rc (prq->sender->last_p2p_replies
			     [prq->sender->last_p2p_replies_woff % P2P_SUCCESS_LIST_SIZE], 
			     -1);
      GNUNET_PEER_change_rc (pr->cp->pid, 1);
      prq->sender->last_p2p_replies
	[(prq->sender->last_p2p_replies_woff++) % P2P_SUCCESS_LIST_SIZE]
	= pr->cp->pid;
    }
  else
    {
      if (NULL != prq->sender->last_client_replies
	  [(prq->sender->last_client_replies_woff) % CS2P_SUCCESS_LIST_SIZE])
	GNUNET_SERVER_client_drop (prq->sender->last_client_replies
				   [(prq->sender->last_client_replies_woff) % CS2P_SUCCESS_LIST_SIZE]);
      prq->sender->last_client_replies
	[(prq->sender->last_client_replies_woff++) % CS2P_SUCCESS_LIST_SIZE]
	= pr->client_request_list->client_list->client;
      GNUNET_SERVER_client_keep (pr->client_request_list->client_list->client);
    }
}
				


/**
 * We have received a reply; handle it!
 *
 * @param cls response (struct ProcessReplyClosure)
 * @param key our query
 * @param value value in the hash map (info about the query)
 * @return GNUNET_YES (we should continue to iterate)
 */
static int
process_reply (void *cls,
	       const GNUNET_HashCode * key,
	       void *value)
{
  struct ProcessReplyClosure *prq = cls;
  struct GSF_PendingRequest *pr = value;
  struct PendingMessage *reply;
  struct ClientResponseMessage *creply;
  struct ClientList *cl;
  struct PutMessage *pm;
  struct ConnectedPeer *cp;
  size_t msize;

#if DEBUG_FS
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Matched result (type %u) for query `%s' with pending request\n",
	      (unsigned int) prq->type,
	      GNUNET_h2s (key));
#endif  
  GNUNET_STATISTICS_update (stats,
			    gettext_noop ("# replies received and matched"),
			    1,
			    GNUNET_NO);
  prq->eval = GNUNET_BLOCK_evaluate (block_ctx,
				     prq->type,
				     key,
				     &pr->bf,
				     pr->mingle,
				     pr->namespace, (pr->namespace != NULL) ? sizeof (GNUNET_HashCode) : 0,
				     prq->data,
				     prq->size);
  switch (prq->eval)
    {
    case GNUNET_BLOCK_EVALUATION_OK_MORE:
      update_request_performance_data (prq, pr);
      break;
    case GNUNET_BLOCK_EVALUATION_OK_LAST:
      update_request_performance_data (prq, pr);
      /* FIXME: adapt code to new API! */
      while (NULL != pr->pending_head)
	destroy_pending_message_list_entry (pr->pending_head);
      if (pr->qe != NULL)
	{
	  if (pr->client_request_list != NULL)
	    GNUNET_SERVER_receive_done (pr->client_request_list->client_list->client, 
					GNUNET_YES);
	  GNUNET_DATASTORE_cancel (pr->qe);
	  pr->qe = NULL;
	}
      pr->do_remove = GNUNET_YES;
      if (pr->task != GNUNET_SCHEDULER_NO_TASK)
	{
	  GNUNET_SCHEDULER_cancel (pr->task);
	  pr->task = GNUNET_SCHEDULER_NO_TASK;
	}
      GNUNET_break (GNUNET_YES ==
		    GNUNET_CONTAINER_multihashmap_remove (query_request_map,
							  key,
							  pr));
      GNUNET_LOAD_update (rt_entry_lifetime,
			  GNUNET_TIME_absolute_get_duration (pr->start_time).rel_value);
      break;
    case GNUNET_BLOCK_EVALUATION_OK_DUPLICATE:
      GNUNET_STATISTICS_update (stats,
				gettext_noop ("# duplicate replies discarded (bloomfilter)"),
				1,
				GNUNET_NO);
#if DEBUG_FS && 0
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Duplicate response `%s', discarding.\n",
		  GNUNET_h2s (&mhash));
#endif
      return GNUNET_YES; /* duplicate */
    case GNUNET_BLOCK_EVALUATION_RESULT_INVALID:
      return GNUNET_YES; /* wrong namespace */	
    case GNUNET_BLOCK_EVALUATION_REQUEST_VALID:
      GNUNET_break (0);
      return GNUNET_YES;
    case GNUNET_BLOCK_EVALUATION_REQUEST_INVALID:
      GNUNET_break (0);
      return GNUNET_YES;
    case GNUNET_BLOCK_EVALUATION_TYPE_NOT_SUPPORTED:
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Unsupported block type %u\n"),
		  prq->type);
      return GNUNET_NO;
    }
  /* FIXME: adapt code to new API! */
  if (pr->client_request_list != NULL)
    {
      if (pr->replies_seen_size == pr->replies_seen_off)
	GNUNET_array_grow (pr->replies_seen,
			   pr->replies_seen_size,
			   pr->replies_seen_size * 2 + 4);	
      GNUNET_CRYPTO_hash (prq->data,
			  prq->size,
			  &pr->replies_seen[pr->replies_seen_off++]);	      
      refresh_bloomfilter (pr);
    }
  if (NULL == prq->sender)
    {
#if DEBUG_FS
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Found result for query `%s' in local datastore\n",
		  GNUNET_h2s (key));
#endif
      GNUNET_STATISTICS_update (stats,
				gettext_noop ("# results found locally"),
				1,
				GNUNET_NO);      
    }
  prq->priority += pr->remaining_priority;
  pr->remaining_priority = 0;
  pr->results_found++;
  prq->request_found = GNUNET_YES;
  /* finally, pass on to other peers / local clients */
  pr->rh (pr->rh_cls, pr, prq->data, prq->size);
  return GNUNET_YES;
}


/**
 * Continuation called to notify client about result of the
 * operation.
 *
 * @param cls closure
 * @param success GNUNET_SYSERR on failure
 * @param msg NULL on success, otherwise an error message
 */
static void 
put_migration_continuation (void *cls,
			    int success,
			    const char *msg)
{
  struct GNUNET_TIME_Absolute *start = cls;
  struct GNUNET_TIME_Relative delay;
  
  delay = GNUNET_TIME_absolute_get_duration (*start);
  GNUNET_free (start);
  /* FIXME: should we really update the load value on failure? */
  GNUNET_LOAD_update (datastore_put_load,
		      delay.rel_value);
  if (GNUNET_OK == success)
    return;
  GNUNET_STATISTICS_update (stats,
			    gettext_noop ("# datastore 'put' failures"),
			    1,
			    GNUNET_NO);
}


/**
 * Test if the DATABASE (PUT) load on this peer is too high
 * to even consider processing the query at
 * all.  
 * 
 * @return GNUNET_YES if the load is too high to do anything (load high)
 *         GNUNET_NO to process normally (load normal or low)
 */
static int
test_put_load_too_high (uint32_t priority)
{
  double ld;

  if (GNUNET_LOAD_get_average (datastore_put_load) < 50)
    return GNUNET_NO; /* very fast */
  ld = GNUNET_LOAD_get_load (datastore_put_load);
  if (ld < 2.0 * (1 + priority))
    return GNUNET_NO;
  GNUNET_STATISTICS_update (stats,
			    gettext_noop ("# storage requests dropped due to high load"),
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
 * @param get_path NULL-terminated array of pointers
 *                 to the peers on reverse GET path (or NULL if not recorded)
 * @param put_path NULL-terminated array of pointers
 *                 to the peers on the PUT path (or NULL if not recorded)
 * @param type type of the result
 * @param size number of bytes in data
 * @param data pointer to the result data
 */
void
GSF_handle_dht_reply_ (void *cls,
		       struct GNUNET_TIME_Absolute exp,
		       const GNUNET_HashCode * key,
		       const struct GNUNET_PeerIdentity * const *get_path,
		       const struct GNUNET_PeerIdentity * const *put_path,
		       enum GNUNET_BLOCK_Type type,
		       size_t size,
		       const void *data)
{
  struct GSF_PendingRequest *pr = cls;
  struct ProcessReplyClosure prq;

  memset (&prq, 0, sizeof (prq));
  prq.data = data;
  prq.expiration = exp;
  prq.size = size;  
  prq.type = type;
  process_reply (&prq, key, pr);
  if ( (GNUNET_YES == active_to_migration) &&
       (GNUNET_NO == test_put_load_too_high (prq.priority)) )
    {      
#if DEBUG_FS
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Replicating result for query `%s' with priority %u\n",
		  GNUNET_h2s (&query),
		  prq.priority);
#endif
      start = GNUNET_malloc (sizeof (struct GNUNET_TIME_Absolute));
      *start = GNUNET_TIME_absolute_get ();
      GNUNET_DATASTORE_put (dsh,
			    0, &query, dsize, &put[1],
			    type, prq.priority, 1 /* anonymity */, 
			    expiration, 
			    1 + prq.priority, MAX_DATASTORE_QUEUE,
			    GNUNET_CONSTANTS_SERVICE_TIMEOUT,
			    &put_migration_continuation, 
			    start);
    }
}


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
			 const struct GNUNET_MessageHeader *message)
{
  const struct PutMessage *put;
  uint16_t msize;
  size_t dsize;
  enum GNUNET_BLOCK_Type type;
  struct GNUNET_TIME_Absolute expiration;
  GNUNET_HashCode query;
  struct ProcessReplyClosure prq;
  struct GNUNET_TIME_Relative block_time;  
  double putl;
  struct GNUNET_TIME_Absolute *start;

  msize = ntohs (message->size);
  if (msize < sizeof (struct PutMessage))
    {
      GNUNET_break_op(0);
      return GNUNET_SYSERR;
    }
  put = (const struct PutMessage*) message;
  dsize = msize - sizeof (struct PutMessage);
  type = ntohl (put->type);
  expiration = GNUNET_TIME_absolute_ntoh (put->expiration);
  if (type == GNUNET_BLOCK_TYPE_FS_ONDEMAND)
    return GNUNET_SYSERR;
  if (GNUNET_OK !=
      GNUNET_BLOCK_get_key (block_ctx,
			    type,
			    &put[1],
			    dsize,
			    &query))
    {
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
  /* now, lookup 'query' */
  prq.data = (const void*) &put[1];
  if (NULL != cp)
    prq.sender = cp;
  else
    prq.sender = NULL;
  prq.size = dsize;
  prq.type = type;
  prq.expiration = expiration;
  prq.priority = 0;
  prq.anonymity_level = 1;
  prq.finished = GNUNET_NO;
  prq.request_found = GNUNET_NO;
  GNUNET_CONTAINER_multihashmap_get_multiple (query_request_map,
					      &query,
					      &process_reply,
					      &prq);
  if (NULL != cp)
    {
      GSF_connected_peer_change_preference (cp, CONTENT_BANDWIDTH_VALUE + 1000 * prq.priority);
      GSF_get_peer_performance_data (cp)->trust += prq.priority;
    }
  if ( (GNUNET_YES == active_to_migration) &&
       (GNUNET_NO == test_put_load_too_high (prq.priority)) )
    {      
#if DEBUG_FS
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Replicating result for query `%s' with priority %u\n",
		  GNUNET_h2s (&query),
		  prq.priority);
#endif
      start = GNUNET_malloc (sizeof (struct GNUNET_TIME_Absolute));
      *start = GNUNET_TIME_absolute_get ();
      GNUNET_DATASTORE_put (dsh,
			    0, &query, dsize, &put[1],
			    type, prq.priority, 1 /* anonymity */, 
			    expiration, 
			    1 + prq.priority, MAX_DATASTORE_QUEUE,
			    GNUNET_CONSTANTS_SERVICE_TIMEOUT,
			    &put_migration_continuation, 
			    start);
    }
  putl = GNUNET_LOAD_get_load (datastore_put_load);
  if ( (NULL != (cp = prq.sender)) &&
       (GNUNET_NO == prq.request_found) &&
       ( (GNUNET_YES != active_to_migration) ||
	 (putl > 2.5 * (1 + prq.priority)) ) ) 
    {
      if (GNUNET_YES != active_to_migration) 
	putl = 1.0 + GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, 5);
      block_time = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS,
						  5000 + GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
										   (unsigned int) (60000 * putl * putl)));
      GSF_block_peer_migration (cp, block_time);
    }
  return GNUNET_OK;
}


/**
 * Setup the subsystem.
 */
void
GSF_pending_request_init_ ()
{
  pr_map = GNUNET_CONTAINER_multihashmap_create (32 * 1024);
}


/**
 * Shutdown the subsystem.
 */
void
GSF_pending_request_done_ ()
{
  GNUNET_CONTAINER_multihashmap_iterate (pr_map,
					 &clean_request,
					 NULL);
  GNUNET_CONTAINER_multihashmap_destroy (pr_map);
  pr_map = NULL;
}


/* end of gnunet-service-fs_pr.c */
