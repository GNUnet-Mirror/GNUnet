/*
     This file is part of GNUnet.
     Copyright (C) 2011 GNUnet e.V.

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
 * @file dht/gnunet-service-dht_routing.c
 * @brief GNUnet DHT tracking of requests for routing replies
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet-service-dht_neighbours.h"
#include "gnunet-service-dht_routing.h"
#include "gnunet-service-dht.h"


/**
 * Number of requests we track at most (for routing replies).
 */
#define DHT_MAX_RECENT (1024 * 16)


/**
 * Information we keep about all recent GET requests
 * so that we can route replies.
 */
struct RecentRequest
{

  /**
   * The peer this request was received from.
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * Key of this request.
   */
  struct GNUNET_HashCode key;

  /**
   * Position of this node in the min heap.
   */
  struct GNUNET_CONTAINER_HeapNode *heap_node;

  /**
   * Bloomfilter for replies to drop.
   */
  struct GNUNET_CONTAINER_BloomFilter *reply_bf;

  /**
   * Type of the requested block.
   */
  enum GNUNET_BLOCK_Type type;

  /**
   * extended query (see gnunet_block_lib.h).  Allocated at the
   * end of this struct.
   */
  const void *xquery;

  /**
   * Number of bytes in xquery.
   */
  size_t xquery_size;

  /**
   * Mutator value for the reply_bf, see gnunet_block_lib.h
   */
  uint32_t reply_bf_mutator;

  /**
   * Request options.
   */
  enum GNUNET_DHT_RouteOption options;

};


/**
 * Recent requests by time inserted.
 */
static struct GNUNET_CONTAINER_Heap *recent_heap;

/**
 * Recently seen requests by key.
 */
static struct GNUNET_CONTAINER_MultiHashMap *recent_map;


/**
 * Closure for the 'process' function.
 */
struct ProcessContext
{
  /**
   * Path of the original PUT
   */
  const struct GNUNET_PeerIdentity *put_path;

  /**
   * Path of the reply.
   */
  const struct GNUNET_PeerIdentity *get_path;

  /**
   * Payload of the reply.
   */
  const void *data;

  /**
   * Expiration time of the result.
   */
  struct GNUNET_TIME_Absolute expiration_time;

  /**
   * Number of entries in @e put_path.
   */
  unsigned int put_path_length;

  /**
   * Number of entries in @e get_path.
   */
  unsigned int get_path_length;

  /**
   * Number of bytes in @e data.
   */
  size_t data_size;

  /**
   * Type of the reply.
   */
  enum GNUNET_BLOCK_Type type;

};


/**
 * Forward the result to the given peer if it matches the request.
 *
 * @param cls the `struct ProcessContext` with the result
 * @param key the query
 * @param value the `struct RecentRequest` with the request
 * @return #GNUNET_OK (continue to iterate),
 *         #GNUNET_SYSERR if the result is malformed or type unsupported
 */
static int
process (void *cls,
         const struct GNUNET_HashCode *key,
         void *value)
{
  struct ProcessContext *pc = cls;
  struct RecentRequest *rr = value;
  enum GNUNET_BLOCK_EvaluationResult eval;
  unsigned int gpl;
  unsigned int ppl;
  struct GNUNET_HashCode hc;
  const struct GNUNET_HashCode *eval_key;

  if ( (rr->type != GNUNET_BLOCK_TYPE_ANY) &&
       (rr->type != pc->type) )
    return GNUNET_OK;           /* type missmatch */

  if (0 != (rr->options & GNUNET_DHT_RO_RECORD_ROUTE))
  {
    gpl = pc->get_path_length;
    ppl = pc->put_path_length;
  }
  else
  {
    gpl = 0;
    ppl = 0;
  }
  if ( (0 != (rr->options & GNUNET_DHT_RO_FIND_PEER)) &&
       (pc->type == GNUNET_BLOCK_TYPE_DHT_HELLO) )
  {
    /* key may not match HELLO, which is OK since
     * the search is approximate.  Still, the evaluation
     * would fail since the match is not exact.  So
     * we fake it by changing the key to the actual PID ... */
    GNUNET_BLOCK_get_key (GDS_block_context,
			  GNUNET_BLOCK_TYPE_DHT_HELLO,
                          pc->data,
                          pc->data_size,
			  &hc);
    eval_key = &hc;
  }
  else
  {
    eval_key = key;
  }
  eval
    = GNUNET_BLOCK_evaluate (GDS_block_context,
                             pc->type,
                             GNUNET_BLOCK_EO_NONE,
                             eval_key,
                             &rr->reply_bf,
                             rr->reply_bf_mutator,
                             rr->xquery,
                             rr->xquery_size,
                             pc->data,
                             pc->data_size);
  switch (eval)
  {
  case GNUNET_BLOCK_EVALUATION_OK_MORE:
  case GNUNET_BLOCK_EVALUATION_OK_LAST:
    GNUNET_STATISTICS_update (GDS_stats,
                              gettext_noop
                              ("# Good REPLIES matched against routing table"),
                              1, GNUNET_NO);
    GDS_NEIGHBOURS_handle_reply (&rr->peer,
				 pc->type,
				 pc->expiration_time,
				 key,
                                 ppl, pc->put_path,
				 gpl, pc->get_path,
				 pc->data,
                                 pc->data_size);
    break;
  case GNUNET_BLOCK_EVALUATION_OK_DUPLICATE:
    GNUNET_STATISTICS_update (GDS_stats,
                              gettext_noop
                              ("# Duplicate REPLIES matched against routing table"),
                              1, GNUNET_NO);
    return GNUNET_OK;
  case GNUNET_BLOCK_EVALUATION_RESULT_INVALID:
    GNUNET_STATISTICS_update (GDS_stats,
                              gettext_noop
                              ("# Invalid REPLIES matched against routing table"),
                              1, GNUNET_NO);
    return GNUNET_SYSERR;
  case GNUNET_BLOCK_EVALUATION_RESULT_IRRELEVANT:
    GNUNET_STATISTICS_update (GDS_stats,
                              gettext_noop
                              ("# Irrelevant REPLIES matched against routing table"),
                              1, GNUNET_NO);
    return GNUNET_OK;
  case GNUNET_BLOCK_EVALUATION_REQUEST_VALID:
    GNUNET_break (0);
    return GNUNET_OK;
  case GNUNET_BLOCK_EVALUATION_REQUEST_INVALID:
    GNUNET_break (0);
    return GNUNET_OK;
  case GNUNET_BLOCK_EVALUATION_TYPE_NOT_SUPPORTED:
    GNUNET_STATISTICS_update (GDS_stats,
                              gettext_noop
                              ("# Unsupported REPLIES matched against routing table"),
                              1, GNUNET_NO);
    return GNUNET_SYSERR;
  default:
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handle a reply (route to origin).  Only forwards the reply back to
 * other peers waiting for it.  Does not do local caching or
 * forwarding to local clients.  Essentially calls
 * GDS_NEIGHBOURS_handle_reply for all peers that sent us a matching
 * request recently.
 *
 * @param type type of the block
 * @param expiration_time when does the content expire
 * @param key key for the content
 * @param put_path_length number of entries in @a put_path
 * @param put_path peers the original PUT traversed (if tracked)
 * @param get_path_length number of entries in @a get_path
 * @param get_path peers this reply has traversed so far (if tracked)
 * @param data payload of the reply
 * @param data_size number of bytes in data
 */
void
GDS_ROUTING_process (void *cls,
                     enum GNUNET_BLOCK_Type type,
                     struct GNUNET_TIME_Absolute expiration_time,
                     const struct GNUNET_HashCode *key,
                     unsigned int put_path_length,
                     const struct GNUNET_PeerIdentity *put_path,
                     unsigned int get_path_length,
                     const struct GNUNET_PeerIdentity *get_path,
                     const void *data,
                     size_t data_size)
{
  struct ProcessContext pc;

  pc.type = type;
  pc.expiration_time = expiration_time;
  pc.put_path_length = put_path_length;
  pc.put_path = put_path;
  pc.get_path_length = get_path_length;
  pc.get_path = get_path;
  pc.data = data;
  pc.data_size = data_size;
  if (NULL == data)
  {
    /* Some apps might have an 'empty' reply as a valid reply; however,
       'process' will call GNUNET_BLOCK_evaluate' which treats a 'NULL'
       reply as request-validation (but we need response-validation).
       So we set 'data' to a 0-byte non-NULL value just to be sure */
    GNUNET_break (0 == data_size);
    pc.data_size = 0;
    pc.data = ""; /* something not null */
  }
  GNUNET_CONTAINER_multihashmap_get_multiple (recent_map,
                                              key,
                                              &process,
                                              &pc);
}


/**
 * Remove the oldest entry from the DHT routing table.  Must only
 * be called if it is known that there is at least one entry
 * in the heap and hashmap.
 */
static void
expire_oldest_entry ()
{
  struct RecentRequest *recent_req;

  GNUNET_STATISTICS_update (GDS_stats,
			    gettext_noop
			    ("# Entries removed from routing table"), 1,
			    GNUNET_NO);
  recent_req = GNUNET_CONTAINER_heap_peek (recent_heap);
  GNUNET_assert (recent_req != NULL);
  GNUNET_CONTAINER_heap_remove_node (recent_req->heap_node);
  GNUNET_CONTAINER_bloomfilter_free (recent_req->reply_bf);
  GNUNET_assert (GNUNET_YES ==
		 GNUNET_CONTAINER_multihashmap_remove (recent_map,
						       &recent_req->key,
						       recent_req));
  GNUNET_free (recent_req);
}


/**
 * Try to combine multiple recent requests for the same value
 * (if they come from the same peer).
 *
 * @param cls the new 'struct RecentRequest' (to discard upon successful combination)
 * @param key the query
 * @param value the existing 'struct RecentRequest' (to update upon successful combination)
 * @return #GNUNET_OK (continue to iterate),
 *         #GNUNET_SYSERR if the request was successfully combined
 */
static int
try_combine_recent (void *cls,
                    const struct GNUNET_HashCode *key,
                    void *value)
{
  struct RecentRequest *in = cls;
  struct RecentRequest *rr = value;

  if ( (0 != memcmp (&in->peer,
		     &rr->peer,
		     sizeof (struct GNUNET_PeerIdentity))) ||
       (in->type != rr->type) ||
       (in->xquery_size != rr->xquery_size) ||
       (0 != memcmp (in->xquery,
		     rr->xquery,
		     in->xquery_size)) )
    return GNUNET_OK;
  if (in->reply_bf_mutator != rr->reply_bf_mutator)
  {
    rr->reply_bf_mutator = in->reply_bf_mutator;
    GNUNET_CONTAINER_bloomfilter_free (rr->reply_bf);
    rr->reply_bf = in->reply_bf;
  }
  else
  {
    GNUNET_CONTAINER_bloomfilter_or2 (rr->reply_bf,
				      in->reply_bf);
    GNUNET_CONTAINER_bloomfilter_free (in->reply_bf);
  }
  GNUNET_free (in);
  return GNUNET_SYSERR;
}


/**
 * Add a new entry to our routing table.
 *
 * @param sender peer that originated the request
 * @param type type of the block
 * @param options options for processing
 * @param key key for the content
 * @param xquery extended query
 * @param xquery_size number of bytes in @a xquery
 * @param reply_bf bloomfilter to filter duplicates
 * @param reply_bf_mutator mutator for @a reply_bf
 */
void
GDS_ROUTING_add (const struct GNUNET_PeerIdentity *sender,
                 enum GNUNET_BLOCK_Type type,
                 enum GNUNET_DHT_RouteOption options,
                 const struct GNUNET_HashCode *key,
                 const void *xquery,
                 size_t xquery_size,
                 const struct GNUNET_CONTAINER_BloomFilter *reply_bf,
                 uint32_t reply_bf_mutator)
{
  struct RecentRequest *recent_req;

  while (GNUNET_CONTAINER_heap_get_size (recent_heap) >= DHT_MAX_RECENT)
    expire_oldest_entry ();
  GNUNET_STATISTICS_update (GDS_stats,
                            gettext_noop ("# Entries added to routing table"),
                            1, GNUNET_NO);
  recent_req = GNUNET_malloc (sizeof (struct RecentRequest) + xquery_size);
  recent_req->peer = *sender;
  recent_req->key = *key;
  recent_req->reply_bf = GNUNET_CONTAINER_bloomfilter_copy (reply_bf);
  recent_req->type = type;
  recent_req->options = options;
  recent_req->xquery = &recent_req[1];
  GNUNET_memcpy (&recent_req[1], xquery, xquery_size);
  recent_req->xquery_size = xquery_size;
  recent_req->reply_bf_mutator = reply_bf_mutator;
  if (GNUNET_SYSERR ==
      GNUNET_CONTAINER_multihashmap_get_multiple (recent_map,
                                                  key,
						  &try_combine_recent,
                                                  recent_req))
  {
    GNUNET_STATISTICS_update (GDS_stats,
                              gettext_noop
                              ("# DHT requests combined"),
                              1, GNUNET_NO);
    return;
  }
  recent_req->heap_node =
      GNUNET_CONTAINER_heap_insert (recent_heap, recent_req,
                                    GNUNET_TIME_absolute_get ().abs_value_us);
  GNUNET_CONTAINER_multihashmap_put (recent_map, key, recent_req,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);


}


/**
 * Initialize routing subsystem.
 */
void
GDS_ROUTING_init ()
{
  recent_heap = GNUNET_CONTAINER_heap_create (GNUNET_CONTAINER_HEAP_ORDER_MIN);
  recent_map = GNUNET_CONTAINER_multihashmap_create (DHT_MAX_RECENT * 4 / 3, GNUNET_NO);
}


/**
 * Shutdown routing subsystem.
 */
void
GDS_ROUTING_done ()
{
  while (GNUNET_CONTAINER_heap_get_size (recent_heap) > 0)
    expire_oldest_entry ();
  GNUNET_assert (0 == GNUNET_CONTAINER_heap_get_size (recent_heap));
  GNUNET_CONTAINER_heap_destroy (recent_heap);
  recent_heap = NULL;
  GNUNET_assert (0 == GNUNET_CONTAINER_multihashmap_size (recent_map));
  GNUNET_CONTAINER_multihashmap_destroy (recent_map);
  recent_map = NULL;
}

/* end of gnunet-service-dht_routing.c */
