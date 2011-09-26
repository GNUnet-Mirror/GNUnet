/*
     This file is part of GNUnet.
     (C) 2011 Christian Grothoff (and other contributing authors)

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
 * @file dht/gnunet-service-dht_routing.c
 * @brief GNUnet DHT tracking of requests for routing replies
 * @author Christian Grothoff
 */

#include "gnunet-service-dht_routing.h"


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
   * Position of this node in the min heap.
   */
  struct GNUNET_CONTAINER_HeapNode *heap_node;

  /**
   * Bloomfilter for replies to drop.
   */
  struct GNUNET_CONTAINER_BloomFilter *reply_bf;

  /**
   * Timestamp of this request, for ordering
   * the min heap.
   */
  struct GNUNET_TIME_Absolute timestamp;

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
   * Key of this request.
   */
  GNUNET_HashCode key;

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
 * Handle a reply (route to origin).  Only forwards the reply back to
 * other peers waiting for it.  Does not do local caching or
 * forwarding to local clients.  Essentially calls
 * GDS_NEIGHBOURS_handle_reply for all peers that sent us a matching
 * request recently.
 *
 * @param type type of the block
 * @param expiration_time when does the content expire
 * @param key key for the content
 * @param put_path_length number of entries in put_path
 * @param put_path peers the original PUT traversed (if tracked)
 * @param get_path_length number of entries in put_path
 * @param get_path peers this reply has traversed so far (if tracked)
 * @param data payload of the reply
 * @param data_size number of bytes in data
 */
void
GDS_ROUTING_process (enum GNUNET_BLOCK_Type type,
		     GNUNET_TIME_Absolute expiration_time,
		     const GNUNET_HashCode *key,
		     unsigned int put_path_length,
		     struct GNUNET_PeerIdentity *put_path,
		     unsigned int get_path_length,
		     struct GNUNET_PeerIdentity *get_path,
		     const void *data,
		     size_t data_size)
{
}


/**
 * Add a new entry to our routing table.
 *
 * @param sender peer that originated the request
 * @param type type of the block
 * @param key key for the content
 * @param xquery extended query
 * @param xquery_size number of bytes in xquery
 * @param reply_bf bloomfilter to filter duplicates
 * @param reply_bf_mutator mutator for reply_bf
*/
void
GDS_ROUTING_add (const GNUNET_PeerIdentity *sender,
		 enum GNUNET_BLOCK_Type type,
		 const GNUNET_HashCode *key,
		 const void *xquery,
		 size_t xquery_size,
		 const struct GNUNET_CONTAINER_BloomFilter *reply_bf,
		 uint32_t reply_bf_mutator)
{
  if (GNUNET_CONTAINER_heap_get_size (recent_heap) >= DHT_MAX_RECENT)
  {
    recent_req = GNUNET_CONTAINER_heap_peek (recent_heap);
    GNUNET_assert (recent_req != NULL);
    GNUNET_SCHEDULER_cancel (recent_req->remove_task);
    GNUNET_CONTAINER_heap_remove_node (recent_req->heap_node);
    GNUNET_CONTAINER_bloomfilter_free (recent_req->bloom);
    GNUNET_free (recent_req);
  }

  recent_req = GNUNET_malloc (sizeof (struct RecentRequest));
  recent_req->uid = msg_ctx->unique_id;
  memcpy (&recent_req->key, &msg_ctx->key, sizeof (GNUNET_HashCode));
  recent_req->heap_node =
    GNUNET_CONTAINER_heap_insert (recent_heap, recent_req,
				  GNUNET_TIME_absolute_get ().abs_value);
  recent_req->bloom =
    GNUNET_CONTAINER_bloomfilter_init (NULL, DHT_BLOOM_SIZE, DHT_BLOOM_K);


}


/**
 * Initialize routing subsystem.
 */
void
GDS_ROUTING_init ()
{
  recent_heap =
    GNUNET_CONTAINER_heap_create (GNUNET_CONTAINER_HEAP_ORDER_MIN);
  recent_map =
      GNUNET_CONTAINER_multihashmap_create (MAX_BUCKETS / 8);
}


/**
 * Shutdown routing subsystem.
 */
void
GDS_ROUTING_done ()
{
  while (GNUNET_CONTAINER_heap_get_size (recent_heap) > 0)
  {
    recent_req = GNUNET_CONTAINER_heap_peek (recent_heap);
    GNUNET_assert (recent_req != NULL);
    GNUNET_CONTAINER_heap_remove_node (recent_req->heap_node);
    GNUNET_CONTAINER_bloomfilter_free (recent_req->bloom);
    GNUNET_free (recent_req);
  }
  GNUNET_CONTAINER_heap_destroy (recent_heap);
  recent_heap = NULL;
  GNUNET_CONTAINER_multihashmap_destroy (recent_map);
  recent_map = NULL;
}

/* end of gnunet-service-dht_routing.c */
