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
 * @file dht/gnunet-service-dht_neighbours.c
 * @brief GNUnet DHT service's bucket and neighbour management code
 * @author Christian Grothoff
 * @author Nathan Evans
 */

#include "platform.h"
#include "gnunet_block_lib.h"
#include "gnunet_util_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_nse_service.h"
#include "gnunet_core_service.h"
#include "gnunet_datacache_lib.h"
#include "gnunet_transport_service.h"
#include "gnunet_hello_lib.h"
#include "gnunet_dht_service.h"
#include "gnunet_statistics_service.h"
#include "dht.h"
#include <fenv.h>

/**
 * How many buckets will we allow total.
 */
#define MAX_BUCKETS sizeof (GNUNET_HashCode) * 8

/**
 * What is the maximum number of peers in a given bucket.
 */
#define DEFAULT_BUCKET_SIZE 4

/**
 * Size of the bloom filter the DHT uses to filter peers.
 */
#define DHT_BLOOM_SIZE 128


/**
 * P2P PUT message
 */
struct PeerPutMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_DHT_P2P_PUT
   */
  struct GNUNET_MessageHeader header;

  /**
   * Processing options
   */
  uint32_t options GNUNET_PACKED;

  /**
   * Content type.
   */
  uint32_t type GNUNET_PACKED;

  /**
   * Hop count
   */
  uint32_t hop_count GNUNET_PACKED;

  /**
   * Replication level for this message
   */
  uint32_t desired_replication_level GNUNET_PACKED;

  /**
   * Generic route path length for a message in the
   * DHT that arrived at a peer and generated
   * a reply. Copied to the end of this message.
   */
  uint32_t outgoing_path_length GNUNET_PACKED;

  /**
   * Bloomfilter (for peer identities) to stop circular routes
   */
  char bloomfilter[DHT_BLOOM_SIZE];

  /**
   * The key we are storing under.
   */
  GNUNET_HashCode key;

  /* put path (if tracked) */

  /* Payload */

};


/**
 * P2P GET message
 */
struct PeerGetMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_DHT_P2P_PUT
   */
  struct GNUNET_MessageHeader header;

  /**
   * Processing options
   */
  uint32_t options GNUNET_PACKED;

  /**
   * Desired content type.
   */
  uint32_t type GNUNET_PACKED;

  /**
   * Hop count
   */
  uint32_t hop_count GNUNET_PACKED;

  /**
   * Desired replication level for this request.
   */
  uint32_t desired_replication_level GNUNET_PACKED;

  /**
   * Size of the extended query.
   */
  uint32_t xquery_size;

  /**
   * Bloomfilter mutator.
   */
  uint32_t bf_mutator;

  /**
   * Bloomfilter (for peer identities) to stop circular routes
   */
  char bloomfilter[DHT_BLOOM_SIZE];

  /**
   * The key we are looking for.
   */
  GNUNET_HashCode key;

  /* xquery */

  /* result bloomfilter */

};


/**
 * Linked list of messages to send to a particular other peer.
 */
struct P2PPendingMessage
{
  /**
   * Pointer to next item in the list
   */
  struct P2PPendingMessage *next;

  /**
   * Pointer to previous item in the list
   */
  struct P2PPendingMessage *prev;

  /**
   * Message importance level.
   */
  unsigned int importance;

  /**
   * Time when this request was scheduled to be sent.
   */
  struct GNUNET_TIME_Absolute scheduled;

  /**
   * How long to wait before sending message.
   */
  struct GNUNET_TIME_Relative timeout;

  /**
   * Actual message to be sent, allocated at the end of the struct:
   * // msg = (cast) &pm[1]; 
   * // memcpy (&pm[1], data, len);
   */
  const struct GNUNET_MessageHeader *msg;

};


/**
 * Entry for a peer in a bucket.
 */
struct PeerInfo
{
  /**
   * Next peer entry (DLL)
   */
  struct PeerInfo *next;

  /**
   *  Prev peer entry (DLL)
   */
  struct PeerInfo *prev;

  /**
   * Count of outstanding messages for peer.
   */
  unsigned int pending_count;

  /**
   * Head of pending messages to be sent to this peer.
   */
  struct P2PPendingMessage *head;

  /**
   * Tail of pending messages to be sent to this peer.
   */
  struct P2PPendingMessage *tail;

  /**
   * Core handle for sending messages to this peer.
   */
  struct GNUNET_CORE_TransmitHandle *th;

  /**
   * Preference update context
   */
  struct GNUNET_CORE_InformationRequestContext *info_ctx;

  /**
   * Task for scheduling message sends.
   */
  GNUNET_SCHEDULER_TaskIdentifier send_task;

  /**
   * Task for scheduling preference updates
   */
  GNUNET_SCHEDULER_TaskIdentifier preference_task;

  /**
   * What is the identity of the peer?
   */
  struct GNUNET_PeerIdentity id;

#if 0
  /**
   * What is the average latency for replies received?
   */
  struct GNUNET_TIME_Relative latency;

  /**
   * Transport level distance to peer.
   */
  unsigned int distance;
#endif

};


/**
 * Peers are grouped into buckets.
 */
struct PeerBucket
{
  /**
   * Head of DLL
   */
  struct PeerInfo *head;

  /**
   * Tail of DLL
   */
  struct PeerInfo *tail;

  /**
   * Number of peers in the bucket.
   */
  unsigned int peers_size;
};


/**
 * The lowest currently used bucket, initially 0 (for 0-bits matching bucket).
 */
static unsigned int closest_bucket;

/**
 * How many peers have we added since we sent out our last
 * find peer request?
 */
static unsigned int newly_found_peers;

/**
 * The buckets.  Array of size MAX_BUCKET_SIZE.  Offset 0 means 0 bits matching.
 */
static struct PeerBucket k_buckets[MAX_BUCKETS];

/**
 * Hash map of all known peers, for easy removal from k_buckets on disconnect.
 */
static struct GNUNET_CONTAINER_MultiHashMap *all_known_peers;

/**
 * Maximum size for each bucket.
 */
static unsigned int bucket_size = DEFAULT_BUCKET_SIZE;

/**
 * Task that sends FIND PEER requests.
 */
static GNUNET_SCHEDULER_TaskIdentifier find_peer_task;


/**
 * Find the optimal bucket for this key.
 *
 * @param hc the hashcode to compare our identity to
 * @return the proper bucket index, or GNUNET_SYSERR
 *         on error (same hashcode)
 */
static int
find_bucket (const GNUNET_HashCode * hc)
{
  unsigned int bits;

  bits = GNUNET_CRYPTO_hash_matching_bits (&my_identity.hashPubKey, hc);
  if (bits == MAX_BUCKETS)
    {
      /* How can all bits match? Got my own ID? */
      GNUNET_break (0);
      return GNUNET_SYSERR; 
    }
  return MAX_BUCKETS - bits - 1;
}


/**
 * Method called whenever a peer connects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 * @param atsi performance data
 */
static void
handle_core_connect (void *cls, const struct GNUNET_PeerIdentity *peer,
                     const struct GNUNET_TRANSPORT_ATS_Information *atsi)
{
  struct PeerInfo *ret;
  int peer_bucket;

  /* Check for connect to self message */
  if (0 == memcmp (&my_identity, peer, sizeof (struct GNUNET_PeerIdentity)))
    return;
  if (GNUNET_YES ==
      GNUNET_CONTAINER_multihashmap_contains (all_known_peers,
                                              &peer->hashPubKey))
  {
    GNUNET_break (0);
    return;
  }
  peer_bucket = find_bucket (&peer->hashPubKey);
  GNUNET_assert ( (peer_bucket >= 0) && (peer_bucket < MAX_BUCKETS) );
  ret = GNUNET_malloc (sizeof (struct PeerInfo));
#if 0
  ret->latency = latency;
  ret->distance = distance;
#endif
  ret->id = *peer;
  GNUNET_CONTAINER_DLL_insert_after (k_buckets[peer_bucket].head,
                                     k_buckets[peer_bucket].tail,
                                     k_buckets[peer_bucket].tail, ret);
  k_buckets[peer_bucket].peers_size++;
  closest_bucket = GNUNET_MAX (closest_bucket,
			       peer_bucket);
  if ( (peer_bucket > 0) &&
       (k_buckets[peer_bucket].peers_size <= bucket_size) )
    ret->preference_task = GNUNET_SCHEDULER_add_now (&update_core_preference, ret);
  newly_found_peers++;
  GNUNET_assert (GNUNET_OK ==
		 GNUNET_CONTAINER_multihashmap_put (all_known_peers, 
						    &peer->hashPubKey, ret,
						    GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  increment_stats (STAT_PEERS_KNOWN);
}


/**
 * Method called whenever a peer disconnects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 */
static void
handle_core_disconnect (void *cls, const struct GNUNET_PeerIdentity *peer)
{
  struct PeerInfo *to_remove;
  int current_bucket;
  struct P2PPendingMessage *pos;
  struct P2PPendingMessage *next;

  /* Check for disconnect from self message */
  if (0 == memcmp (&my_identity, peer, sizeof (struct GNUNET_PeerIdentity)))
    return;
  to_remove =
      GNUNET_CONTAINER_multihashmap_get (all_known_peers, &peer->hashPubKey);
  if (NULL == to_remove)
    {
      GNUNET_break (0);
      return;
    }
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap_remove (all_known_peers,
                                                       &peer->hashPubKey,
                                                       to_remove));
  if (NULL != to_remove->info_ctx)
  {
    GNUNET_CORE_peer_change_preference_cancel (to_remove->info_ctx);
    to_remove->info_ctx = NULL;
  }
  current_bucket = find_current_bucket (&to_remove->id.hashPubKey);
  GNUNET_CONTAINER_DLL_remove (k_buckets[current_bucket].head,
			       k_buckets[current_bucket].tail,
                               to_remove);
  GNUNET_assert (k_buckets[current_bucket].peers_size > 0);
  k_buckets[current_bucket].peers_size--;
  while ( (lowest_bucket > 0) &&
	  (k_buckets[lowest_bucket].peers_size == 0) )
    lowest_bucket--;

  if (to_remove->send_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (peer->send_task);
    peer->send_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (to_remove->th != NULL) 
  {
    GNUNET_CORE_notify_transmit_ready_cancel (to_remove->th);
    to_remove->th = NULL;
  }
  while (NULL != (pos = to_remove->head))
  {
    GNUNET_CONTAINER_DLL_remove (to_remove->head,
				 to_remove->tail,
				 pos);
    GNUNET_free (pos);
  }
}


/**
 * Perform a PUT operation.  // FIXME: document if this is only
 * routing or also storage and/or even local client notification!
 *
 * @param type type of the block
 * @param options routing options
 * @param desired_replication_level desired replication count
 * @param expiration_time when does the content expire
 * @param key key for the content
 * @param put_path_length number of entries in put_path
 * @param put_path peers this request has traversed so far (if tracked)
 * @param data payload to store
 * @param data_size number of bytes in data
 */
void
GST_NEIGHBOURS_handle_put (uint32_t type,
			   uint32_t options,
			   uint32_t desired_replication_level,
			   GNUNET_TIME_Absolute expiration_time,
			   const GNUNET_HashCode *key,
			   unsigned int put_path_length,
			   struct GNUNET_PeerIdentity *put_path,
			   const void *data,
			   size_t data_size)
{
  // FIXME
}


/**
 * Perform a GET operation.  // FIXME: document if this is only
 * routing or also state-tracking and/or even local lookup!
 *
 * @param type type of the block
 * @param options routing options
 * @param desired_replication_level desired replication count
 * @param key key for the content
 * @param xquery extended query
 * @param xquery_size number of bytes in xquery
 * @param reply_bf bloomfilter to filter duplicates
 * @param reply_bf_mutator mutator for reply_bf
 * @param peer_bf filter for peers not to select (again)
 */
void
GST_NEIGHBOURS_handle_get (uint32_t type,
			   uint32_t options,
			   uint32_t desired_replication_level,
			   const GNUNET_HashCode *key,
			   const void *xquery,
			   size_t xquery_size,
			   const struct GNUNET_CONTAINER_BloomFilter *reply_bf,
			   uint32_t reply_bf_mutator,
			   const struct GNUNET_CONTAINER_BloomFilter *peer_bf)
{
  // FIXME
}


/**
 * Handle a reply (route to origin).  FIXME: should this be here?
 * (reply-routing table might be better done elsewhere).
 *
 * @param type type of the block
 * @param options routing options
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
GST_NEIGHBOURS_handle_reply (uint32_t type,
			     uint32_t options,
			     GNUNET_TIME_Absolute expiration_time,
			     const GNUNET_HashCode *key,
			     unsigned int put_path_length,
			     struct GNUNET_PeerIdentity *put_path,
			     unsigned int get_path_length,
			     struct GNUNET_PeerIdentity *get_path,
			     const void *data,
			     size_t data_size)
{
  // FIXME
}


/**
 * Add each of the peers we already know to the bloom filter of
 * the request so that we don't get duplicate HELLOs.
 *
 * @param cls the 'struct GNUNET_CONTAINER_BloomFilter' we're building
 * @param key peer identity to add to the bloom filter
 * @param value value the peer information (unused)
 * @return GNUNET_YES (we should continue to iterate)
 */
static int
add_known_to_bloom (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct GNUNET_CONTAINER_BloomFilter *bloom = cls;

  GNUNET_CONTAINER_bloomfilter_add (bloom, key);
  return GNUNET_YES;
}


/**
 * Task to send a find peer message for our own peer identifier
 * so that we can find the closest peers in the network to ourselves
 * and attempt to connect to them.
 *
 * @param cls closure for this task
 * @param tc the context under which the task is running
 */
static void
send_find_peer_message (void *cls,
                        const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_DHT_FindPeerMessage *find_peer_msg;
  struct DHT_MessageContext msg_ctx;
  struct GNUNET_TIME_Relative next_send_time;
  struct GNUNET_CONTAINER_BloomFilter *temp_bloom;

  find_peer_task = GNUNET_SCHEDULER_NO_TASK;
  if ((tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) != 0)
    return;
  if (newly_found_peers > bucket_size) 
  {
    /* If we are finding many peers already, no need to send out our request right now! */
    find_peer_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_MINUTES,
						   &send_find_peer_message, NULL);
    newly_found_peers = 0;
    return;
  }

  // FIXME: build message...
  find_peer_msg = GNUNET_malloc (sizeof (struct GNUNET_DHT_FindPeerMessage));
  find_peer_msg->header.size =
      htons (sizeof (struct GNUNET_DHT_FindPeerMessage));
  find_peer_msg->header.type = htons (GNUNET_MESSAGE_TYPE_DHT_FIND_PEER);
  temp_bloom =
      GNUNET_CONTAINER_bloomfilter_init (NULL, DHT_BLOOM_SIZE, DHT_BLOOM_K);
  GNUNET_CONTAINER_multihashmap_iterate (all_known_peers, &add_known_to_bloom,
                                         temp_bloom);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_bloomfilter_get_raw_data (temp_bloom,
                                                            find_peer_msg->
                                                            bloomfilter,
                                                            DHT_BLOOM_SIZE));
  GNUNET_CONTAINER_bloomfilter_free (temp_bloom);

  memset (&msg_ctx, 0, sizeof (struct DHT_MessageContext));
  memcpy (&msg_ctx.key, &my_identity.hashPubKey, sizeof (GNUNET_HashCode));
  msg_ctx.unique_id =
      GNUNET_ntohll (GNUNET_CRYPTO_random_u64
                     (GNUNET_CRYPTO_QUALITY_STRONG, UINT64_MAX));
  msg_ctx.replication = DHT_DEFAULT_FIND_PEER_REPLICATION;
  msg_ctx.msg_options = GNUNET_DHT_RO_DEMULTIPLEX_EVERYWHERE;
  msg_ctx.network_size = log_of_network_size_estimate;
  msg_ctx.peer = my_identity;
  msg_ctx.importance = DHT_DEFAULT_FIND_PEER_IMPORTANCE;
  msg_ctx.timeout = DHT_DEFAULT_FIND_PEER_TIMEOUT;
  // FIXME: transmit message...
  demultiplex_message (&find_peer_msg->header, &msg_ctx);
  GNUNET_free (find_peer_msg);

  /* schedule next round */
  newly_found_peers = 0;
  next_send_time.rel_value =
    (DHT_MAXIMUM_FIND_PEER_INTERVAL.rel_value / 2) +
    GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_STRONG,
			      DHT_MAXIMUM_FIND_PEER_INTERVAL.rel_value / 2);
  find_peer_task = GNUNET_SCHEDULER_add_delayed (next_send_time, 
						 &send_find_peer_message,
						 NULL);  
}


/**
 * To be called on core init/fail.
 *
 * @param cls service closure
 * @param server handle to the server for this service
 * @param identity the public identity of this peer
 * @param publicKey the public key of this peer
 */
static void
core_init (void *cls, struct GNUNET_CORE_Handle *server,
           const struct GNUNET_PeerIdentity *identity,
           const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *publicKey)
{
  GNUNET_assert (server != NULL);
  my_identity = *identity;
  next_send_time.rel_value =
    DHT_MINIMUM_FIND_PEER_INTERVAL.rel_value +
    GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_STRONG,
			      (DHT_MAXIMUM_FIND_PEER_INTERVAL.rel_value /
			       2) -
			      DHT_MINIMUM_FIND_PEER_INTERVAL.rel_value);
  find_peer_task = GNUNET_SCHEDULER_add_delayed (next_send_time,
						 &send_find_peer_message,
						 NULL);
}


/**
 * Core handler for p2p get requests.
 *
 * @param cls closure
 * @param message message
 * @param peer peer identity this notification is about
 * @param atsi performance data
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_dht_p2p_get (void *cls, const struct GNUNET_PeerIdentity *peer,
		    const struct GNUNET_MessageHeader *message,
		    const struct GNUNET_TRANSPORT_ATS_Information
		    *atsi)
{
  struct GNUNET_DHT_P2PRouteMessage *incoming =
      (struct GNUNET_DHT_P2PRouteMessage *) message;
  struct GNUNET_MessageHeader *enc_msg =
      (struct GNUNET_MessageHeader *) &incoming[1];
  struct DHT_MessageContext *msg_ctx;
  char *route_path;
  int path_size;

  if (ntohs (enc_msg->size) >= GNUNET_SERVER_MAX_MESSAGE_SIZE - 1)
  {
    GNUNET_break_op (0);
    return GNUNET_YES;
  }

  if (get_max_send_delay ().rel_value > MAX_REQUEST_TIME.rel_value)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Sending of previous replies took too long, backing off!\n");
    increment_stats ("# route requests dropped due to high load");
    decrease_max_send_delay (get_max_send_delay ());
    return GNUNET_YES;
  }
  msg_ctx = GNUNET_malloc (sizeof (struct DHT_MessageContext));
  msg_ctx->bloom =
      GNUNET_CONTAINER_bloomfilter_init (incoming->bloomfilter, DHT_BLOOM_SIZE,
                                         DHT_BLOOM_K);
  GNUNET_assert (msg_ctx->bloom != NULL);
  msg_ctx->hop_count = ntohl (incoming->hop_count);
  memcpy (&msg_ctx->key, &incoming->key, sizeof (GNUNET_HashCode));
  msg_ctx->replication = ntohl (incoming->desired_replication_level);
  msg_ctx->msg_options = ntohl (incoming->options);
  if (GNUNET_DHT_RO_RECORD_ROUTE ==
      (msg_ctx->msg_options & GNUNET_DHT_RO_RECORD_ROUTE))
  {
    path_size =
        ntohl (incoming->outgoing_path_length) *
        sizeof (struct GNUNET_PeerIdentity);
    if (ntohs (message->size) !=
        (sizeof (struct GNUNET_DHT_P2PRouteMessage) + ntohs (enc_msg->size) +
         path_size))
    {
      GNUNET_break_op (0);
      GNUNET_free (msg_ctx);
      return GNUNET_YES;
    }
    route_path = (char *) &incoming[1];
    route_path = route_path + ntohs (enc_msg->size);
    msg_ctx->path_history =
        GNUNET_malloc (sizeof (struct GNUNET_PeerIdentity) + path_size);
    memcpy (msg_ctx->path_history, route_path, path_size);
    memcpy (&msg_ctx->path_history[path_size], &my_identity,
            sizeof (struct GNUNET_PeerIdentity));
    msg_ctx->path_history_len = ntohl (incoming->outgoing_path_length) + 1;
  }
  msg_ctx->network_size = ntohl (incoming->network_size);
  msg_ctx->peer = *peer;
  msg_ctx->importance = DHT_DEFAULT_P2P_IMPORTANCE;
  msg_ctx->timeout = DHT_DEFAULT_P2P_TIMEOUT;
  demultiplex_message (enc_msg, msg_ctx);
  if (msg_ctx->bloom != NULL)
  {
    GNUNET_CONTAINER_bloomfilter_free (msg_ctx->bloom);
    msg_ctx->bloom = NULL;
  }
  GNUNET_free (msg_ctx);
  return GNUNET_YES;
}


/**
 * Core handler for p2p put requests.
 *
 * @param cls closure
 * @param message message
 * @param peer peer identity this notification is about
 * @param atsi performance data
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_dht_p2p_put (void *cls, const struct GNUNET_PeerIdentity *peer,
		    const struct GNUNET_MessageHeader *message,
		    const struct GNUNET_TRANSPORT_ATS_Information
		    *atsi)
{
  struct GNUNET_DHT_P2PRouteMessage *incoming =
      (struct GNUNET_DHT_P2PRouteMessage *) message;
  struct GNUNET_MessageHeader *enc_msg =
      (struct GNUNET_MessageHeader *) &incoming[1];
  struct DHT_MessageContext *msg_ctx;
  char *route_path;
  int path_size;

  if (ntohs (enc_msg->size) >= GNUNET_SERVER_MAX_MESSAGE_SIZE - 1)
  {
    GNUNET_break_op (0);
    return GNUNET_YES;
  }

  if (get_max_send_delay ().rel_value > MAX_REQUEST_TIME.rel_value)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Sending of previous replies took too long, backing off!\n");
    increment_stats ("# route requests dropped due to high load");
    decrease_max_send_delay (get_max_send_delay ());
    return GNUNET_YES;
  }
  msg_ctx = GNUNET_malloc (sizeof (struct DHT_MessageContext));
  msg_ctx->bloom =
      GNUNET_CONTAINER_bloomfilter_init (incoming->bloomfilter, DHT_BLOOM_SIZE,
                                         DHT_BLOOM_K);
  GNUNET_assert (msg_ctx->bloom != NULL);
  msg_ctx->hop_count = ntohl (incoming->hop_count);
  memcpy (&msg_ctx->key, &incoming->key, sizeof (GNUNET_HashCode));
  msg_ctx->replication = ntohl (incoming->desired_replication_level);
  msg_ctx->msg_options = ntohl (incoming->options);
  if (GNUNET_DHT_RO_RECORD_ROUTE ==
      (msg_ctx->msg_options & GNUNET_DHT_RO_RECORD_ROUTE))
  {
    path_size =
        ntohl (incoming->outgoing_path_length) *
        sizeof (struct GNUNET_PeerIdentity);
    if (ntohs (message->size) !=
        (sizeof (struct GNUNET_DHT_P2PRouteMessage) + ntohs (enc_msg->size) +
         path_size))
    {
      GNUNET_break_op (0);
      GNUNET_free (msg_ctx);
      return GNUNET_YES;
    }
    route_path = (char *) &incoming[1];
    route_path = route_path + ntohs (enc_msg->size);
    msg_ctx->path_history =
        GNUNET_malloc (sizeof (struct GNUNET_PeerIdentity) + path_size);
    memcpy (msg_ctx->path_history, route_path, path_size);
    memcpy (&msg_ctx->path_history[path_size], &my_identity,
            sizeof (struct GNUNET_PeerIdentity));
    msg_ctx->path_history_len = ntohl (incoming->outgoing_path_length) + 1;
  }
  msg_ctx->network_size = ntohl (incoming->network_size);
  msg_ctx->peer = *peer;
  msg_ctx->importance = DHT_DEFAULT_P2P_IMPORTANCE;
  msg_ctx->timeout = DHT_DEFAULT_P2P_TIMEOUT;
  demultiplex_message (enc_msg, msg_ctx);
  if (msg_ctx->bloom != NULL)
  {
    GNUNET_CONTAINER_bloomfilter_free (msg_ctx->bloom);
    msg_ctx->bloom = NULL;
  }
  GNUNET_free (msg_ctx);
  return GNUNET_YES;
}


/**
 * Core handler for p2p route results.
 *
 * @param cls closure
 * @param message message
 * @param peer peer identity this notification is about
 * @param atsi performance data
 *
 */
static int
handle_dht_p2p_result (void *cls, const struct GNUNET_PeerIdentity *peer,
		       const struct GNUNET_MessageHeader *message,
		       const struct GNUNET_TRANSPORT_ATS_Information
		       *atsi)
{
  const struct GNUNET_DHT_P2PRouteResultMessage *incoming =
      (const struct GNUNET_DHT_P2PRouteResultMessage *) message;
  struct GNUNET_MessageHeader *enc_msg =
      (struct GNUNET_MessageHeader *) &incoming[1];
  struct DHT_MessageContext msg_ctx;

  if (ntohs (enc_msg->size) >= GNUNET_SERVER_MAX_MESSAGE_SIZE - 1)
  {
    GNUNET_break_op (0);
    return GNUNET_YES;
  }

  memset (&msg_ctx, 0, sizeof (struct DHT_MessageContext));
  memcpy (&msg_ctx.key, &incoming->key, sizeof (GNUNET_HashCode));
  msg_ctx.msg_options = ntohl (incoming->options);
  msg_ctx.hop_count = ntohl (incoming->hop_count);
  msg_ctx.peer = *peer;
  msg_ctx.importance = DHT_DEFAULT_P2P_IMPORTANCE + 2;  /* Make result routing a higher priority */
  msg_ctx.timeout = DHT_DEFAULT_P2P_TIMEOUT;
  if ((GNUNET_DHT_RO_RECORD_ROUTE ==
       (msg_ctx.msg_options & GNUNET_DHT_RO_RECORD_ROUTE)) &&
      (ntohl (incoming->outgoing_path_length) > 0))
  {
    if (ntohs (message->size) -
        sizeof (struct GNUNET_DHT_P2PRouteResultMessage) -
        ntohs (enc_msg->size) !=
        ntohl (incoming->outgoing_path_length) *
        sizeof (struct GNUNET_PeerIdentity))
    {
      GNUNET_break_op (0);
      return GNUNET_NO;
    }
    msg_ctx.path_history = (char *) &incoming[1];
    msg_ctx.path_history += ntohs (enc_msg->size);
    msg_ctx.path_history_len = ntohl (incoming->outgoing_path_length);
  }
  route_result_message (enc_msg, &msg_ctx);
  return GNUNET_YES;
}


/**
 * Initialize neighbours subsystem.
 */
int
GST_NEIGHBOURS_init ()
{
  static struct GNUNET_CORE_MessageHandler core_handlers[] = {
    {&handle_dht_get, GNUNET_MESSAGE_TYPE_DHT_P2P_GET, 0},
    {&handle_dht_put, GNUNET_MESSAGE_TYPE_DHT_P2P_PUT, 0},
    {&handle_dht_result, GNUNET_MESSAGE_TYPE_DHT_P2P_RESULT, 0},
    {NULL, 0, 0}
  };
  unsigned long long temp_config_num;
  struct GNUNET_TIME_Relative next_send_time;
 
  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_get_value_number (cfg, "DHT", "bucket_size",
                                             &temp_config_num))
    bucket_size = (unsigned int) temp_config_num;  
  coreAPI = GNUNET_CORE_connect (GDS_cfg,   /* Main configuration */
                                 DEFAULT_CORE_QUEUE_SIZE,       /* queue size */
                                 NULL,  /* Closure passed to DHT functions */
                                 &core_init,    /* Call core_init once connected */
                                 &handle_core_connect,  /* Handle connects */
                                 &handle_core_disconnect,       /* remove peers on disconnects */
                                 NULL,  /* Do we care about "status" updates? */
                                 NULL,  /* Don't want notified about all incoming messages */
                                 GNUNET_NO,     /* For header only inbound notification */
                                 NULL,  /* Don't want notified about all outbound messages */
                                 GNUNET_NO,     /* For header only outbound notification */
                                 core_handlers);        /* Register these handlers */  
  if (coreAPI == NULL)
    return GNUNET_SYSERR;
  all_known_peers = GNUNET_CONTAINER_multihashmap_create (256);
  return GNUNET_OK;
}


/**
 * Shutdown neighbours subsystem.
 */
void
GST_NEIGHBOURS_done ()
{
  GNUNET_assert (coreAPI != NULL);
  GNUNET_CORE_disconnect (coreAPI);
  coreAPI = NULL;    
  GNUNET_assert (0 == GNUNET_CONTAINER_multihashmap_get_size (all_known_peers));
  GNUNET_CONTAINER_multihashmap_destroy (all_known_peers);
  all_known_peers = NULL;
  if (GNUNET_SCHEDULER_NO_TASK != find_peer_task)
  {
    GNUNET_SCHEDULER_cancel (find_peer_task);
    find_peer_task = GNUNET_SCHEDULER_NO_TASK;
  }
}


/* end of gnunet-service-dht_neighbours.c */
