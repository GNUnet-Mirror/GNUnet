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
#include "gnunet-service-dht_datacache.h"
#include "gnunet-service-dht_routing.h"
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
   * Length of the PUT path that follows (if tracked).
   */
  uint32_t put_path_length GNUNET_PACKED;

  /**
   * When does the content expire?
   */
  struct GNUNET_TIME_AbsoluteNBO expiration_time;

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
 * P2P Result message
 */
struct PeerResultMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_DHT_P2P_RESULT
   */
  struct GNUNET_MessageHeader header;

  /**
   * Content type.
   */
  uint32_t type GNUNET_PACKED;

  /**
   * Length of the PUT path that follows (if tracked).
   */
  uint32_t put_path_length GNUNET_PACKED;

  /**
   * Length of the GET path that follows (if tracked).
   */
  uint32_t get_path_length GNUNET_PACKED;

  /**
   * When does the content expire?
   */
  struct GNUNET_TIME_AbsoluteNBO expiration_time;

  /**
   * The key of the corresponding GET request.
   */
  GNUNET_HashCode key;

  /* put path (if tracked) */

  /* get path (if tracked) */

  /* Payload */

};


/**
 * P2P GET message
 */
struct PeerGetMessage
{
  /**
   * Type: GNUNET_MESSAGE_TYPE_DHT_P2P_GET
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
   * Message importance level.  FIXME: used? useful?
   */
  unsigned int importance;

  /**
   * When does this message time out?
   */
  struct GNUNET_TIME_Absolute timeout;

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
   * Count of outstanding messages for peer.  FIXME: NEEDED?
   * FIXME: bound queue size!?
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
 * Called when core is ready to send a message we asked for
 * out to the destination.
 *
 * @param cls the 'struct PeerInfo' of the target peer
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t
core_transmit_notify (void *cls, size_t size, void *buf)
{
  struct PeerInfo *peer = cls;
  char *cbuf = buf;
  struct P2PPendingMessage *pending;
  size_t off;
  size_t msize;

  peer->th = NULL;
  if (buf == NULL)
  {
    /* client disconnected */
    return 0;
  }
  if (peer->head == NULL)
  {
    /* no messages pending */
    return 0;
  }
  off = 0;
  while ( (NULL != (pending = peer->head)) &&
	  (size - off >= (msize = ntohs (pending->msg->size))) )
  {
    memcpy (&cbuf[off], pending->msg, msize);
    off += msize;
    peer->pending_count--;
    GNUNET_CONTAINER_DLL_remove (peer->head, peer->tail, pending);
    GNUNET_free (pending);
  }
  if (peer->head != NULL)
    peer->th 
      = GNUNET_CORE_notify_transmit_ready (coreAPI, GNUNET_YES,
                                           pending->importance,
                                           pending->timeout, &peer->id, msize,
                                           &core_transmit_notify, peer);

  return off;
}


/**
 * Transmit all messages in the peer's message queue.
 *
 * @param peer message queue to process
 */
static void
process_peer_queue (struct PeerInfo *peer)
{
  struct P2PPendingMessage *pending;

  if (NULL != (pending = peer->head))
    return;
  if (NULL != peer->th)
    return;
  peer->th 
    = GNUNET_CORE_notify_transmit_ready (coreAPI, GNUNET_YES,
					 pending->importance,
					 pending->timeout, &peer->id,
					 ntohs (pending->msg->size),
					 &core_transmit_notify, peer);
}


/**
 * To how many peers should we (on average) forward the request to
 * obtain the desired target_replication count (on average).
 *
 * @param hop_count number of hops the message has traversed
 * @param target_replication the number of total paths desired
 * @return Some number of peers to forward the message to
 */
static unsigned int
get_forward_count (uint32_t hop_count, 
		   uint32_t target_replication)
{
  uint32_t random_value;
  uint32_t forward_count;
  float target_value;

  if (hop_count > log_of_network_size_estimate * 4.0)
  {
    /* forcefully terminate */
    return 0;
  }
  if (hop_count > log_of_network_size_estimate * 2.0)
  {
    /* Once we have reached our ideal number of hops, only forward to 1 peer */
    return 1;
  }
  /* bound by system-wide maximum */
  target_replication = GNUNET_MIN (16 /* FIXME: use named constant */,
				   target_replication);
  target_value =
    1 + (target_replication - 1.0) / (log_of_network_size_estimate +
				      ((float) (target_replication - 1.0) *
				       hop_count));
  /* Set forward count to floor of target_value */
  forward_count = (uint32_t) target_value;
  /* Subtract forward_count (floor) from target_value (yields value between 0 and 1) */
  target_value = target_value - forward_count;
  random_value =
    GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_STRONG, UINT32_MAX); 
  if (random_value < (target_value * UINT32_MAX))
    forward_count++;
  return forward_count;
}


/**
 * Check whether my identity is closer than any known peers.  If a
 * non-null bloomfilter is given, check if this is the closest peer
 * that hasn't already been routed to.
 * FIXME: needed?
 *
 * @param key hash code to check closeness to
 * @param bloom bloomfilter, exclude these entries from the decision
 * @return GNUNET_YES if node location is closest,
 *         GNUNET_NO otherwise.
 */
static int
am_closest_peer (const GNUNET_HashCode *key,
                 const struct GNUNET_CONTAINER_BloomFilter *bloom)
{
  int bits;
  int other_bits;
  int bucket_num;
  int count;
  struct PeerInfo *pos;
  unsigned int my_distance;

  if (0 == memcmp (&my_identity.hashPubKey, key, sizeof (GNUNET_HashCode)))
    return GNUNET_YES;
  bucket_num = find_current_bucket (key);
  bits = GNUNET_CRYPTO_hash_matching_bits (&my_identity.hashPubKey, key);
  my_distance = distance (&my_identity.hashPubKey, key);
  pos = k_buckets[bucket_num].head;
  count = 0;
  while ((pos != NULL) && (count < bucket_size))
  {
    if ((bloom != NULL) &&
        (GNUNET_YES ==
         GNUNET_CONTAINER_bloomfilter_test (bloom, &pos->id.hashPubKey)))
    {
      pos = pos->next;
      continue;                 /* Skip already checked entries */
    }
    other_bits = GNUNET_CRYPTO_hash_matching_bits (&pos->id.hashPubKey, key);
    if (other_bits > bits)
      return GNUNET_NO;
    if (other_bits == bits)        /* We match the same number of bits */
      return GNUNET_YES;
    pos = pos->next;
  }
  /* No peers closer, we are the closest! */
  return GNUNET_YES;
}


/**
 * Select a peer from the routing table that would be a good routing
 * destination for sending a message for "key".  The resulting peer
 * must not be in the set of blocked peers.<p>
 *
 * Note that we should not ALWAYS select the closest peer to the
 * target, peers further away from the target should be chosen with
 * exponentially declining probability.
 *
 * FIXME: double-check that this is fine
 * 
 *
 * @param key the key we are selecting a peer to route to
 * @param bloom a bloomfilter containing entries this request has seen already
 * @param hops how many hops has this message traversed thus far
 * @return Peer to route to, or NULL on error
 */
static struct PeerInfo *
select_peer (const GNUNET_HashCode *key,
             const struct GNUNET_CONTAINER_BloomFilter *bloom, 
	     uint32_t hops)
{
  unsigned int bc;
  unsigned int count;
  unsigned int selected;
  struct PeerInfo *pos;
  unsigned int distance;
  unsigned int largest_distance;
  struct PeerInfo *chosen;

  if (hops >= log_of_network_size_estimate)
  {
    /* greedy selection (closest peer that is not in bloomfilter) */
    largest_distance = 0;
    chosen = NULL;
    for (bc = lowest_bucket; bc < MAX_BUCKETS; bc++)
    {
      pos = k_buckets[bc].head;
      count = 0;
      while ((pos != NULL) && (count < bucket_size))
      {
        /* If we are doing strict Kademlia routing, then checking the bloomfilter is basically cheating! */
        if (GNUNET_NO ==
            GNUNET_CONTAINER_bloomfilter_test (bloom, &pos->id.hashPubKey))
        {
          distance = inverse_distance (key, &pos->id.hashPubKey);
          if (distance > largest_distance)
          {
            chosen = pos;
            largest_distance = distance;
          }
        }
        count++;
        pos = pos->next;
      }
    }
    return chosen;
  }

  /* select "random" peer */
  /* count number of peers that are available and not filtered */
  count = 0;
  for (bc = lowest_bucket; bc < MAX_BUCKETS; bc++)
  {
    pos = k_buckets[bc].head;
    while ((pos != NULL) && (count < bucket_size))
    {
      if (GNUNET_YES ==
          GNUNET_CONTAINER_bloomfilter_test (bloom, &pos->id.hashPubKey))
      {
        pos = pos->next;
        continue;               /* Ignore bloomfiltered peers */
      }
      count++;
      pos = pos->next;
    }
  }
  if (count == 0)               /* No peers to select from! */
  {
    return NULL;
  }
  /* Now actually choose a peer */
  selected = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, count);
  count = 0;
  for (bc = lowest_bucket; bc < MAX_BUCKETS; bc++)
  {
    pos = k_buckets[bc].head;
    while ((pos != NULL) && (count < bucket_size))
    {
      if (GNUNET_YES ==
          GNUNET_CONTAINER_bloomfilter_test (bloom, &pos->id.hashPubKey))
      {
        pos = pos->next;
        continue;               /* Ignore bloomfiltered peers */
      }
      if (0 == selected--)
        return pos;
      pos = pos->next;
    }
  }
  GNUNET_break (0);
  return NULL;
}


/**
 * Compute the set of peers that the given request should be
 * forwarded to.
 *
 * @param key routing key
 * @param bloom bloom filter excluding peers as targets, all selected
 *        peers will be added to the bloom filter
 * @param hop_count number of hops the request has traversed so far
 * @param target_replication desired number of replicas
 * @param targets where to store an array of target peers (to be
 *         free'd by the caller)
 * @return number of peers returned in 'targets'.
 */
static unsigned int
get_target_peers (const GNUNET_HashCode *key,
		  struct GNUNET_CONTAINER_BloomFilter *bloom,
		  uint32_t hop_count,
		  uint32_t target_replication,
		  struct PeerInfo ***targets)
{
  unsigned int ret;
  unsigned int off;
  struct PeerInfo **rtargets;
  struct PeerInfo *nxt;

  ret = get_forward_count (hop_count, target_replication);
  if (ret == 0)
  {
    *targets = NULL;
    return 0;
  }
  rtargets = GNUNET_malloc (sizeof (struct PeerInfo*) * ret);
  off = 0;
  while (ret-- > 0)
  {
    nxt = select_peer (key, bloom, hop_count);
    if (nxt == NULL)
      break;
    rtargets[off++] = nxt;
    GNUNET_CONTAINER_bloomfilter_add (bloom, &nxt->id.hashPubKey);
  }
  if (0 == off)
  {
    GNUNET_free (rtargets);
    *targets = NULL;
    return 0;
  }
  *targets = rtargets;
  return off;
}


/**
 * Perform a PUT operation.   Forwards the given request to other
 * peers.   Does not store the data locally.  Does not give the
 * data to local clients.  May do nothing if this is the only
 * peer in the network (or if we are the closest peer in the
 * network).
 *
 * @param type type of the block
 * @param options routing options
 * @param desired_replication_level desired replication count
 * @param expiration_time when does the content expire
 * @param hop_count how many hops has this message traversed so far
 * @param bf Bloom filter of peers this PUT has already traversed
 * @param key key for the content
 * @param put_path_length number of entries in put_path
 * @param put_path peers this request has traversed so far (if tracked)
 * @param data payload to store
 * @param data_size number of bytes in data
 */
void
GDS_NEIGHBOURS_handle_put (enum GNUNET_BLOCK_Type type,
			   enum GNUNET_DHT_RouteOption options,
			   uint32_t desired_replication_level,
			   GNUNET_TIME_Absolute expiration_time,
			   uint32_t hop_count,
			   struct GNUNET_CONTAINER_BloomFilter *bf,
			   const GNUNET_HashCode *key,
			   unsigned int put_path_length,
			   struct GNUNET_PeerIdentity *put_path,
			   const void *data,
			   size_t data_size)
{
  unsigned int target_count;
  unsigned int i;
  struct PeerInfo **targets;
  struct PeerInfo *target;
  struct P2PPendingMessage *pending;
  size_t msize;
  struct PeerPutMessage *ppm;
  struct GNUNET_PeerIdentity *pp;
  
  target_count = get_target_peers (key, bf, hop_count,
				   desired_replication_level,
				   &targets);
  if (0 == target_count)
    return;
  msize = put_path_length * sizeof (struct GNUNET_PeerIdentity) + data_size + sizeof (struct PeerPutMessage);
  if (msize >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
  {
    put_path_length = 0;
    msize = data_size + sizeof (struct PeerPutMessage);
  }
  if (msize >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    return;
  }
  for (i=0;i<target_count;i++)
  {
    target = targets[i];
    pending = GNUNET_malloc (sizeof (struct P2PPendingMessage) + msize);
    pending->importance = 0; /* FIXME */
    pending->timeout = expiration_time;   
    ppm = (struct PeerPutMessage*) &pending[1];
    pending->msg = &ppm->header;
    ppm->header.size = htons (msize);
    ppm->header.type = htons (GNUNET_MESSAGE_TYPE_DHT_P2P_PUT);
    ppm->options = htonl (options);
    ppm->type = htonl (type);
    ppm->hop_count = htonl (hop_count + 1);
    ppm->desired_replication_level = htonl (desired_replication_level);
    ppm->put_path_length = htonl (put_path_length);
    ppm->expiration_time = GNUNET_TIME_absolute_hton (expiration_time);
    GNUNET_assert (GNUNET_OK ==
		   GNUNET_CONTAINER_bloomfilter_get_raw_data (bf,
							      ppm->bloomfilter,
							      DHT_BLOOM_SIZE));
    ppm->key = *key;
    pp = (const struct GNUNET_PeerIdentity*) &ppm[1];
    memcpy (pp, put_path, sizeof (struct GNUNET_PeerIdentity) * put_path_length);
    memcpy (&pp[put_path_length], data, data_size);
    GNUNET_CONTAINER_DLL_insert (target->head,
				 target->tail,
				 pending);
    target->pending_count++;
    process_peer_queue (target);
  }
  GNUNET_free (targets);
}


/**
 * Perform a GET operation.  Forwards the given request to other
 * peers.  Does not lookup the key locally.  May do nothing if this is
 * the only peer in the network (or if we are the closest peer in the
 * network).
 *
 * @param type type of the block
 * @param options routing options
 * @param desired_replication_level desired replication count
 * @param hop_count how many hops did this request traverse so far?
 * @param key key for the content
 * @param xquery extended query
 * @param xquery_size number of bytes in xquery
 * @param reply_bf bloomfilter to filter duplicates
 * @param reply_bf_mutator mutator for reply_bf
 * @param peer_bf filter for peers not to select (again)
 */
void
GDS_NEIGHBOURS_handle_get (enum GNUNET_BLOCK_Type type,
			   enum GNUNET_DHT_RouteOption options,
			   uint32_t desired_replication_level,
			   uint32_t hop_count,
			   const GNUNET_HashCode *key,
			   const void *xquery,
			   size_t xquery_size,
			   const struct GNUNET_CONTAINER_BloomFilter *reply_bf,
			   uint32_t reply_bf_mutator,
			   const struct GNUNET_CONTAINER_BloomFilter *peer_bf)
{
  unsigned int target_count;
  unsigned int i;
  struct PeerInfo **targets;
  struct PeerInfo *target;
  struct P2PPendingMessage *pending;
  size_t msize;
  struct PeerGetMessage *pgm;
  char *xq;
  size_t reply_bf_size;
  
  target_count = get_target_peers (key, peer_bf, hop_count,
				   desired_replication_level,
				   &targets);
  if (0 == target_count)
    return;
  reply_bf_size = GNUNET_CONTAINER_bloomfilter_get_size (reply_bf);
  msize = xquery_size + sizeof (struct PeerGetMessage) + reply_bf_size;
  if (msize >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    return;
  }
  /* forward request */
  for (i=0;i<target_count;i++)
  {
    target = targets[i];
    pending = GNUNET_malloc (sizeof (struct P2PPendingMessage) + msize); 
    pending->importance = 0; /* FIXME */
    pending->timeout = GNUNET_TIME_relative_to_absolute (GNUNET_TIME_UNIT_HOURS); /* FIXME */
    pgm = (struct PeerGetMessage*) &pending[1];
    pending->msg = &pgm->header;
    pgm->header.size = htons (msize);
    pgm->header.type = htons (GNUNET_MESSAGE_TYPE_DHT_P2P_GET);
    pgm->options = htonl (options);
    pgm->type = htonl (type);
    pgm->hop_count = htonl (hop_count + 1);
    pgm->desired_replication_level = htonl (desired_replication_level);
    pgm->xquery_size = htonl (xquery_size);
    pgm->bf_mutator = reply_bf_mutator; 
    GNUNET_assert (GNUNET_OK ==
		   GNUNET_CONTAINER_bloomfilter_get_raw_data (peer_bf,
							      pgm->bloomfilter,
							      DHT_BLOOM_SIZE));
    pgm->key = *key;
    xq = (const struct GNUNET_PeerIdentity*) &ppm[1];
    memcpy (xq, xquery, xquery_size);
    GNUNET_assert (GNUNET_OK ==
		   GNUNET_CONTAINER_bloomfilter_get_raw_data (reply_bf,
							      &xq[xquery_size],
							      reply_bf_size));
    GNUNET_CONTAINER_DLL_insert (target->head,
				 target->tail,
				 pending);
    target->pending_count++;
    process_peer_queue (target);
  }
  GNUNET_free (targets);
}


/**
 * Handle a reply (route to origin).  Only forwards the reply back to
 * the given peer.  Does not do local caching or forwarding to local
 * clients.
 *
 * @param target neighbour that should receive the block (if still connected)
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
GDS_NEIGHBOURS_handle_reply (const GNUNET_PeerIdentity *target,
			     enum GNUNET_BLOCK_Type type,
			     GNUNET_TIME_Absolute expiration_time,
			     const GNUNET_HashCode *key,
			     unsigned int put_path_length,
			     struct GNUNET_PeerIdentity *put_path,
			     unsigned int get_path_length,
			     struct GNUNET_PeerIdentity *get_path,
			     const void *data,
			     size_t data_size)
{
  struct PeerInfo *pi;
  struct P2PPendingMessage *pending;
  size_t msize;
  struct PeerResultMessage *prm;
  struct GNUNET_PeerIdentity *paths;
  
  msize = data_size + sizeof (struct PeerResultMessage) + 
    (get_path_length + put_path_length) * sizeof (struct GNUNET_PeerIdentity);
  if ( (msize >= GNUNET_SERVER_MAX_MESSAGE_SIZE) ||
       (get_path_length > GNUNET_SERVER_MAX_MESSAGE_SIZE / sizeof (struct GNUNET_PeerIdentity)) ||
       (put_path_length > GNUNET_SERVER_MAX_MESSAGE_SIZE / sizeof (struct GNUNET_PeerIdentity)) ||
       (data_size > GNUNET_SERVER_MAX_MESSAGE_SIZE) )
  {
    GNUNET_break (0);
    return;
  }
  pi = GNUNET_CONTAINER_multihashmap_get (all_known_peers,
					  &target->hashPubKey);
  if (NULL == pi)
  {
    /* peer disconnected in the meantime, drop reply */
    return;
  }
  pending = GNUNET_malloc (sizeof (struct P2PPendingMessage) + msize); 
  pending->importance = 0; /* FIXME */
  pending->timeout = expiration_time;
  prm = (struct PeerResultMessage*) &pending[1];
  pending->msg = &prm->header;
  prm->header.size = htons (msize);
  prm->header.type = htons (GNUNET_MESSAGE_TYPE_DHT_P2P_RESULT);
  prm->type = htonl (type);
  prm->put_path_length = htonl (put_path_length);
  prm->get_path_length = htonl (get_path_length);
  prm->expiration_time = GNUNET_TIME_absolute_hton (expiration_time);
  prm->key = *key;
  paths = (struct GNUNET_PeerIdentity) &prm[1];
  memcpy (paths, put_path, put_path_length * sizeof (struct GNUNET_PeerIdentity));
  memcpy (&paths[put_path_length],
	  get_path, get_path_length * sizeof (struct GNUNET_PeerIdentity));
  memcpy (&paths[put_path_length + get_path_length],
	  data, data_size);
  GNUNET_CONTAINER_DLL_insert (target->head,
			       target->tail,
			       pending);
  target->pending_count++;
  process_peer_queue (target);
}


/**
 * Closure for 'add_known_to_bloom'.
 */
struct BloomConstructorContext
{
  /**
   * Bloom filter under construction.
   */
  struct GNUNET_CONTAINER_BloomFilter *bloom;

  /**
   * Mutator to use.
   */
  uint32_t bf_mutator;
};


/**
 * Add each of the peers we already know to the bloom filter of
 * the request so that we don't get duplicate HELLOs.
 *
 * @param cls the 'struct BloomConstructorContext'.
 * @param key peer identity to add to the bloom filter
 * @param value value the peer information (unused)
 * @return GNUNET_YES (we should continue to iterate)
 */
static int
add_known_to_bloom (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct BloomConstructorContext *ctx = cls;
  GNUNET_HashCode mh;

  GNUNET_BLOCK_mingle_hash (key, ctx->bf_mutator, &mh);
  GNUNET_CONTAINER_bloomfilter_add (ctx->bloom, &mh);
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
  struct BloomConstructorContext bcc;

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
  bcc.bf_mutator = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, UINT32_MAX);
  bcc.bloom =
    GNUNET_CONTAINER_bloomfilter_init (NULL, DHT_BLOOM_SIZE, DHT_BLOOM_K);
  GNUNET_CONTAINER_multihashmap_iterate (all_known_peers, 
					 &add_known_to_bloom,
                                         &bcc);
  // FIXME: pass priority!?
  GDS_NEIGHBOURS_handle_get (GNUNET_BLOCK_TYPE_DHT_HELLO,
			     GNUNET_DHT_RO_FIND_PEER,
			     16 /* FIXME: replication level? */,
			     0,
			     &my_identity.hashPubKey,
			     NULL, 0,
			     bcc.bloom, bcc.bf_mutator, NULL);
  GNUNET_CONTAINER_bloomfilter_free (bcc.bloom);
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
 * Core handler for p2p put requests.
 *
 * @param cls closure
 * @param peer sender of the request
 * @param message message
 * @param peer peer identity this notification is about
 * @param atsi performance data
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_dht_p2p_put (void *cls,
		    const struct GNUNET_PeerIdentity *peer,
		    const struct GNUNET_MessageHeader *message,
		    const struct GNUNET_TRANSPORT_ATS_Information
		    *atsi)
{
  const struct PeerPutMessage *put;
  const struct GNUNET_PeerIdentity *put_path;
  const void *payload;
  uint32_t putlen;
  uint16_t msize;
  size_t payload_size;
  struct GNUNET_CONTAINER_BloomFilter *bf;
  GNUNET_HashCode test_key;
  
  msize = ntohs (message->size);
  if (msize < sizeof (struct PeerPutMessage))
  {
    GNUNET_break_op (0);
    return GNUNET_YES;
  }
  put = (const struct PeerPutMessage*) message;
  putlen = ntohl (put->put_path_length);
  if ( (msize < sizeof (struct PeerPutMessage) + putlen * sizeof (struct GNUNET_PeerIdentity)) ||
       (putlen > GNUNET_SERVER_MAX_MESSAGE_SIZE / sizeof (struct GNUNET_PeerIdentity)) )
    {
      GNUNET_break_op (0);
      return GNUNET_YES;
    }
  put_path = (const struct GNUNET_PeerIdentity*) &put[1];  
  payload = &put_path[putlen];
  payload_size = msize - (sizeof (struct PeerPutMessage) + 
			  putlen * sizeof (struct GNUNET_PeerIdentity));
  switch (GNUNET_BLOCK_get_key (block_context,
				ntohl (put->type),
				payload, payload_size,
				&test_key))
  {
  case GNUNET_YES:
    if (0 != memcmp (&test_key, key, sizeof (GNUNET_HashCode)))
    {
      GNUNET_break_op (0);
      return GNUNET_YES;
    }
    break;
  case GNUNET_NO:
    GNUNET_break_op (0);
    return GNUNET_YES;
  case GNUNET_SYSERR:
    /* cannot verify, good luck */
    break;
  }
  bf = GNUNET_CONTAINER_bloomfilter_init (put->bloomfilter,
					  DHT_BLOOM_SIZE,
					  DHT_BLOOM_K);
  {
    struct GNUNET_PeerIdentity pp[putlen+1];
  
    /* extend 'put path' by sender */
    memcpy (pp, put_path, putlen * sizeof (struct GNUNET_PeerIdentity));
    pp[putlen] = *sender;

    /* give to local clients */
    GDS_CLIENT_handle_reply (GNUNET_TIME_absolute_ntoh (put->expiration_time),
			     &put->key,
			     0, NULL,
			     putlen + 1,
			     pp,
			     ntohl (put->type),
			     payload_size,
			     payload);
    /* store locally */
    GDS_DATACACHE_handle_put (GNUNET_TIME_absolute_ntoh (put->expiration_time),
			      &put->key,
			      putlen + 1, pp,
			      ntohl (put->type),
			      payload_size,
			      payload);
    /* route to other peers */
    GDS_NEIGHBOURS_handle_put (ntohl (put->type),
			       ntohl (put->options),
			       ntohl (put->desired_replication_level),
			       GNUNET_TIME_absolute_ntoh (put->expiration_time),
			       ntohl (put->hop_count),
			       bf,
			       putlen + 1, pp,
			       payload,
			       payload_size);
  }
  GNUNET_CONTAINER_bloomfilter_free (bf);
  return GNUNET_YES;
}


/**
 * Core handler for p2p get requests.
 *
 * @param cls closure
 * @param peer sender of the request
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
  struct PeerGetMessage *get;
  uint32_t xquery_size;
  size_t reply_bf_size;
  uint16_t msize;
  enum GNUNET_BLOCK_Type type;
  enum GNUNET_DHT_RouteOption options;
  enum GNUNET_BLOCK_EvaluationResult eval;
  struct GNUNET_CONTAINER_BloomFilter *reply_bf;
  struct GNUNET_CONTAINER_BloomFilter *peer_bf;
  const char *xquery;
                      
  /* parse and validate message */
  msize = ntohs (message->size);
  if (msize < sizeof (struct PeerGetMessage))
  {
    GNUNET_break_op (0);
    return GNUNET_YES;
  }
  get = (struct PeerGetMessage *) message;
  xquery_size = ntohl (get->xquery_size);
  if (msize < sizeof (struct PeerGetMessage) + xquery_size)
  {
    GNUNET_break_op (0);
    return GNUNET_YES;
  }
  reply_bf_size = msize - (sizeof (struct PeerGetMessage) + xquery_size);
  type = ntohl (get->type);
  options = ntohl (get->options);
  xquery = (const char*) &get[1];
  reply_bf = NULL;
  if (reply_bf_size > 0)
    reply_bf = GNUNET_CONTAINER_bloomfilter_init (&xquery[xquery_size],
						  reply_bf_size,
						  GNUNET_DHT_GET_BLOOMFILTER_K);
  eval = GNUNET_BLOCK_evaluate (block_context,
				type,
				&get->key,
				&reply_bf,
				get->bf_mutator,
				xquery, xquery_size,
				NULL, 0);
  if (eval != GNUNET_BLOCK_EVALUATION_REQUEST_VALID)
  {
    /* request invalid or block type not supported */
    GNUNET_break_op (eval == GNUNET_BLOCK_EVALUATION_TYPE_NOT_SUPPORTED);
    if (NULL != reply_bf)
      GNUNET_CONTAINER_bloomfilter_free (reply_bf);
    return GNUNET_YES;
  }
  peer_bf =
    GNUNET_CONTAINER_bloomfilter_init (get->bloomfilter, 
				       DHT_BLOOM_SIZE,
				       DHT_BLOOM_K);

  /* remember request for routing replies */
  GDS_ROUTING_add (peer,
		   type,
		   &get->key,
		   xquery, xquery_size,
		   reply_bf, get->reply_bf_mutator);
  /* FIXME: check options (find peer, local-processing-only-if-nearest, etc.!) */

  /* local lookup (this may update the reply_bf) */
  GDS_DATACACHE_handle_get (&get->key,
			    type,
			    xquery, xquery_size,
			    &reply_bf, 
			    get->reply_bf_mutator);
  /* FIXME: should track if the local lookup resulted in a
     definitive result and then NOT do P2P forwarding */
    
  /* P2P forwarding */
  GDS_NEIGHBOURS_handle_get (type,
			     options,
			     ntohl (get->desired_replication_level),
			     ntohl (get->hop_count) + 1, /* CHECK: where (else) do we do +1? */
			     &get->key,
			     xquery, xquery_size,
			     reply_bf,
			     get->reply_bf_mutator,
			     peer_bf);
  /* clean up */
  if (NULL != reply_bf)
    GNUNET_CONTAINER_bloomfilter_free (reply_bf);
  GNUNET_CONTAINER_bloomfilter_free (peer_bf);  
  return GNUNET_YES;
}


/**
 * Core handler for p2p result messages.
 *
 * @param cls closure
 * @param message message
 * @param peer peer identity this notification is about
 * @param atsi performance data
 * @return GNUNET_YES (do not cut p2p connection)
 */
static int
handle_dht_p2p_result (void *cls, const struct GNUNET_PeerIdentity *peer,
		       const struct GNUNET_MessageHeader *message,
		       const struct GNUNET_TRANSPORT_ATS_Information
		       *atsi)
{
  const struct PeerResultMessage *prm;
  const struct GNUNET_PeerIdentity *put_path;
  const struct GNUNET_PeerIdentity *get_path;
  const void *data;
  uint32_t get_path_length;
  uint32_t put_path_length;
  uint16_t msize;
  size_t data_size;
  enum GNUNET_BLOCK_Type type;
                       
  /* parse and validate message */
  msize = ntohs (message->size);
  if (msize < sizeof (struct PeerResultMessage))
  {
    GNUNET_break_op (0);
    return GNUNET_YES;
  }
  prm = (struct PeerResultMessage *) message;
  put_path_length = ntohl (prm->put_path_length);
  get_path_length = ntohl (prm->get_path_length);
  if ( (msize < sizeof (struct PeerResultMessage) + 
	(get_path_length + put_path_length) * sizeof (struct GNUNET_PeerIdentity)) ||
       (get_path_length > GNUNET_SERVER_MAX_MESSAGE_SIZE / sizeof (struct GNUNET_PeerIdentity)) ||
       (put_path_length > GNUNET_SERVER_MAX_MESSAGE_SIZE / sizeof (struct GNUNET_PeerIdentity)) )
  {
    GNUNET_break_op (0);
    return GNUNET_YES;
  } 
  put_path = (const struct GNUNET_PeerIdentity*) &prm[1];
  get_path = &put_path[put_path_length];
  type = ntohl (prm->type);
  data = (const void*) &get_path[get_path_length];
  data_size = msize - (sizeof (struct PeerResultMessage) + 
		       (get_path_length + put_path_length) * sizeof (struct GNUNET_PeerIdentity));
  /* append 'peer' to 'get_path' */
  {    
    struct GNUNET_PeerIdentity xget_path[get_path_length+1];
    
    memcpy (xget_path, get_path, get_path_length * sizeof (struct GNUNET_PeerIdentity));
    xget_path[get_path_length] = *peer;

    /* forward to local clients */   
    GDS_CLIENT_handle_reply (GNUNET_TIME_absolute_ntoh (prm->expiration),
			     &prm->key,
			     get_path_length + 1,
			     xget_path,
			     put_path_length,
			     put_path,
			     type,
			     data_size, 
			     data);

    /* forward to other peers */
    GDS_ROUTING_process (type,
			 GNUNET_TIME_absolute_ntoh (prm->expiration),
			 &prm->key,
			 put_path_length,
			 put_path,
			 get_path_length + 1,
			 xget_path,
			 data,
			 data_size);			 
  }
  return GNUNET_YES;
}


/**
 * Initialize neighbours subsystem.
 */
int
GDS_NEIGHBOURS_init ()
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
  coreAPI = GNUNET_CORE_connect (GDS_cfg,
                                 DEFAULT_CORE_QUEUE_SIZE,
                                 NULL,
                                 &core_init,
                                 &handle_core_connect,
                                 &handle_core_disconnect, 
                                 NULL,  /* Do we care about "status" updates? */
                                 NULL, GNUNET_NO,
                                 NULL, GNUNET_NO,
                                 core_handlers);
  if (coreAPI == NULL)
    return GNUNET_SYSERR;
  all_known_peers = GNUNET_CONTAINER_multihashmap_create (256);
  return GNUNET_OK;
}


/**
 * Shutdown neighbours subsystem.
 */
void
GDS_NEIGHBOURS_done ()
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
