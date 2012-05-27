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
#include "gnunet_hello_lib.h"
#include "gnunet_constants.h"
#include "gnunet_protocols.h"
#include "gnunet_nse_service.h"
#include "gnunet_ats_service.h"
#include "gnunet_core_service.h"
#include "gnunet_datacache_lib.h"
#include "gnunet_transport_service.h"
#include "gnunet_hello_lib.h"
#include "gnunet_dht_service.h"
#include "gnunet_statistics_service.h"
#include "gnunet-service-dht.h"
#include "gnunet-service-dht_clients.h"
#include "gnunet-service-dht_datacache.h"
#include "gnunet-service-dht_hello.h"
#include "gnunet-service-dht_neighbours.h"
#include "gnunet-service-dht_nse.h"
#include "gnunet-service-dht_routing.h"
#include <fenv.h>
#include "dht.h"

/**
 * How many buckets will we allow total.
 */
#define MAX_BUCKETS sizeof (GNUNET_HashCode) * 8

/**
 * What is the maximum number of peers in a given bucket.
 */
#define DEFAULT_BUCKET_SIZE 8

/**
 * Desired replication level for FIND PEER requests
 */
#define FIND_PEER_REPLICATION_LEVEL 4

/**
 * Maximum allowed replication level for all requests.
 */
#define MAXIMUM_REPLICATION_LEVEL 16

/**
 * How often to update our preference levels for peers in our routing tables.
 */
#define DHT_DEFAULT_PREFERENCE_INTERVAL GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MINUTES, 2)

/**
 * How long at least to wait before sending another find peer request.
 */
#define DHT_MINIMUM_FIND_PEER_INTERVAL GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 30)

/**
 * How long at most to wait before sending another find peer request.
 */
#define DHT_MAXIMUM_FIND_PEER_INTERVAL GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MINUTES, 10)

/**
 * How long at most to wait for transmission of a GET request to another peer?
 */
#define GET_TIMEOUT GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MINUTES, 2)


GNUNET_NETWORK_STRUCT_BEGIN

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
GNUNET_NETWORK_STRUCT_END

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
 * Identity of this peer.
 */
static struct GNUNET_PeerIdentity my_identity;

/**
 * Handle to CORE.
 */
static struct GNUNET_CORE_Handle *coreAPI;

/**
 * Handle to ATS.
 */
static struct GNUNET_ATS_PerformanceHandle *atsAPI;



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
 * Let GNUnet core know that we like the given peer.
 *
 * @param cls the 'struct PeerInfo' of the peer
 * @param tc scheduler context.
 */
static void
update_core_preference (void *cls,
                        const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct PeerInfo *peer = cls;
  uint64_t preference;
  unsigned int matching;
  int bucket;

  peer->preference_task = GNUNET_SCHEDULER_NO_TASK;
  if ((tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) != 0)
    return;
  matching =
      GNUNET_CRYPTO_hash_matching_bits (&my_identity.hashPubKey,
                                        &peer->id.hashPubKey);
  if (matching >= 64)
    matching = 63;
  bucket = find_bucket (&peer->id.hashPubKey);
  if (bucket == GNUNET_SYSERR)
    preference = 0;
  else
  {
    GNUNET_assert (k_buckets[bucket].peers_size != 0);
    preference = (1LL << matching) / k_buckets[bucket].peers_size;
  }
  if (preference == 0)
  {
    peer->preference_task =
        GNUNET_SCHEDULER_add_delayed (DHT_DEFAULT_PREFERENCE_INTERVAL,
                                      &update_core_preference, peer);
    return;
  }
  GNUNET_STATISTICS_update (GDS_stats,
                            gettext_noop ("# Preference updates given to core"),
                            1, GNUNET_NO);
  GNUNET_ATS_change_preference (atsAPI, &peer->id,
                                GNUNET_ATS_PREFERENCE_BANDWIDTH,
                                (double) preference, GNUNET_ATS_PREFERENCE_END);
  peer->preference_task =
      GNUNET_SCHEDULER_add_delayed (DHT_DEFAULT_PREFERENCE_INTERVAL,
                                    &update_core_preference, peer);


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
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Adding known peer (%s) to bloomfilter for FIND PEER with mutation %u\n",
              GNUNET_h2s (key), ctx->bf_mutator);
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
  struct GNUNET_TIME_Relative next_send_time;
  struct BloomConstructorContext bcc;
  struct GNUNET_CONTAINER_BloomFilter *peer_bf;

  find_peer_task = GNUNET_SCHEDULER_NO_TASK;
  if ((tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) != 0)
    return;
  if (newly_found_peers > bucket_size)
  {
    /* If we are finding many peers already, no need to send out our request right now! */
    find_peer_task =
        GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_MINUTES,
                                      &send_find_peer_message, NULL);
    newly_found_peers = 0;
    return;
  }
  bcc.bf_mutator =
      GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, UINT32_MAX);
  bcc.bloom =
      GNUNET_CONTAINER_bloomfilter_init (NULL, DHT_BLOOM_SIZE,
                                         GNUNET_CONSTANTS_BLOOMFILTER_K);
  GNUNET_CONTAINER_multihashmap_iterate (all_known_peers, &add_known_to_bloom,
                                         &bcc);
  GNUNET_STATISTICS_update (GDS_stats,
                            gettext_noop ("# FIND PEER messages initiated"), 1,
                            GNUNET_NO);
  peer_bf =
      GNUNET_CONTAINER_bloomfilter_init (NULL, DHT_BLOOM_SIZE,
                                         GNUNET_CONSTANTS_BLOOMFILTER_K);
  // FIXME: pass priority!?
  GDS_NEIGHBOURS_handle_get (GNUNET_BLOCK_TYPE_DHT_HELLO,
                             GNUNET_DHT_RO_FIND_PEER,
                             FIND_PEER_REPLICATION_LEVEL, 0,
                             &my_identity.hashPubKey, NULL, 0, bcc.bloom,
                             bcc.bf_mutator, peer_bf);
  GNUNET_CONTAINER_bloomfilter_free (peer_bf);
  GNUNET_CONTAINER_bloomfilter_free (bcc.bloom);
  /* schedule next round */
  next_send_time.rel_value =
      DHT_MINIMUM_FIND_PEER_INTERVAL.rel_value +
      GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_WEAK,
                                DHT_MAXIMUM_FIND_PEER_INTERVAL.rel_value /
                                (newly_found_peers + 1));
  newly_found_peers = 0;
  find_peer_task =
      GNUNET_SCHEDULER_add_delayed (next_send_time, &send_find_peer_message,
                                    NULL);
}


/**
 * Method called whenever a peer connects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 * @param atsi performance data
 * @param atsi_count number of records in 'atsi'
 */
static void
handle_core_connect (void *cls, const struct GNUNET_PeerIdentity *peer,
                     const struct GNUNET_ATS_Information *atsi,
                     unsigned int atsi_count)
{
  struct PeerInfo *ret;
  int peer_bucket;

  /* Check for connect to self message */
  if (0 == memcmp (&my_identity, peer, sizeof (struct GNUNET_PeerIdentity)))
    return;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Connected %s to %s\n",
              GNUNET_i2s (&my_identity), GNUNET_h2s (&peer->hashPubKey));
  if (GNUNET_YES ==
      GNUNET_CONTAINER_multihashmap_contains (all_known_peers,
                                              &peer->hashPubKey))
  {
    GNUNET_break (0);
    return;
  }
  GNUNET_STATISTICS_update (GDS_stats, gettext_noop ("# peers connected"), 1,
                            GNUNET_NO);
  peer_bucket = find_bucket (&peer->hashPubKey);
  GNUNET_assert ((peer_bucket >= 0) && (peer_bucket < MAX_BUCKETS));
  ret = GNUNET_malloc (sizeof (struct PeerInfo));
#if 0
  ret->latency = latency;
  ret->distance = distance;
#endif
  ret->id = *peer;
  GNUNET_CONTAINER_DLL_insert_tail (k_buckets[peer_bucket].head,
                                    k_buckets[peer_bucket].tail, ret);
  k_buckets[peer_bucket].peers_size++;
  closest_bucket = GNUNET_MAX (closest_bucket, peer_bucket);
  if ((peer_bucket > 0) && (k_buckets[peer_bucket].peers_size <= bucket_size))
  {
    ret->preference_task =
        GNUNET_SCHEDULER_add_now (&update_core_preference, ret);
    newly_found_peers++;
  }
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multihashmap_put (all_known_peers,
                                                    &peer->hashPubKey, ret,
                                                    GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  if (1 == GNUNET_CONTAINER_multihashmap_size (all_known_peers))
  {
    /* got a first connection, good time to start with FIND PEER requests... */
    find_peer_task = GNUNET_SCHEDULER_add_now (&send_find_peer_message, NULL);
  }
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
  unsigned int discarded;

  /* Check for disconnect from self message */
  if (0 == memcmp (&my_identity, peer, sizeof (struct GNUNET_PeerIdentity)))
    return;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Disconnected %s from %s\n",
              GNUNET_i2s (&my_identity), GNUNET_h2s (&peer->hashPubKey));
  to_remove =
      GNUNET_CONTAINER_multihashmap_get (all_known_peers, &peer->hashPubKey);
  if (NULL == to_remove)
  {
    GNUNET_break (0);
    return;
  }
  GNUNET_STATISTICS_update (GDS_stats, gettext_noop ("# peers connected"), -1,
                            GNUNET_NO);
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap_remove (all_known_peers,
                                                       &peer->hashPubKey,
                                                       to_remove));
  if (GNUNET_SCHEDULER_NO_TASK != to_remove->preference_task)
  {
    GNUNET_SCHEDULER_cancel (to_remove->preference_task);
    to_remove->preference_task = GNUNET_SCHEDULER_NO_TASK;
  }
  current_bucket = find_bucket (&to_remove->id.hashPubKey);
  GNUNET_assert (current_bucket >= 0);
  GNUNET_CONTAINER_DLL_remove (k_buckets[current_bucket].head,
                               k_buckets[current_bucket].tail, to_remove);
  GNUNET_assert (k_buckets[current_bucket].peers_size > 0);
  k_buckets[current_bucket].peers_size--;
  while ((closest_bucket > 0) && (k_buckets[closest_bucket].peers_size == 0))
    closest_bucket--;

  if (to_remove->th != NULL)
  {
    GNUNET_CORE_notify_transmit_ready_cancel (to_remove->th);
    to_remove->th = NULL;
  }
  discarded = 0;
  while (NULL != (pos = to_remove->head))
  {
    GNUNET_CONTAINER_DLL_remove (to_remove->head, to_remove->tail, pos);
    discarded++;
    GNUNET_free (pos);
  }
  GNUNET_STATISTICS_update (GDS_stats,
                            gettext_noop
                            ("# Queued messages discarded (peer disconnected)"),
                            discarded, GNUNET_NO);
  GNUNET_free (to_remove);
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
  while ((NULL != (pending = peer->head)) &&
         (GNUNET_TIME_absolute_get_remaining (pending->timeout).rel_value == 0))
  {
    peer->pending_count--;
    GNUNET_CONTAINER_DLL_remove (peer->head, peer->tail, pending);
    GNUNET_free (pending);
  }
  if (pending == NULL)
  {
    /* no messages pending */
    return 0;
  }
  if (buf == NULL)
  {
    peer->th =
        GNUNET_CORE_notify_transmit_ready (coreAPI, GNUNET_YES,
                                           pending->importance,
                                           GNUNET_TIME_absolute_get_remaining
                                           (pending->timeout), &peer->id,
                                           ntohs (pending->msg->size),
                                           &core_transmit_notify, peer);
    GNUNET_break (NULL != peer->th);
    return 0;
  }
  off = 0;
  while ((NULL != (pending = peer->head)) &&
         (size - off >= (msize = ntohs (pending->msg->size))))
  {
    GNUNET_STATISTICS_update (GDS_stats,
                              gettext_noop
                              ("# Bytes transmitted to other peers"), msize,
                              GNUNET_NO);
    memcpy (&cbuf[off], pending->msg, msize);
    off += msize;
    peer->pending_count--;
    GNUNET_CONTAINER_DLL_remove (peer->head, peer->tail, pending);
    GNUNET_free (pending);
  }
  if (peer->head != NULL)
  {
    peer->th =
        GNUNET_CORE_notify_transmit_ready (coreAPI, GNUNET_YES,
                                           pending->importance,
                                           GNUNET_TIME_absolute_get_remaining
                                           (pending->timeout), &peer->id, msize,
                                           &core_transmit_notify, peer);
    GNUNET_break (NULL != peer->th);
  }
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

  if (NULL == (pending = peer->head))
    return;
  if (NULL != peer->th)
    return;
  GNUNET_STATISTICS_update (GDS_stats,
                            gettext_noop
                            ("# Bytes of bandwdith requested from core"),
                            ntohs (pending->msg->size), GNUNET_NO);
  peer->th =
      GNUNET_CORE_notify_transmit_ready (coreAPI, GNUNET_YES,
                                         pending->importance,
                                         GNUNET_TIME_absolute_get_remaining
                                         (pending->timeout), &peer->id,
                                         ntohs (pending->msg->size),
                                         &core_transmit_notify, peer);
  GNUNET_break (NULL != peer->th);
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
get_forward_count (uint32_t hop_count, uint32_t target_replication)
{
  uint32_t random_value;
  uint32_t forward_count;
  float target_value;

  if (hop_count > GDS_NSE_get () * 6.0)
  {
    /* forcefully terminate */
    return 0;
  }
  if (hop_count > GDS_NSE_get () * 4.0)
  {
    /* Once we have reached our ideal number of hops, only forward to 1 peer */
    return 1;
  }
  /* bound by system-wide maximum */
  target_replication =
      GNUNET_MIN (MAXIMUM_REPLICATION_LEVEL, target_replication);
  target_value =
      1 + (target_replication - 1.0) / (GDS_NSE_get () +
                                        ((float) (target_replication - 1.0) *
                                         hop_count));
  /* Set forward count to floor of target_value */
  forward_count = (uint32_t) target_value;
  /* Subtract forward_count (floor) from target_value (yields value between 0 and 1) */
  target_value = target_value - forward_count;
  random_value =
      GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, UINT32_MAX);
  if (random_value < (target_value * UINT32_MAX))
    forward_count++;
  return forward_count;
}


/**
 * Compute the distance between have and target as a 32-bit value.
 * Differences in the lower bits must count stronger than differences
 * in the higher bits.
 *
 * @return 0 if have==target, otherwise a number
 *           that is larger as the distance between
 *           the two hash codes increases
 */
static unsigned int
get_distance (const GNUNET_HashCode * target, const GNUNET_HashCode * have)
{
  unsigned int bucket;
  unsigned int msb;
  unsigned int lsb;
  unsigned int i;

  /* We have to represent the distance between two 2^9 (=512)-bit
   * numbers as a 2^5 (=32)-bit number with "0" being used for the
   * two numbers being identical; furthermore, we need to
   * guarantee that a difference in the number of matching
   * bits is always represented in the result.
   *
   * We use 2^32/2^9 numerical values to distinguish between
   * hash codes that have the same LSB bit distance and
   * use the highest 2^9 bits of the result to signify the
   * number of (mis)matching LSB bits; if we have 0 matching
   * and hence 512 mismatching LSB bits we return -1 (since
   * 512 itself cannot be represented with 9 bits) */

  /* first, calculate the most significant 9 bits of our
   * result, aka the number of LSBs */
  bucket = GNUNET_CRYPTO_hash_matching_bits (target, have);
  /* bucket is now a value between 0 and 512 */
  if (bucket == 512)
    return 0;                   /* perfect match */
  if (bucket == 0)
    return (unsigned int) -1;   /* LSB differs; use max (if we did the bit-shifting
                                 * below, we'd end up with max+1 (overflow)) */

  /* calculate the most significant bits of the final result */
  msb = (512 - bucket) << (32 - 9);
  /* calculate the 32-9 least significant bits of the final result by
   * looking at the differences in the 32-9 bits following the
   * mismatching bit at 'bucket' */
  lsb = 0;
  for (i = bucket + 1;
       (i < sizeof (GNUNET_HashCode) * 8) && (i < bucket + 1 + 32 - 9); i++)
  {
    if (GNUNET_CRYPTO_hash_get_bit (target, i) !=
        GNUNET_CRYPTO_hash_get_bit (have, i))
      lsb |= (1 << (bucket + 32 - 9 - i));      /* first bit set will be 10,
                                                 * last bit set will be 31 -- if
                                                 * i does not reach 512 first... */
  }
  return msb | lsb;
}


/**
 * Check whether my identity is closer than any known peers.  If a
 * non-null bloomfilter is given, check if this is the closest peer
 * that hasn't already been routed to.
 *
 * @param key hash code to check closeness to
 * @param bloom bloomfilter, exclude these entries from the decision
 * @return GNUNET_YES if node location is closest,
 *         GNUNET_NO otherwise.
 */
static int
am_closest_peer (const GNUNET_HashCode * key,
                 const struct GNUNET_CONTAINER_BloomFilter *bloom)
{
  int bits;
  int other_bits;
  int bucket_num;
  int count;
  struct PeerInfo *pos;

  if (0 == memcmp (&my_identity.hashPubKey, key, sizeof (GNUNET_HashCode)))
    return GNUNET_YES;
  bucket_num = find_bucket (key);
  GNUNET_assert (bucket_num >= 0);
  bits = GNUNET_CRYPTO_hash_matching_bits (&my_identity.hashPubKey, key);
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
    if (other_bits == bits)     /* We match the same number of bits */
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
select_peer (const GNUNET_HashCode * key,
             const struct GNUNET_CONTAINER_BloomFilter *bloom, uint32_t hops)
{
  unsigned int bc;
  unsigned int count;
  unsigned int selected;
  struct PeerInfo *pos;
  unsigned int dist;
  unsigned int smallest_distance;
  struct PeerInfo *chosen;

  if (hops >= GDS_NSE_get ())
  {
    /* greedy selection (closest peer that is not in bloomfilter) */
    smallest_distance = UINT_MAX;
    chosen = NULL;
    for (bc = 0; bc <= closest_bucket; bc++)
    {
      pos = k_buckets[bc].head;
      count = 0;
      while ((pos != NULL) && (count < bucket_size))
      {
        if ((bloom == NULL) ||
            (GNUNET_NO ==
             GNUNET_CONTAINER_bloomfilter_test (bloom, &pos->id.hashPubKey)))
        {
          dist = get_distance (key, &pos->id.hashPubKey);
          if (dist < smallest_distance)
          {
            chosen = pos;
            smallest_distance = dist;
          }
        }
        else
        {
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                      "Excluded peer `%s' due to BF match in greedy routing for %s\n",
                      GNUNET_i2s (&pos->id), GNUNET_h2s (key));
          GNUNET_STATISTICS_update (GDS_stats,
                                    gettext_noop
                                    ("# Peers excluded from routing due to Bloomfilter"),
                                    1, GNUNET_NO);
        }
        count++;
        pos = pos->next;
      }
    }
    if (NULL == chosen)
      GNUNET_STATISTICS_update (GDS_stats,
                                gettext_noop ("# Peer selection failed"), 1,
                                GNUNET_NO);
    return chosen;
  }

  /* select "random" peer */
  /* count number of peers that are available and not filtered */
  count = 0;
  for (bc = 0; bc <= closest_bucket; bc++)
  {
    pos = k_buckets[bc].head;
    while ((pos != NULL) && (count < bucket_size))
    {
      if ((bloom != NULL) &&
          (GNUNET_YES ==
           GNUNET_CONTAINER_bloomfilter_test (bloom, &pos->id.hashPubKey)))
      {
        GNUNET_STATISTICS_update (GDS_stats,
                                  gettext_noop
                                  ("# Peers excluded from routing due to Bloomfilter"),
                                  1, GNUNET_NO);
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "Excluded peer `%s' due to BF match in random routing for %s\n",
                    GNUNET_i2s (&pos->id), GNUNET_h2s (key));
        pos = pos->next;
        continue;               /* Ignore bloomfiltered peers */
      }
      count++;
      pos = pos->next;
    }
  }
  if (count == 0)               /* No peers to select from! */
  {
    GNUNET_STATISTICS_update (GDS_stats,
                              gettext_noop ("# Peer selection failed"), 1,
                              GNUNET_NO);
    return NULL;
  }
  /* Now actually choose a peer */
  selected = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, count);
  count = 0;
  for (bc = 0; bc <= closest_bucket; bc++)
  {
    pos = k_buckets[bc].head;
    while ((pos != NULL) && (count < bucket_size))
    {
      if ((bloom != NULL) &&
          (GNUNET_YES ==
           GNUNET_CONTAINER_bloomfilter_test (bloom, &pos->id.hashPubKey)))
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
get_target_peers (const GNUNET_HashCode * key,
                  struct GNUNET_CONTAINER_BloomFilter *bloom,
                  uint32_t hop_count, uint32_t target_replication,
                  struct PeerInfo ***targets)
{
  unsigned int ret;
  unsigned int off;
  struct PeerInfo **rtargets;
  struct PeerInfo *nxt;

  GNUNET_assert (NULL != bloom);
  ret = get_forward_count (hop_count, target_replication);
  if (ret == 0)
  {
    *targets = NULL;
    return 0;
  }
  rtargets = GNUNET_malloc (sizeof (struct PeerInfo *) * ret);
  for (off = 0; off < ret; off++)
  {
    nxt = select_peer (key, bloom, hop_count);
    if (nxt == NULL)
      break;
    rtargets[off] = nxt;
    GNUNET_break (GNUNET_NO ==
                  GNUNET_CONTAINER_bloomfilter_test (bloom,
                                                     &nxt->id.hashPubKey));
    GNUNET_CONTAINER_bloomfilter_add (bloom, &rtargets[off]->id.hashPubKey);
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Selected %u/%u peers at hop %u for %s (target was %u)\n", off,
              GNUNET_CONTAINER_multihashmap_size (all_known_peers),
              (unsigned int) hop_count, GNUNET_h2s (key), ret);
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
                           struct GNUNET_TIME_Absolute expiration_time,
                           uint32_t hop_count,
                           struct GNUNET_CONTAINER_BloomFilter *bf,
                           const GNUNET_HashCode * key,
                           unsigned int put_path_length,
                           struct GNUNET_PeerIdentity *put_path,
                           const void *data, size_t data_size)
{
  unsigned int target_count;
  unsigned int i;
  struct PeerInfo **targets;
  struct PeerInfo *target;
  struct P2PPendingMessage *pending;
  size_t msize;
  struct PeerPutMessage *ppm;
  struct GNUNET_PeerIdentity *pp;

  GNUNET_assert (NULL != bf);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Adding myself (%s) to PUT bloomfilter for %s\n",
              GNUNET_i2s (&my_identity), GNUNET_h2s (key));
  GNUNET_CONTAINER_bloomfilter_add (bf, &my_identity.hashPubKey);
  GNUNET_STATISTICS_update (GDS_stats, gettext_noop ("# PUT requests routed"),
                            1, GNUNET_NO);
  target_count =
      get_target_peers (key, bf, hop_count, desired_replication_level,
                        &targets);
  if (0 == target_count)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Routing PUT for %s terminates after %u hops at %s\n",
                GNUNET_h2s (key), (unsigned int) hop_count,
                GNUNET_i2s (&my_identity));
    return;
  }
  msize =
      put_path_length * sizeof (struct GNUNET_PeerIdentity) + data_size +
      sizeof (struct PeerPutMessage);
  if (msize >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
  {
    put_path_length = 0;
    msize = data_size + sizeof (struct PeerPutMessage);
  }
  if (msize >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    GNUNET_free (targets);
    return;
  }
  GNUNET_STATISTICS_update (GDS_stats,
                            gettext_noop
                            ("# PUT messages queued for transmission"),
                            target_count, GNUNET_NO);
  for (i = 0; i < target_count; i++)
  {
    target = targets[i];
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Routing PUT for %s after %u hops to %s\n", GNUNET_h2s (key),
                (unsigned int) hop_count, GNUNET_i2s (&target->id));
    pending = GNUNET_malloc (sizeof (struct P2PPendingMessage) + msize);
    pending->importance = 0;    /* FIXME */
    pending->timeout = expiration_time;
    ppm = (struct PeerPutMessage *) &pending[1];
    pending->msg = &ppm->header;
    ppm->header.size = htons (msize);
    ppm->header.type = htons (GNUNET_MESSAGE_TYPE_DHT_P2P_PUT);
    ppm->options = htonl (options);
    ppm->type = htonl (type);
    ppm->hop_count = htonl (hop_count + 1);
    ppm->desired_replication_level = htonl (desired_replication_level);
    ppm->put_path_length = htonl (put_path_length);
    ppm->expiration_time = GNUNET_TIME_absolute_hton (expiration_time);
    GNUNET_break (GNUNET_YES ==
                  GNUNET_CONTAINER_bloomfilter_test (bf,
                                                     &target->id.hashPubKey));
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CONTAINER_bloomfilter_get_raw_data (bf,
                                                              ppm->bloomfilter,
                                                              DHT_BLOOM_SIZE));
    ppm->key = *key;
    pp = (struct GNUNET_PeerIdentity *) &ppm[1];
    memcpy (pp, put_path,
            sizeof (struct GNUNET_PeerIdentity) * put_path_length);
    memcpy (&pp[put_path_length], data, data_size);
    GNUNET_CONTAINER_DLL_insert_tail (target->head, target->tail, pending);
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
                           uint32_t hop_count, const GNUNET_HashCode * key,
                           const void *xquery, size_t xquery_size,
                           const struct GNUNET_CONTAINER_BloomFilter *reply_bf,
                           uint32_t reply_bf_mutator,
                           struct GNUNET_CONTAINER_BloomFilter *peer_bf)
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

  GNUNET_assert (NULL != peer_bf);
  GNUNET_STATISTICS_update (GDS_stats, gettext_noop ("# GET requests routed"),
                            1, GNUNET_NO);
  target_count =
      get_target_peers (key, peer_bf, hop_count, desired_replication_level,
                        &targets);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Adding myself (%s) to GET bloomfilter for %s\n",
              GNUNET_i2s (&my_identity), GNUNET_h2s (key));
  GNUNET_CONTAINER_bloomfilter_add (peer_bf, &my_identity.hashPubKey);
  if (0 == target_count)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Routing GET for %s terminates after %u hops at %s\n",
                GNUNET_h2s (key), (unsigned int) hop_count,
                GNUNET_i2s (&my_identity));
    return;
  }
  reply_bf_size = GNUNET_CONTAINER_bloomfilter_get_size (reply_bf);
  msize = xquery_size + sizeof (struct PeerGetMessage) + reply_bf_size;
  if (msize >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    GNUNET_free (targets);
    return;
  }
  GNUNET_STATISTICS_update (GDS_stats,
                            gettext_noop
                            ("# GET messages queued for transmission"),
                            target_count, GNUNET_NO);
  /* forward request */
  for (i = 0; i < target_count; i++)
  {
    target = targets[i];
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Routing GET for %s after %u hops to %s\n", GNUNET_h2s (key),
                (unsigned int) hop_count, GNUNET_i2s (&target->id));
    pending = GNUNET_malloc (sizeof (struct P2PPendingMessage) + msize);
    pending->importance = 0;    /* FIXME */
    pending->timeout = GNUNET_TIME_relative_to_absolute (GET_TIMEOUT);
    pgm = (struct PeerGetMessage *) &pending[1];
    pending->msg = &pgm->header;
    pgm->header.size = htons (msize);
    pgm->header.type = htons (GNUNET_MESSAGE_TYPE_DHT_P2P_GET);
    pgm->options = htonl (options);
    pgm->type = htonl (type);
    pgm->hop_count = htonl (hop_count + 1);
    pgm->desired_replication_level = htonl (desired_replication_level);
    pgm->xquery_size = htonl (xquery_size);
    pgm->bf_mutator = reply_bf_mutator;
    GNUNET_break (GNUNET_YES ==
                  GNUNET_CONTAINER_bloomfilter_test (peer_bf,
                                                     &target->id.hashPubKey));
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CONTAINER_bloomfilter_get_raw_data (peer_bf,
                                                              pgm->bloomfilter,
                                                              DHT_BLOOM_SIZE));
    pgm->key = *key;
    xq = (char *) &pgm[1];
    memcpy (xq, xquery, xquery_size);
    if (NULL != reply_bf)
      GNUNET_assert (GNUNET_OK ==
                     GNUNET_CONTAINER_bloomfilter_get_raw_data (reply_bf,
                                                                &xq
                                                                [xquery_size],
                                                                reply_bf_size));
    GNUNET_CONTAINER_DLL_insert_tail (target->head, target->tail, pending);
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
GDS_NEIGHBOURS_handle_reply (const struct GNUNET_PeerIdentity *target,
                             enum GNUNET_BLOCK_Type type,
                             struct GNUNET_TIME_Absolute expiration_time,
                             const GNUNET_HashCode * key,
                             unsigned int put_path_length,
                             const struct GNUNET_PeerIdentity *put_path,
                             unsigned int get_path_length,
                             const struct GNUNET_PeerIdentity *get_path,
                             const void *data, size_t data_size)
{
  struct PeerInfo *pi;
  struct P2PPendingMessage *pending;
  size_t msize;
  struct PeerResultMessage *prm;
  struct GNUNET_PeerIdentity *paths;

  msize =
      data_size + sizeof (struct PeerResultMessage) + (get_path_length +
                                                       put_path_length) *
      sizeof (struct GNUNET_PeerIdentity);
  if ((msize >= GNUNET_SERVER_MAX_MESSAGE_SIZE) ||
      (get_path_length >
       GNUNET_SERVER_MAX_MESSAGE_SIZE / sizeof (struct GNUNET_PeerIdentity)) ||
      (put_path_length >
       GNUNET_SERVER_MAX_MESSAGE_SIZE / sizeof (struct GNUNET_PeerIdentity)) ||
      (data_size > GNUNET_SERVER_MAX_MESSAGE_SIZE))
  {
    GNUNET_break (0);
    return;
  }
  pi = GNUNET_CONTAINER_multihashmap_get (all_known_peers, &target->hashPubKey);
  if (NULL == pi)
  {
    /* peer disconnected in the meantime, drop reply */
    return;
  }
  GNUNET_STATISTICS_update (GDS_stats,
                            gettext_noop
                            ("# RESULT messages queued for transmission"), 1,
                            GNUNET_NO);
  pending = GNUNET_malloc (sizeof (struct P2PPendingMessage) + msize);
  pending->importance = 0;      /* FIXME */
  pending->timeout = expiration_time;
  prm = (struct PeerResultMessage *) &pending[1];
  pending->msg = &prm->header;
  prm->header.size = htons (msize);
  prm->header.type = htons (GNUNET_MESSAGE_TYPE_DHT_P2P_RESULT);
  prm->type = htonl (type);
  prm->put_path_length = htonl (put_path_length);
  prm->get_path_length = htonl (get_path_length);
  prm->expiration_time = GNUNET_TIME_absolute_hton (expiration_time);
  prm->key = *key;
  paths = (struct GNUNET_PeerIdentity *) &prm[1];
  memcpy (paths, put_path,
          put_path_length * sizeof (struct GNUNET_PeerIdentity));
  memcpy (&paths[put_path_length], get_path,
          get_path_length * sizeof (struct GNUNET_PeerIdentity));
  memcpy (&paths[put_path_length + get_path_length], data, data_size);
  GNUNET_CONTAINER_DLL_insert (pi->head, pi->tail, pending);
  pi->pending_count++;
  process_peer_queue (pi);
}


/**
 * To be called on core init/fail.
 *
 * @param cls service closure
 * @param server handle to the server for this service
 * @param identity the public identity of this peer
 */
static void
core_init (void *cls, struct GNUNET_CORE_Handle *server,
           const struct GNUNET_PeerIdentity *identity)
{
  GNUNET_assert (server != NULL);
  my_identity = *identity;
}


/**
 * Core handler for p2p put requests.
 *
 * @param cls closure
 * @param peer sender of the request
 * @param message message
 * @param peer peer identity this notification is about
 * @param atsi performance data
 * @param atsi_count number of records in 'atsi'
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_dht_p2p_put (void *cls, const struct GNUNET_PeerIdentity *peer,
                    const struct GNUNET_MessageHeader *message,
                    const struct GNUNET_ATS_Information *atsi,
                    unsigned int atsi_count)
{
  const struct PeerPutMessage *put;
  const struct GNUNET_PeerIdentity *put_path;
  const void *payload;
  uint32_t putlen;
  uint16_t msize;
  size_t payload_size;
  enum GNUNET_DHT_RouteOption options;
  struct GNUNET_CONTAINER_BloomFilter *bf;
  GNUNET_HashCode test_key;

  msize = ntohs (message->size);
  if (msize < sizeof (struct PeerPutMessage))
  {
    GNUNET_break_op (0);
    return GNUNET_YES;
  }
  put = (const struct PeerPutMessage *) message;
  putlen = ntohl (put->put_path_length);
  if ((msize <
       sizeof (struct PeerPutMessage) +
       putlen * sizeof (struct GNUNET_PeerIdentity)) ||
      (putlen >
       GNUNET_SERVER_MAX_MESSAGE_SIZE / sizeof (struct GNUNET_PeerIdentity)))
  {
    GNUNET_break_op (0);
    return GNUNET_YES;
  }
  GNUNET_STATISTICS_update (GDS_stats,
                            gettext_noop ("# P2P PUT requests received"), 1,
                            GNUNET_NO);
  put_path = (const struct GNUNET_PeerIdentity *) &put[1];
  payload = &put_path[putlen];
  options = ntohl (put->options);
  payload_size =
      msize - (sizeof (struct PeerPutMessage) +
               putlen * sizeof (struct GNUNET_PeerIdentity));
  switch (GNUNET_BLOCK_get_key
          (GDS_block_context, ntohl (put->type), payload, payload_size,
           &test_key))
  {
  case GNUNET_YES:
    if (0 != memcmp (&test_key, &put->key, sizeof (GNUNET_HashCode)))
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
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "PUT for `%s' from %s\n",
              GNUNET_h2s (&put->key), GNUNET_i2s (peer));
  bf = GNUNET_CONTAINER_bloomfilter_init (put->bloomfilter, DHT_BLOOM_SIZE,
                                          GNUNET_CONSTANTS_BLOOMFILTER_K);
  GNUNET_break_op (GNUNET_YES ==
                   GNUNET_CONTAINER_bloomfilter_test (bf, &peer->hashPubKey));
  {
    struct GNUNET_PeerIdentity pp[putlen + 1];

    /* extend 'put path' by sender */
    if (0 != (options & GNUNET_DHT_RO_RECORD_ROUTE))
    {
      memcpy (pp, put_path, putlen * sizeof (struct GNUNET_PeerIdentity));
      pp[putlen] = *peer;
      putlen++;
    }
    else
      putlen = 0;

    /* give to local clients */
    GDS_CLIENTS_handle_reply (GNUNET_TIME_absolute_ntoh (put->expiration_time),
                              &put->key, 0, NULL, putlen, pp, ntohl (put->type),
                              payload_size, payload);
    /* store locally */
    if ((0 != (options & GNUNET_DHT_RO_DEMULTIPLEX_EVERYWHERE)) ||
        (am_closest_peer (&put->key, bf)))
      GDS_DATACACHE_handle_put (GNUNET_TIME_absolute_ntoh
                                (put->expiration_time), &put->key, putlen, pp,
                                ntohl (put->type), payload_size, payload);
    /* route to other peers */
    GDS_NEIGHBOURS_handle_put (ntohl (put->type), options,
                               ntohl (put->desired_replication_level),
                               GNUNET_TIME_absolute_ntoh (put->expiration_time),
                               ntohl (put->hop_count), bf, &put->key, putlen,
                               pp, payload, payload_size);
  }
  GNUNET_CONTAINER_bloomfilter_free (bf);
  GDS_CLIENTS_process_put (options,
                           ntohl (put->type),
                           ntohl (put->hop_count),
                           ntohl (put->desired_replication_level),
                           putlen, put_path,
                           GNUNET_TIME_absolute_ntoh (put->expiration_time),
                           &put->key,
                           payload,
                           payload_size);
  return GNUNET_YES;
}


/**
 * We have received a FIND PEER request.  Send matching
 * HELLOs back.
 *
 * @param sender sender of the FIND PEER request
 * @param key peers close to this key are desired
 * @param bf peers matching this bf are excluded
 * @param bf_mutator mutator for bf
 */
static void
handle_find_peer (const struct GNUNET_PeerIdentity *sender,
                  const GNUNET_HashCode * key,
                  struct GNUNET_CONTAINER_BloomFilter *bf, uint32_t bf_mutator)
{
  int bucket_idx;
  struct PeerBucket *bucket;
  struct PeerInfo *peer;
  unsigned int choice;
  GNUNET_HashCode mhash;
  const struct GNUNET_HELLO_Message *hello;

  /* first, check about our own HELLO */
  if (NULL != GDS_my_hello)
  {
    GNUNET_BLOCK_mingle_hash (&my_identity.hashPubKey, bf_mutator, &mhash);
    if ((NULL == bf) ||
        (GNUNET_YES != GNUNET_CONTAINER_bloomfilter_test (bf, &mhash)))
    {
      GDS_NEIGHBOURS_handle_reply (sender, GNUNET_BLOCK_TYPE_DHT_HELLO,
                                   GNUNET_TIME_relative_to_absolute
                                   (GNUNET_CONSTANTS_HELLO_ADDRESS_EXPIRATION),
                                   key, 0, NULL, 0, NULL, GDS_my_hello,
                                   GNUNET_HELLO_size ((const struct
                                                       GNUNET_HELLO_Message *)
                                                      GDS_my_hello));
    }
    else
    {
      GNUNET_STATISTICS_update (GDS_stats,
                                gettext_noop
                                ("# FIND PEER requests ignored due to Bloomfilter"),
                                1, GNUNET_NO);
    }
  }
  else
  {
    GNUNET_STATISTICS_update (GDS_stats,
                              gettext_noop
                              ("# FIND PEER requests ignored due to lack of HELLO"),
                              1, GNUNET_NO);
  }

  /* then, also consider sending a random HELLO from the closest bucket */
  if (0 == memcmp (&my_identity.hashPubKey, key, sizeof (GNUNET_HashCode)))
    bucket_idx = closest_bucket;
  else
    bucket_idx = GNUNET_MIN (closest_bucket, find_bucket (key));
  if (bucket_idx == GNUNET_SYSERR)
    return;
  bucket = &k_buckets[bucket_idx];
  if (bucket->peers_size == 0)
    return;
  choice =
      GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, bucket->peers_size);
  peer = bucket->head;
  while (choice > 0)
  {
    GNUNET_assert (peer != NULL);
    peer = peer->next;
    choice--;
  }
  choice = bucket->peers_size;
  do
  {
    peer = peer->next;
    if (choice-- == 0)
      return;                   /* no non-masked peer available */
    if (peer == NULL)
      peer = bucket->head;
    GNUNET_BLOCK_mingle_hash (&peer->id.hashPubKey, bf_mutator, &mhash);
    hello = GDS_HELLO_get (&peer->id);
  }
  while ((hello == NULL) ||
         (GNUNET_YES == GNUNET_CONTAINER_bloomfilter_test (bf, &mhash)));
  GDS_NEIGHBOURS_handle_reply (sender, GNUNET_BLOCK_TYPE_DHT_HELLO,
                               GNUNET_TIME_relative_to_absolute
                               (GNUNET_CONSTANTS_HELLO_ADDRESS_EXPIRATION), key,
                               0, NULL, 0, NULL, hello,
                               GNUNET_HELLO_size (hello));
}


/**
 * Core handler for p2p get requests.
 *
 * @param cls closure
 * @param peer sender of the request
 * @param message message
 * @param peer peer identity this notification is about
 * @param atsi performance data
 * @param atsi_count number of records in 'atsi'
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_dht_p2p_get (void *cls, const struct GNUNET_PeerIdentity *peer,
                    const struct GNUNET_MessageHeader *message,
                    const struct GNUNET_ATS_Information *atsi,
                    unsigned int atsi_count)
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

  GNUNET_break (0 !=
                memcmp (peer, &my_identity,
                        sizeof (struct GNUNET_PeerIdentity)));
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
  GNUNET_STATISTICS_update (GDS_stats,
                            gettext_noop ("# P2P GET requests received"), 1,
                            GNUNET_NO);
  reply_bf_size = msize - (sizeof (struct PeerGetMessage) + xquery_size);
  type = ntohl (get->type);
  options = ntohl (get->options);
  xquery = (const char *) &get[1];
  reply_bf = NULL;
  if (reply_bf_size > 0)
    reply_bf =
        GNUNET_CONTAINER_bloomfilter_init (&xquery[xquery_size], reply_bf_size,
                                           GNUNET_CONSTANTS_BLOOMFILTER_K);
  eval =
      GNUNET_BLOCK_evaluate (GDS_block_context, type, &get->key, &reply_bf,
                             get->bf_mutator, xquery, xquery_size, NULL, 0);
  if (eval != GNUNET_BLOCK_EVALUATION_REQUEST_VALID)
  {
    /* request invalid or block type not supported */
    GNUNET_break_op (eval == GNUNET_BLOCK_EVALUATION_TYPE_NOT_SUPPORTED);
    if (NULL != reply_bf)
      GNUNET_CONTAINER_bloomfilter_free (reply_bf);
    return GNUNET_YES;
  }
  peer_bf =
      GNUNET_CONTAINER_bloomfilter_init (get->bloomfilter, DHT_BLOOM_SIZE,
                                         GNUNET_CONSTANTS_BLOOMFILTER_K);
  GNUNET_break_op (GNUNET_YES ==
                   GNUNET_CONTAINER_bloomfilter_test (peer_bf,
                                                      &peer->hashPubKey));
  /* remember request for routing replies */
  GDS_ROUTING_add (peer, type, options, &get->key, xquery, xquery_size,
                   reply_bf, get->bf_mutator);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "GET for %s at %s after %u hops\n",
              GNUNET_h2s (&get->key), GNUNET_i2s (&my_identity),
              (unsigned int) ntohl (get->hop_count));
  /* local lookup (this may update the reply_bf) */
  if ((0 != (options & GNUNET_DHT_RO_DEMULTIPLEX_EVERYWHERE)) ||
      (am_closest_peer (&get->key, peer_bf)))
  {
    if ((0 != (options & GNUNET_DHT_RO_FIND_PEER)))
    {
      GNUNET_STATISTICS_update (GDS_stats,
                                gettext_noop
                                ("# P2P FIND PEER requests processed"), 1,
                                GNUNET_NO);
      handle_find_peer (peer, &get->key, reply_bf, get->bf_mutator);
    }
    else
    {
      eval =
          GDS_DATACACHE_handle_get (&get->key, type, xquery, xquery_size,
                                    &reply_bf, get->bf_mutator);
    }
  }
  else
  {
    GNUNET_STATISTICS_update (GDS_stats,
                              gettext_noop ("# P2P GET requests ONLY routed"),
                              1, GNUNET_NO);
  }

  /* FIXME Path */
  GDS_CLIENTS_process_get (options,
                           type,
                           ntohl(get->hop_count),
                           ntohl(get->desired_replication_level),
                           0, NULL,
                           &get->key);

  /* P2P forwarding */
  if (eval != GNUNET_BLOCK_EVALUATION_OK_LAST)
    GDS_NEIGHBOURS_handle_get (type, options,
                               ntohl (get->desired_replication_level),
                               ntohl (get->hop_count), &get->key, xquery,
                               xquery_size, reply_bf, get->bf_mutator, peer_bf);
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
 * @param atsi_count number of records in 'atsi'
 * @return GNUNET_YES (do not cut p2p connection)
 */
static int
handle_dht_p2p_result (void *cls, const struct GNUNET_PeerIdentity *peer,
                       const struct GNUNET_MessageHeader *message,
                       const struct GNUNET_ATS_Information *atsi,
                       unsigned int atsi_count)
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
  if ((msize <
       sizeof (struct PeerResultMessage) + (get_path_length +
                                            put_path_length) *
       sizeof (struct GNUNET_PeerIdentity)) ||
      (get_path_length >
       GNUNET_SERVER_MAX_MESSAGE_SIZE / sizeof (struct GNUNET_PeerIdentity)) ||
      (put_path_length >
       GNUNET_SERVER_MAX_MESSAGE_SIZE / sizeof (struct GNUNET_PeerIdentity)))
  {
    GNUNET_break_op (0);
    return GNUNET_YES;
  }
  GNUNET_STATISTICS_update (GDS_stats, gettext_noop ("# P2P RESULTS received"),
                            1, GNUNET_NO);
  put_path = (const struct GNUNET_PeerIdentity *) &prm[1];
  get_path = &put_path[put_path_length];
  type = ntohl (prm->type);
  data = (const void *) &get_path[get_path_length];
  data_size =
      msize - (sizeof (struct PeerResultMessage) +
               (get_path_length +
                put_path_length) * sizeof (struct GNUNET_PeerIdentity));

  /* if we got a HELLO, consider it for our own routing table */
  if (type == GNUNET_BLOCK_TYPE_DHT_HELLO)
  {
    const struct GNUNET_MessageHeader *h;
    struct GNUNET_PeerIdentity pid;
    int bucket;

    /* Should be a HELLO, validate and consider using it! */
    if (data_size < sizeof (struct GNUNET_MessageHeader))
    {
      GNUNET_break_op (0);
      return GNUNET_YES;
    }
    h = data;
    if (data_size != ntohs (h->size))
    {
      GNUNET_break_op (0);
      return GNUNET_YES;
    }
    if (GNUNET_OK !=
        GNUNET_HELLO_get_id ((const struct GNUNET_HELLO_Message *) h, &pid))
    {
      GNUNET_break_op (0);
      return GNUNET_YES;
    }
    if (0 != memcmp (&my_identity, &pid, sizeof (struct GNUNET_PeerIdentity)))
    {
      bucket = find_bucket (&pid.hashPubKey);
      if ((bucket >= 0) && (k_buckets[bucket].peers_size < bucket_size))
      {
        if (NULL != GDS_transport_handle)
        {
          GNUNET_TRANSPORT_offer_hello (GDS_transport_handle, h, NULL, NULL);
          GNUNET_TRANSPORT_try_connect (GDS_transport_handle, &pid);
        }
      }
    }
  }

  /* append 'peer' to 'get_path' */
  {
    struct GNUNET_PeerIdentity xget_path[get_path_length + 1];

    memcpy (xget_path, get_path,
            get_path_length * sizeof (struct GNUNET_PeerIdentity));
    xget_path[get_path_length] = *peer;
    get_path_length++;

    /* forward to local clients */
    GDS_CLIENTS_handle_reply (GNUNET_TIME_absolute_ntoh (prm->expiration_time),
                              &prm->key, get_path_length, xget_path,
                              put_path_length, put_path, type, data_size, data);

    /* forward to other peers */
    GDS_ROUTING_process (type, GNUNET_TIME_absolute_ntoh (prm->expiration_time),
                         &prm->key, put_path_length, put_path, get_path_length,
                         xget_path, data, data_size);
  }

  GDS_CLIENTS_process_get_resp (type,
                                get_path,
                                get_path_length,
                                put_path,
                                put_path_length,
                                GNUNET_TIME_absolute_ntoh (
                                  prm->expiration_time),
                                &prm->key,
                                data,
                                data_size);

  return GNUNET_YES;
}


/**
 * Initialize neighbours subsystem.
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GDS_NEIGHBOURS_init ()
{
  static struct GNUNET_CORE_MessageHandler core_handlers[] = {
    {&handle_dht_p2p_get, GNUNET_MESSAGE_TYPE_DHT_P2P_GET, 0},
    {&handle_dht_p2p_put, GNUNET_MESSAGE_TYPE_DHT_P2P_PUT, 0},
    {&handle_dht_p2p_result, GNUNET_MESSAGE_TYPE_DHT_P2P_RESULT, 0},
    {NULL, 0, 0}
  };
  unsigned long long temp_config_num;

  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_get_value_number (GDS_cfg, "DHT", "bucket_size",
                                             &temp_config_num))
    bucket_size = (unsigned int) temp_config_num;
  atsAPI = GNUNET_ATS_performance_init (GDS_cfg, NULL, NULL);
  coreAPI =
      GNUNET_CORE_connect (GDS_cfg, 1, NULL, &core_init, &handle_core_connect,
                           &handle_core_disconnect, NULL, GNUNET_NO, NULL,
                           GNUNET_NO, core_handlers);
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
  if (coreAPI == NULL)
    return;
  GNUNET_CORE_disconnect (coreAPI);
  coreAPI = NULL;
  GNUNET_ATS_performance_done (atsAPI);
  atsAPI = NULL;
  GNUNET_assert (0 == GNUNET_CONTAINER_multihashmap_size (all_known_peers));
  GNUNET_CONTAINER_multihashmap_destroy (all_known_peers);
  all_known_peers = NULL;
  if (GNUNET_SCHEDULER_NO_TASK != find_peer_task)
  {
    GNUNET_SCHEDULER_cancel (find_peer_task);
    find_peer_task = GNUNET_SCHEDULER_NO_TASK;
  }
}

/**
 * Get the ID of the local node.
 * 
 * @return identity of the local node
 */
struct GNUNET_PeerIdentity *
GDS_NEIGHBOURS_get_id ()
{
    return &my_identity;
}


/* end of gnunet-service-dht_neighbours.c */
