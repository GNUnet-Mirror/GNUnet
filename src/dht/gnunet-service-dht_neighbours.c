/*
     This file is part of GNUnet.
     Copyright (C) 2009-2017 GNUnet e.V.

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
 * @file dht/gnunet-service-dht_neighbours.c
 * @brief GNUnet DHT service's bucket and neighbour management code
 * @author Christian Grothoff
 * @author Nathan Evans
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_block_lib.h"
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
#include "gnunet-service-dht_datacache.h"
#include "gnunet-service-dht_hello.h"
#include "gnunet-service-dht_neighbours.h"
#include "gnunet-service-dht_nse.h"
#include "gnunet-service-dht_routing.h"
#include "dht.h"

#define LOG_TRAFFIC(kind, ...) GNUNET_log_from (kind, "dht-traffic", \
                                                __VA_ARGS__)

/**
 * Enable slow sanity checks to debug issues.
 */
#define SANITY_CHECKS 1

/**
 * How many buckets will we allow total.
 */
#define MAX_BUCKETS sizeof(struct GNUNET_HashCode) * 8

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
 * Maximum allowed number of pending messages per peer.
 */
#define MAXIMUM_PENDING_PER_PEER 64

/**
 * How long at least to wait before sending another find peer request.
 */
#define DHT_MINIMUM_FIND_PEER_INTERVAL GNUNET_TIME_relative_multiply ( \
    GNUNET_TIME_UNIT_SECONDS, 30)

/**
 * How long at most to wait before sending another find peer request.
 */
#define DHT_MAXIMUM_FIND_PEER_INTERVAL GNUNET_TIME_relative_multiply ( \
    GNUNET_TIME_UNIT_MINUTES, 10)

/**
 * How long at most to wait for transmission of a GET request to another peer?
 */
#define GET_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 2)

/**
 * Hello address expiration
 */
extern struct GNUNET_TIME_Relative hello_expiration;


GNUNET_NETWORK_STRUCT_BEGIN

/**
 * P2P PUT message
 */
struct PeerPutMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_DHT_P2P_PUT
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
  struct GNUNET_HashCode key;

  /* put path (if tracked) */

  /* Payload */
};


/**
 * P2P Result message
 */
struct PeerResultMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_DHT_P2P_RESULT
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
  struct GNUNET_HashCode key;

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
   * Type: #GNUNET_MESSAGE_TYPE_DHT_P2P_GET
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
  struct GNUNET_HashCode key;

  /* xquery */

  /* result bloomfilter */
};
GNUNET_NETWORK_STRUCT_END


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
   * Handle for sending messages to this peer.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * What is the identity of the peer?
   */
  const struct GNUNET_PeerIdentity *id;

  /**
   * Hash of @e id.
   */
  struct GNUNET_HashCode phash;

  /**
   * Which bucket is this peer in?
   */
  int peer_bucket;
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
 * Information about a peer that we would like to connect to.
 */
struct ConnectInfo
{
  /**
   * Handle to active HELLO offer operation, or NULL.
   */
  struct GNUNET_TRANSPORT_OfferHelloHandle *oh;

  /**
   * Handle to active connectivity suggestion operation, or NULL.
   */
  struct GNUNET_ATS_ConnectivitySuggestHandle *sh;

  /**
   * How much would we like to connect to this peer?
   */
  uint32_t strength;
};


/**
 * Do we cache all results that we are routing in the local datacache?
 */
static int cache_results;

/**
 * Should routing details be logged to stderr (for debugging)?
 */
static int log_route_details_stderr;

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
 * Option for testing that disables the 'connect' function of the DHT.
 */
static int disable_try_connect;

/**
 * The buckets.  Array of size #MAX_BUCKETS.  Offset 0 means 0 bits matching.
 */
static struct PeerBucket k_buckets[MAX_BUCKETS];

/**
 * Hash map of all CORE-connected peers, for easy removal from
 * #k_buckets on disconnect.  Values are of type `struct PeerInfo`.
 */
static struct GNUNET_CONTAINER_MultiPeerMap *all_connected_peers;

/**
 * Hash map of all peers we would like to be connected to.
 * Values are of type `struct ConnectInfo`.
 */
static struct GNUNET_CONTAINER_MultiPeerMap *all_desired_peers;

/**
 * Maximum size for each bucket.
 */
static unsigned int bucket_size = DEFAULT_BUCKET_SIZE;

/**
 * Task that sends FIND PEER requests.
 */
static struct GNUNET_SCHEDULER_Task *find_peer_task;

/**
 * Identity of this peer.
 */
static struct GNUNET_PeerIdentity my_identity;

/**
 * Hash of the identity of this peer.
 */
struct GNUNET_HashCode my_identity_hash;

/**
 * Handle to CORE.
 */
static struct GNUNET_CORE_Handle *core_api;

/**
 * Handle to ATS connectivity.
 */
static struct GNUNET_ATS_ConnectivityHandle *ats_ch;


/**
 * Find the optimal bucket for this key.
 *
 * @param hc the hashcode to compare our identity to
 * @return the proper bucket index, or #GNUNET_SYSERR
 *         on error (same hashcode)
 */
static int
find_bucket (const struct GNUNET_HashCode *hc)
{
  unsigned int bits;

  bits = GNUNET_CRYPTO_hash_matching_bits (&my_identity_hash, hc);
  if (bits == MAX_BUCKETS)
  {
    /* How can all bits match? Got my own ID? */
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return MAX_BUCKETS - bits - 1;
}


/**
 * Function called when #GNUNET_TRANSPORT_offer_hello() is done.
 * Clean up the "oh" field in the @a cls
 *
 * @param cls a `struct ConnectInfo`
 */
static void
offer_hello_done (void *cls)
{
  struct ConnectInfo *ci = cls;

  ci->oh = NULL;
}


/**
 * Function called for all entries in #all_desired_peers to clean up.
 *
 * @param cls NULL
 * @param peer peer the entry is for
 * @param value the value to remove
 * @return #GNUNET_YES
 */
static int
free_connect_info (void *cls,
                   const struct GNUNET_PeerIdentity *peer,
                   void *value)
{
  struct ConnectInfo *ci = value;

  (void) cls;
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multipeermap_remove (all_desired_peers,
                                                       peer,
                                                       ci));
  if (NULL != ci->sh)
  {
    GNUNET_ATS_connectivity_suggest_cancel (ci->sh);
    ci->sh = NULL;
  }
  if (NULL != ci->oh)
  {
    GNUNET_TRANSPORT_offer_hello_cancel (ci->oh);
    ci->oh = NULL;
  }
  GNUNET_free (ci);
  return GNUNET_YES;
}


/**
 * Consider if we want to connect to a given peer, and if so
 * let ATS know.  If applicable, the HELLO is offered to the
 * TRANSPORT service.
 *
 * @param pid peer to consider connectivity requirements for
 * @param h a HELLO message, or NULL
 */
static void
try_connect (const struct GNUNET_PeerIdentity *pid,
             const struct GNUNET_MessageHeader *h)
{
  int bucket;
  struct GNUNET_HashCode pid_hash;
  struct ConnectInfo *ci;
  uint32_t strength;

  GNUNET_CRYPTO_hash (pid,
                      sizeof(struct GNUNET_PeerIdentity),
                      &pid_hash);
  bucket = find_bucket (&pid_hash);
  if (bucket < 0)
    return; /* self? */
  ci = GNUNET_CONTAINER_multipeermap_get (all_desired_peers,
                                          pid);

  if (k_buckets[bucket].peers_size < bucket_size)
    strength = (bucket_size - k_buckets[bucket].peers_size) * bucket;
  else
    strength = bucket; /* minimum value of connectivity */
  if (GNUNET_YES ==
      GNUNET_CONTAINER_multipeermap_contains (all_connected_peers,
                                              pid))
    strength *= 2; /* double for connected peers */
  else if (k_buckets[bucket].peers_size > bucket_size)
    strength = 0; /* bucket full, we really do not care about more */

  if ((0 == strength) &&
      (NULL != ci))
  {
    /* release request */
    GNUNET_assert (GNUNET_YES ==
                   free_connect_info (NULL,
                                      pid,
                                      ci));
    return;
  }
  if (NULL == ci)
  {
    ci = GNUNET_new (struct ConnectInfo);
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CONTAINER_multipeermap_put (all_desired_peers,
                                                      pid,
                                                      ci,
                                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  }
  if ((NULL != ci->oh) &&
      (NULL != h))
    GNUNET_TRANSPORT_offer_hello_cancel (ci->oh);
  if (NULL != h)
    ci->oh = GNUNET_TRANSPORT_offer_hello (GDS_cfg,
                                           h,
                                           &offer_hello_done,
                                           ci);
  if ((NULL != ci->sh) &&
      (ci->strength != strength))
    GNUNET_ATS_connectivity_suggest_cancel (ci->sh);
  if (ci->strength != strength)
    ci->sh = GNUNET_ATS_connectivity_suggest (ats_ch,
                                              pid,
                                              strength);
  ci->strength = strength;
}


/**
 * Function called for each peer in #all_desired_peers during
 * #update_connect_preferences() if we have reason to adjust
 * the strength of our desire to keep connections to certain
 * peers.  Calls #try_connect() to update the calculations for
 * the given @a pid.
 *
 * @param cls NULL
 * @param pid peer to update
 * @param value unused
 * @return #GNUNET_YES (continue to iterate)
 */
static int
update_desire_strength (void *cls,
                        const struct GNUNET_PeerIdentity *pid,
                        void *value)
{
  (void) cls;
  (void) value;
  try_connect (pid,
               NULL);
  return GNUNET_YES;
}


/**
 * Update our preferences for connectivity as given to ATS.
 *
 * @param cls the `struct PeerInfo` of the peer
 * @param tc scheduler context.
 */
static void
update_connect_preferences ()
{
  GNUNET_CONTAINER_multipeermap_iterate (all_desired_peers,
                                         &update_desire_strength,
                                         NULL);
}


/**
 * Add each of the peers we already know to the bloom filter of
 * the request so that we don't get duplicate HELLOs.
 *
 * @param cls the `struct GNUNET_BLOCK_Group`
 * @param key peer identity to add to the bloom filter
 * @param value value the peer information (unused)
 * @return #GNUNET_YES (we should continue to iterate)
 */
static int
add_known_to_bloom (void *cls,
                    const struct GNUNET_PeerIdentity *key,
                    void *value)
{
  struct GNUNET_BLOCK_Group *bg = cls;
  struct GNUNET_HashCode key_hash;

  (void) cls;
  (void) value;
  GNUNET_CRYPTO_hash (key,
                      sizeof(struct GNUNET_PeerIdentity),
                      &key_hash);
  GNUNET_BLOCK_group_set_seen (bg,
                               &key_hash,
                               1);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Adding known peer (%s) to bloomfilter for FIND PEER\n",
              GNUNET_i2s (key));
  return GNUNET_YES;
}


/**
 * Task to send a find peer message for our own peer identifier
 * so that we can find the closest peers in the network to ourselves
 * and attempt to connect to them.
 *
 * @param cls closure for this task
 */
static void
send_find_peer_message (void *cls)
{
  struct GNUNET_TIME_Relative next_send_time;
  struct GNUNET_BLOCK_Group *bg;
  struct GNUNET_CONTAINER_BloomFilter *peer_bf;

  (void) cls;
  find_peer_task = NULL;
  if (newly_found_peers > bucket_size)
  {
    /* If we are finding many peers already, no need to send out our request right now! */
    find_peer_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_MINUTES,
                                    &send_find_peer_message,
                                    NULL);
    newly_found_peers = 0;
    return;
  }
  bg = GNUNET_BLOCK_group_create (GDS_block_context,
                                  GNUNET_BLOCK_TYPE_DHT_HELLO,
                                  GNUNET_CRYPTO_random_u32 (
                                    GNUNET_CRYPTO_QUALITY_WEAK,
                                    UINT32_MAX),
                                  NULL,
                                  0,
                                  "filter-size",
                                  DHT_BLOOM_SIZE,
                                  NULL);
  GNUNET_CONTAINER_multipeermap_iterate (all_connected_peers,
                                         &add_known_to_bloom,
                                         bg);
  GNUNET_STATISTICS_update (GDS_stats,
                            gettext_noop ("# FIND PEER messages initiated"),
                            1,
                            GNUNET_NO);
  peer_bf
    = GNUNET_CONTAINER_bloomfilter_init (NULL,
                                         DHT_BLOOM_SIZE,
                                         GNUNET_CONSTANTS_BLOOMFILTER_K);
  // FIXME: pass priority!?
  GDS_NEIGHBOURS_handle_get (GNUNET_BLOCK_TYPE_DHT_HELLO,
                             GNUNET_DHT_RO_FIND_PEER
                             | GNUNET_DHT_RO_RECORD_ROUTE,
                             FIND_PEER_REPLICATION_LEVEL,
                             0,
                             &my_identity_hash,
                             NULL,
                             0,
                             bg,
                             peer_bf);
  GNUNET_CONTAINER_bloomfilter_free (peer_bf);
  GNUNET_BLOCK_group_destroy (bg);
  /* schedule next round */
  next_send_time.rel_value_us =
    DHT_MINIMUM_FIND_PEER_INTERVAL.rel_value_us
    + GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_WEAK,
                                DHT_MAXIMUM_FIND_PEER_INTERVAL.rel_value_us
                                / (newly_found_peers + 1));
  newly_found_peers = 0;
  GNUNET_assert (NULL == find_peer_task);
  find_peer_task =
    GNUNET_SCHEDULER_add_delayed (next_send_time,
                                  &send_find_peer_message,
                                  NULL);
}


/**
 * Method called whenever a peer connects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 * @param mq message queue for sending messages to @a peer
 * @return our `struct PeerInfo` for @a peer
 */
static void *
handle_core_connect (void *cls,
                     const struct GNUNET_PeerIdentity *peer,
                     struct GNUNET_MQ_Handle *mq)
{
  struct PeerInfo *pi;

  (void) cls;
  /* Check for connect to self message */
  if (0 == GNUNET_memcmp (&my_identity,
                          peer))
    return NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Connected to %s\n",
              GNUNET_i2s (peer));
  GNUNET_assert (GNUNET_NO ==
                 GNUNET_CONTAINER_multipeermap_get (all_connected_peers,
                                                    peer));
  GNUNET_STATISTICS_update (GDS_stats,
                            gettext_noop ("# peers connected"),
                            1,
                            GNUNET_NO);
  pi = GNUNET_new (struct PeerInfo);
  pi->id = peer;
  pi->mq = mq;
  GNUNET_CRYPTO_hash (peer,
                      sizeof(struct GNUNET_PeerIdentity),
                      &pi->phash);
  pi->peer_bucket = find_bucket (&pi->phash);
  GNUNET_assert ((pi->peer_bucket >= 0) &&
                 ((unsigned int) pi->peer_bucket < MAX_BUCKETS));
  GNUNET_CONTAINER_DLL_insert_tail (k_buckets[pi->peer_bucket].head,
                                    k_buckets[pi->peer_bucket].tail,
                                    pi);
  k_buckets[pi->peer_bucket].peers_size++;
  closest_bucket = GNUNET_MAX (closest_bucket,
                               (unsigned int) pi->peer_bucket);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multipeermap_put (all_connected_peers,
                                                    pi->id,
                                                    pi,
                                                    GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  if ((pi->peer_bucket > 0) &&
      (k_buckets[pi->peer_bucket].peers_size <= bucket_size))
  {
    update_connect_preferences ();
    newly_found_peers++;
  }
  if ((1 == GNUNET_CONTAINER_multipeermap_size (all_connected_peers)) &&
      (GNUNET_YES != disable_try_connect))
  {
    /* got a first connection, good time to start with FIND PEER requests... */
    GNUNET_assert (NULL == find_peer_task);
    find_peer_task = GNUNET_SCHEDULER_add_now (&send_find_peer_message,
                                               NULL);
  }
  return pi;
}


/**
 * Method called whenever a peer disconnects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 * @param internal_cls our `struct PeerInfo` for @a peer
 */
static void
handle_core_disconnect (void *cls,
                        const struct GNUNET_PeerIdentity *peer,
                        void *internal_cls)
{
  struct PeerInfo *to_remove = internal_cls;

  (void) cls;
  /* Check for disconnect from self message */
  if (NULL == to_remove)
    return;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Disconnected %s\n",
              GNUNET_i2s (peer));
  GNUNET_STATISTICS_update (GDS_stats,
                            gettext_noop ("# peers connected"),
                            -1,
                            GNUNET_NO);
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multipeermap_remove (all_connected_peers,
                                                       peer,
                                                       to_remove));
  if ((0 == GNUNET_CONTAINER_multipeermap_size (all_connected_peers)) &&
      (GNUNET_YES != disable_try_connect))
  {
    GNUNET_SCHEDULER_cancel (find_peer_task);
    find_peer_task = NULL;
  }
  GNUNET_assert (to_remove->peer_bucket >= 0);
  GNUNET_CONTAINER_DLL_remove (k_buckets[to_remove->peer_bucket].head,
                               k_buckets[to_remove->peer_bucket].tail,
                               to_remove);
  GNUNET_assert (k_buckets[to_remove->peer_bucket].peers_size > 0);
  k_buckets[to_remove->peer_bucket].peers_size--;
  while ((closest_bucket > 0) &&
         (0 == k_buckets[to_remove->peer_bucket].peers_size))
    closest_bucket--;
  if (k_buckets[to_remove->peer_bucket].peers_size < bucket_size)
    update_connect_preferences ();
  GNUNET_free (to_remove);
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

  if (hop_count > GDS_NSE_get () * 4.0)
  {
    /* forcefully terminate */
    GNUNET_STATISTICS_update (GDS_stats,
                              gettext_noop ("# requests TTL-dropped"),
                              1, GNUNET_NO);
    return 0;
  }
  if (hop_count > GDS_NSE_get () * 2.0)
  {
    /* Once we have reached our ideal number of hops, only forward to 1 peer */
    return 1;
  }
  /* bound by system-wide maximum */
  target_replication =
    GNUNET_MIN (MAXIMUM_REPLICATION_LEVEL, target_replication);
  target_value =
    1 + (target_replication - 1.0) / (GDS_NSE_get ()
                                      + ((float) (target_replication - 1.0)
                                         * hop_count));
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
 * @param target
 * @param have
 * @return 0 if have==target, otherwise a number
 *           that is larger as the distance between
 *           the two hash codes increases
 */
static unsigned int
get_distance (const struct GNUNET_HashCode *target,
              const struct GNUNET_HashCode *have)
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
   * 512 itself cannot be represented with 9 bits) *//* first, calculate the most significant 9 bits of our
   * result, aka the number of LSBs */bucket = GNUNET_CRYPTO_hash_matching_bits (target,
                                             have);
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
       (i < sizeof(struct GNUNET_HashCode) * 8) && (i < bucket + 1 + 32 - 9);
       i++)
  {
    if (GNUNET_CRYPTO_hash_get_bit_rtl (target, i) !=
        GNUNET_CRYPTO_hash_get_bit_rtl (have, i))
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
 * @return #GNUNET_YES if node location is closest,
 *         #GNUNET_NO otherwise.
 */
int
GDS_am_closest_peer (const struct GNUNET_HashCode *key,
                     const struct GNUNET_CONTAINER_BloomFilter *bloom)
{
  int bits;
  int other_bits;
  int bucket_num;
  struct PeerInfo *pos;

  if (0 == GNUNET_memcmp (&my_identity_hash,
                          key))
    return GNUNET_YES;
  bucket_num = find_bucket (key);
  GNUNET_assert (bucket_num >= 0);
  bits = GNUNET_CRYPTO_hash_matching_bits (&my_identity_hash,
                                           key);
  pos = k_buckets[bucket_num].head;
  while (NULL != pos)
  {
    if ((NULL != bloom) &&
        (GNUNET_YES ==
         GNUNET_CONTAINER_bloomfilter_test (bloom,
                                            &pos->phash)))
    {
      pos = pos->next;
      continue;                 /* Skip already checked entries */
    }
    other_bits = GNUNET_CRYPTO_hash_matching_bits (&pos->phash,
                                                   key);
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
select_peer (const struct GNUNET_HashCode *key,
             const struct GNUNET_CONTAINER_BloomFilter *bloom,
             uint32_t hops)
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
        if ((NULL == bloom) ||
            (GNUNET_NO ==
             GNUNET_CONTAINER_bloomfilter_test (bloom,
                                                &pos->phash)))
        {
          dist = get_distance (key,
                               &pos->phash);
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
                      GNUNET_i2s (pos->id),
                      GNUNET_h2s (key));
          GNUNET_STATISTICS_update (GDS_stats,
                                    gettext_noop (
                                      "# Peers excluded from routing due to Bloomfilter"),
                                    1,
                                    GNUNET_NO);
          dist = get_distance (key,
                               &pos->phash);
          if (dist < smallest_distance)
          {
            chosen = NULL;
            smallest_distance = dist;
          }
        }
        count++;
        pos = pos->next;
      }
    }
    if (NULL == chosen)
      GNUNET_STATISTICS_update (GDS_stats,
                                gettext_noop ("# Peer selection failed"),
                                1,
                                GNUNET_NO);
    else
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Selected peer `%s' in greedy routing for %s\n",
                  GNUNET_i2s (chosen->id),
                  GNUNET_h2s (key));
    return chosen;
  }

  /* select "random" peer */
  /* count number of peers that are available and not filtered */
  count = 0;
  for (bc = 0; bc <= closest_bucket; bc++)
  {
    pos = k_buckets[bc].head;
    while ((NULL != pos) && (count < bucket_size))
    {
      if ((NULL != bloom) &&
          (GNUNET_YES ==
           GNUNET_CONTAINER_bloomfilter_test (bloom,
                                              &pos->phash)))
      {
        GNUNET_STATISTICS_update (GDS_stats,
                                  gettext_noop
                                  (
                                    "# Peers excluded from routing due to Bloomfilter"),
                                  1, GNUNET_NO);
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "Excluded peer `%s' due to BF match in random routing for %s\n",
                    GNUNET_i2s (pos->id),
                    GNUNET_h2s (key));
        pos = pos->next;
        continue;               /* Ignore bloomfiltered peers */
      }
      count++;
      pos = pos->next;
    }
  }
  if (0 == count)               /* No peers to select from! */
  {
    GNUNET_STATISTICS_update (GDS_stats,
                              gettext_noop ("# Peer selection failed"), 1,
                              GNUNET_NO);
    return NULL;
  }
  /* Now actually choose a peer */
  selected = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
                                       count);
  count = 0;
  for (bc = 0; bc <= closest_bucket; bc++)
  {
    for (pos = k_buckets[bc].head; ((pos != NULL) && (count < bucket_size));
         pos = pos->next)
    {
      if ((bloom != NULL) &&
          (GNUNET_YES ==
           GNUNET_CONTAINER_bloomfilter_test (bloom,
                                              &pos->phash)))
      {
        continue;               /* Ignore bloomfiltered peers */
      }
      if (0 == selected--)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "Selected peer `%s' in random routing for %s\n",
                    GNUNET_i2s (pos->id),
                    GNUNET_h2s (key));
        return pos;
      }
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
get_target_peers (const struct GNUNET_HashCode *key,
                  struct GNUNET_CONTAINER_BloomFilter *bloom,
                  uint32_t hop_count,
                  uint32_t target_replication,
                  struct PeerInfo ***targets)
{
  unsigned int ret;
  unsigned int off;
  struct PeerInfo **rtargets;
  struct PeerInfo *nxt;

  GNUNET_assert (NULL != bloom);
  ret = get_forward_count (hop_count,
                           target_replication);
  if (0 == ret)
  {
    *targets = NULL;
    return 0;
  }
  rtargets = GNUNET_new_array (ret,
                               struct PeerInfo *);
  for (off = 0; off < ret; off++)
  {
    nxt = select_peer (key,
                       bloom,
                       hop_count);
    if (NULL == nxt)
      break;
    rtargets[off] = nxt;
    GNUNET_break (GNUNET_NO ==
                  GNUNET_CONTAINER_bloomfilter_test (bloom,
                                                     &nxt->phash));
    GNUNET_CONTAINER_bloomfilter_add (bloom,
                                      &nxt->phash);
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Selected %u/%u peers at hop %u for %s (target was %u)\n",
              off,
              GNUNET_CONTAINER_multipeermap_size (all_connected_peers),
              (unsigned int) hop_count,
              GNUNET_h2s (key),
              ret);
  if (0 == off)
  {
    GNUNET_free (rtargets);
    *targets = NULL;
    return 0;
  }
  *targets = rtargets;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Forwarding query `%s' to %u peers (goal was %u peers)\n",
              GNUNET_h2s (key),
              off,
              ret);
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
 * @param put_path_length number of entries in @a put_path
 * @param put_path peers this request has traversed so far (if tracked)
 * @param data payload to store
 * @param data_size number of bytes in @a data
 * @return #GNUNET_OK if the request was forwarded, #GNUNET_NO if not
 */
int
GDS_NEIGHBOURS_handle_put (enum GNUNET_BLOCK_Type type,
                           enum GNUNET_DHT_RouteOption options,
                           uint32_t desired_replication_level,
                           struct GNUNET_TIME_Absolute expiration_time,
                           uint32_t hop_count,
                           struct GNUNET_CONTAINER_BloomFilter *bf,
                           const struct GNUNET_HashCode *key,
                           unsigned int put_path_length,
                           struct GNUNET_PeerIdentity *put_path,
                           const void *data,
                           size_t data_size)
{
  unsigned int target_count;
  unsigned int i;
  struct PeerInfo **targets;
  struct PeerInfo *target;
  size_t msize;
  struct GNUNET_MQ_Envelope *env;
  struct PeerPutMessage *ppm;
  struct GNUNET_PeerIdentity *pp;
  unsigned int skip_count;

  GNUNET_assert (NULL != bf);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Adding myself (%s) to PUT bloomfilter for %s\n",
              GNUNET_i2s (&my_identity),
              GNUNET_h2s (key));
  GNUNET_CONTAINER_bloomfilter_add (bf,
                                    &my_identity_hash);
  GNUNET_STATISTICS_update (GDS_stats,
                            gettext_noop ("# PUT requests routed"),
                            1,
                            GNUNET_NO);
  target_count
    = get_target_peers (key,
                        bf,
                        hop_count,
                        desired_replication_level,
                        &targets);
  if (0 == target_count)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Routing PUT for %s terminates after %u hops at %s\n",
                GNUNET_h2s (key),
                (unsigned int) hop_count,
                GNUNET_i2s (&my_identity));
    return GNUNET_NO;
  }
  msize = put_path_length * sizeof(struct GNUNET_PeerIdentity) + data_size;
  if (msize + sizeof(struct PeerPutMessage)
      >= GNUNET_CONSTANTS_MAX_ENCRYPTED_MESSAGE_SIZE)
  {
    put_path_length = 0;
    msize = data_size;
  }
  if (msize + sizeof(struct PeerPutMessage)
      >= GNUNET_CONSTANTS_MAX_ENCRYPTED_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    GNUNET_free (targets);
    return GNUNET_NO;
  }
  GNUNET_STATISTICS_update (GDS_stats,
                            gettext_noop (
                              "# PUT messages queued for transmission"),
                            target_count,
                            GNUNET_NO);
  skip_count = 0;
  for (i = 0; i < target_count; i++)
  {
    target = targets[i];
    if (GNUNET_MQ_get_length (target->mq) >= MAXIMUM_PENDING_PER_PEER)
    {
      /* skip */
      GNUNET_STATISTICS_update (GDS_stats,
                                gettext_noop (
                                  "# P2P messages dropped due to full queue"),
                                1,
                                GNUNET_NO);
      skip_count++;
      continue;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Routing PUT for %s after %u hops to %s\n",
                GNUNET_h2s (key),
                (unsigned int) hop_count,
                GNUNET_i2s (target->id));
    env = GNUNET_MQ_msg_extra (ppm,
                               msize,
                               GNUNET_MESSAGE_TYPE_DHT_P2P_PUT);
    ppm->options = htonl (options);
    ppm->type = htonl (type);
    ppm->hop_count = htonl (hop_count + 1);
    ppm->desired_replication_level = htonl (desired_replication_level);
    ppm->put_path_length = htonl (put_path_length);
    ppm->expiration_time = GNUNET_TIME_absolute_hton (expiration_time);
    GNUNET_break (GNUNET_YES ==
                  GNUNET_CONTAINER_bloomfilter_test (bf,
                                                     &target->phash));
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CONTAINER_bloomfilter_get_raw_data (bf,
                                                              ppm->bloomfilter,
                                                              DHT_BLOOM_SIZE));
    ppm->key = *key;
    pp = (struct GNUNET_PeerIdentity *) &ppm[1];
    GNUNET_memcpy (pp,
                   put_path,
                   sizeof(struct GNUNET_PeerIdentity) * put_path_length);
    GNUNET_memcpy (&pp[put_path_length],
                   data,
                   data_size);
    GNUNET_MQ_send (target->mq,
                    env);
  }
  GNUNET_free (targets);
  return (skip_count < target_count) ? GNUNET_OK : GNUNET_NO;
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
 * @param xquery_size number of bytes in @a xquery
 * @param bg group to use for filtering replies
 * @param peer_bf filter for peers not to select (again)
 * @return #GNUNET_OK if the request was forwarded, #GNUNET_NO if not
 */
int
GDS_NEIGHBOURS_handle_get (enum GNUNET_BLOCK_Type type,
                           enum GNUNET_DHT_RouteOption options,
                           uint32_t desired_replication_level,
                           uint32_t hop_count,
                           const struct GNUNET_HashCode *key,
                           const void *xquery,
                           size_t xquery_size,
                           struct GNUNET_BLOCK_Group *bg,
                           struct GNUNET_CONTAINER_BloomFilter *peer_bf)
{
  unsigned int target_count;
  struct PeerInfo **targets;
  struct PeerInfo *target;
  struct GNUNET_MQ_Envelope *env;
  size_t msize;
  struct PeerGetMessage *pgm;
  char *xq;
  size_t reply_bf_size;
  void *reply_bf;
  unsigned int skip_count;
  uint32_t bf_nonce;

  GNUNET_assert (NULL != peer_bf);
  GNUNET_STATISTICS_update (GDS_stats,
                            gettext_noop ("# GET requests routed"),
                            1,
                            GNUNET_NO);
  target_count = get_target_peers (key,
                                   peer_bf,
                                   hop_count,
                                   desired_replication_level,
                                   &targets);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Adding myself (%s) to GET bloomfilter for %s\n",
              GNUNET_i2s (&my_identity),
              GNUNET_h2s (key));
  GNUNET_CONTAINER_bloomfilter_add (peer_bf,
                                    &my_identity_hash);
  if (0 == target_count)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Routing GET for %s terminates after %u hops at %s\n",
                GNUNET_h2s (key),
                (unsigned int) hop_count,
                GNUNET_i2s (&my_identity));
    return GNUNET_NO;
  }
  if (GNUNET_OK !=
      GNUNET_BLOCK_group_serialize (bg,
                                    &bf_nonce,
                                    &reply_bf,
                                    &reply_bf_size))
  {
    reply_bf = NULL;
    reply_bf_size = 0;
    bf_nonce = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
                                         UINT32_MAX);
  }
  msize = xquery_size + reply_bf_size;
  if (msize + sizeof(struct PeerGetMessage) >= GNUNET_MAX_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    GNUNET_free_non_null (reply_bf);
    GNUNET_free (targets);
    return GNUNET_NO;
  }
  GNUNET_STATISTICS_update (GDS_stats,
                            gettext_noop (
                              "# GET messages queued for transmission"),
                            target_count,
                            GNUNET_NO);
  /* forward request */
  skip_count = 0;
  for (unsigned int i = 0; i < target_count; i++)
  {
    target = targets[i];
    if (GNUNET_MQ_get_length (target->mq) >= MAXIMUM_PENDING_PER_PEER)
    {
      /* skip */
      GNUNET_STATISTICS_update (GDS_stats,
                                gettext_noop (
                                  "# P2P messages dropped due to full queue"),
                                1, GNUNET_NO);
      skip_count++;
      continue;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Routing GET for %s after %u hops to %s\n",
                GNUNET_h2s (key),
                (unsigned int) hop_count,
                GNUNET_i2s (target->id));
    env = GNUNET_MQ_msg_extra (pgm,
                               msize,
                               GNUNET_MESSAGE_TYPE_DHT_P2P_GET);
    pgm->options = htonl (options);
    pgm->type = htonl (type);
    pgm->hop_count = htonl (hop_count + 1);
    pgm->desired_replication_level = htonl (desired_replication_level);
    pgm->xquery_size = htonl (xquery_size);
    pgm->bf_mutator = bf_nonce;
    GNUNET_break (GNUNET_YES ==
                  GNUNET_CONTAINER_bloomfilter_test (peer_bf,
                                                     &target->phash));
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CONTAINER_bloomfilter_get_raw_data (peer_bf,
                                                              pgm->bloomfilter,
                                                              DHT_BLOOM_SIZE));
    pgm->key = *key;
    xq = (char *) &pgm[1];
    GNUNET_memcpy (xq,
                   xquery,
                   xquery_size);
    GNUNET_memcpy (&xq[xquery_size],
                   reply_bf,
                   reply_bf_size);
    GNUNET_MQ_send (target->mq,
                    env);
  }
  GNUNET_free (targets);
  GNUNET_free_non_null (reply_bf);
  return (skip_count < target_count) ? GNUNET_OK : GNUNET_NO;
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
 * @param put_path_length number of entries in @a put_path
 * @param put_path peers the original PUT traversed (if tracked)
 * @param get_path_length number of entries in @a get_path
 * @param get_path peers this reply has traversed so far (if tracked)
 * @param data payload of the reply
 * @param data_size number of bytes in @a data
 */
void
GDS_NEIGHBOURS_handle_reply (const struct GNUNET_PeerIdentity *target,
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
  struct PeerInfo *pi;
  struct GNUNET_MQ_Envelope *env;
  size_t msize;
  struct PeerResultMessage *prm;
  struct GNUNET_PeerIdentity *paths;

  msize = data_size + (get_path_length + put_path_length)
          * sizeof(struct GNUNET_PeerIdentity);
  if ((msize + sizeof(struct PeerResultMessage) >= GNUNET_MAX_MESSAGE_SIZE) ||
      (get_path_length >
       GNUNET_MAX_MESSAGE_SIZE / sizeof(struct GNUNET_PeerIdentity)) ||
      (put_path_length >
       GNUNET_MAX_MESSAGE_SIZE / sizeof(struct GNUNET_PeerIdentity)) ||
      (data_size > GNUNET_MAX_MESSAGE_SIZE))
  {
    GNUNET_break (0);
    return;
  }
  pi = GNUNET_CONTAINER_multipeermap_get (all_connected_peers,
                                          target);
  if (NULL == pi)
  {
    /* peer disconnected in the meantime, drop reply */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "No matching peer for reply for key %s\n",
                GNUNET_h2s (key));
    return;
  }
  if (GNUNET_MQ_get_length (pi->mq) >= MAXIMUM_PENDING_PER_PEER)
  {
    /* skip */
    GNUNET_STATISTICS_update (GDS_stats,
                              gettext_noop (
                                "# P2P messages dropped due to full queue"),
                              1,
                              GNUNET_NO);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Peer queue full, ignoring reply for key %s\n",
                GNUNET_h2s (key));
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Forwarding reply for key %s to peer %s\n",
              GNUNET_h2s (key),
              GNUNET_i2s (target));
  GNUNET_STATISTICS_update (GDS_stats,
                            gettext_noop
                              ("# RESULT messages queued for transmission"), 1,
                            GNUNET_NO);
  env = GNUNET_MQ_msg_extra (prm,
                             msize,
                             GNUNET_MESSAGE_TYPE_DHT_P2P_RESULT);
  prm->type = htonl (type);
  prm->put_path_length = htonl (put_path_length);
  prm->get_path_length = htonl (get_path_length);
  prm->expiration_time = GNUNET_TIME_absolute_hton (expiration_time);
  prm->key = *key;
  paths = (struct GNUNET_PeerIdentity *) &prm[1];
  GNUNET_memcpy (paths,
                 put_path,
                 put_path_length * sizeof(struct GNUNET_PeerIdentity));
  GNUNET_memcpy (&paths[put_path_length],
                 get_path,
                 get_path_length * sizeof(struct GNUNET_PeerIdentity));
  GNUNET_memcpy (&paths[put_path_length + get_path_length],
                 data,
                 data_size);
  GNUNET_MQ_send (pi->mq,
                  env);
}


/**
 * To be called on core init/fail.
 *
 * @param cls service closure
 * @param identity the public identity of this peer
 */
static void
core_init (void *cls,
           const struct GNUNET_PeerIdentity *identity)
{
  (void) cls;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "CORE called, I am %s\n",
              GNUNET_i2s (identity));
  my_identity = *identity;
  GNUNET_CRYPTO_hash (identity,
                      sizeof(struct GNUNET_PeerIdentity),
                      &my_identity_hash);
  GNUNET_SERVICE_resume (GDS_service);
}


/**
 * Check validity of a p2p put request.
 *
 * @param cls closure with the `struct PeerInfo` of the sender
 * @param message message
 * @return #GNUNET_OK if the message is valid
 */
static int
check_dht_p2p_put (void *cls,
                   const struct PeerPutMessage *put)
{
  uint32_t putlen;
  uint16_t msize;

  (void) cls;
  msize = ntohs (put->header.size);
  putlen = ntohl (put->put_path_length);
  if ((msize <
       sizeof(struct PeerPutMessage)
       + putlen * sizeof(struct GNUNET_PeerIdentity)) ||
      (putlen >
       GNUNET_MAX_MESSAGE_SIZE / sizeof(struct GNUNET_PeerIdentity)))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Core handler for p2p put requests.
 *
 * @param cls closure with the `struct PeerInfo` of the sender
 * @param message message
 */
static void
handle_dht_p2p_put (void *cls,
                    const struct PeerPutMessage *put)
{
  struct PeerInfo *peer = cls;
  const struct GNUNET_PeerIdentity *put_path;
  const void *payload;
  uint32_t putlen;
  uint16_t msize;
  size_t payload_size;
  enum GNUNET_DHT_RouteOption options;
  struct GNUNET_CONTAINER_BloomFilter *bf;
  struct GNUNET_HashCode test_key;
  int forwarded;
  struct GNUNET_TIME_Absolute exp_time;

  exp_time = GNUNET_TIME_absolute_ntoh (put->expiration_time);
  if (0 == GNUNET_TIME_absolute_get_remaining (exp_time).rel_value_us)
  {
    GNUNET_STATISTICS_update (GDS_stats,
                              gettext_noop ("# Expired PUTs discarded"),
                              1,
                              GNUNET_NO);
    return;
  }
  msize = ntohs (put->header.size);
  putlen = ntohl (put->put_path_length);
  GNUNET_STATISTICS_update (GDS_stats,
                            gettext_noop ("# P2P PUT requests received"),
                            1,
                            GNUNET_NO);
  GNUNET_STATISTICS_update (GDS_stats,
                            gettext_noop ("# P2P PUT bytes received"),
                            msize,
                            GNUNET_NO);
  put_path = (const struct GNUNET_PeerIdentity *) &put[1];
  payload = &put_path[putlen];
  options = ntohl (put->options);
  payload_size = msize - (sizeof(struct PeerPutMessage)
                          + putlen * sizeof(struct GNUNET_PeerIdentity));

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "PUT for `%s' from %s\n",
              GNUNET_h2s (&put->key),
              GNUNET_i2s (peer->id));
  if (GNUNET_YES == log_route_details_stderr)
  {
    char *tmp;
    char *pp;

    pp = GNUNET_STRINGS_pp2s (put_path,
                              putlen);
    tmp = GNUNET_strdup (GNUNET_i2s (&my_identity));
    LOG_TRAFFIC (GNUNET_ERROR_TYPE_DEBUG,
                 "R5N PUT %s: %s->%s (%u, %u=>%u, PP: %s)\n",
                 GNUNET_h2s (&put->key),
                 GNUNET_i2s (peer->id),
                 tmp,
                 ntohl (put->hop_count),
                 GNUNET_CRYPTO_hash_matching_bits (&peer->phash,
                                                   &put->key),
                 GNUNET_CRYPTO_hash_matching_bits (&my_identity_hash,
                                                   &put->key),
                 pp);
    GNUNET_free (pp);
    GNUNET_free (tmp);
  }
  switch (GNUNET_BLOCK_get_key
            (GDS_block_context,
            ntohl (put->type),
            payload,
            payload_size,
            &test_key))
  {
  case GNUNET_YES:
    if (0 != memcmp (&test_key,
                     &put->key,
                     sizeof(struct GNUNET_HashCode)))
    {
      char *put_s = GNUNET_strdup (GNUNET_h2s_full (&put->key));

      GNUNET_break_op (0);
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "PUT with key `%s' for block with key %s\n",
                  put_s,
                  GNUNET_h2s_full (&test_key));
      GNUNET_free (put_s);
      return;
    }
    break;

  case GNUNET_NO:
    GNUNET_break_op (0);
    return;

  case GNUNET_SYSERR:
    /* cannot verify, good luck */
    break;
  }
  if (ntohl (put->type) == GNUNET_BLOCK_TYPE_REGEX)  /* FIXME: do for all tpyes */
  {
    switch (GNUNET_BLOCK_evaluate (GDS_block_context,
                                   ntohl (put->type),
                                   NULL,  /* query group */
                                   GNUNET_BLOCK_EO_NONE,
                                   NULL,    /* query */
                                   NULL, 0,  /* xquery */
                                   payload,
                                   payload_size))
    {
    case GNUNET_BLOCK_EVALUATION_OK_MORE:
    case GNUNET_BLOCK_EVALUATION_OK_LAST:
      break;

    case GNUNET_BLOCK_EVALUATION_OK_DUPLICATE:
    case GNUNET_BLOCK_EVALUATION_RESULT_INVALID:
    case GNUNET_BLOCK_EVALUATION_RESULT_IRRELEVANT:
    case GNUNET_BLOCK_EVALUATION_REQUEST_VALID:
    case GNUNET_BLOCK_EVALUATION_REQUEST_INVALID:
    case GNUNET_BLOCK_EVALUATION_TYPE_NOT_SUPPORTED:
    default:
      GNUNET_break_op (0);
      return;
    }
  }

  bf = GNUNET_CONTAINER_bloomfilter_init (put->bloomfilter,
                                          DHT_BLOOM_SIZE,
                                          GNUNET_CONSTANTS_BLOOMFILTER_K);
  GNUNET_break_op (GNUNET_YES ==
                   GNUNET_CONTAINER_bloomfilter_test (bf,
                                                      &peer->phash));
  {
    struct GNUNET_PeerIdentity pp[putlen + 1];

    /* extend 'put path' by sender */
    if (0 != (options & GNUNET_DHT_RO_RECORD_ROUTE))
    {
#if SANITY_CHECKS
      for (unsigned int i = 0; i <= putlen; i++)
      {
        for (unsigned int j = 0; j < i; j++)
        {
          GNUNET_break (0 != memcmp (&pp[i],
                                     &pp[j],
                                     sizeof(struct GNUNET_PeerIdentity)));
        }
        GNUNET_break (0 != memcmp (&pp[i],
                                   peer->id,
                                   sizeof(struct GNUNET_PeerIdentity)));
      }
#endif
      GNUNET_memcpy (pp,
                     put_path,
                     putlen * sizeof(struct GNUNET_PeerIdentity));
      pp[putlen] = *peer->id;
      putlen++;
    }
    else
      putlen = 0;

    /* give to local clients */
    GDS_CLIENTS_handle_reply (exp_time,
                              &put->key,
                              0,
                              NULL,
                              putlen,
                              pp,
                              ntohl (put->type),
                              payload_size,
                              payload);
    /* store locally */
    if ((0 != (options & GNUNET_DHT_RO_DEMULTIPLEX_EVERYWHERE)) ||
        (GDS_am_closest_peer (&put->key, bf)))
      GDS_DATACACHE_handle_put (exp_time,
                                &put->key,
                                putlen,
                                pp,
                                ntohl (put->type),
                                payload_size,
                                payload);
    /* route to other peers */
    forwarded = GDS_NEIGHBOURS_handle_put (ntohl (put->type),
                                           options,
                                           ntohl (
                                             put->desired_replication_level),
                                           exp_time,
                                           ntohl (put->hop_count),
                                           bf,
                                           &put->key,
                                           putlen,
                                           pp,
                                           payload,
                                           payload_size);
    /* notify monitoring clients */
    GDS_CLIENTS_process_put (options
                             | ((GNUNET_OK == forwarded)
                                ? GNUNET_DHT_RO_LAST_HOP
                                : 0),
                             ntohl (put->type),
                             ntohl (put->hop_count),
                             ntohl (put->desired_replication_level),
                             putlen, pp,
                             exp_time,
                             &put->key,
                             payload,
                             payload_size);
  }
  GNUNET_CONTAINER_bloomfilter_free (bf);
}


/**
 * We have received a FIND PEER request.  Send matching
 * HELLOs back.
 *
 * @param sender sender of the FIND PEER request
 * @param key peers close to this key are desired
 * @param bg group for filtering peers
 */
static void
handle_find_peer (const struct GNUNET_PeerIdentity *sender,
                  const struct GNUNET_HashCode *key,
                  struct GNUNET_BLOCK_Group *bg)
{
  int bucket_idx;
  struct PeerBucket *bucket;
  struct PeerInfo *peer;
  unsigned int choice;
  const struct GNUNET_HELLO_Message *hello;
  size_t hello_size;

  /* first, check about our own HELLO */
  if (NULL != GDS_my_hello)
  {
    hello_size = GNUNET_HELLO_size ((const struct
                                     GNUNET_HELLO_Message *) GDS_my_hello);
    GNUNET_break (hello_size >= sizeof(struct GNUNET_MessageHeader));
    if (GNUNET_BLOCK_EVALUATION_OK_MORE ==
        GNUNET_BLOCK_evaluate (GDS_block_context,
                               GNUNET_BLOCK_TYPE_DHT_HELLO,
                               bg,
                               GNUNET_BLOCK_EO_LOCAL_SKIP_CRYPTO,
                               &my_identity_hash,
                               NULL, 0,
                               GDS_my_hello,
                               hello_size))
    {
      GDS_NEIGHBOURS_handle_reply (sender,
                                   GNUNET_BLOCK_TYPE_DHT_HELLO,
                                   GNUNET_TIME_relative_to_absolute (
                                     hello_expiration),
                                   key,
                                   0,
                                   NULL,
                                   0,
                                   NULL,
                                   GDS_my_hello,
                                   hello_size);
    }
    else
    {
      GNUNET_STATISTICS_update (GDS_stats,
                                gettext_noop (
                                  "# FIND PEER requests ignored due to Bloomfilter"),
                                1,
                                GNUNET_NO);
    }
  }
  else
  {
    GNUNET_STATISTICS_update (GDS_stats,
                              gettext_noop (
                                "# FIND PEER requests ignored due to lack of HELLO"),
                              1,
                              GNUNET_NO);
  }

  /* then, also consider sending a random HELLO from the closest bucket */
  if (0 == memcmp (&my_identity_hash,
                   key,
                   sizeof(struct GNUNET_HashCode)))
    bucket_idx = closest_bucket;
  else
    bucket_idx = GNUNET_MIN ((int) closest_bucket,
                             find_bucket (key));
  if (bucket_idx < 0)
    return;
  bucket = &k_buckets[bucket_idx];
  if (bucket->peers_size == 0)
    return;
  choice = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
                                     bucket->peers_size);
  peer = bucket->head;
  while (choice > 0)
  {
    GNUNET_assert (NULL != peer);
    peer = peer->next;
    choice--;
  }
  choice = bucket->peers_size;
  do
  {
    peer = peer->next;
    if (0 == choice--)
      return;                   /* no non-masked peer available */
    if (NULL == peer)
      peer = bucket->head;
    hello = GDS_HELLO_get (peer->id);
  }
  while ((NULL == hello) ||
         (GNUNET_BLOCK_EVALUATION_OK_MORE !=
          GNUNET_BLOCK_evaluate (GDS_block_context,
                                 GNUNET_BLOCK_TYPE_DHT_HELLO,
                                 bg,
                                 GNUNET_BLOCK_EO_LOCAL_SKIP_CRYPTO,
                                 &peer->phash,
                                 NULL, 0,
                                 hello,
                                 (hello_size = GNUNET_HELLO_size (hello)))));
  GDS_NEIGHBOURS_handle_reply (sender,
                               GNUNET_BLOCK_TYPE_DHT_HELLO,
                               GNUNET_TIME_relative_to_absolute
                                 (GNUNET_CONSTANTS_HELLO_ADDRESS_EXPIRATION),
                               key,
                               0,
                               NULL,
                               0,
                               NULL,
                               hello,
                               hello_size);
}


/**
 * Handle a result from local datacache for a GET operation.
 *
 * @param cls the `struct PeerInfo` for which this is a reply
 * @param type type of the block
 * @param expiration_time when does the content expire
 * @param key key for the content
 * @param put_path_length number of entries in @a put_path
 * @param put_path peers the original PUT traversed (if tracked)
 * @param get_path_length number of entries in @a get_path
 * @param get_path peers this reply has traversed so far (if tracked)
 * @param data payload of the reply
 * @param data_size number of bytes in @a data
 */
static void
handle_local_result (void *cls,
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
  struct PeerInfo *peer = cls;
  char *pp;

  pp = GNUNET_STRINGS_pp2s (put_path,
                            put_path_length);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Found local result for %s (PP: %s)\n",
              GNUNET_h2s (key),
              pp);
  GNUNET_free (pp);
  GDS_NEIGHBOURS_handle_reply (peer->id,
                               type,
                               expiration_time,
                               key,
                               put_path_length, put_path,
                               get_path_length, get_path,
                               data, data_size);
}


/**
 * Check validity of p2p get request.
 *
 * @param cls closure with the `struct PeerInfo` of the sender
 * @param get the message
 * @return #GNUNET_OK if the message is well-formed
 */
static int
check_dht_p2p_get (void *cls,
                   const struct PeerGetMessage *get)
{
  uint32_t xquery_size;
  uint16_t msize;

  (void) cls;
  msize = ntohs (get->header.size);
  xquery_size = ntohl (get->xquery_size);
  if (msize < sizeof(struct PeerGetMessage) + xquery_size)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Core handler for p2p get requests.
 *
 * @param cls closure with the `struct PeerInfo` of the sender
 * @param get the message
 */
static void
handle_dht_p2p_get (void *cls,
                    const struct PeerGetMessage *get)
{
  struct PeerInfo *peer = cls;
  uint32_t xquery_size;
  size_t reply_bf_size;
  uint16_t msize;
  enum GNUNET_BLOCK_Type type;
  enum GNUNET_DHT_RouteOption options;
  enum GNUNET_BLOCK_EvaluationResult eval;
  struct GNUNET_BLOCK_Group *bg;
  struct GNUNET_CONTAINER_BloomFilter *peer_bf;
  const char *xquery;
  int forwarded;

  /* parse and validate message */
  msize = ntohs (get->header.size);
  xquery_size = ntohl (get->xquery_size);
  reply_bf_size = msize - (sizeof(struct PeerGetMessage) + xquery_size);
  type = ntohl (get->type);
  options = ntohl (get->options);
  xquery = (const char *) &get[1];
  GNUNET_STATISTICS_update (GDS_stats,
                            gettext_noop ("# P2P GET requests received"),
                            1,
                            GNUNET_NO);
  GNUNET_STATISTICS_update (GDS_stats,
                            gettext_noop ("# P2P GET bytes received"),
                            msize,
                            GNUNET_NO);
  if (GNUNET_YES == log_route_details_stderr)
  {
    char *tmp;

    tmp = GNUNET_strdup (GNUNET_i2s (&my_identity));
    LOG_TRAFFIC (GNUNET_ERROR_TYPE_DEBUG,
                 "R5N GET %s: %s->%s (%u, %u=>%u) xq: %.*s\n",
                 GNUNET_h2s (&get->key),
                 GNUNET_i2s (peer->id),
                 tmp,
                 ntohl (get->hop_count),
                 GNUNET_CRYPTO_hash_matching_bits (&peer->phash,
                                                   &get->key),
                 GNUNET_CRYPTO_hash_matching_bits (&my_identity_hash,
                                                   &get->key),
                 ntohl (get->xquery_size),
                 xquery);
    GNUNET_free (tmp);
  }
  eval
    = GNUNET_BLOCK_evaluate (GDS_block_context,
                             type,
                             NULL,
                             GNUNET_BLOCK_EO_NONE,
                             &get->key,
                             xquery,
                             xquery_size,
                             NULL,
                             0);
  if (eval != GNUNET_BLOCK_EVALUATION_REQUEST_VALID)
  {
    /* request invalid or block type not supported */
    GNUNET_break_op (eval == GNUNET_BLOCK_EVALUATION_TYPE_NOT_SUPPORTED);
    return;
  }
  peer_bf = GNUNET_CONTAINER_bloomfilter_init (get->bloomfilter,
                                               DHT_BLOOM_SIZE,
                                               GNUNET_CONSTANTS_BLOOMFILTER_K);
  GNUNET_break_op (GNUNET_YES ==
                   GNUNET_CONTAINER_bloomfilter_test (peer_bf,
                                                      &peer->phash));
  bg = GNUNET_BLOCK_group_create (GDS_block_context,
                                  type,
                                  get->bf_mutator,
                                  &xquery[xquery_size],
                                  reply_bf_size,
                                  "filter-size",
                                  reply_bf_size,
                                  NULL);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "GET for %s at %s after %u hops\n",
              GNUNET_h2s (&get->key),
              GNUNET_i2s (&my_identity),
              (unsigned int) ntohl (get->hop_count));
  /* local lookup (this may update the reply_bf) */
  if ((0 != (options & GNUNET_DHT_RO_DEMULTIPLEX_EVERYWHERE)) ||
      (GDS_am_closest_peer (&get->key,
                            peer_bf)))
  {
    if ((0 != (options & GNUNET_DHT_RO_FIND_PEER)))
    {
      GNUNET_STATISTICS_update (GDS_stats,
                                gettext_noop (
                                  "# P2P FIND PEER requests processed"),
                                1,
                                GNUNET_NO);
      handle_find_peer (peer->id,
                        &get->key,
                        bg);
    }
    else
    {
      eval = GDS_DATACACHE_handle_get (&get->key,
                                       type,
                                       xquery,
                                       xquery_size,
                                       bg,
                                       &handle_local_result,
                                       peer);
    }
  }
  else
  {
    GNUNET_STATISTICS_update (GDS_stats,
                              gettext_noop ("# P2P GET requests ONLY routed"),
                              1,
                              GNUNET_NO);
  }

  /* remember request for routing replies */
  GDS_ROUTING_add (peer->id,
                   type,
                   bg,      /* bg now owned by routing, but valid at least until end of this function! */
                   options,
                   &get->key,
                   xquery,
                   xquery_size);

  /* P2P forwarding */
  forwarded = GNUNET_NO;
  if (eval != GNUNET_BLOCK_EVALUATION_OK_LAST)
    forwarded = GDS_NEIGHBOURS_handle_get (type,
                                           options,
                                           ntohl (
                                             get->desired_replication_level),
                                           ntohl (get->hop_count),
                                           &get->key,
                                           xquery,
                                           xquery_size,
                                           bg,
                                           peer_bf);
  GDS_CLIENTS_process_get (options
                           | (GNUNET_OK == forwarded)
                           ? GNUNET_DHT_RO_LAST_HOP : 0,
                           type,
                           ntohl (get->hop_count),
                           ntohl (get->desired_replication_level),
                           0,
                           NULL,
                           &get->key);

  /* clean up; note that 'bg' is owned by routing now! */
  GNUNET_CONTAINER_bloomfilter_free (peer_bf);
}


/**
 * Check validity of p2p result message.
 *
 * @param cls closure
 * @param message message
 * @return #GNUNET_YES if the message is well-formed
 */
static int
check_dht_p2p_result (void *cls,
                      const struct PeerResultMessage *prm)
{
  uint32_t get_path_length;
  uint32_t put_path_length;
  uint16_t msize;

  (void) cls;
  msize = ntohs (prm->header.size);
  put_path_length = ntohl (prm->put_path_length);
  get_path_length = ntohl (prm->get_path_length);
  if ((msize <
       sizeof(struct PeerResultMessage) + (get_path_length
                                           + put_path_length)
       * sizeof(struct GNUNET_PeerIdentity)) ||
      (get_path_length >
       GNUNET_MAX_MESSAGE_SIZE / sizeof(struct GNUNET_PeerIdentity)) ||
      (put_path_length >
       GNUNET_MAX_MESSAGE_SIZE / sizeof(struct GNUNET_PeerIdentity)))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Process a reply, after the @a get_path has been updated.
 *
 * @param expiration_time when does the reply expire
 * @param key key matching the query
 * @param get_path_length number of entries in @a get_path
 * @param get_path path the reply has taken
 * @param put_path_length number of entries in @a put_path
 * @param put_path path the PUT has taken
 * @param type type of the block
 * @param data_size number of bytes in @a data
 * @param data payload of the reply
 */
static void
process_reply_with_path (struct GNUNET_TIME_Absolute expiration_time,
                         const struct GNUNET_HashCode *key,
                         unsigned int get_path_length,
                         const struct GNUNET_PeerIdentity *get_path,
                         unsigned int put_path_length,
                         const struct GNUNET_PeerIdentity *put_path,
                         enum GNUNET_BLOCK_Type type,
                         size_t data_size,
                         const void *data)
{
  /* forward to local clients */
  GDS_CLIENTS_handle_reply (expiration_time,
                            key,
                            get_path_length,
                            get_path,
                            put_path_length,
                            put_path,
                            type,
                            data_size,
                            data);
  GDS_CLIENTS_process_get_resp (type,
                                get_path,
                                get_path_length,
                                put_path,
                                put_path_length,
                                expiration_time,
                                key,
                                data,
                                data_size);
  if (GNUNET_YES == cache_results)
  {
    struct GNUNET_PeerIdentity xput_path[get_path_length + 1 + put_path_length];

    GNUNET_memcpy (xput_path,
                   put_path,
                   put_path_length * sizeof(struct GNUNET_PeerIdentity));
    GNUNET_memcpy (&xput_path[put_path_length],
                   get_path,
                   get_path_length * sizeof(struct GNUNET_PeerIdentity));

    GDS_DATACACHE_handle_put (expiration_time,
                              key,
                              get_path_length + put_path_length,
                              xput_path,
                              type,
                              data_size,
                              data);
  }
  /* forward to other peers */
  GDS_ROUTING_process (type,
                       expiration_time,
                       key,
                       put_path_length,
                       put_path,
                       get_path_length,
                       get_path,
                       data,
                       data_size);
}


/**
 * Core handler for p2p result messages.
 *
 * @param cls closure
 * @param message message
 */
static void
handle_dht_p2p_result (void *cls,
                       const struct PeerResultMessage *prm)
{
  struct PeerInfo *peer = cls;
  const struct GNUNET_PeerIdentity *put_path;
  const struct GNUNET_PeerIdentity *get_path;
  const void *data;
  uint32_t get_path_length;
  uint32_t put_path_length;
  uint16_t msize;
  size_t data_size;
  enum GNUNET_BLOCK_Type type;
  struct GNUNET_TIME_Absolute exp_time;

  /* parse and validate message */
  exp_time = GNUNET_TIME_absolute_ntoh (prm->expiration_time);
  if (0 == GNUNET_TIME_absolute_get_remaining (exp_time).rel_value_us)
  {
    GNUNET_STATISTICS_update (GDS_stats,
                              gettext_noop ("# Expired results discarded"),
                              1,
                              GNUNET_NO);
    return;
  }
  msize = ntohs (prm->header.size);
  put_path_length = ntohl (prm->put_path_length);
  get_path_length = ntohl (prm->get_path_length);
  put_path = (const struct GNUNET_PeerIdentity *) &prm[1];
  get_path = &put_path[put_path_length];
  type = ntohl (prm->type);
  data = (const void *) &get_path[get_path_length];
  data_size = msize - (sizeof(struct PeerResultMessage)
                       + (get_path_length
                          + put_path_length) * sizeof(struct
                                                      GNUNET_PeerIdentity));
  GNUNET_STATISTICS_update (GDS_stats,
                            gettext_noop ("# P2P RESULTS received"),
                            1,
                            GNUNET_NO);
  GNUNET_STATISTICS_update (GDS_stats,
                            gettext_noop ("# P2P RESULT bytes received"),
                            msize,
                            GNUNET_NO);
  if (GNUNET_YES == log_route_details_stderr)
  {
    char *tmp;
    char *pp;
    char *gp;

    gp = GNUNET_STRINGS_pp2s (get_path,
                              get_path_length);
    pp = GNUNET_STRINGS_pp2s (put_path,
                              put_path_length);
    tmp = GNUNET_strdup (GNUNET_i2s (&my_identity));
    LOG_TRAFFIC (GNUNET_ERROR_TYPE_DEBUG,
                 "R5N RESULT %s: %s->%s (GP: %s, PP: %s)\n",
                 GNUNET_h2s (&prm->key),
                 GNUNET_i2s (peer->id),
                 tmp,
                 gp,
                 pp);
    GNUNET_free (gp);
    GNUNET_free (pp);
    GNUNET_free (tmp);
  }
  /* if we got a HELLO, consider it for our own routing table */
  if (GNUNET_BLOCK_TYPE_DHT_HELLO == type)
  {
    const struct GNUNET_MessageHeader *h;
    struct GNUNET_PeerIdentity pid;

    /* Should be a HELLO, validate and consider using it! */
    if (data_size < sizeof(struct GNUNET_HELLO_Message))
    {
      GNUNET_break_op (0);
      return;
    }
    h = data;
    if (data_size != ntohs (h->size))
    {
      GNUNET_break_op (0);
      return;
    }
    if (GNUNET_OK !=
        GNUNET_HELLO_get_id ((const struct GNUNET_HELLO_Message *) h,
                             &pid))
    {
      GNUNET_break_op (0);
      return;
    }
    if ((GNUNET_YES != disable_try_connect) &&
        (0 != memcmp (&my_identity,
                      &pid,
                      sizeof(struct GNUNET_PeerIdentity))))
      try_connect (&pid,
                   h);
  }

  /* First, check if 'peer' is already on the path, and if
     so, truncate it instead of expanding. */
  for (unsigned int i = 0; i <= get_path_length; i++)
    if (0 == memcmp (&get_path[i],
                     peer->id,
                     sizeof(struct GNUNET_PeerIdentity)))
    {
      process_reply_with_path (exp_time,
                               &prm->key,
                               i,
                               get_path,
                               put_path_length,
                               put_path,
                               type,
                               data_size,
                               data);
      return;
    }

  /* Need to append 'peer' to 'get_path' (normal case) */
  {
    struct GNUNET_PeerIdentity xget_path[get_path_length + 1];

    GNUNET_memcpy (xget_path,
                   get_path,
                   get_path_length * sizeof(struct GNUNET_PeerIdentity));
    xget_path[get_path_length] = *peer->id;

    process_reply_with_path (exp_time,
                             &prm->key,
                             get_path_length + 1,
                             xget_path,
                             put_path_length,
                             put_path,
                             type,
                             data_size,
                             data);
  }
}


/**
 * Initialize neighbours subsystem.
 *
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GDS_NEIGHBOURS_init ()
{
  struct GNUNET_MQ_MessageHandler core_handlers[] = {
    GNUNET_MQ_hd_var_size (dht_p2p_get,
                           GNUNET_MESSAGE_TYPE_DHT_P2P_GET,
                           struct PeerGetMessage,
                           NULL),
    GNUNET_MQ_hd_var_size (dht_p2p_put,
                           GNUNET_MESSAGE_TYPE_DHT_P2P_PUT,
                           struct PeerPutMessage,
                           NULL),
    GNUNET_MQ_hd_var_size (dht_p2p_result,
                           GNUNET_MESSAGE_TYPE_DHT_P2P_RESULT,
                           struct PeerResultMessage,
                           NULL),
    GNUNET_MQ_handler_end ()
  };
  unsigned long long temp_config_num;

  disable_try_connect
    = GNUNET_CONFIGURATION_get_value_yesno (GDS_cfg,
                                            "DHT",
                                            "DISABLE_TRY_CONNECT");
  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_get_value_number (GDS_cfg,
                                             "DHT",
                                             "bucket_size",
                                             &temp_config_num))
    bucket_size = (unsigned int) temp_config_num;
  cache_results
    = GNUNET_CONFIGURATION_get_value_yesno (GDS_cfg,
                                            "DHT",
                                            "CACHE_RESULTS");

  log_route_details_stderr =
    (NULL != getenv ("GNUNET_DHT_ROUTE_DEBUG")) ? GNUNET_YES : GNUNET_NO;
  ats_ch = GNUNET_ATS_connectivity_init (GDS_cfg);
  core_api = GNUNET_CORE_connect (GDS_cfg,
                                  NULL,
                                  &core_init,
                                  &handle_core_connect,
                                  &handle_core_disconnect,
                                  core_handlers);
  if (NULL == core_api)
    return GNUNET_SYSERR;
  all_connected_peers = GNUNET_CONTAINER_multipeermap_create (256,
                                                              GNUNET_YES);
  all_desired_peers = GNUNET_CONTAINER_multipeermap_create (256,
                                                            GNUNET_NO);
  return GNUNET_OK;
}


/**
 * Shutdown neighbours subsystem.
 */
void
GDS_NEIGHBOURS_done ()
{
  if (NULL == core_api)
    return;
  GNUNET_CORE_disconnect (core_api);
  core_api = NULL;
  GNUNET_assert (0 ==
                 GNUNET_CONTAINER_multipeermap_size (all_connected_peers));
  GNUNET_CONTAINER_multipeermap_destroy (all_connected_peers);
  all_connected_peers = NULL;
  GNUNET_CONTAINER_multipeermap_iterate (all_desired_peers,
                                         &free_connect_info,
                                         NULL);
  GNUNET_CONTAINER_multipeermap_destroy (all_desired_peers);
  all_desired_peers = NULL;
  GNUNET_ATS_connectivity_done (ats_ch);
  ats_ch = NULL;
  GNUNET_assert (NULL == find_peer_task);
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
