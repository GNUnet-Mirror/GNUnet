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
 * The lowest currently used bucket.
 */
static unsigned int lowest_bucket;      /* Initially equal to MAX_BUCKETS - 1 */

/**
 * The buckets (Kademlia routing table, complete with growth).
 * Array of size MAX_BUCKET_SIZE.
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

#if DEBUG_DHT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%s:%s Receives core connect message for peer %s distance %d!\n",
              my_short_id, "dht", GNUNET_i2s (peer), distance);
#endif

  if (GNUNET_YES ==
      GNUNET_CONTAINER_multihashmap_contains (all_known_peers,
                                              &peer->hashPubKey))
  {
#if DEBUG_DHT
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "%s:%s Received %s message for peer %s, but already have peer in RT!",
                my_short_id, "DHT", "CORE CONNECT", GNUNET_i2s (peer));
#endif
    GNUNET_break (0);
    return;
  }

  peer_bucket = find_current_bucket (&peer->hashPubKey);
  GNUNET_assert (peer_bucket >= lowest_bucket);
  GNUNET_assert (peer_bucket < MAX_BUCKETS);
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
  if ((GNUNET_CRYPTO_hash_matching_bits
       (&my_identity.hashPubKey, &peer->hashPubKey) > 0) &&
      (k_buckets[peer_bucket].peers_size <= bucket_size))
    ret->preference_task =
        GNUNET_SCHEDULER_add_now (&update_core_preference, ret);
  if ((k_buckets[lowest_bucket].peers_size) >= bucket_size)
    enable_next_bucket ();
  newly_found_peers++;
  GNUNET_CONTAINER_multihashmap_put (all_known_peers, &peer->hashPubKey, ret,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
  increment_stats (STAT_PEERS_KNOWN);

#if DEBUG_DHT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%s:%s Adding peer to routing list: %s\n", my_short_id, "DHT",
              ret == NULL ? "NOT ADDED" : "PEER ADDED");
#endif
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

  /* Check for disconnect from self message */
  if (0 == memcmp (&my_identity, peer, sizeof (struct GNUNET_PeerIdentity)))
    return;
#if DEBUG_DHT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%s:%s: Received peer disconnect message for peer `%s' from %s\n",
              my_short_id, "DHT", GNUNET_i2s (peer), "CORE");
#endif

  if (GNUNET_YES !=
      GNUNET_CONTAINER_multihashmap_contains (all_known_peers,
                                              &peer->hashPubKey))
  {
    GNUNET_break (0);
#if DEBUG_DHT
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "%s:%s: do not have peer `%s' in RT, can't disconnect!\n",
                my_short_id, "DHT", GNUNET_i2s (peer));
#endif
    return;
  }
  increment_stats (STAT_DISCONNECTS);
  GNUNET_assert (GNUNET_CONTAINER_multihashmap_contains
                 (all_known_peers, &peer->hashPubKey));
  to_remove =
      GNUNET_CONTAINER_multihashmap_get (all_known_peers, &peer->hashPubKey);
  GNUNET_assert (to_remove != NULL);
  if (NULL != to_remove->info_ctx)
  {
    GNUNET_CORE_peer_change_preference_cancel (to_remove->info_ctx);
    to_remove->info_ctx = NULL;
  }
  GNUNET_assert (0 ==
                 memcmp (peer, &to_remove->id,
                         sizeof (struct GNUNET_PeerIdentity)));
  current_bucket = find_current_bucket (&to_remove->id.hashPubKey);
  delete_peer (to_remove, current_bucket);
}



/**
 * Initialize neighbours subsystem.
 */
void
GST_NEIGHBOURS_init ()
{
}


/**
 * Shutdown neighbours subsystem.
 */
void
GST_NEIGHBOURS_done ()
{
}






/* end of gnunet-service-dht_neighbours.c */
