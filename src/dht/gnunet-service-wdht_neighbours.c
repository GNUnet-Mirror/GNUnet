/*
     This file is part of GNUnet.
     Copyright (C) 2009-2015 Christian Grothoff (and other contributing authors)

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
 * @file dht/gnunet-service-wdht_neighbours.c
 * @brief GNUnet DHT service's finger and friend table management code
 * @author Supriti Singh
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_block_lib.h"
#include "gnunet_hello_lib.h"
#include "gnunet_constants.h"
#include "gnunet_protocols.h"
#include "gnunet_ats_service.h"
#include "gnunet_core_service.h"
#include "gnunet_datacache_lib.h"
#include "gnunet_transport_service.h"
#include "gnunet_dht_service.h"
#include "gnunet_statistics_service.h"
#include "gnunet-service-wdht.h"
#include "gnunet-service-wdht_clients.h"
#include "gnunet-service-wdht_datacache.h"
#include "gnunet-service-wdht_neighbours.h"
#include "gnunet-service-wdht_nse.h"
#include <fenv.h>
#include <stdlib.h>
#include <string.h>
#include "dht.h"

#define DEBUG(...)                                           \
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, __VA_ARGS__)

/**
 * Trail timeout. After what time do trails always die?
 */
#define TRAIL_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 42)

/**
 * Random walk delay. How often do we walk the overlay?
 */
#define RANDOM_WALK_DELAY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 42)

/**
 * The number of layered ID to use.
 */
#define NUMBER_LAYERED_ID 8

/**
 * The number of random walk to launch at the beginning of the initialization
 */
/* FIXME: find a better value */
#define NUMBER_RANDOM_WALK 20


/******************* The db structure and related functions *******************/

/**
 * Entry in #friends_peermap.
 */
struct FriendInfo;


/**
 * Information we keep per trail.
 */
struct Trail
{

  /**
   * MDLL entry in the list of all trails with the same predecessor.
   */
  struct Trail *prev_succ;

  /**
   * MDLL entry in the list of all trails with the same predecessor.
   */
  struct Trail *next_succ;

  /**
   * MDLL entry in the list of all trails with the same predecessor.
   */
  struct Trail *prev_pred;

  /**
   * MDLL entry in the list of all trails with the same predecessor.
   */
  struct Trail *next_pred;

  /**
   * Our predecessor in the trail, NULL if we are initiator (?).
   */
  struct FriendInfo *pred;

  /**
   * Our successor in the trail, NULL if we are the last peer.
   */
  struct FriendInfo *succ;

  /**
   * Identifier of the trail with the predecessor.
   */
  struct GNUNET_HashCode pred_id;

  /**
   * Identifier of the trail with the successor.
   */
  struct GNUNET_HashCode succ_id;

  /**
   * When does this trail expire.
   */
  struct GNUNET_TIME_Absolute expiration_time;

  /**
   * Location of this trail in the heap.
   */
  struct GNUNET_CONTAINER_HeapNode *hn;

  /**
   * If this peer started the to create a Finger (and thus @e pred is
   * NULL), this is the Finger we are trying to intialize.
   */
  struct Finger **finger;

};


/**
 *  Entry in #friends_peermap.
 */
struct FriendInfo
{
  /**
   * Friend Identity
   */
  struct GNUNET_PeerIdentity id;

  /**
   *
   */
  struct Trail *pred_head;

  /**
   *
   */
  struct Trail *pred_tail;

  /**
   *
   */
  struct Trail *succ_head;

  /**
   *
   */
  struct Trail *succ_tail;

  /**
   * Core handle for sending messages to this friend.
   */
  struct GNUNET_MQ_Handle *mq;

};


/**
 *
 */
struct FingerTable;


/**
 *
 */
struct Finger
{
  /**
   *
   */
  struct Trail *trail;

  /**
   *
   */
  struct FingerTable *ft;

  /**
   *
   */
  struct GNUNET_HashCode destination;

  /**
   * #GNUNET_YES if a response has been received. Otherwise #GNUNET_NO.
   */
  int valid;
};


struct FingerTable
{
  /**
   * Array of our fingers, unsorted.
   */
  struct Finger **fingers;

  /**
   * Array of sorted fingers (sorted by destination, valid fingers first).
   */
  struct Finger **sorted_fingers;

  /**
   * Size of the finger array.
   */
  unsigned int finger_array_size;

  /**
   * Number of valid entries in @e sorted_fingers (contiguous from offset 0)
   */
  unsigned int number_valid_fingers;

  /**
   * Which offset in @e fingers will we redo next.
   */
  unsigned int walk_offset;

  /**
   * Is the finger array sorted?
   */
  int is_sorted;

};


/***********************  end of the db structure part  ***********************/


GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Setup a finger using the underlay topology ("social network").
 */
struct RandomWalkMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_WDHT_RANDOM_WALK
   */
  struct GNUNET_MessageHeader header;

  /**
   * Number of hops this message has taken so far, we stop at
   * log(NSE), in NBO.
   */
  uint16_t hops_taken GNUNET_PACKED;

  /**
   * Layer for the request, in NBO.
   */
  uint16_t layer GNUNET_PACKED;

  /**
   * Unique (random) identifier this peer will use to
   * identify the trail (in future messages).
   */
  struct GNUNET_HashCode trail_id;

};

/**
 * Response to a `struct RandomWalkMessage`.
 */
struct RandomWalkResponseMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_WDHT_RANDOM_WALK_RESPONSE
   */
  struct GNUNET_MessageHeader header;

  /**
   * Zero, for alignment.
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * Unique (random) identifier from the
   * `struct RandomWalkMessage`.
   */
  struct GNUNET_HashCode trail_id;

  /**
   * Random location in the respective layer where the
   * random path of the finger setup terminated.
   */
  struct GNUNET_HashCode location;

};

/**
 * Response to an event that causes a trail to die.
 */
struct TrailDestroyMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_WDHT_TRAIL_DESTROY
   */
  struct GNUNET_MessageHeader header;

  /**
   * Zero, for alignment.
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * Unique (random) identifier this peer will use to
   * identify the finger (in future messages).
   */
  struct GNUNET_HashCode trail_id;

};


/**
 * Send a message along a trail.
 */
struct FindSuccessorMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_WDHT_FIND_SUCCESSOR
   */
  struct GNUNET_MessageHeader header;

  /**
   * Zero, for alignment.
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * Unique (random) identifier this peer will use to
   * identify the finger (in future messages).
   */
  struct GNUNET_HashCode trail_id;

  /**
   * Key for which we would like close values returned.
   * identify the finger (in future messages).
   */
  struct GNUNET_HashCode key;

};


/**
 * Send a message along a trail.
 */
struct TrailRouteMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_WDHT_TRAIL_ROUTE
   */
  struct GNUNET_MessageHeader header;

  /**
   * #GNUNET_YES if the path should be recorded, #GNUNET_NO if not; in NBO.
   */
  uint16_t record_path GNUNET_PACKED;

  /**
   * Length of the recorded trail, 0 if @e record_path is #GNUNET_NO; in NBO.
   */
  uint16_t path_length GNUNET_PACKED;

  /**
   * Unique (random) identifier this peer will use to
   * identify the finger (in future messages).
   */
  struct GNUNET_HashCode trail_id;

  /**
   * Path the message has taken so far (excluding sender).
   */
  /* struct GNUNET_PeerIdentity path[path_length]; */

  /* followed by payload (another `struct GNUNET_MessageHeader`) to
     send along the trail */
};


/**
 * P2P PUT message
 */
struct PeerPutMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_WDHT_PUT
   */
  struct GNUNET_MessageHeader header;

  /**
   * Processing options
   */
  uint32_t options GNUNET_PACKED;

  /**
   * Content type.
   */
  uint32_t block_type GNUNET_PACKED;

  /**
   * Hop count
   */
  uint32_t hop_count GNUNET_PACKED;

  /**
   * Replication level for this message
   * In the current implementation, this value is not used.
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
   * The key to store the value under.
   */
  struct GNUNET_HashCode key GNUNET_PACKED;

  /* put path (if tracked) */

  /* Payload */

};

/**
 * P2P GET message
 */
struct PeerGetMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_WDHT_GET
   */
  struct GNUNET_MessageHeader header;

  /**
   * Processing options
   */
  uint32_t options GNUNET_PACKED;

  /**
   * Desired content type.
   */
  uint32_t block_type GNUNET_PACKED;

  /**
   * Hop count
   */
  uint32_t hop_count GNUNET_PACKED;

  /**
   * Desired replication level for this request.
   * In the current implementation, this value is not used.
   */
  uint32_t desired_replication_level GNUNET_PACKED;

  /**
   * Total number of peers in get path.
   */
  unsigned int get_path_length;

  /**
   * The key we are looking for.
   */
  struct GNUNET_HashCode key;

  /* Get path. */
  /* struct GNUNET_PeerIdentity[]*/
};


/**
 * P2P Result message
 */
struct PeerGetResultMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_WDHT_GET_RESULT
   */
  struct GNUNET_MessageHeader header;

  /**
   * The type for the data.
   */
  uint32_t type GNUNET_PACKED;

  /**
   * Number of peers recorded in the outgoing path from source to the
   * stored location of this message.
   */
  uint32_t put_path_length GNUNET_PACKED;

  /**
   * Length of the GET path that follows (if tracked).
   */
  uint32_t get_path_length GNUNET_PACKED;

  /**
   * Peer which queried for get and should get the result.
   */
  struct GNUNET_PeerIdentity querying_peer;

  /**
   * When does the content expire?
   */
  struct GNUNET_TIME_Absolute expiration_time;

  /**
   * The key of the corresponding GET request.
   */
  struct GNUNET_HashCode key;

  /* put path (if tracked) */

  /* get path (if tracked) */

  /* Payload */

};

GNUNET_NETWORK_STRUCT_END


/**
 * Contains all the layered IDs of this peer.
 */
struct GNUNET_PeerIdentity layered_id[NUMBER_LAYERED_ID];

/**
 * Task to timeout trails that have expired.
 */
static struct GNUNET_SCHEDULER_Task *trail_timeout_task;

/**
 * Task to perform random walks.
 */
static struct GNUNET_SCHEDULER_Task *random_walk_task;

/**
 * Identity of this peer.
 */
static struct GNUNET_PeerIdentity my_identity;

/**
 * Peer map of all the friends of a peer
 */
static struct GNUNET_CONTAINER_MultiPeerMap *friends_peermap;

/**
 * Fingers per layer.
 */
static struct FingerTable fingers[NUMBER_LAYERED_ID];

/**
 * Tail map, mapping tail identifiers to `struct Trail`s
 */
static struct GNUNET_CONTAINER_MultiHashMap *trail_map;

/**
 * Tail heap, organizing trails by expiration time.
 */
static struct GNUNET_CONTAINER_Heap *trail_heap;

/**
 * Handle to CORE.
 */
static struct GNUNET_CORE_Handle *core_api;


/**
 * Handle the put request from the client.
 *
 * @param key Key for the content
 * @param block_type Type of the block
 * @param options Routing options
 * @param desired_replication_level Desired replication count
 * @param expiration_time When does the content expire
 * @param data Content to store
 * @param data_size Size of content @a data in bytes
 */
void
GDS_NEIGHBOURS_handle_put (const struct GNUNET_HashCode *key,
                           enum GNUNET_BLOCK_Type block_type,
                           enum GNUNET_DHT_RouteOption options,
                           uint32_t desired_replication_level,
                           struct GNUNET_TIME_Absolute expiration_time,
                           const void *data,
                           size_t data_size)
{
  GDS_DATACACHE_handle_put (expiration_time,
                            key,
                            0, NULL,
                            0, NULL,
                            block_type,
                            data_size,
                            data);
  GDS_CLIENTS_process_put (options,
                           block_type,
                           0, 0,
                           0, NULL,
                           expiration_time,
                           key,
                           data,
                           data_size);
}


/**
 * Handle the get request from the client file. If I am destination do
 * datacache put and return. Else find the target friend and forward message
 * to it.
 *
 * @param key Key for the content
 * @param block_type Type of the block
 * @param options Routing options
 * @param desired_replication_level Desired replication count
 */
void
GDS_NEIGHBOURS_handle_get (const struct GNUNET_HashCode *key,
                           enum GNUNET_BLOCK_Type block_type,
                           enum GNUNET_DHT_RouteOption options,
                           uint32_t desired_replication_level)
{
  // find closest finger(s) on all layers
  // use TrailRoute with PeerGetMessage embedded to contact peer
}


/**
 * Delete a trail, it died (timeout, link failure, etc.).
 *
 * @param trail trail to delete from all data structures
 * @param inform_pred should we notify the predecessor?
 * @param inform_succ should we inform the successor?
 */
static void
delete_trail (struct Trail *trail,
              int inform_pred,
              int inform_succ)
{
  struct FriendInfo *friend;
  struct GNUNET_MQ_Envelope *env;
  struct TrailDestroyMessage *tdm;
  struct Finger *finger;

  friend = trail->pred;
  if (NULL != friend)
  {
    if (GNUNET_YES == inform_pred)
    {
      env = GNUNET_MQ_msg (tdm,
                           GNUNET_MESSAGE_TYPE_WDHT_TRAIL_DESTROY);
      tdm->trail_id = trail->pred_id;
      GNUNET_MQ_send (friend->mq,
                      env);
    }
    GNUNET_CONTAINER_MDLL_remove (pred,
                                  friend->pred_head,
                                  friend->pred_tail,
                                  trail);
  }
  friend = trail->succ;
  if (NULL != friend)
  {
    if (GNUNET_YES == inform_succ)
    {
      env = GNUNET_MQ_msg (tdm,
                           GNUNET_MESSAGE_TYPE_WDHT_TRAIL_DESTROY);
      tdm->trail_id = trail->pred_id;
      GNUNET_MQ_send (friend->mq,
                      env);
    }
    GNUNET_CONTAINER_MDLL_remove (succ,
                                  friend->pred_head,
                                  friend->pred_tail,
                                  trail);
  }
  GNUNET_break (trail ==
                GNUNET_CONTAINER_heap_remove_node (trail->hn));
  finger = *trail->finger;
  if (NULL != finger)
  {
    *trail->finger = NULL;
    GNUNET_free (finger);
  }
  GNUNET_free (trail);
}


/**
 * Send the get result to requesting client.
 *
 * @param trail_id trail identifying where to send the result to, NULL for us
 * @param key Key of the requested data.
 * @param type Block type
 * @param put_path_length Number of peers in @a put_path
 * @param put_path Path taken to put the data at its stored location.
 * @param expiration When will this result expire?
 * @param data Payload to store
 * @param data_size Size of the @a data
 */
void
GDS_NEIGHBOURS_send_get_result (const struct GNUNET_HashCode *trail_id,
                                const struct GNUNET_HashCode *key,
                                enum GNUNET_BLOCK_Type type,
                                unsigned int put_path_length,
                                const struct GNUNET_PeerIdentity *put_path,
                                struct GNUNET_TIME_Absolute expiration,
                                const void *data,
                                size_t data_size)
{
  // TRICKY: need to introduce some context to remember trail from
  // the lookup...
}


/**
 * Method called whenever a peer disconnects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 */
static void
handle_core_disconnect (void *cls,
                        const struct GNUNET_PeerIdentity *peer)
{
  struct FriendInfo *remove_friend;
  struct Trail *t;

  /* If disconnected to own identity, then return. */
  if (0 == memcmp (&my_identity,
                   peer,
                   sizeof (struct GNUNET_PeerIdentity)))
    return;

  if (NULL == (remove_friend =
               GNUNET_CONTAINER_multipeermap_get (friends_peermap,
                                                  peer)))
  {
    GNUNET_break (0);
    return;
  }

  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multipeermap_remove (friends_peermap,
                                                       peer,
                                                       remove_friend));
  while (NULL != (t = remove_friend->succ_head))
    delete_trail (t,
                  GNUNET_YES,
                  GNUNET_NO);
  while (NULL != (t = remove_friend->pred_head))
    delete_trail (t,
                  GNUNET_NO,
                  GNUNET_YES);
  GNUNET_MQ_destroy (remove_friend->mq);
  GNUNET_free (remove_friend);
  if (0 ==
      GNUNET_CONTAINER_multipeermap_size (friends_peermap))
  {
    GNUNET_SCHEDULER_cancel (random_walk_task);
    random_walk_task = NULL;
  }
}


/**
 * Pick random friend from friends for random walk.
 */
static struct FriendInfo *
pick_random_friend ()
{
  // TODO: need to extend peermap API to return random entry...
  // (Note: same extension exists for hashmap API).
  return NULL; // FIXME...
}


/**
 * One of our trails might have timed out, check and
 * possibly initiate cleanup.
 *
 * @param cls NULL
 * @param tc unused
 */
static void
trail_timeout_callback (void *cls,
                        const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Trail *trail;
  struct GNUNET_TIME_Relative left;

  trail_timeout_task = NULL;
  while (NULL != (trail = GNUNET_CONTAINER_heap_peek (trail_heap)))
  {
    left = GNUNET_TIME_absolute_get_remaining (trail->expiration_time);
    if (0 != left.rel_value_us)
      break;
    delete_trail (trail,
                  GNUNET_YES,
                  GNUNET_YES);
  }
  if (NULL != trail)
    trail_timeout_task = GNUNET_SCHEDULER_add_delayed (left,
                                                       &trail_timeout_callback,
                                                       NULL);
}


/**
 * Initiate a random walk.
 *
 * @param cls NULL
 * @param tc unused
 */
static void
do_random_walk (void *cls,
                const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  static unsigned int walk_layer;
  struct FriendInfo *friend;
  struct GNUNET_MQ_Envelope *env;
  struct RandomWalkMessage *rwm;
  struct FingerTable *ft;
  struct Finger *finger;
  struct Trail *trail;

  random_walk_task = NULL;
  friend = pick_random_friend ();

  trail = GNUNET_new (struct Trail);
  /* We create the random walk so, no predecessor */
  trail->succ = friend;
  GNUNET_CRYPTO_hash_create_random (GNUNET_CRYPTO_QUALITY_NONCE,
                                    &trail->succ_id);
  if (GNUNET_OK !=
      GNUNET_CONTAINER_multihashmap_put (trail_map,
                                         &trail->succ_id,
                                         trail,
                                         GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY))
  {
    GNUNET_break (0);
    GNUNET_free (trail);
    return;
  }
  GNUNET_CONTAINER_MDLL_insert (succ,
                                friend->succ_head,
                                friend->succ_tail,
                                trail);
  trail->expiration_time = GNUNET_TIME_relative_to_absolute (TRAIL_TIMEOUT);
  trail->hn = GNUNET_CONTAINER_heap_insert (trail_heap,
                                            trail,
                                            trail->expiration_time.abs_value_us);
  if (NULL == trail_timeout_task)
    trail_timeout_task = GNUNET_SCHEDULER_add_delayed (TRAIL_TIMEOUT,
                                                       &trail_timeout_callback,
                                                       NULL);
  env = GNUNET_MQ_msg (rwm,
                       GNUNET_MESSAGE_TYPE_WDHT_RANDOM_WALK);
  rwm->hops_taken = htonl (0);
  rwm->trail_id = trail->succ_id;
  GNUNET_MQ_send (friend->mq,
                  env);
  /* clean up 'old' entry (implicitly via trail cleanup) */
  ft = &fingers[walk_layer];

  if ( (NULL != ft->fingers) &&
       (NULL != (finger = ft->fingers[ft->walk_offset])) )
    delete_trail (finger->trail,
                  GNUNET_NO,
                  GNUNET_YES);
  if (ft->finger_array_size < 42)
  {
    // FIXME: must have finger array of the right size here,
    // FIXME: growing / shrinking are tricy -- with pointers
    // from Trails!!!
  }

  GNUNET_assert (NULL == ft->fingers[ft->walk_offset]);

  finger = GNUNET_new (struct Finger);
  finger->trail = trail;
  trail->finger = &ft->fingers[ft->walk_offset];
  finger->ft = ft;
  ft->fingers[ft->walk_offset] = finger;
  ft->is_sorted = GNUNET_NO;
  ft->walk_offset = (ft->walk_offset + 1) % ft->finger_array_size;

  walk_layer = (walk_layer + 1) % NUMBER_LAYERED_ID;
  random_walk_task = GNUNET_SCHEDULER_add_delayed (RANDOM_WALK_DELAY,
                                                   &do_random_walk,
                                                   NULL);
}


/**
 * Method called whenever a peer connects.
 *
 * @param cls closure
 * @param peer_identity peer identity this notification is about
 */
static void
handle_core_connect (void *cls,
                     const struct GNUNET_PeerIdentity *peer_identity)
{
  struct FriendInfo *friend;

  /* Check for connect to self message */
  if (0 == memcmp (&my_identity,
                   peer_identity,
                   sizeof (struct GNUNET_PeerIdentity)))
    return;

  /* If peer already exists in our friend_peermap, then exit. */
  if (GNUNET_YES ==
      GNUNET_CONTAINER_multipeermap_contains (friends_peermap,
                                              peer_identity))
  {
    GNUNET_break (0);
    return;
  }

  friend = GNUNET_new (struct FriendInfo);
  friend->id = *peer_identity;
  friend->mq = GNUNET_CORE_mq_create (core_api,
                                      peer_identity);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multipeermap_put (friends_peermap,
                                                    peer_identity,
                                                    friend,
                                                    GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  if (NULL == random_walk_task)
  {
    /* random walk needs to be started -- we have a first connection */
    random_walk_task = GNUNET_SCHEDULER_add_now (&do_random_walk,
                                                 NULL);
  }
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
  my_identity = *identity;
}


/**
 * Handle a `struct RandomWalkMessage` from a
 * #GNUNET_MESSAGE_TYPE_WDHT_RANDOM_WALK message.
 *
 * @param cls closure (NULL)
 * @param peer sender identity
 * @param message the setup message
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static int
handle_dht_p2p_random_walk (void *cls,
                            const struct GNUNET_PeerIdentity *peer,
                            const struct GNUNET_MessageHeader *message)
{
  const struct RandomWalkMessage *m;
  struct Trail *t;
  struct FriendInfo *pred;

  m = (const struct RandomWalkMessage *) message;
  pred = GNUNET_CONTAINER_multipeermap_get (friends_peermap,
                                            peer);
  t = GNUNET_new (struct Trail);
  t->pred_id = m->trail_id;
  t->pred = pred;
  if (GNUNET_OK !=
      GNUNET_CONTAINER_multihashmap_put (trail_map,
                                         &t->pred_id,
                                         t,
                                         GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY))
  {
    GNUNET_break_op (0);
    GNUNET_free (t);
    return GNUNET_SYSERR;
  }
  GNUNET_CONTAINER_MDLL_insert (pred,
                                pred->pred_head,
                                pred->pred_tail,
                                t);
  t->expiration_time = GNUNET_TIME_relative_to_absolute (TRAIL_TIMEOUT);
  t->hn = GNUNET_CONTAINER_heap_insert (trail_heap,
                                        t,
                                        t->expiration_time.abs_value_us);
  if (NULL == trail_timeout_task)
    trail_timeout_task = GNUNET_SCHEDULER_add_delayed (TRAIL_TIMEOUT,
                                                       &trail_timeout_callback,
                                                       NULL);

  if (ntohl (m->hops_taken) > GDS_NSE_get ())
  {
    /* We are the last hop, generate response */
    struct GNUNET_MQ_Envelope *env;
    struct RandomWalkResponseMessage *rwrm;
    uint16_t layer;

    env = GNUNET_MQ_msg (rwrm,
                         GNUNET_MESSAGE_TYPE_WDHT_RANDOM_WALK_RESPONSE);
    rwrm->reserved = htonl (0);
    rwrm->trail_id = m->trail_id;
    layer = ntohs (m->layer);
    if (0 == layer)
      (void) GDS_DATACACHE_get_random_key (&rwrm->location);
    else
    {
      struct FingerTable *ft;

      if (layer > NUMBER_LAYERED_ID)
      {
        GNUNET_break_op (0);
        // FIXME: clean up 't'...
        return GNUNET_SYSERR;
      }
      ft = &fingers[layer-1];
      if (0 == ft->number_valid_fingers)
      {
        GNUNET_CRYPTO_hash_create_random (GNUNET_CRYPTO_QUALITY_NONCE,
                                          &rwrm->location);
      }
      else
      {
        struct Finger *f;

        f = ft->fingers[GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_NONCE,
                                                  ft->number_valid_fingers)];
        rwrm->location = f->destination;
      }
    }
    GNUNET_MQ_send (pred->mq,
                    env);
  }
  else
  {
    struct GNUNET_MQ_Envelope *env;
    struct RandomWalkMessage *rwm;
    struct FriendInfo *succ;

    /* extend the trail by another random hop */
    succ = pick_random_friend ();
    GNUNET_CRYPTO_hash_create_random (GNUNET_CRYPTO_QUALITY_NONCE,
                                      &t->succ_id);
    t->succ = succ;
    if (GNUNET_OK !=
        GNUNET_CONTAINER_multihashmap_put (trail_map,
                                           &t->succ_id,
                                           t,
                                           GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY))
    {
      GNUNET_break (0);
      GNUNET_CONTAINER_MDLL_remove (pred,
                                    pred->pred_head,
                                    pred->pred_tail,
                                    t);
      GNUNET_free (t);
      return GNUNET_OK;
    }
    GNUNET_CONTAINER_MDLL_insert (succ,
                                  succ->succ_head,
                                  succ->succ_tail,
                                  t);
    env = GNUNET_MQ_msg (rwm,
                         GNUNET_MESSAGE_TYPE_WDHT_RANDOM_WALK);
    rwm->hops_taken = htons (1 + ntohs (m->hops_taken));
    rwm->layer = m->layer;
    rwm->trail_id = t->succ_id;
    GNUNET_MQ_send (succ->mq,
                    env);
  }
  return GNUNET_OK;
}


/**
 * Handle a `struct RandomWalkResponseMessage` from a GNUNET_MESSAGE_TYPE_WDHT_RANDOM_WALK_RESPONSE
 * message.
 *
 * @param cls closure (NULL)
 * @param peer sender identity
 * @param message the setup response message
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static int
handle_dht_p2p_random_walk_response (void *cls,
                                     const struct GNUNET_PeerIdentity *peer,
                                     const struct GNUNET_MessageHeader *message)
{
  const struct RandomWalkResponseMessage *rwrm;

  rwrm = (const struct RandomWalkResponseMessage *) message;
  // 1) lookup trail => find Finger entry => fill in 'destination' and mark valid, move to end of sorted array, mark unsorted, update links from 'trails'
  /*
   * Steps :
   *  1 check if we are the correct layer
   *  1.a if true : add the returned value (finger) in the db structure
   *  1.b if true : do nothing
   */
  /* FIXME: add the value in db structure 1.a */

  return GNUNET_OK;
}


/**
 * Handle a `struct TrailDestroyMessage`.
 *
 * @param cls closure (NULL)
 * @param peer sender identity
 * @param message the finger destroy message
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static int
handle_dht_p2p_trail_destroy (void *cls,
                             const struct GNUNET_PeerIdentity *peer,
                             const struct GNUNET_MessageHeader *message)
{
  const struct TrailDestroyMessage *tdm;

  tdm = (const struct TrailDestroyMessage *) message;

  /*
   * Steps :
   *  1 check if message comme from a trail (that we still remember...)
   *  1.a.1 if true: send the destroy message to the rest trail
   *  1.a.2 clean the trail structure
   *  1.a.3 did i have to remove the trail and ID from the db structure?
   *  1.b if false: do nothing
   */

  return GNUNET_OK;
}


/**
 * Handler for a message we received along some trail.
 *
 * @param cls closure
 * @param trail_id trail identifier
 * @param message the message we got
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
typedef int
(*TrailHandlerCallback)(void *cls,
                        const struct GNUNET_HashCode *trail_id,
                        const struct GNUNET_MessageHandler *message);


/**
 * Definition of a handler for a message received along some trail.
 */
struct TrailHandler
{
  /**
   * NULL for end-of-list.
   */
  TrailHandlerCallback callback;

  /**
   * Closure for @e callback.
   */
  void *cls;

  /**
   * Message type this handler addresses.
   */
  uint16_t message_type;

  /**
   * Use 0 for variable-size.
   */
  uint16_t message_size;
};


/**
 * Handle a `struct TrailRouteMessage`.
 *
 * @param cls closure (NULL)
 * @param peer sender identity
 * @param message the finger destroy message
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static int
handle_dht_p2p_trail_route (void *cls,
                            const struct GNUNET_PeerIdentity *peer,
                            const struct GNUNET_MessageHeader *message)
{
  const struct TrailRouteMessage *trm;

  trm = (const struct TrailRouteMessage *) message;

  /*
   * Steps :
   *  1 check if message comme from a trail
   *  1.a.1 if trail not finished with us, continue to forward
   *  1.a.2 otherwise handle body message embedded in trail
   */
  return GNUNET_OK;
}


/**
 * Handle a `struct FindSuccessorMessage` from a #GNUNET_MESSAGE_TYPE_WDHT_SUCCESSOR_FIND
 * message.
 *
 * @param cls closure (NULL)
 * @param trail_id path to the originator
 * @param message the finger setup message
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static int
handle_dht_p2p_successor_find (void *cls,
                               const struct GNUNET_HashCode *trail_id,
                               const struct GNUNET_MessageHeader *message)
{
  const struct FindSuccessorMessage *fsm;

  fsm = (const struct FindSuccessorMessage *) message;
  // locate trail (for sending reply), if not exists, fail nicely.
  // otherwise, go to datacache and return 'top k' elements closest to 'key'
  // as "PUT" messages via the trail (need to extend DB API!)
#if 0
  GDS_DATACACHE_get_successors (trail_id,
                                key);
#endif
  return GNUNET_OK;
}


/**
 * Handle a `struct PeerGetMessage`.
 *
 * @param cls closure (NULL)
 * @param trail_id path to the originator
 * @param message the peer get message
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static int
handle_dht_p2p_peer_get (void *cls,
                         const struct GNUNET_HashCode *trail_id,
                         const struct GNUNET_MessageHeader *message)
{
  const struct PeerGetMessage *pgm;

  // FIXME: note: never called like this, message embedded with trail route!
  pgm = (const struct PeerGetMessage *) message;
  // -> lookup in datacache (figure out way to remember trail!)
     /*
    * steps :
    *   1 extract the result
    *   2 save the peer
    *   3 send it using the good trail
    *
    * What do i do when i don't have the key/value?
    */

  return GNUNET_OK;
}


/**
 * Handle a `struct PeerGetResultMessage`.
 *
 * @param cls closure (NULL)
 * @param trail_id path to the originator
 * @param message the peer get result message
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static int
handle_dht_p2p_peer_get_result (void *cls,
                                const struct GNUNET_HashCode *trail_id,
                                const struct GNUNET_MessageHeader *message)
{
  const struct PeerGetResultMessage *pgrm;

  pgrm = (const struct PeerGetResultMessage *) message;
  // pretty much: parse, & pass to client (there is some call for that...)

#if 0
  GDS_CLIENTS_process_get (options,
                           type,
                           0, 0,
                           path_length, path,
                           key);
  (void) GDS_DATACACHE_handle_get (trail_id,
                                   key,
                                   type,
                                   xquery,
                                   xquery_size,
                                   &reply_bf,
                                   reply_bf_mutator);
#endif
  return GNUNET_OK;
}


/**
 * Handle a `struct PeerPutMessage`.
 *
 * @param cls closure (NULL)
 * @param trail_id path to the originator
 * @param message the peer put message
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static int
handle_dht_p2p_peer_put (void *cls,
                         const struct GNUNET_HashCode *trail_id,
                         const struct GNUNET_MessageHeader *message)
{
  const struct PeerGetResultMessage *pgrm;

  pgrm = (const struct PeerGetResultMessage *) message;
  // parse & store in datacache, this is in response to us asking for successors.
  /*
   * steps :
   * 1 check the size of the message
   * 2 use the API to add the value in the "database". Check on the xdht file, how to do it.
   * 3 Did i a have to return a notification or did i have to return GNUNET_[OK|SYSERR]?
   */
#if 0
  GDS_DATACACHE_handle_put (expiration_time,
                            key,
                            path_length, path,
                            block_type,
                            data_size,
                            data);
  GDS_CLIENTS_process_put (options,
                           block_type,
                           0, 0,
                           path_length, path,
                           expiration_time,
                           key,
                           data,
                           data_size);
#endif
  return GNUNET_OK;
}


/**
 * Initialize neighbours subsystem.
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GDS_NEIGHBOURS_init (void)
{
  static const struct GNUNET_CORE_MessageHandler core_handlers[] = {
    { &handle_dht_p2p_random_walk,
      GNUNET_MESSAGE_TYPE_WDHT_RANDOM_WALK,
      sizeof (struct RandomWalkMessage) },
    { &handle_dht_p2p_random_walk_response,
      GNUNET_MESSAGE_TYPE_WDHT_RANDOM_WALK_RESPONSE,
      sizeof (struct RandomWalkResponseMessage) },
    { &handle_dht_p2p_trail_destroy,
      GNUNET_MESSAGE_TYPE_WDHT_TRAIL_DESTROY,
      sizeof (struct TrailDestroyMessage) },
    { &handle_dht_p2p_trail_route,
      GNUNET_MESSAGE_TYPE_WDHT_TRAIL_ROUTE,
      0},
    {NULL, 0, 0}
  };

  core_api =
    GNUNET_CORE_connect (GDS_cfg, NULL,
                         &core_init,
                         &handle_core_connect,
                         &handle_core_disconnect,
                         NULL, GNUNET_NO,
                         NULL, GNUNET_NO,
                         core_handlers);

  if (NULL == core_api)
    return GNUNET_SYSERR;
  friends_peermap = GNUNET_CONTAINER_multipeermap_create (256, GNUNET_NO);
  trail_map = GNUNET_CONTAINER_multihashmap_create (1024, GNUNET_YES);
  trail_heap = GNUNET_CONTAINER_heap_create (GNUNET_CONTAINER_HEAP_ORDER_MIN);
  return GNUNET_OK;
}


/**
 * Shutdown neighbours subsystem.
 */
void
GDS_NEIGHBOURS_done (void)
{
  if (NULL == core_api)
    return;
  GNUNET_CORE_disconnect (core_api);
  core_api = NULL;
  GNUNET_assert (0 == GNUNET_CONTAINER_multipeermap_size (friends_peermap));
  GNUNET_CONTAINER_multipeermap_destroy (friends_peermap);
  friends_peermap = NULL;
  GNUNET_assert (0 == GNUNET_CONTAINER_multihashmap_size (trail_map));
  GNUNET_CONTAINER_multihashmap_destroy (trail_map);
  trail_map = NULL;
  GNUNET_CONTAINER_heap_destroy (trail_heap);
  trail_heap = NULL;
  if (NULL != trail_timeout_task)
  {
    GNUNET_SCHEDULER_cancel (trail_timeout_task);
    trail_timeout_task = NULL;
  }
}


/**
 * Get my identity
 *
 * @return my identity
 */
struct GNUNET_PeerIdentity
GDS_NEIGHBOURS_get_my_id (void)
{
  return my_identity;
}

/* end of gnunet-service-wdht_neighbours.c */
