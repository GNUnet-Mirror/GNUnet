/*
     This file is part of GNUnet.
     Copyright (C) 2009-2016 GNUnet e.V.

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
 * @file dht/gnunet-service-wdht_neighbours.c
 * @brief GNUnet DHT service's finger and friend table management code
 * @author Supriti Singh
 * @author Christian Grothoff
 * @author Arthur Dewarumez
 *
 * TODO:
 * - initiate finding of successors
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
#include "gnunet-service-dht.h"
#include "gnunet-service-dht_datacache.h"
#include "gnunet-service-dht_neighbours.h"
#include "gnunet-service-dht_nse.h"
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
 *
 */
struct FingerTable;

/**
 * Information we keep per trail.
 */
struct Trail
{

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
   * Location of this trail in the heap.
   */
  struct GNUNET_CONTAINER_HeapNode *hn;

  /**
   * If this peer started the to create a Finger (and thus @e pred is
   * NULL), this is the finger table of the finger we are trying to
   * intialize.
   */
  struct FingerTable *ft;

  /**
   * If this peer started the trail to create a Finger (and thus @e
   * pred is NULL), this is the offset of the finger we are trying to
   * intialize in the unsorted array.
   */
  unsigned int finger_off;

};


/**
 *  Entry in #friends_peermap.
 */
struct FriendInfo
{
  /**
   * Friend Identity
   */
  const struct GNUNET_PeerIdentity *id;

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
   * Size of the finger array.
   */
  unsigned int finger_array_size;

  /**
   * Number of valid entries in @e fingers
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
   * Type: #GNUNET_MESSAGE_TYPE_WDHT_SUCCESSOR_FIND
   */
  struct GNUNET_MessageHeader header;

  /**
   * Zero, for alignment.
   */
  uint32_t reserved GNUNET_PACKED;

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
   * The type for the data in NBO.
   */
  uint32_t type GNUNET_PACKED;

  /**
   * Number of peers recorded in the outgoing path from source to the
   * stored location of this message.
   */
  uint32_t put_path_length GNUNET_PACKED;

  /**
   * When does the content expire?
   */
  struct GNUNET_TIME_AbsoluteNBO expiration_time;

  /**
   * The key of the corresponding GET request.
   */
  struct GNUNET_HashCode key;

  /* put path (if tracked) */

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
 * @param block_type Type of the block
 * @param options routing options
 * @param desired_replication_level desired replication level
 * @param expiration_time when does the content expire
 * @param hop_count how many hops has this message traversed so far
 * @param bf Bloom filter of peers this PUT has already traversed
 * @param key key for the content
 * @param put_path_length number of entries in put_path
 * @param put_path peers this request has traversed so far (if tracked)
 * @param data payload to store
 * @param data_size number of bytes in data
 * @return #GNUNET_OK if the request was forwarded, #GNUNET_NO if not
 */
int
GDS_NEIGHBOURS_handle_put (enum GNUNET_BLOCK_Type block_type,
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
  GDS_DATACACHE_handle_put (expiration_time,
                            key,
                            0, NULL,
                            block_type,
                            data_size,
                            data);
  GDS_CLIENTS_process_put (options,
                           block_type,
                           hop_count,
                           desired_replication_level,
                           put_path_length, put_path,
                           expiration_time,
                           key,
                           data,
                           data_size);
  return GNUNET_OK; /* FIXME... */
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
 * @param bg block group to filter duplicates
 * @param peer_bf filter for peers not to select (again, updated)
 * @return #GNUNET_OK if the request was forwarded, #GNUNET_NO if not
 */
int
GDS_NEIGHBOURS_handle_get (enum GNUNET_BLOCK_Type type,
                           enum GNUNET_DHT_RouteOption options,
                           uint32_t desired_replication_level,
                           uint32_t hop_count,
                           const struct GNUNET_HashCode *key,
                           const void *xquery, size_t xquery_size,
                           struct GNUNET_BLOCK_Group *bg,
                           struct GNUNET_CONTAINER_BloomFilter *peer_bf)
{
  // find closest finger(s) on all layers
  // use TrailRoute with PeerGetMessage embedded to contact peer
  // NOTE: actually more complicated, see paper!
  GNUNET_break (0); // not implemented!
  return GNUNET_SYSERR;
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
  finger = trail->ft->fingers[trail->finger_off];
  if (NULL != finger)
  {
    trail->ft->fingers[trail->finger_off] = NULL;
    trail->ft->number_valid_fingers--;
    GNUNET_free (finger);
  }
  GNUNET_free (trail);
}


/**
 * Forward the given payload message along the trail.
 *
 * @param next_target which direction along the trail should we forward
 * @param trail_id which trail should we forward along
 * @param have_path do we track the forwarding path?
 * @param predecessor which peer do we tack on to the path?
 * @param path path the message has taken so far along the trail
 * @param path_length number of entries in @a path
 * @param payload payload of the message
 */
static void
forward_message_on_trail (struct FriendInfo *next_target,
                          const struct GNUNET_HashCode *trail_id,
                          int have_path,
                          const struct GNUNET_PeerIdentity *predecessor,
                          const struct GNUNET_PeerIdentity *path,
                          uint16_t path_length,
                          const struct GNUNET_MessageHeader *payload)
{
  struct GNUNET_MQ_Envelope *env;
  struct TrailRouteMessage *trm;
  struct GNUNET_PeerIdentity *new_path;
  unsigned int plen;
  uint16_t payload_len;

  payload_len = ntohs (payload->size);
  if (have_path)
  {
    plen = path_length + 1;
    if (plen >= (GNUNET_SERVER_MAX_MESSAGE_SIZE
                 - payload_len
                 - sizeof (struct TrailRouteMessage))
        / sizeof (struct GNUNET_PeerIdentity))
    {
      /* Should really not have paths this long... */
      GNUNET_break_op (0);
      plen = 0;
      have_path = 0;
    }
  }
  else
  {
    GNUNET_break_op (0 == path_length);
    path_length = 0;
    plen = 0;
  }
  env = GNUNET_MQ_msg_extra (trm,
                             payload_len +
                             plen * sizeof (struct GNUNET_PeerIdentity),
                             GNUNET_MESSAGE_TYPE_WDHT_TRAIL_ROUTE);
  trm->record_path = htons (have_path);
  trm->path_length = htons (plen);
  trm->trail_id = *trail_id;
  new_path = (struct GNUNET_PeerIdentity *) &trm[1];
  if (have_path)
  {
    GNUNET_memcpy (new_path,
            path,
            path_length * sizeof (struct GNUNET_PeerIdentity));
    new_path[path_length] = *predecessor;
  }
  GNUNET_memcpy (&new_path[plen],
          payload,
          payload_len);
  GNUNET_MQ_send (next_target->mq,
                  env);
}


/**
 * Send the get result to requesting client.
 *
 * @param cls trail identifying where to send the result to, NULL for us
 * @param options routing options (from GET request)
 * @param key Key of the requested data.
 * @param type Block type
 * @param put_path_length Number of peers in @a put_path
 * @param put_path Path taken to put the data at its stored location.
 * @param expiration When will this result expire?
 * @param data Payload to store
 * @param data_size Size of the @a data
 */
void
GDS_NEIGHBOURS_send_get_result (void *cls,
                                enum GNUNET_DHT_RouteOption options,
                                const struct GNUNET_HashCode *key,
                                enum GNUNET_BLOCK_Type type,
                                unsigned int put_path_length,
                                const struct GNUNET_PeerIdentity *put_path,
                                struct GNUNET_TIME_Absolute expiration,
                                const void *data,
                                size_t data_size)
{
  const struct GNUNET_HashCode *trail_id = cls;
  struct GNUNET_MessageHeader *payload;
  struct Trail *trail;

  trail = GNUNET_CONTAINER_multihashmap_get (trail_map,
                                             trail_id);
  if (NULL == trail)
  {
    /* TODO: inform statistics */
    return;
  }
  if (NULL == trail->pred)
  {
    /* result is for *us* (local client) */
    GDS_CLIENTS_handle_reply (expiration,
                              key,
                              0, NULL,
                              put_path_length, put_path,
                              type,
                              data_size,
                              data);
    return;
  }

  payload = GNUNET_malloc(sizeof(struct GNUNET_MessageHeader) + data_size);
  payload->size = data_size;
  payload->type = GNUNET_MESSAGE_TYPE_WDHT_GET_RESULT;

  forward_message_on_trail (trail->pred,
                            trail_id,
                            0 != (options & GNUNET_DHT_RO_RECORD_ROUTE),
                            &my_identity,
                            NULL, 0,
                            payload);
  GNUNET_free (payload);
}


/**
 * Method called whenever a peer disconnects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 * @param internal_cls our `struct FriendInfo` for @a peer
 */
static void
handle_core_disconnect (void *cls,
                        const struct GNUNET_PeerIdentity *peer,
			void *internal_cls)
{
  struct FriendInfo *remove_friend = internal_cls;
  struct Trail *t;

  /* If disconnected to own identity, then return. */
  if (NULL == remove_friend)
    return;
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
  GNUNET_free (remove_friend);
  if (0 == GNUNET_CONTAINER_multipeermap_size (friends_peermap))
  {
    GNUNET_SCHEDULER_cancel (random_walk_task);
    random_walk_task = NULL;
  }
}


/**
 * Function called with a random friend to be returned.
 *
 * @param cls a `struct FriendInfo **` with where to store the result
 * @param peer the peer identity of the friend (ignored)
 * @param value the `struct FriendInfo *` that was selected at random
 * @return #GNUNET_OK (all good)
 */
static int
pick_random_helper (void *cls,
                    const struct GNUNET_PeerIdentity *peer,
                    void *value)
{
  struct FriendInfo **fi = cls;
  struct FriendInfo *v = value;

  *fi = v;
  return GNUNET_OK;
}


/**
 * Pick random friend from friends for random walk.
 *
 * @return NULL if we have no friends
 */
static struct FriendInfo *
pick_random_friend ()
{
  struct FriendInfo *ret;

  ret = NULL;
  if (0 ==
      GNUNET_CONTAINER_multipeermap_get_random (friends_peermap,
                                                &pick_random_helper,
                                                &ret))
    return NULL;
  return ret;
}


/**
 * One of our trails might have timed out, check and
 * possibly initiate cleanup.
 *
 * @param cls NULL
 */
static void
trail_timeout_callback (void *cls)
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
 * Compute how big our finger arrays should be (at least).
 *
 * @return size of the finger array, never 0
 */
static unsigned int
get_desired_finger_array_size ()
{
  /* FIXME: This is just a stub... */
  return 64;
}


/**
 * Initiate a random walk.
 *
 * @param cls NULL
 */
static void
do_random_walk (void *cls)
{
  static unsigned int walk_layer;
  struct FriendInfo *friend;
  struct GNUNET_MQ_Envelope *env;
  struct RandomWalkMessage *rwm;
  struct FingerTable *ft;
  struct Finger *finger;
  struct Trail *trail;
  unsigned int nsize;

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
  if (ft->finger_array_size < (nsize = get_desired_finger_array_size()) )
    GNUNET_array_grow (ft->fingers,
                       ft->finger_array_size,
                       nsize);
  GNUNET_assert (NULL == ft->fingers[ft->walk_offset]);
  trail->ft = ft;
  trail->finger_off = ft->walk_offset;
  finger = GNUNET_new (struct Finger);
  finger->trail = trail;
  finger->ft = ft;
  ft->fingers[ft->walk_offset] = finger;
  ft->is_sorted = GNUNET_NO;
  ft->number_valid_fingers++;
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
 * @param mq message queue for transmission to @a peer_identity
 * @return the `struct FriendInfo` for the @a peer_identity, NULL for us
 */
static void *
handle_core_connect (void *cls,
                     const struct GNUNET_PeerIdentity *peer_identity,
		     struct GNUNET_MQ_Handle *mq)
{
  struct FriendInfo *friend;

  /* Check for connect to self message */
  if (0 == memcmp (&my_identity,
                   peer_identity,
                   sizeof (struct GNUNET_PeerIdentity)))
    return NULL;

  friend = GNUNET_new (struct FriendInfo);
  friend->id = peer_identity;
  friend->mq = mq;
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
  return friend;
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
 * @param cls the `struct FriendInfo` for the sender
 * @param m the setup message
 */
static void
handle_dht_p2p_random_walk (void *cls,
                            const struct RandomWalkMessage *m)
{
  struct FriendInfo *pred = cls;
  struct Trail *t;
  uint16_t layer;

  layer = ntohs (m->layer);
  if (layer > NUMBER_LAYERED_ID)
  {
    GNUNET_break_op (0);
    return;
  }
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
    return;
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

    env = GNUNET_MQ_msg (rwrm,
                         GNUNET_MESSAGE_TYPE_WDHT_RANDOM_WALK_RESPONSE);
    rwrm->reserved = htonl (0);
    rwrm->trail_id = m->trail_id;
    if (0 == layer)
      (void) GDS_DATACACHE_get_random_key (&rwrm->location);
    else
    {
      struct FingerTable *ft;

      ft = &fingers[layer-1];
      if (0 == ft->number_valid_fingers)
      {
        GNUNET_CRYPTO_hash_create_random (GNUNET_CRYPTO_QUALITY_NONCE,
                                          &rwrm->location);
      }
      else
      {
        struct Finger *f;
        unsigned int off;
        unsigned int i;

        off = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_NONCE,
                                        ft->number_valid_fingers);
        for (i=0; (NULL == (f = ft->fingers[i])) || (off > 0); i++)
          if (NULL != f) off--;
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
      return;
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
}


/**
 * Handle a `struct RandomWalkResponseMessage`.
 *
 * @param cls closure
 * @param rwrm the setup response message
 */
static void
handle_dht_p2p_random_walk_response (void *cls,
                                     const struct RandomWalkResponseMessage *rwrm)
{
  struct Trail *trail;
  struct FriendInfo *pred;
  struct FingerTable *ft;
  struct Finger *finger;

  trail = GNUNET_CONTAINER_multihashmap_get (trail_map,
                                             &rwrm->trail_id);
  if (NULL == trail)
  {
    /* TODO: log/statistics: we didn't find the trail (can happen) */
    return;
  }
  if (NULL != (pred = trail->pred))
  {
    /* We are not the first hop, keep forwarding */
    struct GNUNET_MQ_Envelope *env;
    struct RandomWalkResponseMessage *rwrm2;

    env = GNUNET_MQ_msg (rwrm2,
                         GNUNET_MESSAGE_TYPE_WDHT_RANDOM_WALK_RESPONSE);
    rwrm2->reserved = htonl (0);
    rwrm2->location = rwrm->location;
    rwrm2->trail_id = trail->pred_id;
    GNUNET_MQ_send (pred->mq,
                    env);
    return;
  }
  /* We are the first hop, complete finger */
  if (NULL == (ft = trail->ft))
  {
    /* Eh, why did we create the trail if we have no FT? */
    GNUNET_break (0);
    delete_trail (trail,
                  GNUNET_NO,
                  GNUNET_YES);
    return;
  }
  if (NULL == (finger = ft->fingers[trail->finger_off]))
  {
    /* Eh, finger got deleted, but why not the trail as well? */
    GNUNET_break (0);
    delete_trail (trail,
                  GNUNET_NO,
                  GNUNET_YES);
    return;
  }


  // 1) lookup trail => find Finger entry => fill in 'destination' and mark valid, move to end of sorted array,
  //mark unsorted, update links from 'trails'
  /*
   * Steps :
   *  1 check if we are the correct layer
   *  1.a if true : add the returned value (finger) in the db structure
   *  1.b if true : do nothing
   */
  /* FIXME: add the value in db structure 1.a */

}


/**
 * Handle a `struct TrailDestroyMessage`.
 *
 * @param cls closure
 * @param tdm the trail destroy message
 */
static void
handle_dht_p2p_trail_destroy (void *cls,
			      const struct TrailDestroyMessage *tdm)
{
  struct FriendInfo *sender = cls;
  struct Trail *trail;

  trail = GNUNET_CONTAINER_multihashmap_get (trail_map,
                                             &tdm->trail_id);
  delete_trail (trail,
                ( (NULL != trail->succ) &&
                  (0 == memcmp (sender->id,
                                &trail->succ->id,
                                sizeof (struct GNUNET_PeerIdentity))) ),
                ( (NULL != trail->pred) &&
                  (0 == memcmp (sender->id,
                                &trail->pred->id,
                                sizeof (struct GNUNET_PeerIdentity))) ));
}


/**
 * Handle a `struct FindSuccessorMessage` from a #GNUNET_MESSAGE_TYPE_WDHT_SUCCESSOR_FIND
 * message.
 *
 * @param cls closure (NULL)
 * @param trail_id path to the originator
 * @param trail_path path the message took on the trail, if available
 * @param trail_path_length number of entries on the @a trail_path
 * @param message the finger setup message
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static int
handle_dht_p2p_successor_find (void *cls,
                               const struct GNUNET_HashCode *trail_id,
                               const struct GNUNET_PeerIdentity *trail_path,
                               unsigned int trail_path_length,
                               const struct GNUNET_MessageHeader *message)
{
  const struct FindSuccessorMessage *fsm;

  /* We do not expect to track trails for the forward-direction
     of successor finding... */
  GNUNET_break_op (0 == trail_path_length);
  fsm = (const struct FindSuccessorMessage *) message;
  GDS_DATACACHE_get_successors (&fsm->key,
                                &GDS_NEIGHBOURS_send_get_result,
                                (void *) trail_id);
  return GNUNET_OK;
}


/**
 * Handle a `struct PeerGetMessage`.
 *
 * @param cls closure (NULL)
 * @param trail_id path to the originator
 * @param trail_path path the message took on the trail, if available
 * @param trail_path_length number of entries on the @a trail_path
 * @param message the peer get message
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static int
handle_dht_p2p_peer_get (void *cls,
                         const struct GNUNET_HashCode *trail_id,
                         const struct GNUNET_PeerIdentity *trail_path,
                         unsigned int trail_path_length,
                         const struct GNUNET_MessageHeader *message)
{
#if 0
  const struct PeerGetMessage *pgm;

  // FIXME: note: never called like this, message embedded with trail route!
  pgm = (const struct PeerGetMessage *) message;
#endif
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
 * @param trail_path path the message took on the trail, if available
 * @param trail_path_length number of entries on the @a trail_path
 * @param message the peer get result message
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static int
handle_dht_p2p_peer_get_result (void *cls,
                                const struct GNUNET_HashCode *trail_id,
                                const struct GNUNET_PeerIdentity *trail_path,
                                unsigned int trail_path_length,
                                const struct GNUNET_MessageHeader *message)
{
#if 0
  const struct PeerGetResultMessage *pgrm;

  pgrm = (const struct PeerGetResultMessage *) message;
#endif
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
 * @param trail_path path the message took on the trail, if available
 * @param trail_path_length number of entries on the @a trail_path
 * @param message the peer put message
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static int
handle_dht_p2p_peer_put (void *cls,
                         const struct GNUNET_HashCode *trail_id,
                         const struct GNUNET_PeerIdentity *trail_path,
                         unsigned int trail_path_length,
                         const struct GNUNET_MessageHeader *message)
{
#if 0
  const struct PeerGetResultMessage *pgrm;

  pgrm = (const struct PeerGetResultMessage *) message;
#endif
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
                            combined_path_length, combined_path,
                            block_type,
                            data_size,
                            data);
  GDS_CLIENTS_process_put (options,
                           block_type,
                           0, 0,
                           combined_path_length, combined_path,
                           expiration_time,
                           key,
                           data,
                           data_size);
#endif
  return GNUNET_OK;
}


/**
 * Handler for a message we received along some trail.
 *
 * @param cls closure
 * @param trail_id trail identifier
 * @param trail_path path the message took on the trail, if available
 * @param trail_path_length number of entries on the @a trail_path
 * @param message the message we got
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
typedef int
(*TrailHandlerCallback)(void *cls,
                        const struct GNUNET_HashCode *trail_id,
                        const struct GNUNET_PeerIdentity *trail_path,
                        unsigned int trail_path_length,
                        const struct GNUNET_MessageHeader *message);


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
 * Check that a `struct TrailRouteMessage` is well-formed.
 *
 * @param cls closure
 * @param trm the finger destroy message
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static int
check_dht_p2p_trail_route (void *cls,
			   const struct TrailRouteMessage *trm)
{
  const struct GNUNET_PeerIdentity *path;
  uint16_t path_length;
  const struct GNUNET_MessageHeader *payload;
  size_t msize;

  msize = ntohs (trm->header.size);
  path_length = ntohs (trm->path_length);
  if (msize < sizeof (struct TrailRouteMessage) +
      path_length * sizeof (struct GNUNET_PeerIdentity) +
      sizeof (struct GNUNET_MessageHeader) )
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  path = (const struct GNUNET_PeerIdentity *) &trm[1];
  payload = (const struct GNUNET_MessageHeader *) &path[path_length];
  if (msize != (ntohs (payload->size) +
                sizeof (struct TrailRouteMessage) +
                path_length * sizeof (struct GNUNET_PeerIdentity)))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  /* FIXME: verify payload is OK!? */
  return GNUNET_OK;
}


/**
 * Handle a `struct TrailRouteMessage`.
 *
 * @param cls closure
 * @param trm the finger destroy message
 */
static void
handle_dht_p2p_trail_route (void *cls,
                            const struct TrailRouteMessage *trm)
{
  static const struct TrailHandler handlers[] = {
    { &handle_dht_p2p_successor_find, NULL,
      GNUNET_MESSAGE_TYPE_WDHT_SUCCESSOR_FIND,
      sizeof (struct FindSuccessorMessage) },
    { &handle_dht_p2p_peer_get, NULL,
      GNUNET_MESSAGE_TYPE_WDHT_GET,
      0 },
    { &handle_dht_p2p_peer_get_result, NULL,
      GNUNET_MESSAGE_TYPE_WDHT_GET_RESULT,
      0 },
    { &handle_dht_p2p_peer_put, NULL,
      GNUNET_MESSAGE_TYPE_WDHT_PUT,
      0 },
    { NULL, NULL, 0, 0 }
  };
  struct FriendInfo *sender = cls;
  unsigned int i;
  const struct GNUNET_PeerIdentity *path;
  uint16_t path_length;
  const struct GNUNET_MessageHeader *payload;
  const struct TrailHandler *th;
  struct Trail *trail;

  path_length = ntohs (trm->path_length);
  path = (const struct GNUNET_PeerIdentity *) &trm[1];
  payload = (const struct GNUNET_MessageHeader *) &path[path_length];
  /* Is this message for us? */
  trail = GNUNET_CONTAINER_multihashmap_get (trail_map,
                                             &trm->trail_id);
  if ( (NULL != trail->pred) &&
       (0 == memcmp (sender->id,
                     &trail->pred->id,
                     sizeof (struct GNUNET_PeerIdentity))) )
  {
    /* forward to 'successor' */
    if (NULL != trail->succ)
    {
      forward_message_on_trail (trail->succ,
                                &trail->succ_id,
                                ntohs (trm->record_path),
                                sender->id,
                                path,
                                path_length,
                                payload);
      return;
    }
  }
  else
  {
    /* forward to 'predecessor' */
    GNUNET_break_op ( (NULL != trail->succ) &&
                      (0 == memcmp (sender->id,
                                    &trail->succ->id,
                                    sizeof (struct GNUNET_PeerIdentity))) );
    if (NULL != trail->pred)
    {
      forward_message_on_trail (trail->pred,
                                &trail->pred_id,
                                ntohs (trm->record_path),
                                sender->id,
                                path,
                                path_length,
                                payload);
      return;
    }
  }

  /* Message is for us, dispatch to handler */
  th = NULL;
  for (i=0; NULL != handlers[i].callback; i++)
  {
    th = &handlers[i];
    if (ntohs (payload->type) == th->message_type)
    {
      if ( (0 == th->message_size) ||
           (ntohs (payload->size) == th->message_size) )
        th->callback (th->cls,
                      &trm->trail_id,
                      path,
                      path_length,
                      payload);
      else
        GNUNET_break_op (0);
      break;
    }
  }
  GNUNET_break_op (NULL != th);
}


/**
 * Initialize neighbours subsystem.
 *
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GDS_NEIGHBOURS_init (void)
{
  struct GNUNET_MQ_MessageHandler core_handlers[] = {
    GNUNET_MQ_hd_fixed_size (dht_p2p_random_walk,
                             GNUNET_MESSAGE_TYPE_WDHT_RANDOM_WALK,
                             struct RandomWalkMessage,
                             NULL),
    GNUNET_MQ_hd_fixed_size (dht_p2p_random_walk_response,
                             GNUNET_MESSAGE_TYPE_WDHT_RANDOM_WALK_RESPONSE,
                             struct RandomWalkResponseMessage,
                             NULL),
    GNUNET_MQ_hd_fixed_size (dht_p2p_trail_destroy,
                             GNUNET_MESSAGE_TYPE_WDHT_TRAIL_DESTROY,
                             struct TrailDestroyMessage,
                             NULL),
    GNUNET_MQ_hd_var_size (dht_p2p_trail_route,
                           GNUNET_MESSAGE_TYPE_WDHT_TRAIL_ROUTE,
                           struct TrailRouteMessage,
                           NULL),
    GNUNET_MQ_handler_end ()
  };

  core_api = GNUNET_CORE_connect (GDS_cfg, NULL,
				  &core_init,
				  &handle_core_connect,
				  &handle_core_disconnect,
				  core_handlers);
  if (NULL == core_api)
    return GNUNET_SYSERR;
  friends_peermap = GNUNET_CONTAINER_multipeermap_create (256,
							  GNUNET_NO);
  trail_map = GNUNET_CONTAINER_multihashmap_create (1024,
						    GNUNET_YES);
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
struct GNUNET_PeerIdentity *
GDS_NEIGHBOURS_get_id (void)
{
  return &my_identity;
}

/* end of gnunet-service-wdht_neighbours.c */
