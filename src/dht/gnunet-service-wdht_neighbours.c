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
#include "gnunet-service-xdht.h"
#include "gnunet-service-wdht_clients.h"
#include "gnunet-service-wdht_datacache.h"
#include "gnunet-service-wdht_neighbours.h"
#include <fenv.h>
#include "dht.h"

#define DEBUG(...)                                           \
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, __VA_ARGS__)

/**
 * FIXME
 */
#define FOO_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 2)


GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Setup a finger using the underlay topology ("social network").
 */
struct FingerSetupMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_WDHT_FINGER_SETUP
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
   * identify the finger (in future messages).
   */
  struct GNUNET_HashCode finger_id;

};


/**
 * Response to a `struct FingerSetupMessage`.
 */
struct FingerSetupResponseMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_WDHT_FINGER_SETUP_RESPONSE
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
  struct GNUNET_HashCode finger_id;

  /**
   * Random location in the respective layer where the
   * random path of the finger setup terminated.
   */
  struct GNUNET_HashCode location;

};


/**
 * Response to an event that causes a finger to die.
 */
struct FingerDestroyMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_WDHT_FINGER_DESTROY
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
  struct GNUNET_HashCode finger_id;

};


/**
 * Send a message along a finger.
 */
struct FingerRouteMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_WDHT_FINGER_ROUTE
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
  struct GNUNET_HashCode finger_id;

  /* followed by payload to send along the finger */
};


/**
 * P2P PUT message
 */
struct PeerPutMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_WDHT_P2P_PUT
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
   * Type: #GNUNET_MESSAGE_TYPE_WDHT_P2P_GET
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
   * Type: #GNUNET_MESSAGE_TYPE_WDHT_P2P_GET_RESULT
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
 * Entry in friend_peermap.
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
  struct Tail *prev_succ;

  /**
   * MDLL entry in the list of all trails with the same predecessor.
   */
  struct Tail *next_succ;

  /**
   * MDLL entry in the list of all trails with the same predecessor.
   */
  struct Tail *prev_pred;

  /**
   * MDLL entry in the list of all trails with the same predecessor.
   */
  struct Tail *next_pred;

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

};


/**
 *  Entry in friend_peermap.
 */
struct FriendInfo
{
  /**
   * Friend Identity
   */
  struct GNUNET_PeerIdentity id;

  struct Tail *pred_head;

  struct Tail *pred_tail;

  struct Tail *succ_head;

  struct Tail *succ_tail;

  /**
   * Core handle for sending messages to this friend.
   * FIXME: use MQ?
   */
  struct GNUNET_CORE_TransmitHandle *th;

};



/**
 * Task to timeout trails that have expired.
 */
static struct GNUNET_SCHEDULER_Task *trail_timeout_task;

/**
 * Identity of this peer.
 */
static struct GNUNET_PeerIdentity my_identity;

/**
 * Peer map of all the friends of a peer
 */
static struct GNUNET_CONTAINER_MultiPeerMap *friend_peermap;

/**
 * Tail map, mapping tail identifiers to `struct Trail`s
 */
static struct GNUNET_CONTAINER_MultiHashMap *tail_map;

/**
 * Tail heap, organizing trails by expiration time.
 */
static struct GNUNET_CONTAINER_Heap *tail_heap;

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
                           const void *data, size_t data_size)
{
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
}



/**
 * Send the get result to requesting client.
 *
 * @param key Key of the requested data.
 * @param type Block type
 * @param target_peer Next peer to forward the message to.
 * @param source_peer Peer which has the data for the key.
 * @param put_path_length Number of peers in @a put_path
 * @param put_path Path taken to put the data at its stored location.
 * @param get_path_length Number of peers in @a get_path
 * @param get_path Path taken to reach to the location of the key.
 * @param expiration When will this result expire?
 * @param data Payload to store
 * @param data_size Size of the @a data
 */
void
GDS_NEIGHBOURS_send_get_result (const struct GNUNET_HashCode *key,
                                enum GNUNET_BLOCK_Type type,
                                const struct GNUNET_PeerIdentity *target_peer,
                                const struct GNUNET_PeerIdentity *source_peer,
                                unsigned int put_path_length,
                                const struct GNUNET_PeerIdentity *put_path,
                                unsigned int get_path_length,
                                const struct GNUNET_PeerIdentity *get_path,
                                struct GNUNET_TIME_Absolute expiration,
                                const void *data, size_t data_size)
{
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

  /* If disconnected to own identity, then return. */
  if (0 == memcmp (&my_identity,
                   peer,
                   sizeof (struct GNUNET_PeerIdentity)))
    return;

  if (NULL == (remove_friend =
               GNUNET_CONTAINER_multipeermap_get (friend_peermap,
                                                  peer)))
  {
    GNUNET_break (0);
    return;
  }

  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multipeermap_remove (friend_peermap,
                                                       peer,
                                                       remove_friend));
  /* FIXME: do stuff */
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
      GNUNET_CONTAINER_multipeermap_contains (friend_peermap,
                                              peer_identity))
  {
    GNUNET_break (0);
    return;
  }

  friend = GNUNET_new (struct FriendInfo);
  friend->id = *peer_identity;

  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multipeermap_put (friend_peermap,
                                                    peer_identity,
                                                    friend,
                                                    GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  /* do work? */
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
 * Handle a `struct FingerSetupMessage`.
 *
 * @param cls closure (NULL)
 * @param peer sender identity
 * @param message the setup message
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static int
handle_dht_p2p_finger_setup (void *cls,
                             const struct GNUNET_PeerIdentity *peer,
                             const struct GNUNET_MessageHeader *message)
{
  const struct FingerSetupMessage *fsm;

  fsm = (const struct FingerSetupMessage *) message;

  return GNUNET_OK;
}

/**
 * Handle a `struct FingerSetupResponseMessage`.
 *
 * @param cls closure (NULL)
 * @param peer sender identity
 * @param message the setup response message
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static int
handle_dht_p2p_finger_setup_response (void *cls,
                             const struct GNUNET_PeerIdentity *peer,
                             const struct GNUNET_MessageHeader *message)
{
  const struct FingerSetupResponseMessage *fsrm;

  fsm = (const struct  *) message;

  return GNUNET_OK;
}


/**
 * Handle a `struct FingerDestroyMessage`.
 *
 * @param cls closure (NULL)
 * @param peer sender identity
 * @param message the finger destroy message
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static int
handle_dht_p2p_finger_destroy (void *cls,
                             const struct GNUNET_PeerIdentity *peer,
                             const struct GNUNET_MessageHeader *message)
{
  const struct FingerDestroyMessage *fdm;

  fsm = (const struct  *) message;

  return GNUNET_OK;
}

/**
 * Handle a `struct FingerRouteMessage`.
 *
 * @param cls closure (NULL)
 * @param peer sender identity
 * @param message the finger route message
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static int
handle_dht_p2p_finger_route (void *cls,
                             const struct GNUNET_PeerIdentity *peer,
                             const struct GNUNET_MessageHeader *message)
{
  const struct FingerRouteMessage *frm;

  fsm = (const struct  *) message;
  /* FIXME: check the size of the message */

  return GNUNET_OK;
}

/**
 * Handle a `struct FingerRouteMessage`.
 *
 * @param cls closure (NULL)
 * @param peer sender identity
 * @param message the finger route message
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static int
handle_dht_p2p_neighbour_find (void *cls,
                             const struct GNUNET_PeerIdentity *peer,
                             const struct GNUNET_MessageHeader *message)
{
  const struct FingerSetupMessage *fsm;

  fsm = (const struct  *) message;

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
    { &handle_dht_p2p_finger_setup,
      GNUNET_MESSAGE_TYPE_WDHT_FINGER_SETUP,
      sizeof (struct FingerSetupMessage) },
    { &handle_dht_p2p_finger_setup_response,
      GNUNET_MESSAGE_TYPE_WDHT_FINGER_SETUP_RESPONSE,
      sizeof (struct FingerSetupResponseMessage) },
    { &handle_dht_p2p_finger_destroy,
      GNUNET_MESSAGE_TYPE_WDHT_FINGER_DESTROY,
      sizeof (struct FingerDestroyMessage) },
    { &handle_dht_p2p_finger_route,
      GNUNET_MESSAGE_TYPE_WDHT_FINGER_ROUTE,
      0},
    { &handle_dht_p2p_neighbour_find,
      GNUNET_MESSAGE_TYPE_WDHT_NEIGHBOUR_FIND,
      sizeof (struct FingerSetupMessage) },
	{ &handle_dht_p2p_neighbour_find,
      GNUNET_MESSAGE_TYPE_WDHT_NEIGHBOUR_FOUND,
      sizeof (struct FingerSetupMessage) },
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

  friend_peermap = GNUNET_CONTAINER_multipeermap_create (256, GNUNET_NO);
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

  GNUNET_assert (0 == GNUNET_CONTAINER_multipeermap_size (friend_peermap));
  GNUNET_CONTAINER_multipeermap_destroy (friend_peermap);
  friend_peermap = NULL;
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
