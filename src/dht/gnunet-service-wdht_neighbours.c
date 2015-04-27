/*
     This file is part of GNUnet.
     Copyright (C) 2009-2014 Christian Grothoff (and other contributing authors)

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
 * @file dht/gnunet-service-xdht_neighbours.c
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
#include "gnunet-service-wdht_routing.h"
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
 * Construct a trail setup message and forward it to target_friend
 * @param source_peer Peer which wants to setup the trail
 * @param ultimate_destination_finger_value Peer identity closest to this value
 *                                          will be finger to @a source_peer
 * @param best_known_destination Best known destination (could be finger or friend)
 *                               which should get this message. In case it is
 *                               friend, then it is same as target_friend
 * @param target_friend Friend to which message is forwarded now.
 * @param trail_length Total number of peers in trail setup so far.
 * @param trail_peer_list Trail setup so far
 * @param is_predecessor Is @a source_peer looking for trail to a predecessor or not.
 * @param trail_id Unique identifier for the trail we are trying to setup.
 * @param intermediate_trail_id Trail id of intermediate trail to reach to
 *                              best_known_destination when its a finger. If not
 *                              used then set to 0.
 */
void
GDS_NEIGHBOURS_send_trail_setup (struct GNUNET_PeerIdentity source_peer,
                                 uint64_t ultimate_destination_finger_value,
                                 struct GNUNET_PeerIdentity best_known_destination,
                                 struct FriendInfo *target_friend,
                                 unsigned int trail_length,
                                 const struct GNUNET_PeerIdentity *trail_peer_list,
                                 unsigned int is_predecessor,
                                 struct GNUNET_HashCode trail_id,
                                 struct GNUNET_HashCode intermediate_trail_id)
{
  struct P2PPendingMessage *pending;
  struct PeerTrailSetupMessage *tsm;
  struct GNUNET_PeerIdentity *peer_list;
  size_t msize;

  msize = sizeof (struct PeerTrailSetupMessage) +
          (trail_length * sizeof (struct GNUNET_PeerIdentity));

  if (msize >= GNUNET_CONSTANTS_MAX_ENCRYPTED_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    return;
  }

  if (target_friend->pending_count >= MAXIMUM_PENDING_PER_FRIEND)
  {
    GNUNET_STATISTICS_update (GDS_stats, gettext_noop ("# P2P messages dropped due to full queue"),
				1, GNUNET_NO);
  }
  pending = GNUNET_malloc (sizeof (struct P2PPendingMessage) + msize);
  pending->timeout = GNUNET_TIME_relative_to_absolute (PENDING_MESSAGE_TIMEOUT);
  tsm = (struct PeerTrailSetupMessage *) &pending[1];
  pending->msg = &(tsm->header);
  tsm->header.size = htons (msize);
  tsm->header.type = htons (GNUNET_MESSAGE_TYPE_XDHT_P2P_TRAIL_SETUP);
  tsm->final_destination_finger_value = GNUNET_htonll (ultimate_destination_finger_value);
  tsm->source_peer = source_peer;
  tsm->best_known_destination = best_known_destination;
  tsm->is_predecessor = htonl (is_predecessor);
  tsm->trail_id = trail_id;
  tsm->intermediate_trail_id = intermediate_trail_id;

  if (trail_length > 0)
  {
    peer_list = (struct GNUNET_PeerIdentity *) &tsm[1];
    memcpy (peer_list, trail_peer_list, trail_length * sizeof(struct GNUNET_PeerIdentity));
  }

  GNUNET_CONTAINER_DLL_insert_tail (target_friend->head, target_friend->tail, pending);
  target_friend->pending_count++;
  process_friend_queue (target_friend);
}


/**
 * Construct a trail setup result message and forward it to target friend.
 * @param querying_peer Peer which sent the trail setup request and should get
 *                      the result back.
 * @param Finger Peer to which the trail has been setup to.
 * @param target_friend Friend to which this message should be forwarded.
 * @param trail_length Numbers of peers in the trail.
 * @param trail_peer_list Peers which are part of the trail from
 *                        querying_peer to Finger, NOT including them.
 * @param is_predecessor Is @a Finger predecessor to @a querying_peer ?
 * @param ultimate_destination_finger_value Value to which @a finger is the closest
 *                                          peer.
 * @param trail_id Unique identifier of the trail.
 */
void
GDS_NEIGHBOURS_send_trail_setup_result (struct GNUNET_PeerIdentity querying_peer,
                                        struct GNUNET_PeerIdentity finger,
                                        struct FriendInfo *target_friend,
                                        unsigned int trail_length,
                                        const struct GNUNET_PeerIdentity *trail_peer_list,
                                        unsigned int is_predecessor,
                                        uint64_t ultimate_destination_finger_value,
                                        struct GNUNET_HashCode trail_id)
{
  struct P2PPendingMessage *pending;
  struct PeerTrailSetupResultMessage *tsrm;
  struct GNUNET_PeerIdentity *peer_list;
  size_t msize;

  msize = sizeof (struct PeerTrailSetupResultMessage) +
          (trail_length * sizeof (struct GNUNET_PeerIdentity));

  if (msize >= GNUNET_CONSTANTS_MAX_ENCRYPTED_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    return;
  }

  if (target_friend->pending_count >= MAXIMUM_PENDING_PER_FRIEND)
  {
    GNUNET_STATISTICS_update (GDS_stats,
                              gettext_noop ("# P2P messages dropped due to full queue"),
                              1, GNUNET_NO);
  }

  pending = GNUNET_malloc (sizeof (struct P2PPendingMessage) + msize);
  pending->importance = 0;
  pending->timeout = GNUNET_TIME_relative_to_absolute (PENDING_MESSAGE_TIMEOUT);
  tsrm = (struct PeerTrailSetupResultMessage *) &pending[1];
  pending->msg = &tsrm->header;
  tsrm->header.size = htons (msize);
  tsrm->header.type = htons (GNUNET_MESSAGE_TYPE_XDHT_P2P_TRAIL_SETUP_RESULT);
  tsrm->querying_peer = querying_peer;
  tsrm->finger_identity = finger;
  tsrm->is_predecessor = htonl (is_predecessor);
  tsrm->trail_id = trail_id;
  tsrm->ulitmate_destination_finger_value =
          GNUNET_htonll (ultimate_destination_finger_value);
  peer_list = (struct GNUNET_PeerIdentity *) &tsrm[1];
  memcpy (peer_list, trail_peer_list, trail_length * sizeof (struct GNUNET_PeerIdentity));

  /* Send the message to chosen friend. */
  GNUNET_CONTAINER_DLL_insert_tail (target_friend->head, target_friend->tail, pending);
  target_friend->pending_count++;
  process_friend_queue (target_friend);
}

/**
 * Send notify successor confirmation message.
 * @param trail_id Unique Identifier of the trail.
 * @param trail_direction Destination to Source.
 * @param target_friend Friend to get this message next.
 */
void
GDS_NEIGHBOURS_send_notify_succcessor_confirmation (struct GNUNET_HashCode trail_id,
                                                    unsigned int trail_direction,
                                                     struct FriendInfo *target_friend)
{
  struct PeerNotifyConfirmationMessage *ncm;
  struct P2PPendingMessage *pending;
  size_t msize;

  msize = sizeof (struct PeerNotifyConfirmationMessage);
  if (msize >= GNUNET_CONSTANTS_MAX_ENCRYPTED_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    return;
  }

  if (target_friend->pending_count >= MAXIMUM_PENDING_PER_FRIEND)
  {
    GNUNET_STATISTICS_update (GDS_stats, gettext_noop ("# P2P messages dropped due to full queue"),
				1, GNUNET_NO);
  }

  pending = GNUNET_malloc (sizeof (struct P2PPendingMessage) + msize);
  pending->importance = 0;    /* FIXME */
  pending->timeout = GNUNET_TIME_relative_to_absolute (PENDING_MESSAGE_TIMEOUT);
  ncm = (struct PeerNotifyConfirmationMessage *) &pending[1];
  pending->msg = &ncm->header;
  ncm->header.size = htons (msize);
  ncm->header.type = htons (GNUNET_MESSAGE_TYPE_XDHT_P2P_NOTIFY_SUCCESSOR_CONFIRMATION);
  ncm->trail_id = trail_id;
  ncm->trail_direction = htonl (trail_direction);

  /* Send the message to chosen friend. */
  GNUNET_CONTAINER_DLL_insert_tail (target_friend->head, target_friend->tail, pending);
  target_friend->pending_count++;
  process_friend_queue (target_friend);
}


/**
 * Send trail rejection message to target friend
 * @param source_peer Peer which is trying to setup the trail.
 * @param ultimate_destination_finger_value Peer closest to this value will be
 *                                          @a source_peer's finger
 * @param congested_peer Peer which sent this message as it is congested.
 * @param is_predecessor Is source_peer looking for trail to a predecessor or not.
 * @param trail_peer_list Trails seen so far in trail setup before getting rejected
 *                        by congested_peer. This does NOT include @a source_peer
 *                        and congested_peer.
 * @param trail_length Total number of peers in trail_peer_list, NOT including
 *                     @a source_peer and @a congested_peer
 * @param trail_id Unique identifier of this trail.
 * @param congestion_timeout Duration given by congested peer as an estimate of
 *                           how long it may remain congested.
 */
void
GDS_NEIGHBOURS_send_trail_rejection (struct GNUNET_PeerIdentity source_peer,
                                     uint64_t ultimate_destination_finger_value,
                                     struct GNUNET_PeerIdentity congested_peer,
                                     unsigned int is_predecessor,
                                     const struct GNUNET_PeerIdentity *trail_peer_list,
                                     unsigned int trail_length,
                                     struct GNUNET_HashCode trail_id,
                                     struct FriendInfo *target_friend,
                                     const struct GNUNET_TIME_Relative congestion_timeout)
{
  struct PeerTrailRejectionMessage *trm;
  struct P2PPendingMessage *pending;
  struct GNUNET_PeerIdentity *peer_list;
  size_t msize;

  msize = sizeof (struct PeerTrailRejectionMessage) +
          (trail_length * sizeof (struct GNUNET_PeerIdentity));

  if (msize >= GNUNET_CONSTANTS_MAX_ENCRYPTED_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    return;
  }

  if (target_friend->pending_count >= MAXIMUM_PENDING_PER_FRIEND)
  {
    GNUNET_STATISTICS_update (GDS_stats, gettext_noop ("# P2P messages dropped due to full queue"),
				1, GNUNET_NO);
  }

  pending = GNUNET_malloc (sizeof (struct P2PPendingMessage) + msize);
  pending->importance = 0;
  pending->timeout = GNUNET_TIME_relative_to_absolute (PENDING_MESSAGE_TIMEOUT);
  trm = (struct PeerTrailRejectionMessage *)&pending[1];
  pending->msg = &trm->header;
  trm->header.size = htons (msize);
  trm->header.type = htons (GNUNET_MESSAGE_TYPE_XDHT_P2P_TRAIL_SETUP_REJECTION);
  trm->source_peer = source_peer;
  trm->congested_peer = congested_peer;
  trm->congestion_time = congestion_timeout;
  trm->is_predecessor = htonl (is_predecessor);
  trm->trail_id = trail_id;
  trm->ultimate_destination_finger_value =
          GNUNET_htonll (ultimate_destination_finger_value);

  peer_list = (struct GNUNET_PeerIdentity *) &trm[1];
  if (trail_length > 0)
  {
    memcpy (peer_list, trail_peer_list, trail_length * sizeof (struct GNUNET_PeerIdentity));
  }

  /* Send the message to chosen friend. */
  GNUNET_CONTAINER_DLL_insert_tail (target_friend->head, target_friend->tail, pending);
  target_friend->pending_count++;
  process_friend_queue (target_friend);
}


/**
 * Construct a verify successor message and forward it to target_friend.
 * @param source_peer Peer which wants to verify its successor.
 * @param successor Peer which is @a source_peer's current successor.
 * @param trail_id Unique Identifier of trail from @a source_peer to @a successor,
 *                 NOT including them.
 * @param trail List of peers which are part of trail to reach from @a source_peer
 *              to @a successor, NOT including them.
 * @param trail_length Total number of peers in @a trail.
 * @param target_friend Next friend to get this message.
 */
void
GDS_NEIGHBOURS_send_verify_successor_message (struct GNUNET_PeerIdentity source_peer,
                                              struct GNUNET_PeerIdentity successor,
                                              struct GNUNET_HashCode trail_id,
                                              struct GNUNET_PeerIdentity *trail,
                                              unsigned int trail_length,
                                              struct FriendInfo *target_friend)
{
  struct PeerVerifySuccessorMessage *vsm;
  struct P2PPendingMessage *pending;
  struct GNUNET_PeerIdentity *peer_list;
  size_t msize;

  msize = sizeof (struct PeerVerifySuccessorMessage) +
         (trail_length * sizeof (struct GNUNET_PeerIdentity));

  if (msize >= GNUNET_CONSTANTS_MAX_ENCRYPTED_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    return;
  }

  if (target_friend->pending_count >= MAXIMUM_PENDING_PER_FRIEND)
  {
    GNUNET_STATISTICS_update (GDS_stats, gettext_noop ("# P2P messages dropped due to full queue"),
				1, GNUNET_NO);
  }

  pending = GNUNET_malloc (sizeof (struct P2PPendingMessage) + msize);
  pending->importance = 0;    /* FIXME */
  pending->timeout = GNUNET_TIME_relative_to_absolute (PENDING_MESSAGE_TIMEOUT);
  vsm = (struct PeerVerifySuccessorMessage *) &pending[1];
  pending->msg = &vsm->header;
  vsm->header.size = htons (msize);
  vsm->header.type = htons (GNUNET_MESSAGE_TYPE_XDHT_P2P_VERIFY_SUCCESSOR);
  vsm->source_peer = source_peer;
  vsm->successor = successor;
  vsm->trail_id = trail_id;
  peer_list = (struct GNUNET_PeerIdentity *) &vsm[1];
  memcpy (peer_list, trail, trail_length * sizeof (struct GNUNET_PeerIdentity));

  /* Send the message to chosen friend. */
  GNUNET_CONTAINER_DLL_insert_tail (target_friend->head, target_friend->tail, pending);
  target_friend->pending_count++;
  process_friend_queue (target_friend);
}


/**
 * FIXME: In every function we pass target friend except for this one.
 * so, either change everything or this one. also, should se just store
 * the pointer to friend in routing table rather than gnunet_peeridentity.
 * if yes then we should keep friend info in.h  andmake lot of changes.
 * Construct a trail teardown message and forward it to target friend.
 *
 * @param trail_id Unique identifier of the trail.
 * @param trail_direction Direction of trail.
 * @param target_friend Friend to get this message.
 */
void
GDS_NEIGHBOURS_send_trail_teardown (const struct GNUNET_HashCode *trail_id,
                                    unsigned int trail_direction,
                                    const struct GNUNET_PeerIdentity *peer)
{
  struct PeerTrailTearDownMessage *ttdm;
  struct P2PPendingMessage *pending;
  struct FriendInfo *target_friend;
  size_t msize;

  msize = sizeof (struct PeerTrailTearDownMessage);
  if (msize >= GNUNET_CONSTANTS_MAX_ENCRYPTED_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    return;
  }

  if (NULL == (target_friend =
               GNUNET_CONTAINER_multipeermap_get (friend_peermap, peer)))
  {
    /* FIXME: In what case friend can be null. ?*/
    GNUNET_break (0);
    return;
  }

  if (target_friend->pending_count >= MAXIMUM_PENDING_PER_FRIEND)
  {
    GNUNET_STATISTICS_update (GDS_stats, gettext_noop ("# P2P messages dropped due to full queue"),
				1, GNUNET_NO);
  }

  pending = GNUNET_malloc (sizeof (struct P2PPendingMessage) + msize);
  pending->importance = 0;    /* FIXME */
  pending->timeout = GNUNET_TIME_relative_to_absolute (PENDING_MESSAGE_TIMEOUT);
  ttdm = (struct PeerTrailTearDownMessage *) &pending[1];
  pending->msg = &ttdm->header;
  ttdm->header.size = htons (msize);
  ttdm->header.type = htons (GNUNET_MESSAGE_TYPE_XDHT_P2P_TRAIL_TEARDOWN);
  ttdm->trail_id = *trail_id;
  ttdm->trail_direction = htonl (trail_direction);

  /* Send the message to chosen friend. */
  GNUNET_CONTAINER_DLL_insert_tail (target_friend->head, target_friend->tail, pending);
  target_friend->pending_count++;
  process_friend_queue (target_friend);
}


/**
 * Construct a verify successor result message and send it to target_friend
 * @param querying_peer Peer which sent the verify successor message.
 * @param source_successor Current_successor of @a querying_peer.
 * @param current_predecessor Current predecessor of @a successor. Could be same
 *                            or different from @a querying_peer.
 * @param trail_id Unique identifier of the trail from @a querying_peer to
 *                 @a successor, NOT including them.
 * @param trail List of peers which are part of trail from @a querying_peer to
 *                 @a successor, NOT including them.
 * @param trail_length Total number of peers in @a trail
 * @param trail_direction Direction in which we are sending the message. In this
 *                        case we are sending result from @a successor to @a querying_peer.
 * @param target_friend Next friend to get this message.
 */
void
GDS_NEIGHBOURS_send_verify_successor_result (struct GNUNET_PeerIdentity querying_peer,
                                             struct GNUNET_PeerIdentity current_successor,
                                             struct GNUNET_PeerIdentity probable_successor,
                                             struct GNUNET_HashCode trail_id,
                                             const struct GNUNET_PeerIdentity *trail,
                                             unsigned int trail_length,
                                             enum GDS_ROUTING_trail_direction trail_direction,
                                             struct FriendInfo *target_friend)
{
  struct PeerVerifySuccessorResultMessage *vsmr;
  struct P2PPendingMessage *pending;
  struct GNUNET_PeerIdentity *peer_list;
  size_t msize;

  msize = sizeof (struct PeerVerifySuccessorResultMessage) +
          (trail_length * sizeof(struct GNUNET_PeerIdentity));

  if (msize >= GNUNET_CONSTANTS_MAX_ENCRYPTED_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    return;
  }

  if (target_friend->pending_count >= MAXIMUM_PENDING_PER_FRIEND)
  {
    GNUNET_STATISTICS_update (GDS_stats, gettext_noop ("# P2P messages dropped due to full queue"),
				1, GNUNET_NO);
  }

  pending = GNUNET_malloc (sizeof (struct P2PPendingMessage) + msize);
  pending->importance = 0;    /* FIXME */
  pending->timeout = GNUNET_TIME_relative_to_absolute (PENDING_MESSAGE_TIMEOUT);
  vsmr = (struct PeerVerifySuccessorResultMessage *) &pending[1];
  pending->msg = &vsmr->header;
  vsmr->header.size = htons (msize);
  vsmr->header.type = htons (GNUNET_MESSAGE_TYPE_XDHT_P2P_VERIFY_SUCCESSOR_RESULT);
  vsmr->querying_peer = querying_peer;
  vsmr->current_successor = current_successor;
  vsmr->probable_successor = probable_successor;
  vsmr->trail_direction = htonl (trail_direction);
  vsmr->trail_id = trail_id;
  peer_list = (struct GNUNET_PeerIdentity *) &vsmr[1];
  memcpy (peer_list, trail, trail_length * sizeof (struct GNUNET_PeerIdentity));

   /* Send the message to chosen friend. */
  GNUNET_CONTAINER_DLL_insert_tail (target_friend->head, target_friend->tail, pending);
  target_friend->pending_count++;
  process_friend_queue (target_friend);
}

/**
 * Construct a Put message and send it to target_peer.
 * @param key Key for the content
 * @param block_type Type of the block
 * @param options Routing options
 * @param desired_replication_level Desired replication count
 * @param best_known_dest Peer to which this message should reach eventually,
 *                        as it is best known destination to me.
 * @param intermediate_trail_id Trail id in case
 * @param target_peer Peer to which this message will be forwarded.
 * @param hop_count Number of hops traversed so far.
 * @param put_path_length Total number of peers in @a put_path
 * @param put_path Number of peers traversed so far
 * @param expiration_time When does the content expire
 * @param data Content to store
 * @param data_size Size of content @a data in bytes
 */
void
GDS_NEIGHBOURS_send_put (const struct GNUNET_HashCode *key,
                         enum GNUNET_BLOCK_Type block_type,
			                   enum GNUNET_DHT_RouteOption options,
			                   uint32_t desired_replication_level,
			                   struct GNUNET_PeerIdentity best_known_dest,
			                   struct GNUNET_HashCode intermediate_trail_id,
			                   struct GNUNET_PeerIdentity *target_peer,
                         uint32_t hop_count,
                         uint32_t put_path_length,
                         struct GNUNET_PeerIdentity *put_path,
                         struct GNUNET_TIME_Absolute expiration_time,
                         const void *data, size_t data_size)
{
  struct PeerPutMessage *ppm;
  struct P2PPendingMessage *pending;
  struct FriendInfo *target_friend;
  struct GNUNET_PeerIdentity *pp;
  size_t msize;

  msize = put_path_length * sizeof (struct GNUNET_PeerIdentity) + data_size +
          sizeof (struct PeerPutMessage);
  if (msize >= GNUNET_CONSTANTS_MAX_ENCRYPTED_MESSAGE_SIZE)
  {
    put_path_length = 0;
    msize = data_size + sizeof (struct PeerPutMessage);
  }

  if (msize >= GNUNET_CONSTANTS_MAX_ENCRYPTED_MESSAGE_SIZE)
  {
    DEBUG("msize = %lu\n",msize);
    GNUNET_break (0);
    return;
  }

  GNUNET_assert (NULL !=
                 (target_friend =
                  GNUNET_CONTAINER_multipeermap_get (friend_peermap, target_peer)));
  pending = GNUNET_malloc (sizeof (struct P2PPendingMessage) + msize);
  pending->timeout = expiration_time;
  ppm = (struct PeerPutMessage *) &pending[1];
  pending->msg = &ppm->header;
  ppm->header.size = htons (msize);
  ppm->header.type = htons (GNUNET_MESSAGE_TYPE_XDHT_P2P_PUT);
  ppm->options = htonl (options);
  ppm->block_type = htonl (block_type);
  ppm->hop_count = htonl (hop_count + 1);
  ppm->desired_replication_level = htonl (desired_replication_level);
  ppm->expiration_time = GNUNET_TIME_absolute_hton (expiration_time);
  ppm->best_known_destination = best_known_dest;
  ppm->intermediate_trail_id = intermediate_trail_id;
  ppm->key = *key;
  pp = (struct GNUNET_PeerIdentity *) &ppm[1];
  ppm->put_path_length = htonl (put_path_length);
  if(put_path_length > 0)
  {
    memcpy (pp, put_path,
            sizeof (struct GNUNET_PeerIdentity) * put_path_length);
  }
  memcpy (&pp[put_path_length], data, data_size);
  GNUNET_assert (NULL != target_friend);
  GNUNET_CONTAINER_DLL_insert_tail (target_friend->head, target_friend->tail, pending);
  target_friend->pending_count++;
  process_friend_queue (target_friend);
}


/**
 * Handle the put request from the client.
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
  struct GNUNET_PeerIdentity best_known_dest;
  struct GNUNET_HashCode intermediate_trail_id;
  struct GNUNET_PeerIdentity next_hop;
  uint64_t key_value;
  struct Closest_Peer successor;

  memcpy (&key_value, key, sizeof (uint64_t));
  key_value = GNUNET_ntohll (key_value);
  successor = find_local_best_known_next_hop (key_value,
                                              GDS_FINGER_TYPE_NON_PREDECESSOR);
  best_known_dest = successor.best_known_destination;
  next_hop = successor.next_hop;
  intermediate_trail_id = successor.trail_id;

  if (0 == GNUNET_CRYPTO_cmp_peer_identity (&best_known_dest, &my_identity))
  {
    DEBUG("\n PUT_REQUEST_SUCCESSFUL for key = %s",GNUNET_h2s(key));
    /* I am the destination. */
    GDS_DATACACHE_handle_put (expiration_time, key, 0, NULL,
                              block_type,data_size,data);
    GDS_CLIENTS_process_put (options, block_type, 0,
                             ntohl (desired_replication_level),
                             1, &my_identity, expiration_time, //FIXME: GNUNETnthoh something on expiration time.
                             key, data, data_size);
    return;
  }
  /* In case we are sending the request to  a finger, then send across all of its
   trail.*/
#if ENABLE_MALICIOUS
  if (0 != GNUNET_CRYPTO_cmp_peer_identity (&successor.best_known_destination,
                                            &successor.next_hop))
  {
    struct FingerInfo *next_hop_finger;
    unsigned int i;

    next_hop_finger = &finger_table[successor.finger_table_index];
    for (i = 0; i < next_hop_finger->trails_count; i++)
    {
      if (GNUNET_YES == next_hop_finger->trail_list[i].is_present)
      {
        if(0 == next_hop_finger->trail_list[i].trail_length)
        {
           GDS_NEIGHBOURS_send_put (key, block_type, options, desired_replication_level,
                                    best_known_dest, intermediate_trail_id, &next_hop,
                                    0, 1, &my_identity, expiration_time,
                                    data, data_size);
           return;
        }
        next_hop = next_hop_finger->trail_list[i].trail_head->peer;
        GDS_NEIGHBOURS_send_put (key, block_type, options, desired_replication_level,
                                 best_known_dest,
                                 next_hop_finger->trail_list[i].trail_id,
                                 &next_hop, 0, 1, &my_identity,
                                 expiration_time,
                                 data, data_size);
       }
    }
    return;
  }
#endif
 GDS_NEIGHBOURS_send_put (key, block_type, options, desired_replication_level,
                          best_known_dest, intermediate_trail_id, &next_hop,
                          0, 1, &my_identity, expiration_time,
                          data, data_size);
}

/**
 * Construct a Get message and send it to target_peer.
 * @param key Key for the content
 * @param block_type Type of the block
 * @param options Routing options
 * @param desired_replication_level Desired replication count
 * @param best_known_dest Peer which should get this message. Same as target peer
 *                        if best_known_dest is a friend else its a finger.
 * @param intermediate_trail_id  Trail id to reach to @a best_known_dest
 *                              in case it is a finger else set to 0.
 * @param target_peer Peer to which this message will be forwarded.
 * @param hop_count Number of hops traversed so far.
 * @param data Content to store
 * @param data_size Size of content @a data in bytes
 * @param get_path_length Total number of peers in @a get_path
 * @param get_path Number of peers traversed so far
 */
void
GDS_NEIGHBOURS_send_get (const struct GNUNET_HashCode *key,
                         enum GNUNET_BLOCK_Type block_type,
                         enum GNUNET_DHT_RouteOption options,
                         uint32_t desired_replication_level,
                         struct GNUNET_PeerIdentity best_known_dest,
                         struct GNUNET_HashCode intermediate_trail_id,
                         struct GNUNET_PeerIdentity *target_peer,
                         uint32_t hop_count,
                         uint32_t get_path_length,
                         struct GNUNET_PeerIdentity *get_path)
{
  struct PeerGetMessage *pgm;
  struct P2PPendingMessage *pending;
  struct FriendInfo *target_friend;
  struct GNUNET_PeerIdentity *gp;
  size_t msize;

  msize = sizeof (struct PeerGetMessage) +
          (get_path_length * sizeof (struct GNUNET_PeerIdentity));

  if (msize >= GNUNET_CONSTANTS_MAX_ENCRYPTED_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    return;
  }
  GNUNET_assert (NULL !=
                 (target_friend =
                  GNUNET_CONTAINER_multipeermap_get (friend_peermap, target_peer)));

  pending = GNUNET_malloc (sizeof (struct P2PPendingMessage) + msize);
  pending->timeout = GNUNET_TIME_relative_to_absolute (PENDING_MESSAGE_TIMEOUT);
  pending->importance = 0;    /* FIXME */
  pgm = (struct PeerGetMessage *) &pending[1];
  pending->msg = &pgm->header;
  pgm->header.size = htons (msize);
  pgm->header.type = htons (GNUNET_MESSAGE_TYPE_XDHT_P2P_GET);
  pgm->get_path_length = htonl (get_path_length);
  pgm->best_known_destination = best_known_dest;
  pgm->key = *key;
  pgm->intermediate_trail_id = intermediate_trail_id;
  pgm->hop_count = htonl (hop_count + 1);
  pgm->get_path_length = htonl (get_path_length);
  gp = (struct GNUNET_PeerIdentity *) &pgm[1];
  memcpy (gp, get_path,
          sizeof (struct GNUNET_PeerIdentity) * get_path_length);
  GNUNET_CONTAINER_DLL_insert_tail (target_friend->head, target_friend->tail, pending);
  target_friend->pending_count++;
  process_friend_queue (target_friend);
}


/**
 * Handle the get request from the client file. If I am destination do
 * datacache put and return. Else find the target friend and forward message
 * to it.
 * @param key Key for the content
 * @param block_type Type of the block
 * @param options Routing options
 * @param desired_replication_level Desired replication count
 */
void
GDS_NEIGHBOURS_handle_get(const struct GNUNET_HashCode *key,
                          enum GNUNET_BLOCK_Type block_type,
                          enum GNUNET_DHT_RouteOption options,
                          uint32_t desired_replication_level)
{
  struct Closest_Peer successor;
  struct GNUNET_PeerIdentity best_known_dest;
  struct GNUNET_HashCode intermediate_trail_id;
  uint64_t key_value;

  memcpy (&key_value, key, sizeof (uint64_t));
  key_value = GNUNET_ntohll (key_value);

  successor = find_local_best_known_next_hop (key_value,
                                              GDS_FINGER_TYPE_NON_PREDECESSOR);

  best_known_dest = successor.best_known_destination;
  intermediate_trail_id = successor.trail_id;

  /* I am the destination. I have the data. */
  if (0 == GNUNET_CRYPTO_cmp_peer_identity (&my_identity,
                                            &best_known_dest))
  {
    GDS_DATACACHE_handle_get (key,block_type, NULL, 0,
                              NULL, 0, 1, &my_identity, NULL,&my_identity);
    return;
  }

#if ENABLE_MALICIOUS
  struct GNUNET_PeerIdentity next_hop;
  if (0 != GNUNET_CRYPTO_cmp_peer_identity (&successor.best_known_destination,
                                            &successor.next_hop))
  {
    struct FingerInfo *next_hop_finger;
    unsigned int i;

    next_hop_finger = &finger_table[successor.finger_table_index];
    for (i = 0; i < next_hop_finger->trails_count; i++)
    {
      if (GNUNET_YES == next_hop_finger->trail_list[i].is_present)
      {
        if(0 == next_hop_finger->trail_list[i].trail_length)
        {
           GDS_NEIGHBOURS_send_get (key, block_type, options,
                                    desired_replication_level,
                                    best_known_dest,intermediate_trail_id,
                                    &successor.next_hop,
                                    0, 1, &my_identity);
           return;
        }
        next_hop = next_hop_finger->trail_list[i].trail_head->peer;
        GDS_NEIGHBOURS_send_get (key, block_type, options, desired_replication_level,
                                 best_known_dest,
                                 next_hop_finger->trail_list[i].trail_id,
                                 &next_hop, 0, 1, &my_identity);
       }
    }
    return;
  }
#endif
  GDS_NEIGHBOURS_send_get (key, block_type, options, desired_replication_level,
                           best_known_dest,intermediate_trail_id, &successor.next_hop,
                           0, 1, &my_identity);
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
  struct PeerGetResultMessage *get_result;
  struct GNUNET_PeerIdentity *paths;
  struct P2PPendingMessage *pending;
  struct FriendInfo *target_friend;
  int current_path_index;
  size_t msize;

  msize = (put_path_length + get_path_length )* sizeof (struct GNUNET_PeerIdentity) +
          data_size +
          sizeof (struct PeerGetResultMessage);

  if (msize >= GNUNET_CONSTANTS_MAX_ENCRYPTED_MESSAGE_SIZE)
  {
    put_path_length = 0;
    msize = msize - put_path_length * sizeof (struct GNUNET_PeerIdentity);
  }

  if (msize >= GNUNET_CONSTANTS_MAX_ENCRYPTED_MESSAGE_SIZE)
  {
    GNUNET_break(0);
    return;
  }
  current_path_index = 0;
  if(get_path_length > 0)
  {
    current_path_index = search_my_index(get_path, get_path_length);
    if (-1 == current_path_index)
    {
      GNUNET_break (0);
      return;
    }
    if ((get_path_length + 1) == current_path_index)
    {
      DEBUG ("Peer found twice in get path. Not allowed \n");
      GNUNET_break (0);
      return;
    }
  }
  if (0 == current_path_index)
  {
    DEBUG ("GET_RESULT TO CLIENT KEY = %s, Peer = %s",GNUNET_h2s(key),GNUNET_i2s(&my_identity));
    GDS_CLIENTS_handle_reply (expiration, key, get_path_length,
                              get_path, put_path_length,
                              put_path, type, data_size, data);
    return;
  }

  pending = GNUNET_malloc (sizeof (struct P2PPendingMessage) + msize);
  pending->timeout = GNUNET_TIME_relative_to_absolute (PENDING_MESSAGE_TIMEOUT);
  pending->importance = 0;
  get_result = (struct PeerGetResultMessage *)&pending[1];
  pending->msg = &get_result->header;
  get_result->header.size = htons (msize);
  get_result->header.type = htons (GNUNET_MESSAGE_TYPE_XDHT_P2P_GET_RESULT);
  get_result->key = *key;
  get_result->querying_peer = *source_peer;
  get_result->expiration_time = expiration;
  get_result->get_path_length = htonl (get_path_length);
  get_result->put_path_length = htonl (put_path_length);
  paths = (struct GNUNET_PeerIdentity *)&get_result[1];
  memcpy (paths, put_path,
          put_path_length * sizeof (struct GNUNET_PeerIdentity));
  memcpy (&paths[put_path_length], get_path,
          get_path_length * sizeof (struct GNUNET_PeerIdentity));
  memcpy (&paths[put_path_length + get_path_length], data, data_size);

  GNUNET_assert (NULL !=
                (target_friend =
                 GNUNET_CONTAINER_multipeermap_get (friend_peermap,
                                                    &get_path[current_path_index - 1])));
  GNUNET_CONTAINER_DLL_insert_tail (target_friend->head, target_friend->tail, pending);
  target_friend->pending_count++;
  process_friend_queue (target_friend);
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
    {NULL, 0, 0}
  };

#if ENABLE_MALICIOUS
  act_malicious = 0;
#endif

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

  //TODO: check size of this peer map?
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
