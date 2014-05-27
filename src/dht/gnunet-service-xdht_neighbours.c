/*
     This file is part of GNUnet.
     (C) 2009-2014 Christian Grothoff (and other contributing authors)

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
#include "gnunet-service-xdht_clients.h"
#include "gnunet-service-xdht_datacache.h"
#include "gnunet-service-xdht_neighbours.h"
#include "gnunet-service-xdht_routing.h"
#include <fenv.h>
#include "dht.h"

/**
 * Maximum possible fingers of a peer.
 */
#define MAX_FINGERS 65

/**
 * Maximum allowed number of pending messages per friend peer.
 */
#define MAXIMUM_PENDING_PER_FRIEND 64

/**
 * How long to wait before sending another find finger trail request
 */
#define DHT_FIND_FINGER_TRAIL_INTERVAL GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 30)

/**
 * How long at most to wait for transmission of a request to another peer?
 */
#define GET_TIMEOUT GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MINUTES, 2)

/**
 * How long will I remain congested?
 */
#define CONGESTION_TIMEOUT GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MINUTES, 2)

/**
 * Maximum number of trails stored per finger.
 */
#define MAXIMUM_TRAILS_PER_FINGER 2

/**
 * Used to distinguish put/get request use of find_successor() from others 
 */
#define PUT_GET_REQUEST 65

/**
 * Finger map index for predecessor entry in finger peermap. 
 */
#define PREDECESSOR_FINGER_ID 64

/**
 * Maximum number of trails allowed to go through a friend.
 */
#define TRAILS_THROUGH_FRIEND_THRESHOLD 64

GNUNET_NETWORK_STRUCT_BEGIN

/**
 * P2P Trail setup message
 */
struct PeerTrailSetupMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_DHT_P2P_TRAIL_SETUP
   */
  struct GNUNET_MessageHeader header;
  
  /**
   * Peer closest to this value will be our finger. 
   */
  uint64_t ultimate_destination_finger;

  /**
   * Source peer which wants to setup the trail to one of its finger. 
   */
  struct GNUNET_PeerIdentity source_peer;
  
  /**
   * Peer to which this packet is forwarded.
   */
  struct GNUNET_PeerIdentity next_destination;
  
  /**
   * Index into finger peer map, in Network Byte Order. 
   */
  uint32_t finger_map_index;
  
  /**
   * Number of entries in trail list, in Network Byte Order.
   */
  uint32_t trail_length GNUNET_PACKED;
  
  /**
   * Trail id of any intermediate trail we may encounter while doing trail setup.
   */
  struct GNUNET_HashCode intermediate_trail_id;
  
  /**
   * Trail id for trail which we are trying to setup. 
   */
  struct GNUNET_HashCode new_trail_id;
  
  /* Trail formed in the process. */
};

/**
  * P2P Trail Setup Result message
 */
struct PeerTrailSetupResultMessage
{
  
  /**
   * Type: #GNUNET_MESSAGE_TYPE_DHT_P2P_TRAIL_SETUP_RESULT
   */
  struct GNUNET_MessageHeader header;
  
  /**
   * Finger to which we have found the path. 
   */
  struct GNUNET_PeerIdentity finger_identity;

  /**
   * Peer which was looking for the trail to finger. 
   */
  struct GNUNET_PeerIdentity destination_peer;
  
  /**
   * Index into finger peer map in NBO.
   */
  uint32_t finger_map_index;
  
  /**
   * Number of entries in trail list in NBO.
   */
  uint32_t trail_length GNUNET_PACKED;
  
  /**
   * Identifier of the trail. 
   */
  struct GNUNET_HashCode trail_id;
  /* Trail from destination_peer to finger_identity */
  
};

struct PeerVerifySuccessorMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_DHT_P2P_VERIFY_SUCCESSOR
   */
  struct GNUNET_MessageHeader header;
  
  /**
   * Source peer which wants to verify its successor. 
   */
  struct GNUNET_PeerIdentity source_peer;
  
  /**
   * My current successor.
   */
  struct GNUNET_PeerIdentity successor;
  
  /**
   * Identifier of trail to reach from source_peer to successor.
   */
  struct GNUNET_HashCode trail_id;
};

struct PeerVerifySuccessorResultMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_DHT_P2P_VERIFY_SUCCESSOR_RESULT
   */
  struct GNUNET_MessageHeader header;
  
  /**
   * Destination peer which sent the request to verify its successor. 
   */
  struct GNUNET_PeerIdentity destination_peer;
  
  /**
   * Successor to which PeerVerifySuccessorMessage was sent.
   */
  struct GNUNET_PeerIdentity source_successor;
  
  /**
   * source_successor's predecessor
   */
  struct GNUNET_PeerIdentity my_predecessor;
  
  /**
   * Trail identifier of trail from my_predecessor to source_successor. 
   */
  struct GNUNET_HashCode trail_id;
  
  enum GDS_ROUTING_trail_direction trail_direction;
  /**
   * Total number of peers in trail from source_successor to my_predecessor
   * if my_predecessor is not same as destination_peer. 
   */
  uint32_t trail_length; 
  
  /* Trail from source_successor to my_predecessor where 
   * my_predecessor != destination_peer*/
};

struct PeerNotifyNewSuccessorMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_DHT_P2P_NOTIFY_NEW_SUCCESSOR
   */
  struct GNUNET_MessageHeader header;
  
  /**
   * Source peer which wants to notify its new successor. 
   */
  struct GNUNET_PeerIdentity source_peer;
  
  /**
   * New successor identity.
   */
  struct GNUNET_PeerIdentity destination_peer;
  
  unsigned int trail_length;
  
  struct GNUNET_HashCode trail_id;
  
  /* Trail. */
};

/**
 * Trail compressiong message. 
 */
struct PeerTrailCompressionMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_DHT_P2P_TRAIL_COMPRESSION
   */
  struct GNUNET_MessageHeader header;
  
  /**
   * Source peer of this trail.  
   */
  struct GNUNET_PeerIdentity source_peer;
  
  /**
   * Destination of this trail. 
   */
  struct GNUNET_PeerIdentity destination_peer;
  
  /**
   * Trail from source_peer to destination_peer compressed such that 
   * new_first_friend is the first hop in the trail from source to 
   * destination. 
   */
  struct GNUNET_PeerIdentity new_first_friend;
  
  /**
   * Unique identifier of trail. 
   */
  struct GNUNET_HashCode trail_id;
};

/**
 * Trail Tear Down message. 
 */
struct PeerTrailTearDownMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_DHT_P2P_TRAIL_TEARDOWN
   */
  struct GNUNET_MessageHeader header;
};

/**
 * Trail Rejection Message.
 */
struct PeerTrailRejectionMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_DHT_P2P_TRAIL_REJECTION
   */
  struct GNUNET_MessageHeader header;
  
  /**
   * Source peer which wants to set up the trail. 
   */
  struct GNUNET_PeerIdentity source_peer;
  
  /**
   * Peer which sent trail rejection message. 
   */
  struct GNUNET_PeerIdentity congested_peer;
  
  /**
   * Peer identity which will be successor to this value will be finger of
   * source_peer. 
   */
  uint64_t ultimate_destination_finger_identity_value;
  
  /**
   * Index in finger peer map of source peer.
   */
  uint32_t finger_map_index;
  
  /**
   * Total number of peers in the trail.
   */
  uint32_t trail_length;
  
  /**
   * Identifier for the trail source peer is trying to setup. 
   */
  struct GNUNET_HashCode trail_id;
  /**
   * Relative time for which congested_peer will remain congested. 
   */
  struct GNUNET_TIME_Relative congestion_time;
  
  /* Trail_list from source_peer to peer which sent the message for trail setup
   * to congested peer.*/
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
 *  Entry in friend_peermap.
 */
struct FriendInfo
{
  /**
   * Friend Identity 
   */
  struct GNUNET_PeerIdentity id;

  /**
   * Number of trails for which this friend is the first hop. 
   */
  unsigned int trails_count;
  
  /**
   * Count of outstanding messages for this friend.
   */
  unsigned int pending_count;
  
  /**
   * In case not 0, then amount of time for which this friend is congested. 
   */
  struct GNUNET_TIME_Absolute congestion_duration;
  
  /**
   * Head of pending messages to be sent to this friend.
   */
  struct P2PPendingMessage *head;

  /**
   * Tail of pending messages to be sent to this friend.
   */
  struct P2PPendingMessage *tail;
 
  /**
   * Core handle for sending messages to this friend.
   */
  struct GNUNET_CORE_TransmitHandle *th;

};

/**
 * An individual trail to reach to a finger.
 */
struct Trail
{
  /**
    * Pointer to next item in the list
    */
  struct Trail *next;
  
  /**
    * Pointer to prev item in the list
    */
  struct Trail *prev;
  
  /**
   * An element in this trail. 
   */
  struct GNUNET_PeerIdentity peer;
};

/**
 * List of all trails to reach a particular finger.
 */
struct TrailList
{
  /**
   * Head of trail.
   */
  struct Trail *trail_head;
  
  /**
   * Tail of trail.
   */
  struct Trail *trail_tail;
  
  /**
   * Unique identifier of this trail. 
   */
  struct GNUNET_HashCode trail_id;
  
  /**
   * Length of trail pointed 
   */
  unsigned int trail_length;
  
  /**
   * Number of trails that the first friend of this trail is a part of. 
   */
  unsigned int first_friend_trail_count;
};


/**
 * An entry in finger_hashmap. 
 */
struct FingerInfo
{
  /**
   * Finger identity.
   */
  struct GNUNET_PeerIdentity finger_identity;
  
  /**
   * Index in finger peer map
   */
  unsigned int finger_map_index;  
  
  /**
   * Number of trails setup so far for this finger. 
   */
  unsigned int trails_count;
  
  /**
   * Array of trails. 
   */
  struct TrailList trail_list[MAXIMUM_TRAILS_PER_FINGER];
};


/**
 * Task that sends FIND FINGER TRAIL requests. This task is started when we have
 * get our first friend. 
 */
static GNUNET_SCHEDULER_TaskIdentifier find_finger_trail_task;

/**
 * Identity of this peer.
 */
static struct GNUNET_PeerIdentity my_identity;

/**
 * Peer map of all the friends of a peer
 */
static struct GNUNET_CONTAINER_MultiPeerMap *friend_peermap;

/**
 * Hash map of all the fingers of a peer
 */
static struct GNUNET_CONTAINER_MultiHashMap32 *finger_hashmap;

/**
 * Handle to CORE.
 */
static struct GNUNET_CORE_Handle *core_api;

/**
 * The current finger index that we have want to find trail to. We start the 
 * search with value = 0, i.e. successor peer and then go to PREDCESSOR_FINGER_ID
 * and decrement it. For any index 63 <= index < 0, if finger is same as successor,
 * we reset this index to 0.
 */
static unsigned int current_search_finger_index;


/**
 * Called when core is ready to send a message we asked for
 * out to the destination.
 *
 * @param cls the 'struct FriendInfo' of the target friend
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t
core_transmit_notify (void *cls, size_t size, void *buf)
{
  struct FriendInfo *peer = cls;
  char *cbuf = buf;
  struct P2PPendingMessage *pending;
  size_t off;
  size_t msize;
  
  peer->th = NULL;
  while ((NULL != (pending = peer->head)) &&
         (0 == GNUNET_TIME_absolute_get_remaining (pending->timeout).rel_value_us))
  {
    peer->pending_count--;
    GNUNET_CONTAINER_DLL_remove (peer->head, peer->tail, pending);  
    GNUNET_free (pending);
  }
  if (NULL == pending)
  {
    /* no messages pending */
    return 0;
  }
  if (NULL == buf)
  {
    peer->th =
        GNUNET_CORE_notify_transmit_ready (core_api, GNUNET_NO,
                                           GNUNET_CORE_PRIO_BEST_EFFORT,
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
        GNUNET_CORE_notify_transmit_ready (core_api, GNUNET_NO,
                                           GNUNET_CORE_PRIO_BEST_EFFORT,
                                           GNUNET_TIME_absolute_get_remaining
                                           (pending->timeout), &peer->id, msize,
                                           &core_transmit_notify, peer);
    GNUNET_break (NULL != peer->th);
  }
 
  return off;
}


/**
 * FIXME: assertion fails at the end of this function. also in core_api.c at 1299.
 * Transmit all messages in the friend's message queue.
 *
 * @param peer message queue to process
 */
static void
process_friend_queue (struct FriendInfo *peer)
{
  struct P2PPendingMessage *pending;
  
  if (NULL == (pending = peer->head))
    return;
  if (NULL != peer->th)
    return;
  
  GNUNET_STATISTICS_update (GDS_stats,
                            gettext_noop
                            ("# Bytes of bandwidth requested from core"),
                            ntohs (pending->msg->size), GNUNET_NO);
  
  peer->th =
      GNUNET_CORE_notify_transmit_ready (core_api, GNUNET_NO,
                                         pending->importance,
                                         GNUNET_TIME_absolute_get_remaining
                                         (pending->timeout), &peer->id,
                                         ntohs (pending->msg->size),
                                         &core_transmit_notify, peer);
  GNUNET_break (NULL != peer->th);
}


/**
 * Construct a trail setup message and forward it to target_friend
 * @param source_peer Source peer which wants to setup the trail
 * @param ultimate_destination_finger Peer identity closest to this value will 
 *                                    be finger to @a source_peer
 * @param next_destination Peer which should get the packet. I can be same as
 *                         target_friend or different. 
 * @param target_friend Friend to which message is forwarded now. 
 * @param trail_length Total number of peers in trail setup so far.
 * @param trail_peer_list Trail setup so far
 * @param finger_map_index Index in finger map for which we are looking for finger.
 * @param trail_id Unique identifier for the trail we are trying to setup.
 * @param intermediate_trail_id Trail id of any intermediate trail we may have to
 *                              traverse during trail setup. If not used then set to
 *                              0. 
 */
void
GDS_NEIGHBOURS_send_trail_setup (const struct GNUNET_PeerIdentity source_peer,
                                 uint64_t ultimate_destination_finger,
                                 struct GNUNET_PeerIdentity next_destination,
                                 struct FriendInfo *target_friend,
                                 unsigned int trail_length,
                                 const struct GNUNET_PeerIdentity *trail_peer_list,
                                 unsigned int finger_map_index,
                                 struct GNUNET_HashCode new_trail_id, 
                                 struct GNUNET_HashCode intermediate_trail_id)
{
  struct P2PPendingMessage *pending;
  struct PeerTrailSetupMessage *tsm;
  struct GNUNET_PeerIdentity *peer_list;
  size_t msize;
  
  msize = sizeof (struct PeerTrailSetupMessage) + 
          (trail_length * sizeof (struct GNUNET_PeerIdentity));
  
  if (msize >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
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
  pending->timeout = GNUNET_TIME_relative_to_absolute (GET_TIMEOUT);
  tsm = (struct PeerTrailSetupMessage *) &pending[1]; 
  pending->msg = &tsm->header;
  tsm->header.size = htons (msize);
  tsm->header.type = htons (GNUNET_MESSAGE_TYPE_DHT_P2P_TRAIL_SETUP);
  tsm->ultimate_destination_finger = GNUNET_htonll (ultimate_destination_finger);
  tsm->source_peer = source_peer;
  tsm->next_destination = next_destination;
  tsm->trail_length = htonl (trail_length); 
  tsm->finger_map_index = htonl (finger_map_index);
  tsm->new_trail_id = new_trail_id;
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
 * @param destination_peer 
 * @param source_finger
 * @param target_friend
 * @param trail_length
 * @param trail_peer_list
 * @param finger_map_index
 * @param trail_id
 */
void
GDS_NEIGHBOURS_send_trail_setup_result (struct GNUNET_PeerIdentity destination_peer,
                                        struct GNUNET_PeerIdentity source_finger,
                                        struct FriendInfo *target_friend,
                                        unsigned int trail_length,
                                        const struct GNUNET_PeerIdentity *trail_peer_list,
                                        unsigned int finger_map_index,
                                        struct GNUNET_HashCode trail_id)
{
  struct P2PPendingMessage *pending;
  struct PeerTrailSetupResultMessage *tsrm;
  struct GNUNET_PeerIdentity *peer_list;
  size_t msize;
  
  msize = sizeof (struct PeerTrailSetupResultMessage) + 
          (trail_length * sizeof (struct GNUNET_PeerIdentity));
  
  if (msize >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
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
  pending->timeout = GNUNET_TIME_relative_to_absolute (GET_TIMEOUT);
  tsrm = (struct PeerTrailSetupResultMessage *) &pending[1]; 
  pending->msg = &tsrm->header;
  tsrm->header.size = htons (msize);
  tsrm->header.type = htons (GNUNET_MESSAGE_TYPE_DHT_P2P_TRAIL_SETUP_RESULT);
  tsrm->destination_peer = destination_peer;
  tsrm->finger_identity = source_finger;
  tsrm->trail_length = htonl (trail_length);
  tsrm->finger_map_index = htonl (finger_map_index);
  tsrm->trail_id = trail_id;
  
  peer_list = (struct GNUNET_PeerIdentity *) &tsrm[1];
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
 * Send trail rejection message to next_hop
 * @param source_peer Source peer which is trying to setup the trail.
 * @param finger_identity Peer closest to this value will be @a source_peer's finger 
 * @param congested_peer Peer which sent this message as it is congested.
 * @param next_hop Peer to which we are forwarding this message. 
 * @param finger_map_index Index in finger peermap for which we are searching for finger.
 * @param trail_peer_list Trails seen so far in trail setup before getting rejected
 *                        by congested_peer
 * @param trail_length Total number of peers in trail_peer_list
 * @param trail_id Unique identifier of this trail.
 * @param congestion_timeout Duration given by congested peer as an estimate of 
 *                           how long it may remain congested.  
 */
void
GDS_NEIGHBOURS_send_trail_rejection (struct GNUNET_PeerIdentity source_peer,
                                     uint64_t finger_identity,
                                     struct GNUNET_PeerIdentity congested_peer,
                                     unsigned int finger_map_index,
                                     struct GNUNET_PeerIdentity *trail_peer_list,
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
  
  if (msize >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
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
  pending->timeout = GNUNET_TIME_relative_to_absolute (GET_TIMEOUT);
  trm = (struct PeerTrailRejectionMessage *)&pending[1];
  pending->msg = &trm->header;
  trm->header.size = htons (msize);
  trm->header.type = htons (GNUNET_MESSAGE_TYPE_DHT_P2P_TRAIL_REJECTION);
  trm->source_peer = source_peer;
  trm->congested_peer = congested_peer;
  trm->congestion_time = congestion_timeout;
  trm->finger_map_index = htonl (finger_map_index);
  trm->trail_id = trail_id;
  
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
 * @param trail_id Identifier of trail to reach successor. 
 * @param target_friend Message send to this friend. 
 */
void
GDS_NEIGHBOURS_send_verify_successor_message (struct GNUNET_PeerIdentity source_peer,
                                              struct GNUNET_PeerIdentity successor,
                                              const struct GNUNET_HashCode trail_id,
                                              struct FriendInfo *target_friend)
{
  struct PeerVerifySuccessorMessage *vsm;
  struct P2PPendingMessage *pending;
  size_t msize;
  
  msize = sizeof (struct PeerVerifySuccessorMessage);
  if (msize >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
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
  pending->timeout = GNUNET_TIME_relative_to_absolute (GET_TIMEOUT);
  vsm = (struct PeerVerifySuccessorMessage *) &pending[1];
  pending->msg = &vsm->header;
  vsm->header.size = htons (msize);
  vsm->header.type = htons (GNUNET_MESSAGE_TYPE_DHT_P2P_VERIFY_SUCCESSOR);
  vsm->source_peer = source_peer;
  vsm->successor = successor;
  vsm->trail_id = trail_id;
  
  /* Send the message to chosen friend. */
  GNUNET_CONTAINER_DLL_insert_tail (target_friend->head, target_friend->tail, pending);
  target_friend->pending_count++;
  process_friend_queue (target_friend);
}


/**
 * 
 * @param source_peer
 * @param destination_peer
 * @param trail_id
 * @param trail_direction
 * @param target_friend
 */
void
GDS_NEIGHBOURS_send_trail_teardown (struct GNUNET_PeerIdentity source_peer,
                                    struct GNUNET_PeerIdentity destination_peer,
                                    struct GNUNET_HashCode trail_id,
                                    enum GDS_ROUTING_trail_direction trail_direction,
                                    struct FriendInfo *target_friend)
{
  
}


/**
 * 
 * @param destination_peer
 * @param source_successor
 * @param succ_predecessor
 * @param trail_id
 * @param trail
 * @param trail_length
 * @param target_friend
 */
void
GDS_NEIGHBOURS_send_verify_successor_result (struct GNUNET_PeerIdentity destination_peer,
                                             struct GNUNET_PeerIdentity source_successor,
                                             struct GNUNET_PeerIdentity succ_predecessor,
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
  
  if (msize >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
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
  pending->timeout = GNUNET_TIME_relative_to_absolute (GET_TIMEOUT);
  vsmr = (struct PeerVerifySuccessorResultMessage *) &pending[1];
  pending->msg = &vsmr->header;
  vsmr->header.size = htons (msize);
  vsmr->header.type = htons (GNUNET_MESSAGE_TYPE_DHT_P2P_VERIFY_SUCCESSOR_RESULT);
  vsmr->destination_peer = destination_peer;
  vsmr->my_predecessor = succ_predecessor;
  vsmr->source_successor = source_successor;
  vsmr->trail_direction = htonl (trail_direction);
  
  if (trail_length > 0)
  {
    peer_list = (struct GNUNET_PeerIdentity *) &vsmr[1];
    memcpy (peer_list, trail, trail_length * sizeof (struct GNUNET_PeerIdentity));
  }
  
   /* Send the message to chosen friend. */
  GNUNET_CONTAINER_DLL_insert_tail (target_friend->head, target_friend->tail, pending);
  target_friend->pending_count++;
  process_friend_queue (target_friend);
}


/**
 * 
 * @param source_peer
 * @param new_successor
 * @param new_successor_trail
 * @param new_successor_trail_length
 * @param new_succesor_trail_id
 */
void 
GDS_NEIGHBOURS_send_notify_new_successor (struct GNUNET_PeerIdentity source_peer,
                                          struct GNUNET_PeerIdentity new_successor,
                                          struct GNUNET_PeerIdentity *new_successor_trail,
                                          unsigned int new_successor_trail_length,
                                          struct GNUNET_HashCode new_succesor_trail_id,
                                          struct FriendInfo *target_friend)
{
  struct PeerNotifyNewSuccessorMessage *nsm;
  struct P2PPendingMessage *pending;
  struct GNUNET_PeerIdentity *peer_list;
  size_t msize;
  
  msize = sizeof (struct PeerNotifyNewSuccessorMessage) + 
          (new_successor_trail_length * sizeof(struct GNUNET_PeerIdentity));
  
  if (msize >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
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
  pending->timeout = GNUNET_TIME_relative_to_absolute (GET_TIMEOUT);
  nsm = (struct PeerNotifyNewSuccessorMessage *) &pending[1];
  pending->msg = &nsm->header;
  nsm->header.size = htons (msize);
  nsm->header.type = htons (GNUNET_MESSAGE_TYPE_DHT_P2P_NOTIFY_NEW_SUCCESSOR);
  nsm->source_peer = source_peer;
  nsm->destination_peer = new_successor;
  nsm->trail_length = htonl (new_successor_trail_length);
  nsm->trail_id = new_succesor_trail_id;
  if (new_successor_trail_length > 0)
  {
    peer_list = (struct GNUNET_PeerIdentity *) &nsm[1];
    memcpy (peer_list, new_successor_trail, 
            new_successor_trail_length * sizeof (struct GNUNET_PeerIdentity));
  }
  
   /* Send the message to chosen friend. */
  GNUNET_CONTAINER_DLL_insert_tail (target_friend->head, target_friend->tail, pending);
  target_friend->pending_count++;
  process_friend_queue (target_friend);
}


/**
 * Send a trail compression message to target_friend.
 * @param source_peer Source of the trail. 
 * @param destination_finger Destination of trail. 
 * @param trail_id Unique identifier of trail.
 * @param first_friend First hop in compressed trail to reach from source to finger
 * @param target_friend Next friend to get this message. 
 */
void
GDS_NEIGHBOURS_send_trail_compression (struct GNUNET_PeerIdentity source_peer,
                                       struct GNUNET_PeerIdentity destination_peer,
                                       struct GNUNET_HashCode trail_id,
                                       struct GNUNET_PeerIdentity first_friend,
                                       struct FriendInfo *target_friend)
{
  struct P2PPendingMessage *pending;
  struct PeerTrailCompressionMessage *tcm;
  size_t msize;
  
  msize = sizeof (struct PeerTrailCompressionMessage);
  
  if (msize >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
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
  pending->importance = 0;    /* FIXME */
  pending->timeout = GNUNET_TIME_relative_to_absolute (GET_TIMEOUT);
  tcm = (struct PeerTrailCompressionMessage *) &pending[1];
  pending->msg = &tcm->header;
  tcm->header.size = htons (msize);
  tcm->header.type = htons (GNUNET_MESSAGE_TYPE_DHT_P2P_TRAIL_COMPRESSION);
  tcm->source_peer = source_peer;
  tcm->new_first_friend = first_friend;
  tcm->trail_id = trail_id;
  tcm->destination_peer = destination_peer;
  
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
 * @param current_destination Next current destination which will get this message.
 * @param current_source Source for @a current_destination
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
                         struct GNUNET_PeerIdentity current_destination,
                         struct GNUNET_PeerIdentity current_source,
                         struct GNUNET_PeerIdentity *target_peer,
                         uint32_t hop_count,
                         uint32_t put_path_length,
                         struct GNUNET_PeerIdentity *put_path,
                         struct GNUNET_TIME_Absolute expiration_time,
                         const void *data, size_t data_size)
{
  
}

/** 
 * Construct a Get message and send it to target_peer. 
 * @param key Key for the content  
 * @param block_type Type of the block
 * @param options Routing options
 * @param desired_replication_level Desired replication count
 * @param current_destination Next current destination which will get this message.
 * @param current_source Source for @a current_destination
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
                         struct GNUNET_PeerIdentity current_destination,
                         struct GNUNET_PeerIdentity current_source,
                         struct GNUNET_PeerIdentity *target_peer,
                         uint32_t hop_count,
                         uint32_t get_path_length,
                         struct GNUNET_PeerIdentity *get_path)
{
  
}


/**
 * Send the get result to requesting client.
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
                                struct GNUNET_PeerIdentity *target_peer,
                                struct GNUNET_PeerIdentity *source_peer,
                                unsigned int put_path_length,
                                const struct GNUNET_PeerIdentity *put_path,
                                unsigned int get_path_length,
                                struct GNUNET_PeerIdentity *get_path,
                                struct GNUNET_TIME_Absolute expiration,
                                const void *data, size_t data_size)
{
  
}


/**
 * Seach my location in trail. 
 * @param trail List of peers
 * @return my_index if found
 *         #GNUNET_SYSERR if no entry found. 
 */
static int
search_my_index (const struct GNUNET_PeerIdentity *trail,
                 int trail_length)
{
  int i;
  
  for (i = 0; i < trail_length; i++)
  {
    if (0 == GNUNET_CRYPTO_cmp_peer_identity (&my_identity, &trail[i]))
      return i;
  }
  
  return GNUNET_SYSERR;
}


/**
 * Find the successor for destination_finger_value among my_identity, all my
 * friend and all my fingers. Don't consider friends/ fingers with first friend in
 * the trail which are congested or have crossed the threshold. 
 * @param destination_finger_value Peer closest to this value will be the next successor.
 * @param next_destination [out] Updated to friend identity in case a friend is 
 *                               successor, updated to first friend to reach to finger
 *                               in case finger is the destination. 
 * @param new_intermediate_trail_id [out] In case we finger is the @a next_destination,
 *                                then we updated the field with trail id to reach 
 *                                to that finger. 
 * @param finger_map_index Index in finger peermap for which we are looking for a finger. 
 * @return 
 */
static struct GNUNET_PeerIdentity *
find_successor (uint64_t destination_finger_value,
                struct GNUNET_PeerIdentity *next_destination,
                struct GNUNET_HashCode *new_intermediate_trail_id,
                unsigned int finger_map_index)
{
  /* FIXME; IMPLEMENT*/
  return NULL;
}


/**
 * Select closest finger to value.
 * @param peer1 First peer
 * @param peer2 Second peer
 * @param value Value to be compare
 * @return Closest peer
 */
static struct GNUNET_PeerIdentity *
select_closest_finger (struct GNUNET_PeerIdentity *peer1,
                       struct GNUNET_PeerIdentity *peer2,
                       uint64_t value)
{
  uint64_t peer1_value;
  uint64_t peer2_value;
  
  memcpy (&peer1_value, peer1, sizeof (uint64_t));
  memcpy (&peer2_value, peer2, sizeof (uint64_t));
  
  if ((peer1_value <= value) && (value <= peer2_value))
    return peer2;
  else if ((peer2_value <= value) && (value <= peer1_value))
    return peer1;
  else if ((peer1_value <= peer2_value) && (peer2_value <= value))
    return peer1;
  else if ((peer2_value <= peer1_value) && (peer1_value <= value))
    return peer2;
  else if ((value <= peer1_value) && (peer1_value <= peer2_value))
    return peer1;
  else /*if ((value <= peer2_value) && (peer2_value <= peer1_value))*/
    return peer2;
}


/**
 * Select closest predecessor to value.
 * @param peer1 First peer
 * @param peer2 Second peer
 * @param value Value to be compare
 * @return Closest peer
 */
static struct GNUNET_PeerIdentity *
select_closest_predecessor (struct GNUNET_PeerIdentity *peer1,
                            struct GNUNET_PeerIdentity *peer2,
                            uint64_t value)
{
  uint64_t peer1_value;
  uint64_t peer2_value;
  
  memcpy (&peer1_value, peer1, sizeof (uint64_t));
  memcpy (&peer2_value, peer2, sizeof (uint64_t));
  
  if ((peer1_value <= value) && (value <= peer2_value))
    return peer1;
  else if ((peer2_value <= value) && (value <= peer1_value))
    return peer2;
  else if ((peer1_value <= peer2_value) && (peer2_value <= value))
    return peer2;
  else if ((peer2_value <= peer1_value) && (peer1_value <= value))
    return peer1;
  else if ((value <= peer1_value) && (peer1_value <= peer2_value))
    return peer2;
  else /*if ((value <= peer2_value) && (peer2_value <= peer1_value))*/
    return peer1;
}


/**
 * Select the closest peer among two peers (which should not be same)
 * with respect to value and finger_map_index
 * @param peer1 First peer
 * @param peer2 Second peer
 * @param value Value relative to which we find the closest
 * @param finger_map_index Index in finger map. If equal to PREDECESSOR_FINGER_ID,
 *                         then we use different logic than other  
 *                         finger_map_index
 * @return Closest peer among two peers. 
 */
static struct GNUNET_PeerIdentity *
select_closest_peer (struct GNUNET_PeerIdentity *peer1,
                     struct GNUNET_PeerIdentity *peer2,
                     uint64_t value,
                     unsigned int finger_map_index)
{
  struct GNUNET_PeerIdentity *closest_peer;
  
  if (PREDECESSOR_FINGER_ID == finger_map_index)
    closest_peer = select_closest_predecessor (peer1, peer2, value);
  else
    closest_peer = select_closest_finger (peer1, peer2, value);
  
  return closest_peer;
}



/** 
 * Randomly choose one of your friends (which is not congested and have not crossed
 * trail threshold) from the friends_peer map
 * @return Friend Randomly chosen friend. 
 *         NULL in case friend peermap is empty, or all the friends are either
 *              congested or have crossed trail threshold. 
 */
static struct FriendInfo *
select_random_friend ()
{  
  unsigned int current_size;
  uint32_t index; 
  unsigned int j = 0;
  struct GNUNET_CONTAINER_MultiPeerMapIterator *iter;
  struct GNUNET_PeerIdentity key_ret;
  struct FriendInfo *friend;
  
  current_size = GNUNET_CONTAINER_multipeermap_size (friend_peermap);
  if (0 == current_size)
    return NULL;
  
  index = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, current_size);
  iter = GNUNET_CONTAINER_multipeermap_iterator_create (friend_peermap);
 
  for (j = 0; j < index ; j++)
    GNUNET_assert (GNUNET_YES == 
                   GNUNET_CONTAINER_multipeermap_iterator_next (iter, NULL, NULL));
  do
  {
    if (j == current_size)
    {
      j = 0;
      GNUNET_CONTAINER_multipeermap_iterator_destroy (iter);
      iter = GNUNET_CONTAINER_multipeermap_iterator_create (friend_peermap);
      
    }
    GNUNET_assert (GNUNET_YES == 
                GNUNET_CONTAINER_multipeermap_iterator_next (iter,
                                                             &key_ret,
                                                             (const void **)&friend));
  
 
    if ((TRAILS_THROUGH_FRIEND_THRESHOLD > friend->trails_count) &&
        (0 == GNUNET_TIME_absolute_get_remaining (friend->congestion_duration).rel_value_us))
    {
      break;
    }
    friend = NULL;
    j++;
  } while (j != index);
  
  GNUNET_CONTAINER_multipeermap_iterator_destroy (iter);
  return friend;
}


/**
 * Compute finger_identity to which we want to setup the trail
 * @return finger_identity 
 */
static uint64_t 
compute_finger_identity()
{
  uint64_t my_id64;

  memcpy (&my_id64, &my_identity, sizeof (uint64_t));
  my_id64 = GNUNET_ntohll (my_id64);
  return (my_id64 + (unsigned long) pow (2, current_search_finger_index));
}


/**
 * Compute immediate predecessor identity in the network.
 * @return peer identity of immediate predecessor.
 */
static uint64_t 
compute_predecessor_identity()
{
  uint64_t my_id64;

  memcpy (&my_id64, &my_identity, sizeof (uint64_t));
  my_id64 = GNUNET_ntohll (my_id64);
  return (my_id64 -1);
}


/*
 * Choose a random friend and start looking for the trail to reach to 
 * finger identity through this random friend. 
 *
 * @param cls closure for this task
 * @param tc the context under which the task is running
 */
static void
send_find_finger_trail_message (void *cls,
                                const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct FriendInfo *target_friend;
  struct GNUNET_TIME_Relative next_send_time;
  struct GNUNET_HashCode trail_id;
  struct GNUNET_HashCode intermediate_trail_id;
  unsigned int finger_map_index;
  uint64_t finger_identity;
  
  next_send_time.rel_value_us =
      DHT_FIND_FINGER_TRAIL_INTERVAL.rel_value_us +
      GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_WEAK,
                                DHT_FIND_FINGER_TRAIL_INTERVAL.rel_value_us);
  find_finger_trail_task =
      GNUNET_SCHEDULER_add_delayed (next_send_time, &send_find_finger_trail_message,
                                    NULL);
  
  target_friend = select_random_friend (); 
  if (NULL == target_friend) 
  {
    return;
  }
  
  if (PREDECESSOR_FINGER_ID == current_search_finger_index)
  {
    finger_identity = compute_predecessor_identity();  
  }
  else
  {
    finger_identity = compute_finger_identity();
  }
    
  finger_map_index = current_search_finger_index;
  
  /* FIXME: Find the correct function to generate a random trail id which is of
   * type struct GNUNET_HashCode. */
  //trail_id = GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_STRONG, UINT64_MAX);
  
  GDS_NEIGHBOURS_send_trail_setup (my_identity, finger_identity, 
                                   target_friend->id, target_friend, 0, NULL,
                                   finger_map_index, trail_id, intermediate_trail_id);
}


/**
 * In case there are already maximum number of possible trail to reach to a finger,
 * then check if the new trail's length is lesser than any of the existing trails.
 * If yes then replace that old trail by new trail.
 * Note: Here we are taking length as a parameter to choose the best possible trail,
 * but there could be other parameters also like - 1. duration of existence of a
 * trail - older the better. 2. if the new trail is completely disjoint than the 
 * other trails, then may be choosing it is better. 
 * @param existing_finger
 * @param new_finger_trail
 * @param new_finger_trail_length
 * @param new_finger_trail_id
 */
static void
select_and_replace_trail (struct FingerInfo *existing_finger, 
                          struct GNUNET_PeerIdentity *new_trail,
                          unsigned int new_trail_length, 
                          struct GNUNET_HashCode new_trail_id)
{
  struct TrailList *trail_list_iterator;
  unsigned int largest_trail_length;
  unsigned int largest_trail_index;
  struct Trail *trail_element;
  unsigned int i;
  
  largest_trail_length = new_trail_length;
  largest_trail_index = MAXIMUM_TRAILS_PER_FINGER + 1;
  
  GNUNET_assert (MAXIMUM_TRAILS_PER_FINGER == existing_finger->trails_count);
  
  for (i = 0; i < existing_finger->trails_count; i++)
  {
    trail_list_iterator = &existing_finger->trail_list[i];
    if (trail_list_iterator->trail_length > largest_trail_length)
    {
      largest_trail_length = trail_list_iterator->trail_length;
      largest_trail_index = i;
    }
  }
  
  if (largest_trail_index == (MAXIMUM_TRAILS_PER_FINGER + 1))
    return;
  
  /* Send trail teardown message across the replaced trail. */
  struct TrailList *replace_trail = &existing_finger->trail_list[largest_trail_index];
  struct FriendInfo *target_friend = 
  GNUNET_CONTAINER_multipeermap_get (friend_peermap,
                                     &replace_trail->trail_head->peer);
  
  GDS_NEIGHBOURS_send_trail_teardown (my_identity, 
                                      existing_finger->finger_identity, 
                                      replace_trail->trail_id, 
                                      GDS_ROUTING_SRC_TO_DEST, target_friend);
  /* Free the trail .*/
  while (NULL != (trail_element = replace_trail->trail_head))
  {
    GNUNET_CONTAINER_DLL_remove (replace_trail->trail_head,
                                 replace_trail->trail_tail, trail_element);
    GNUNET_free (trail_element);
  }
  
  /* Add new trial at that location. */
  i = 0;
  while ( i < new_trail_length)
  {
    struct Trail *element = GNUNET_new (struct Trail);
    element->next = NULL;
    element->prev = NULL;
    element->peer = new_trail[0];
    
    GNUNET_CONTAINER_DLL_insert_tail (replace_trail->trail_head, 
                                      replace_trail->trail_tail,
                                      element);
  }
}


/**
 * Check if the new trail to reach to finger is unique or do we already have
 * such a trail present for finger. 
 * @param existing_finger Finger identity 
 * @param new_trail New trail to reach @a existing_finger
 * @param trail_length Total number of peers in new_trail.
 * @return #GNUNET_YES if the new trail is unique
 *         #GNUNET_NO if same trail is already present. 
 */
static int
is_new_trail_unique (struct FingerInfo *existing_finger,
                     struct GNUNET_PeerIdentity *new_trail,
                     unsigned int trail_length)
{
  struct TrailList *trail_list_iterator;
  struct Trail *trail_element;
  int i;
  int j;
  int trail_unique = GNUNET_NO;
  
  for (i = 0; i < existing_finger->trails_count; i++)
  {
    trail_list_iterator = &existing_finger->trail_list[i];
    trail_element = trail_list_iterator->trail_head;
    for (j = 0; j < trail_list_iterator->trail_length; j++)
    {
      if (0 != GNUNET_CRYPTO_cmp_peer_identity (&new_trail[j],
                                                 &trail_element->peer))
      {
        trail_unique = GNUNET_YES;
        break;
      }
    }
  }
  return trail_unique;
}


/**
 * Add a new trail to existing finger. 
 * @param existing_finger
 * @param new_finger_trail
 * @param new_finger_trail_length
 * @param new_finger_trail_id
 */
static void
add_new_trail (struct FingerInfo *existing_finger, 
               struct GNUNET_PeerIdentity *new_trail,
               unsigned int new_trail_length, 
               struct GNUNET_HashCode new_trail_id)
{
  struct TrailList *trail_list_iterator;
  struct FriendInfo *first_friend;
  int i = 0;
  int j;
  
  if (GNUNET_NO == is_new_trail_unique (existing_finger,
                                         new_trail,
                                         new_trail_length))
    return;
  
  do
  {
    trail_list_iterator = &existing_finger->trail_list[i];
    i++;
  } while (trail_list_iterator->trail_head != NULL);
  
  if (new_trail_length > 0)
    first_friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, 
                                                      &new_trail[0]);
  else
    first_friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap,
                                                      &(existing_finger->finger_identity));
  first_friend->trails_count++;
  trail_list_iterator->first_friend_trail_count = first_friend->trails_count;
  trail_list_iterator->trail_length = new_trail_length;
  
  for (j = 0; j < new_trail_length; j++)
  {
    struct Trail *element;
    element = GNUNET_new (struct Trail);
    
    element->next = NULL;
    element->prev = NULL;
    element->peer = new_trail[j];
    GNUNET_CONTAINER_DLL_insert_tail (trail_list_iterator->trail_head, 
                                      trail_list_iterator->trail_tail,
                                      element);
  }
  existing_finger->trails_count++;
}


/**
 * Send trail teardown message on all trails associated with finger. 
 * @param finger_to_be_removed
 */
static void
send_trail_teardown (struct FingerInfo *finger)
{
  struct TrailList *trail_list_iterator;
  struct GNUNET_HashCode trail_id;
  struct FriendInfo *target_friend;
  int i;
  
  if (0 == GNUNET_CRYPTO_cmp_peer_identity (&finger->finger_identity, &my_identity)
     || (NULL != GNUNET_CONTAINER_multipeermap_get (friend_peermap, 
                                                    &finger->finger_identity)))
    return;
  
  for (i = 0; i < finger->trails_count; i++)
  {
    trail_list_iterator = &finger->trail_list[i];
    if (trail_list_iterator->trail_length > 0)
    {
      trail_id = trail_list_iterator->trail_id;
      target_friend = 
              GNUNET_CONTAINER_multipeermap_get (friend_peermap,
                                                 &trail_list_iterator->trail_head->peer);
    GDS_NEIGHBOURS_send_trail_teardown (my_identity, finger->finger_identity,
                                        trail_id, GDS_ROUTING_SRC_TO_DEST,
                                        target_friend);
    }
  }
}


/**
 * Decrement the trail count of the first friend to reach the finger
 * In case finger is the friend, then decrement its trail count.
 * @param finger
 */
static void
decrement_friend_trail_count (struct FingerInfo *finger)
{
  struct TrailList *trail_list_iterator;
  struct FriendInfo *target_friend;
  int i = 0;
  
  if (0 == GNUNET_CRYPTO_cmp_peer_identity (&finger->finger_identity,
                                            &my_identity))
    return;
  
  for (i = 0; i < finger->trails_count; i++)
  {
    trail_list_iterator = &finger->trail_list[i];
    if (trail_list_iterator->trail_length > 0)
      target_friend = 
              GNUNET_CONTAINER_multipeermap_get (friend_peermap, 
                                                 &trail_list_iterator->trail_head->peer);
    else
     target_friend = 
              GNUNET_CONTAINER_multipeermap_get (friend_peermap, 
                                                 &finger->finger_identity);
    
    target_friend->trails_count--;
    trail_list_iterator->first_friend_trail_count--;
  }
  return;
}


/**
 * Free finger and its trail.  
 * @param finger Finger to be freed.
 */
static void
free_finger (struct FingerInfo *finger)
{
  struct TrailList *trail_list_iterator;
  struct Trail *trail_element;
  unsigned int i;
  
  for (i = 0; i < finger->trails_count; i++)
  {
    trail_list_iterator = &finger->trail_list[i];
    while (NULL != (trail_element = trail_list_iterator->trail_head))
    {
      GNUNET_CONTAINER_DLL_remove (trail_list_iterator->trail_head,
                                   trail_list_iterator->trail_tail, trail_element);
      GNUNET_free (trail_element);
    }
  }
  GNUNET_free (finger);
}


/**
 * Check if new finger is closer than existing_finger. If both new finger and 
 * existing finger are same then we may add a new trail (if there is space)
 * or choose the best trail among existing trails and new trails.
 * @param existing_finger Finger present in finger_peermap at @a finger_map_index
 * @param new_finger_identity Peer identity of new finger.
 * @param new_finger_trail Trail to reach from source to new_finger. 
 * @param new_finger_trail_length Total number of peers in @a new_finger_trail.
 * @param trail_id Unique identifier of trail. 
 * @param finger_map_index Index in finger map. 
 * @return #GNUNET_YES if the new finger is closest.
 *         #GNUNET_NO either new_finger and existing_finger are same, or 
 *                    existing_finger is closest.
 */
static int
is_new_finger_closest (struct FingerInfo *existing_finger, 
                       struct GNUNET_PeerIdentity new_finger_identity,
                       struct GNUNET_PeerIdentity *new_finger_trail,
                       unsigned int new_finger_trail_length,
                       struct GNUNET_HashCode new_finger_trail_id,
                       unsigned int finger_map_index)
{
  struct GNUNET_PeerIdentity *closest_peer;
  uint64_t my_id64;
  
  if (NULL == existing_finger)
    return GNUNET_YES;
  
  if (0 != GNUNET_CRYPTO_cmp_peer_identity (&(existing_finger->finger_identity),
                                            &new_finger_identity))
  {
    memcpy (&my_id64, &my_identity, sizeof (uint64_t));
    closest_peer = select_closest_peer (&existing_finger->finger_identity,
                                        &new_finger_identity,
                                        my_id64, finger_map_index);
  
    if (0 == GNUNET_CRYPTO_cmp_peer_identity (&new_finger_identity, closest_peer))
    {
      if (0 == GNUNET_CRYPTO_cmp_peer_identity (&my_identity, 
                                                &new_finger_identity)) /* FIXME: not sure what to do here? */
        return GNUNET_NO;
    
      send_trail_teardown (existing_finger);
      decrement_friend_trail_count (existing_finger);
      free_finger (existing_finger);
      return GNUNET_YES;
    }
  }
  else
  {
    if (0 != GNUNET_CRYPTO_cmp_peer_identity (&(existing_finger->finger_identity), 
                                              &my_identity))
    {
      if (NULL == 
          GNUNET_CONTAINER_multipeermap_get (friend_peermap,
                                             &(existing_finger->finger_identity)))
      {
        if (existing_finger->trails_count < MAXIMUM_TRAILS_PER_FINGER)
          add_new_trail (existing_finger, new_finger_trail,
                         new_finger_trail_length, new_finger_trail_id);
        else
          select_and_replace_trail (existing_finger, new_finger_trail,
                                    new_finger_trail_length, new_finger_trail_id); 
      }
    }
  } 
  return GNUNET_NO;
}


/**
 * Add a new entry in finger hashmap at finger_map_index
 * @param finger_identity Peer Identity of new finger
 * @param finger_trail Trail to reach from me to finger (excluding both end points).
 * @param finger_trail_length Total number of peers in @a finger_trail.
 * @param trail_id Unique identifier of the trail. 
 * @param finger_map_index Index in finger hashmap. 
 * @return #GNUNET_OK if new entry is added
 *         #GNUNET_NO -- FIXME: need to check what value does hahsmap put
 *                       returns on failure. 
 */
static int
add_new_entry (struct GNUNET_PeerIdentity finger_identity,
               struct GNUNET_PeerIdentity *finger_trail,
               unsigned int finger_trail_length,
               struct GNUNET_HashCode trail_id,
               unsigned int finger_map_index)
{
  struct FingerInfo *new_entry;
  struct FriendInfo *first_trail_hop;
  struct TrailList *first_trail;
  int i = 0;
  
  new_entry = GNUNET_new (struct FingerInfo);
  new_entry->finger_identity = finger_identity;
  new_entry->finger_map_index = finger_map_index;
  new_entry->trails_count = 1;
  
  if (0 != GNUNET_CRYPTO_cmp_peer_identity (&my_identity, &finger_identity))
  {
    if (finger_trail_length > 0)
    {
      first_trail_hop = GNUNET_CONTAINER_multipeermap_get (friend_peermap,
                                                           &finger_trail[0]);
    }
    else
    {
      first_trail_hop = GNUNET_CONTAINER_multipeermap_get (friend_peermap,
                                                           &finger_identity);
    }
    
    first_trail_hop->trails_count++;
    first_trail = &new_entry->trail_list[0];
    first_trail->first_friend_trail_count = first_trail_hop->trails_count;
    
    while (i < finger_trail_length)
    {
      struct Trail *element = GNUNET_new (struct Trail);
      
      element->next = NULL;
      element->prev = NULL;
      element->peer = finger_trail[i];
      GNUNET_CONTAINER_DLL_insert_tail (first_trail->trail_head, 
                                        first_trail->trail_tail,
                                        element);
      i++;
    }
  }
 
  return GNUNET_CONTAINER_multihashmap32_put (finger_hashmap, 
                                              new_entry->finger_map_index,
                                              new_entry,
                                              GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);   
}


/**
 * Scan the trail to check if there is any other friend in the trail other than
 * first hop. If yes the shortcut the trail, send trail compression message to
 * peers which are no longer part of trail and send back the updated trail
 * and trail_length to calling function. 
 * @param finger_identity Finger whose trail we will scan. 
 * @param finger_trail [in, out] Trail to reach from source to finger,              
 * @param finger_trail_length  Total number of peers in original finger_trail.
 * @param finger_trail_id Unique identifier of the finger trail.
 * @return updated trail length in case we shortcut the trail, else original
 *         trail length.  
 */
static int
scan_and_compress_trail (struct GNUNET_PeerIdentity finger_identity,
                         struct GNUNET_PeerIdentity *trail,
                         unsigned int trail_length,
                         struct GNUNET_HashCode trail_id)
{
  struct FriendInfo *target_friend;
  int i;
  
  if (0 == GNUNET_CRYPTO_cmp_peer_identity (&my_identity, &finger_identity))
  {
    trail = NULL;
    return 0;
  }
  
  if (GNUNET_CONTAINER_multipeermap_get (friend_peermap, &finger_identity))
  {
    target_friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, 
                                                       &trail[0]);
    GDS_NEIGHBOURS_send_trail_compression (my_identity, finger_identity, 
                                           trail_id, finger_identity, 
                                           target_friend);
    trail = NULL;
    return 0;
  }
  
  for ( i = trail_length - 1; i > 0; i--)
  {
    if (NULL != GNUNET_CONTAINER_multipeermap_get (friend_peermap, &trail[i]))
    {
      struct FriendInfo *target_friend;
      int j = 0;

      target_friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, 
                                                         &trail[0]);
      GDS_NEIGHBOURS_send_trail_compression (my_identity, finger_identity, 
                                             trail_id, trail[i], 
                                             target_friend);
     
      /* Copy the trail from index i to index trail_length -1 and change
       trail length and return */
      while (i < trail_length)
      {
        memcpy (&trail[j], &trail[i], sizeof(struct GNUNET_PeerIdentity));
        j++;
        i++;
      }
      trail_length = j+1;
      break;
    }
  }
  return trail_length;
}


/**
 * Send verify successor message to your successor on all trails to reach successor.
 * @param successor My current successor 
 */
static void
send_verify_successor_message (struct FingerInfo *successor)
{
  struct TrailList *trail_list_iterator;
  struct GNUNET_HashCode trail_id;
  struct GNUNET_PeerIdentity next_hop;
  struct FriendInfo *target_friend;
  int i;
  
  for (i = 0; i < successor->trails_count; i++)
  {
    trail_list_iterator = &successor->trail_list[i];
    if (trail_list_iterator->trail_length > 0)
      next_hop = trail_list_iterator->trail_head->peer;
    else
      next_hop = successor->finger_identity;
    
    trail_id = trail_list_iterator->trail_id;
    target_friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, &next_hop);
    GDS_NEIGHBOURS_send_verify_successor_message (my_identity,
                                                  successor->finger_identity,
                                                  trail_id, target_friend);
  }
}


/**
 * Check if there is already an entry in finger peermap for given finger map index.
 * If yes, then select the closest finger. If new and existing finger are same,
 * the check if you can store more trails. If yes then add trail, else keep the best
 * trails to reach to the finger. If the new finger is closest, add it.
 * Then, update current_search_finger_index.
 * @param new_finger_identity Peer Identity of new finger
 * @param new_finger_trail Trail to reach the new finger
 * @param new_finger_length Total number of peers in @a new_finger_trail.
 * @param finger_map_index Index in finger peermap.
 * @param new_finger_trail_id Unique identifier of @new_finger_trail.
 * @return #GNUNET_YES if the new entry is added
 *         #GNUNET_NO if new entry is not added, either it was discarded or
 *                    it was same as existing finger at finger map index.
 */
static int
finger_table_add (struct GNUNET_PeerIdentity new_finger_identity,
                  struct GNUNET_PeerIdentity *new_finger_trail,
                  unsigned int new_finger_trail_length,
                  unsigned int finger_map_index,
                  struct GNUNET_HashCode new_finger_trail_id)
{
  struct FingerInfo *existing_finger;
  struct FingerInfo *successor;
  unsigned int new_entry_added = GNUNET_NO;
  
  int new_finger_updated_trail_length = 
       scan_and_compress_trail (new_finger_identity, new_finger_trail, 
                                new_finger_trail_length, new_finger_trail_id);
 
  successor = GNUNET_CONTAINER_multihashmap32_get (finger_hashmap, 
                                                   finger_map_index);
  existing_finger = GNUNET_CONTAINER_multihashmap32_get (finger_hashmap,
                                                         finger_map_index);
  
  if  (GNUNET_YES == is_new_finger_closest (existing_finger,
                                            new_finger_identity,
                                            new_finger_trail, 
                                            new_finger_updated_trail_length,
                                            new_finger_trail_id, finger_map_index))
  {
    GNUNET_assert (GNUNET_YES == add_new_entry (new_finger_identity, 
                                                new_finger_trail, 
                                                new_finger_updated_trail_length, 
                                                new_finger_trail_id, 
                                                finger_map_index));
    new_entry_added = GNUNET_YES;
  }
  
  if (0 == finger_map_index)
  {   
    current_search_finger_index = PREDECESSOR_FINGER_ID;
 
    if (0 != GNUNET_CRYPTO_cmp_peer_identity (&my_identity,&new_finger_identity))
    {
      send_verify_successor_message (successor);
    }
  }
  else if (0 == GNUNET_CRYPTO_cmp_peer_identity (&new_finger_identity, 
                                                 &(successor->finger_identity)))
  {
    current_search_finger_index = 0;
  }
  else 
    current_search_finger_index = current_search_finger_index - 1;
  
  return new_entry_added;
}


/**
 * Core handler for P2P put messages. 
 * @param cls closure
 * @param peer sender of the request
 * @param message message
 * @return #GNUNET_OK to keep the connection open,
 *         #GNUNET_SYSERR to close it (signal serious error)
 */
static int 
handle_dht_p2p_put (void *cls, const struct GNUNET_PeerIdentity *peer,
                    const struct GNUNET_MessageHeader *message)
{
  return GNUNET_OK;
}


/**
 * Core handler for p2p get requests.
 *
 * @param cls closure
 * @param peer sender of the request
 * @param message message
 * @return #GNUNET_OK to keep the connection open,
 *         #GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_dht_p2p_get (void *cls, const struct GNUNET_PeerIdentity *peer,
                    const struct GNUNET_MessageHeader *message)
{
  return GNUNET_OK;
}


/**
 * Core handler for get result
 * @param cls closure
 * @param peer sender of the request
 * @param message message
 * @return #GNUNET_OK to keep the connection open,
 *         #GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_dht_p2p_get_result (void *cls, const struct GNUNET_PeerIdentity *peer,
                           const struct GNUNET_MessageHeader *message)
{
  return GNUNET_OK;
}


/* Core handle for PeerTrailSetupMessage. 
 * @param cls closure
 * @param message message
 * @param peer peer identity this notification is about
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static int
handle_dht_p2p_trail_setup (void *cls, const struct GNUNET_PeerIdentity *peer,
                            const struct GNUNET_MessageHeader *message)
{
  struct PeerTrailSetupMessage *trail_setup; 
  struct GNUNET_PeerIdentity *trail_peer_list;
  struct GNUNET_PeerIdentity next_destination;
  struct GNUNET_PeerIdentity *current_destination;
  struct GNUNET_PeerIdentity *next_hop;
  struct GNUNET_PeerIdentity next_peer;
  struct FriendInfo *target_friend;
  struct GNUNET_PeerIdentity source;
  uint64_t ultimate_destination_finger_value;
  struct GNUNET_HashCode new_intermediate_trail_id;
  struct GNUNET_HashCode intermediate_trail_id;
  struct GNUNET_HashCode new_trail_id;
  unsigned int finger_map_index;
  uint32_t trail_length;
  size_t msize;

  msize = ntohs (message->size);
  if (msize != sizeof (struct PeerTrailSetupMessage))
  {
    GNUNET_break_op (0);
    return GNUNET_YES;
  }
  
  trail_setup = (struct PeerTrailSetupMessage *) message;
  trail_length = ntohl (trail_setup->trail_length); 
  if ((msize != sizeof (struct PeerTrailSetupMessage) +
       trail_length * sizeof (struct GNUNET_PeerIdentity)) ||
       (trail_length >
        GNUNET_SERVER_MAX_MESSAGE_SIZE / sizeof (struct GNUNET_PeerIdentity)))
  {
    GNUNET_break_op (0);
    return GNUNET_OK; 
  }
  
  trail_peer_list = (struct GNUNET_PeerIdentity *)&trail_setup[1];
  current_destination = &trail_setup->next_destination;
  intermediate_trail_id = trail_setup->intermediate_trail_id;
  new_trail_id = trail_setup->new_trail_id;
  ultimate_destination_finger_value = GNUNET_ntohll (trail_setup->ultimate_destination_finger);
  source = trail_setup->source_peer;
  finger_map_index = ntohl (trail_setup->finger_map_index);
  
  if (GNUNET_YES == GDS_ROUTING_threshold_reached())
  {
    target_friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, peer);
    GDS_NEIGHBOURS_send_trail_rejection (source, ultimate_destination_finger_value,
                                         my_identity, finger_map_index,
                                         trail_peer_list, trail_length,
                                         new_trail_id, target_friend, 
                                         CONGESTION_TIMEOUT);
    return GNUNET_OK;
  }
  
  next_hop = find_successor (ultimate_destination_finger_value, &next_destination,
                             &new_intermediate_trail_id, finger_map_index);
  
  if (0 != (GNUNET_CRYPTO_cmp_peer_identity(&my_identity, current_destination)))
  {
    struct GNUNET_PeerIdentity *closest_peer;
    struct GNUNET_PeerIdentity *peer1 = 
    GDS_ROUTING_get_next_hop (intermediate_trail_id, GDS_ROUTING_SRC_TO_DEST);
    if (0 != GNUNET_CRYPTO_cmp_peer_identity (peer1, next_hop))
    {
       closest_peer = select_closest_peer (peer1, next_hop, 
                                           ultimate_destination_finger_value,
                                           finger_map_index);
    }
    if (0 == GNUNET_CRYPTO_cmp_peer_identity (peer1, closest_peer) ||
        (0 == GNUNET_CRYPTO_cmp_peer_identity (peer1, next_hop)))
    {
      next_hop = peer1;
      next_destination = *current_destination;
      new_intermediate_trail_id = intermediate_trail_id;
    }
  }
  
  GNUNET_assert (NULL != next_hop);
  if (0 == (GNUNET_CRYPTO_cmp_peer_identity (next_hop, &my_identity)))/* This means I am the final destination */
  {
    if (0 == trail_length)
      memcpy (&next_peer, &source, sizeof (struct GNUNET_PeerIdentity));
    else
      memcpy (&next_peer, &trail_peer_list[trail_length-1], sizeof (struct GNUNET_PeerIdentity));
    
    target_friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, &next_peer);
    GDS_NEIGHBOURS_send_trail_setup_result (source,
                                            my_identity,
                                            target_friend, trail_length,
                                            trail_peer_list,
                                            finger_map_index, new_trail_id);
  }
  else
  {
    struct GNUNET_PeerIdentity peer_list[trail_length + 1];
    
    memcpy (peer_list, trail_peer_list, trail_length * sizeof (struct GNUNET_PeerIdentity));
    peer_list[trail_length] = my_identity;
    target_friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, next_hop);
    GDS_NEIGHBOURS_send_trail_setup (source,
                                     ultimate_destination_finger_value,
                                     next_destination, 
                                     target_friend, trail_length + 1, peer_list, 
                                     finger_map_index, new_trail_id,
                                     new_intermediate_trail_id);
  }
  return GNUNET_OK;
}


/**
 * Core handle for p2p trail construction result messages.
 * @param closure
 * @param message message
 * @param peer peer identity this notification is about
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static int
handle_dht_p2p_trail_setup_result(void *cls, const struct GNUNET_PeerIdentity *peer,
                                  const struct GNUNET_MessageHeader *message)
{
  struct PeerTrailSetupResultMessage *trail_result;
  struct GNUNET_PeerIdentity *trail_peer_list;
  struct GNUNET_PeerIdentity destination_peer;
  struct GNUNET_PeerIdentity finger_identity;    
  uint32_t trail_length;
  uint32_t finger_map_index;
  struct GNUNET_HashCode trail_id;
  size_t msize;
  
  msize = ntohs (message->size);
  if (msize != sizeof (struct PeerTrailSetupResultMessage))
  {
    GNUNET_break_op (0);
    return GNUNET_YES;
  }
  
  trail_result = (struct PeerTrailSetupResultMessage *) message; 
  trail_length = ntohl (trail_result->trail_length); 
  
  if ((msize !=
       sizeof (struct PeerTrailSetupResultMessage) +
       trail_length * sizeof (struct GNUNET_PeerIdentity)) ||
       (trail_length >
        GNUNET_SERVER_MAX_MESSAGE_SIZE / sizeof (struct GNUNET_PeerIdentity)))
  {
    GNUNET_break_op (0);
    return GNUNET_YES;
  }
  
  finger_map_index = htonl (trail_result->finger_map_index);
  destination_peer = trail_result->destination_peer;
  finger_identity = trail_result->finger_identity;
  trail_id = trail_result->trail_id;
  trail_peer_list = (struct GNUNET_PeerIdentity *) &trail_result[1];
  
  if (0 == (GNUNET_CRYPTO_cmp_peer_identity (&destination_peer,
                                             &my_identity)))
  {
    finger_table_add (finger_identity, trail_peer_list, 
                      trail_length, 
                      finger_map_index, trail_id);
    return GNUNET_YES;
  }
  
  struct GNUNET_PeerIdentity next_hop;
  struct FriendInfo *target_friend;
  int my_index;

  my_index = search_my_index(trail_peer_list, trail_length);
  if (my_index == GNUNET_SYSERR) 
  {
    GNUNET_break_op(0);
    return GNUNET_SYSERR;
  }
  
  if (my_index == 0)
    next_hop = trail_result->destination_peer;
  else
    next_hop = trail_peer_list[my_index - 1];
  
  if (0 != (GNUNET_CRYPTO_cmp_peer_identity (&(trail_result->destination_peer),
                                               &(trail_result->finger_identity))))
  {
    GDS_ROUTING_add (trail_id, &next_hop, peer);
  }
  
  target_friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, &next_hop);
  GDS_NEIGHBOURS_send_trail_setup_result (destination_peer, finger_identity,
                                          target_friend, trail_length, trail_peer_list,
                                          finger_map_index, trail_id);
  return GNUNET_OK;
}


/**
 * Core handle for p2p verify successor messages.
 * @param cls closure
 * @param message message
 * @param peer peer identity this notification is about
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static int
handle_dht_p2p_verify_successor(void *cls, const struct GNUNET_PeerIdentity *peer,
                                const struct GNUNET_MessageHeader *message)
{
  struct PeerVerifySuccessorMessage *vsm; 
  struct GNUNET_PeerIdentity successor;
  struct GNUNET_PeerIdentity source_peer;
  struct GNUNET_PeerIdentity *next_hop;
  struct FriendInfo *target_friend;
  //struct FingerInfo *my_predecessor;
  //struct GNUNET_PeerIdentity *my_predecessor_trail;
  //unsigned int my_predecessor_trail_length;
  struct GNUNET_HashCode trail_id;
  size_t msize;
  
  msize = ntohs (message->size);
  if (msize != sizeof (struct PeerVerifySuccessorMessage))
  {
    GNUNET_break_op (0);
    return GNUNET_YES;
  }
  
  vsm = (struct PeerVerifySuccessorMessage *) message;
  source_peer = vsm->source_peer;
  successor = vsm->successor;
  trail_id = vsm->trail_id;
  
  if(0 != (GNUNET_CRYPTO_cmp_peer_identity (&successor, &my_identity)))
  {
    GNUNET_assert (NULL != (next_hop = 
                            GDS_ROUTING_get_next_hop (trail_id, 
                                                      GDS_ROUTING_SRC_TO_DEST)));
    target_friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, next_hop);
    GDS_NEIGHBOURS_send_verify_successor_message (source_peer, successor, 
                                                  trail_id, target_friend);
    return GNUNET_OK;
  }
#if 0
  my_predecessor = GNUNET_CONTAINER_multihashmap32_get (finger_hashmap, 
                                                        PREDECESSOR_FINGER_ID);
  if (NULL == my_predecessor) /* FIXME: not sure how to handle this case */
    return GNUNET_OK;
  
  if (0 == (GNUNET_CRYPTO_cmp_peer_identity (&source_peer,
                                             &(my_predecessor->finger_identity))))
  {
    my_predecessor_trail = NULL;
    my_predecessor_trail_length = 0;
  }
  else
  {
    /* FIXME: copy from my_predecessor trail. now we may have multiple routes
     choose the one with shortest length and send that one. */
  }
  
  /* Here you are sending the result back along the trail through which the source
   peer send the message to you. now you have to specify the direction such
   that the trail id is used but now prev_hop is next_hop. */

  GDS_NEIGHBOURS_send_verify_successor_result (source_peer, my_identity,
                                               my_predecessor->finger_identity,
                                               trail_id,
                                               my_predecessor_trail,
                                               my_predecessor_trail_length,
                                               GDS_ROUTING_DEST_TO_SRC,
                                               target_friend);
#endif
  return GNUNET_OK;
}


/**
 * Core handle for p2p verify successor result messages.
 * @param cls closure
 * @param message message
 * @param peer peer identity this notification is about
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static int
handle_dht_p2p_verify_successor_result(void *cls, const struct GNUNET_PeerIdentity *peer,
                                       const struct GNUNET_MessageHeader *message)
{
  struct PeerVerifySuccessorResultMessage *vsrm;
  enum GDS_ROUTING_trail_direction trail_direction;
  struct GNUNET_HashCode trail_id;
  unsigned int successor_current_predecessor_trail_length;
  struct GNUNET_PeerIdentity *successor_current_predecessor_trail;
  struct GNUNET_PeerIdentity destination_peer;
  struct GNUNET_PeerIdentity my_new_successor;
  struct GNUNET_PeerIdentity *next_hop;
  struct FriendInfo *target_friend;
  size_t msize;
  
  msize = ntohs (message->size);
  if (msize != sizeof (struct PeerVerifySuccessorResultMessage))
  {
    GNUNET_break_op (0);
    return GNUNET_YES;
  }
  vsrm = (struct PeerVerifySuccessorResultMessage *) message;
  successor_current_predecessor_trail_length = ntohl (vsrm->trail_length);
  trail_direction = ntohl (vsrm->trail_direction);
  trail_id = vsrm->trail_id;
  
  if ((msize !=
       sizeof (struct PeerVerifySuccessorResultMessage) +
       successor_current_predecessor_trail_length * 
       sizeof (struct GNUNET_PeerIdentity)) ||
       (successor_current_predecessor_trail_length >
       GNUNET_SERVER_MAX_MESSAGE_SIZE / sizeof (struct GNUNET_PeerIdentity)))
  {
    GNUNET_break_op (0);
    return GNUNET_YES;
  }
  
  successor_current_predecessor_trail = (struct GNUNET_PeerIdentity *) &vsrm[1];
  destination_peer = vsrm->destination_peer;
  my_new_successor = vsrm->my_predecessor;
  
  if(0 == (GNUNET_CRYPTO_cmp_peer_identity (&destination_peer, &my_identity)))
  {
    
  }
  
  next_hop = GDS_ROUTING_get_next_hop (trail_id, trail_direction);
  target_friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, next_hop); 
  GDS_NEIGHBOURS_send_verify_successor_result (destination_peer, 
                                               vsrm->source_successor,
                                               my_new_successor, trail_id,
                                               successor_current_predecessor_trail,
                                               successor_current_predecessor_trail_length,
                                               trail_direction, target_friend);
  return GNUNET_OK;
}


#if 0
/**
 * Adapt it to use trail list array. 
 * Core handle for p2p verify successor result messages.
 * @param cls closure
 * @param message message
 * @param peer peer identity this notification is about
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static int
handle_dht_p2p_verify_successor_result(void *cls, const struct GNUNET_PeerIdentity *peer,
                                       const struct GNUNET_MessageHeader *message)
{

  const struct PeerVerifySuccessorResultMessage *vsrm;
  unsigned int trail_length;
  struct GNUNET_HashCode trail_id;
  struct GNUNET_PeerIdentity *trail;
  struct FriendInfo *target_friend;
  struct GNUNET_PeerIdentity *next_hop;
  struct GNUNET_PeerIdentity destination_peer;
  struct GNUNET_PeerIdentity my_new_successor;
  struct FingerInfo *current_successor;
  struct GNUNET_HashCode old_successor_trail_id;
  size_t msize;
  
  msize = ntohs (message->size);
  if (msize < sizeof (struct PeerVerifySuccessorResultMessage))
  {
    GNUNET_break_op (0);
    return GNUNET_YES;
  }
  vsrm = (const struct PeerVerifySuccessorResultMessage *) message;
  trail_length = ntohl (vsrm->trail_length); 
  trail_id = vsrm->trail_id;
  
  if ((msize <
       sizeof (struct PeerVerifySuccessorResultMessage) +
       trail_length * sizeof (struct GNUNET_PeerIdentity)) ||
       (trail_length >
       GNUNET_SERVER_MAX_MESSAGE_SIZE / sizeof (struct GNUNET_PeerIdentity)))
  {
    GNUNET_break_op (0);
    return GNUNET_YES;
  }
  
  trail = (struct GNUNET_PeerIdentity *) &vsrm[1];
  destination_peer = vsrm->destination_peer;
  my_new_successor = vsrm->my_predecessor;
  
  if(0 == (GNUNET_CRYPTO_cmp_peer_identity (&destination_peer, &my_identity)))
  {
    unsigned int *new_trail_length;
    struct GNUNET_PeerIdentity *new_trail;
    struct GNUNET_HashCode new_finger_trail_id;
    
    /* FIXME: generate a new_finger_trail_id */
    current_successor = GNUNET_CONTAINER_multihashmap32_get (finger_hashmap, 0);
    old_successor_trail_id = current_successor->head->trail_id;
    target_friend = 
            GNUNET_CONTAINER_multipeermap_get (friend_peermap,
                                               &(current_successor->head->head->peer));
    
    if (0 != GNUNET_CRYPTO_cmp_peer_identity (&my_new_successor,
                                              &current_successor->finger_identity))
    {
      *new_trail_length = 0;
      new_trail = update_trail_to_new_predecessor (current_successor, 
                                                   trail_length, trail,
                                                   new_trail_length);
     
      if (GNUNET_OK == finger_table_add (&my_new_successor, new_trail,
                                         new_trail_length , 0, new_finger_trail_id))
      {
        /*FIXME:
         *Here you should send a trail teardown message for old trail id
         and trail add for new trail. */
      }  
      GDS_NEIGHBOURS_send_notify_new_successor (my_identity, my_new_successor,
                                                new_trail, new_trail_length,
                                                new_finger_trail_id, target_friend);
    }
  }
  
  next_hop = GDS_ROUTING_get_next_hop (trail_id);
  target_friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, next_hop); 
  GDS_NEIGHBOURS_send_verify_successor_result (vsrm->destination_peer,
                                               vsrm->source_successor,
                                               vsrm->my_predecessor,
                                               vsrm->trail_id, trail,

  return GNUNET_OK;
} 
                                               trail_length, target_friend);
#endif

                                               
/**
 * Core handle for p2p notify new successor messages.
 * @param cls closure
 * @param message message
 * @param peer peer identity this notification is about
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static int
handle_dht_p2p_notify_new_successor(void *cls, const struct GNUNET_PeerIdentity *peer,
                                    const struct GNUNET_MessageHeader *message)
{
  /* Here we need to pass the whole trail to reach to new successor as we
   don't have that stored in our routing table. while passing through each
   peer we will have to add an entry. also when you are the destination and
   if you have added it back as pred, then you also need to add the trail in 
   your own finger table and send add trail message to add this trail. you 
   shoudl generate a new trail id. although they are same trails but you have
   to ahve different trail id. */
  return GNUNET_OK;
}


/**
 * FIXME: Here you should keep the trail id with you.
 * Core handler for P2P trail rejection message 
 * @param cls closure
 * @param message message
 * @param peer peer identity this notification is about
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static int 
handle_dht_p2p_trail_rejection(void *cls, const struct GNUNET_PeerIdentity *peer,
                               const struct GNUNET_MessageHeader *message)
{
  struct PeerTrailRejectionMessage *trail_rejection;
  unsigned int trail_length;
  struct GNUNET_PeerIdentity *trail_peer_list;
  struct FriendInfo *target_friend;
  struct GNUNET_TIME_Relative congestion_timeout;
  struct GNUNET_HashCode trail_id;
  struct GNUNET_PeerIdentity next_destination;
  struct GNUNET_HashCode new_intermediate_trail_id;
  struct GNUNET_PeerIdentity next_peer;
  struct GNUNET_PeerIdentity source;
  struct GNUNET_PeerIdentity *next_hop;
  uint64_t ultimate_destination_finger_value;
  unsigned int finger_map_index;
  size_t msize;
  
  msize = ntohs (message->size);
  if (msize != sizeof (struct PeerTrailRejectionMessage))
  {
    GNUNET_break_op (0);
    return GNUNET_YES;
  }
  
  trail_rejection = (struct PeerTrailRejectionMessage *) message;
  trail_length = ntohl (trail_rejection->trail_length);
  
  if ((msize != sizeof (struct PeerTrailRejectionMessage) +
               trail_length * sizeof (struct GNUNET_PeerIdentity)) ||
      (trail_length >
       GNUNET_SERVER_MAX_MESSAGE_SIZE / sizeof (struct GNUNET_PeerIdentity)))
  {
    GNUNET_break_op (0);
    return GNUNET_YES;
  }
  
  trail_peer_list = (struct GNUNET_PeerIdentity *)&trail_rejection[1];
  finger_map_index = ntohl (trail_rejection->finger_map_index);
  congestion_timeout = trail_rejection->congestion_time;
  source = trail_rejection->source_peer;
  trail_id = trail_rejection->trail_id;
  ultimate_destination_finger_value = 
  trail_rejection->ultimate_destination_finger_identity_value;
  
  /* First set the congestion time of the friend that sent you this message. */
  target_friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, peer);
  target_friend->congestion_duration = GNUNET_TIME_absolute_add (GNUNET_TIME_absolute_get(),
                                                                 congestion_timeout);
  
  if(0 == (GNUNET_CRYPTO_cmp_peer_identity (&my_identity, &source)))
  {
    return GNUNET_OK;
  }
  
  /* If I am congested then pass this message to peer before me in trail. */
  if(GNUNET_YES == GDS_ROUTING_threshold_reached())
  {
    struct GNUNET_PeerIdentity *new_trail;
    unsigned int new_trail_length;
    
    if (trail_length == 1)
    {
      new_trail = NULL;
      new_trail_length = 0;
      next_hop = &source;
    }
    else 
    {
      next_hop = &trail_peer_list[trail_length - 2];
      /* Remove myself from the trail. */
      new_trail_length = trail_length -1;
      new_trail = GNUNET_malloc (new_trail_length * sizeof (struct GNUNET_PeerIdentity));
      memcpy (new_trail, trail_peer_list, new_trail_length * sizeof (struct GNUNET_PeerIdentity));
    }
    
    target_friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, next_hop);
    GDS_NEIGHBOURS_send_trail_rejection (source, 
                                         ultimate_destination_finger_value,
                                         my_identity, finger_map_index,
                                         new_trail,new_trail_length,trail_id,
                                         target_friend, CONGESTION_TIMEOUT);
    return GNUNET_YES;
  }
  
  /* Look for next_hop to pass the trail setup message */
  next_hop = find_successor (ultimate_destination_finger_value, 
                             &next_destination,
                             &new_intermediate_trail_id,
                             finger_map_index);
  
  if (0 == (GNUNET_CRYPTO_cmp_peer_identity (next_hop, &my_identity)))/* This means I am the final destination */
  {
    if (0 == trail_length)
      next_peer = source;
    else
      next_peer = trail_peer_list[trail_length-1];
    
    target_friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, &next_peer);
    GDS_NEIGHBOURS_send_trail_setup_result (source,
                                            my_identity,
                                            target_friend, trail_length,
                                            trail_peer_list,
                                            finger_map_index, trail_id);
  }
  else
  {
    struct GNUNET_PeerIdentity peer_list[trail_length + 1];
    
    memcpy (peer_list, trail_peer_list, trail_length * sizeof (struct GNUNET_PeerIdentity));
    peer_list[trail_length] = my_identity;
    
    target_friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, next_hop);
    GDS_NEIGHBOURS_send_trail_setup (source,
                                     ultimate_destination_finger_value,
                                     next_destination, 
                                     target_friend, trail_length + 1, peer_list, 
                                     finger_map_index, trail_id,
                                     new_intermediate_trail_id);
  }
  return GNUNET_OK;
}


/*
 * Core handle for p2p trail tear down messages.
 * @param cls closure
 * @param message message
 * @param peer peer identity this notification is about
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static int 
handle_dht_p2p_trail_compression (void *cls, const struct GNUNET_PeerIdentity *peer,
                               const struct GNUNET_MessageHeader *message)
{
  struct PeerTrailCompressionMessage *trail_compression;
  struct GNUNET_PeerIdentity *next_hop;
  struct GNUNET_HashCode trail_id;
  struct FriendInfo *target_friend;
  size_t msize;
  
  msize = ntohs (message->size);
  if (msize != sizeof (struct PeerTrailCompressionMessage))
  {
    GNUNET_break_op (0);
    return GNUNET_OK;
  }
  
  trail_compression = (struct PeerTrailCompressionMessage *) message;
  trail_id = trail_compression->trail_id;
  
  if (0 == (GNUNET_CRYPTO_cmp_peer_identity (&(trail_compression->new_first_friend),
                                             &my_identity)))
  {
     if(0 != (GNUNET_CRYPTO_cmp_peer_identity (&(trail_compression->destination_peer), 
                                               &my_identity)))
     {
       GDS_ROUTING_update_trail_prev_hop (trail_id, 
                                          trail_compression->source_peer);
     }
     return GNUNET_OK;
  }
  
  next_hop = GDS_ROUTING_get_next_hop (trail_id, GDS_ROUTING_SRC_TO_DEST);
  if (NULL == next_hop)
  {
    GNUNET_break (0); /*FIXME: How to handle this case.  */
    return GNUNET_OK;
  }
  GNUNET_assert (GNUNET_YES == GDS_ROUTING_remove_trail (trail_id));
  target_friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, next_hop);
  GDS_NEIGHBOURS_send_trail_compression (trail_compression->source_peer, 
                                         trail_compression->destination_peer,
                                         trail_id,
                                         trail_compression->new_first_friend,
                                         target_friend);
  return GNUNET_OK;
}


/**
 * Core handler for trail teardown message. 
 * @param cls closure
 * @param message message
 * @param peer peer identity this notification is about
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static int 
handle_dht_p2p_trail_teardown (void *cls, const struct GNUNET_PeerIdentity *peer,
                               const struct GNUNET_MessageHeader *message)
{
  return GNUNET_OK;
}


/**
 * TRAIL ID and each peer should add an entry in the routing table. 
 * Core handle for p2p add trail message. 
 * @param cls closure
 * @param message message
 * @param peer peer identity this notification is about
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static int 
handle_dht_p2p_add_trail (void *cls, const struct GNUNET_PeerIdentity *peer,
                          const struct GNUNET_MessageHeader *message)
{
  return GNUNET_OK;  
}


/**
 *FIXME; call send_trail_teardown_message on all the trails of the finger that
 * you remove. Also you don't need to decerement friend trail count as that
 * friend is removed. But you can not send trail teardown message as the friend
 * is disconnected. then you don't have any next_hop. and in case there are 
 * multiple trails. and friend is the first trail then you remove only the trail.  
 * Iterate over finger_hashmap, and remove entries if finger is the disconnected
 * peer or if disconnected peer is the first friend in the trail to reach the
 * finger. 
 * @param cls closure
 * @param key current public key
 * @param value value in the hash map
 * @return #GNUNET_YES if we should continue to
 *         iterate,
 *         #GNUNET_NO if not.
 */
static int
remove_matching_finger (void *cls,
                        uint32_t key,
                        void *value)
{
  struct FingerInfo *remove_finger = value;
  const struct GNUNET_PeerIdentity *disconnected_peer = cls;
  struct TrailList *trail_list;
  int i;
  
  if (0 == GNUNET_CRYPTO_cmp_peer_identity (&remove_finger->finger_identity,
                                            disconnected_peer))
  {
    GNUNET_assert (GNUNET_YES ==
                   GNUNET_CONTAINER_multihashmap32_remove (finger_hashmap,
                                                         key, 
                                                         remove_finger));
    free_finger (remove_finger);
    return GNUNET_YES;
  }
  
  for (i = 0; i< remove_finger->trails_count; i++)
  {
    trail_list = &remove_finger->trail_list[i];  
    if (0 == GNUNET_CRYPTO_cmp_peer_identity (&trail_list->trail_head->peer,
                                                disconnected_peer))
    {
      GNUNET_assert (GNUNET_YES ==
                     GNUNET_CONTAINER_multihashmap32_remove (finger_hashmap,
                                                           key, 
                                                           remove_finger));
       free_finger (remove_finger);
    }
  }
  
  return GNUNET_YES;
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
  
  if (0 == memcmp (&my_identity, peer, sizeof (struct GNUNET_PeerIdentity)))
    return;

  remove_friend =
      GNUNET_CONTAINER_multipeermap_get (friend_peermap, peer);
  
  if (NULL == remove_friend)
  {
    GNUNET_break (0);
    return;
  }
  
  GNUNET_assert (GNUNET_SYSERR != 
                 GNUNET_CONTAINER_multihashmap32_iterate (finger_hashmap,
                                                          &remove_matching_finger,
                                                          (void *)peer));
  GDS_ROUTING_remove_trail_by_peer (peer);
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multipeermap_remove (friend_peermap,
                                                       peer,
                                                       remove_friend));
  
  if (0 != GNUNET_CONTAINER_multipeermap_size (friend_peermap))
    return;
  
  if (GNUNET_SCHEDULER_NO_TASK != find_finger_trail_task)
  {
      GNUNET_SCHEDULER_cancel (find_finger_trail_task);
      find_finger_trail_task = GNUNET_SCHEDULER_NO_TASK;
  }
  else
    GNUNET_break (0);
}


/**
 * Method called whenever a peer connects.
 *
 * @param cls closure
 * @param peer_identity peer identity this notification is about
 */
static void
handle_core_connect (void *cls, const struct GNUNET_PeerIdentity *peer_identity)
{
  struct FriendInfo *friend;

  /* Check for connect to self message */
  if (0 == memcmp (&my_identity, peer_identity, sizeof (struct GNUNET_PeerIdentity)))
    return;
  
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Connected to %s\n", GNUNET_i2s (peer_identity));
  
  /* If peer already exists in our friend_peermap, then exit. */
  if (GNUNET_YES == GNUNET_CONTAINER_multipeermap_contains (friend_peermap, peer_identity))
  {
    GNUNET_break (0);
    return;
  }
  
  GNUNET_STATISTICS_update (GDS_stats, gettext_noop ("# peers connected"), 1,
                            GNUNET_NO);

  friend = GNUNET_new (struct FriendInfo);
  friend->id = *peer_identity;
  
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multipeermap_put (friend_peermap,
                                                    peer_identity, friend,
                                                    GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));

  /* got a first connection, good time to start with FIND FINGER TRAIL requests... */
  if (GNUNET_SCHEDULER_NO_TASK == find_finger_trail_task)
    find_finger_trail_task = GNUNET_SCHEDULER_add_now (&send_find_finger_trail_message, NULL);
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
 * Initialize neighbours subsystem.
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GDS_NEIGHBOURS_init (void)
{
  static struct GNUNET_CORE_MessageHandler core_handlers[] = {
    {&handle_dht_p2p_put, GNUNET_MESSAGE_TYPE_DHT_P2P_PUT, 0},
    {&handle_dht_p2p_get, GNUNET_MESSAGE_TYPE_DHT_P2P_GET, 0},
    {&handle_dht_p2p_get_result, GNUNET_MESSAGE_TYPE_DHT_P2P_GET_RESULT, 0},   
    {&handle_dht_p2p_trail_setup, GNUNET_MESSAGE_TYPE_DHT_P2P_TRAIL_SETUP, 0},
    {&handle_dht_p2p_trail_setup_result, GNUNET_MESSAGE_TYPE_DHT_P2P_TRAIL_SETUP_RESULT, 0},
    {&handle_dht_p2p_verify_successor, GNUNET_MESSAGE_TYPE_DHT_P2P_VERIFY_SUCCESSOR, 0},
    {&handle_dht_p2p_verify_successor_result, GNUNET_MESSAGE_TYPE_DHT_P2P_VERIFY_SUCCESSOR_RESULT, 0},
    {&handle_dht_p2p_notify_new_successor, GNUNET_MESSAGE_TYPE_DHT_P2P_NOTIFY_NEW_SUCCESSOR, 0},
    {&handle_dht_p2p_trail_rejection, GNUNET_MESSAGE_TYPE_DHT_P2P_TRAIL_REJECTION, 0},
    {&handle_dht_p2p_trail_compression, GNUNET_MESSAGE_TYPE_DHT_P2P_TRAIL_COMPRESSION, 0},
    {&handle_dht_p2p_trail_teardown, GNUNET_MESSAGE_TYPE_DHT_P2P_TRAIL_TEARDOWN, 0},
    {&handle_dht_p2p_add_trail, GNUNET_MESSAGE_TYPE_DHT_P2P_ADD_TRAIL, 0},
    {NULL, 0, 0}
  };
  
  core_api =
    GNUNET_CORE_connect (GDS_cfg, NULL, &core_init, &handle_core_connect,
                         &handle_core_disconnect, NULL, GNUNET_NO, NULL,
                         GNUNET_NO, core_handlers);
  if (NULL == core_api)
    return GNUNET_SYSERR;
  
  friend_peermap = GNUNET_CONTAINER_multipeermap_create (256, GNUNET_NO);
  finger_hashmap = GNUNET_CONTAINER_multihashmap32_create (MAX_FINGERS * 4/3);
  
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
  
  GNUNET_assert (0 == GNUNET_CONTAINER_multihashmap32_size (finger_hashmap));
  GNUNET_CONTAINER_multihashmap32_destroy (finger_hashmap);
  finger_hashmap = NULL;

  if (GNUNET_SCHEDULER_NO_TASK != find_finger_trail_task)
  {
    GNUNET_break (0);
    GNUNET_SCHEDULER_cancel (find_finger_trail_task);
    find_finger_trail_task = GNUNET_SCHEDULER_NO_TASK;
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