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

/* TODO:
 1. Use a global array of all known peers in find_successor, Only when 
 a new peer is added in finger or friend peer map, then re calculate
 the array. Or else use the old one. The benefit of having this list is something
 * I am not sure. only when the code is complete and working I will do this part. 
 2. Structure alignment.
 3. In case of trail setup, you can see the comment on top of finger map index,
 * trial length --> in NBO. Check how do we keep it in NBO, and make sure its 
 * same everywhere. When i send any message across the network i use htonl, so that
 * converts it into network byte order.  
 4.THAT IN ROUTING TABLE SOURCE PEER IS INDEED THE SOURCE PEER.
  should trail contain last element as finger or just the last element.? if
  you can get some value then you should not keep at different places. 
  remove finger as last element in the trail.
 5. I have removed the last element in the trail which was finger identity as we
 * are already sending finger identity in the message. handle the case in case
 * of notify new successor and verify the successor.   */

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
   * Current destination to which this message is forwarded.
   */
  struct GNUNET_PeerIdentity current_destination;
  
  /**
   * Peer whose finger is current_destination. 
   */
  struct GNUNET_PeerIdentity current_source;
  
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
 * P2P Result message
 */
struct PeerGetResultMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_DHT_P2P_GET_RESULT
   */
  struct GNUNET_MessageHeader header;

  /**
   * The type for the data.
   */
  uint32_t type GNUNET_PACKED;
  
  /**
   * Peer which will receive the get result message. 
   */
  struct GNUNET_PeerIdentity source_peer;

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
   * Peer which is an intermediate destination. 
   */
  struct GNUNET_PeerIdentity current_destination;
  
  /**
   * Source for which current_destination is the finger. 
   */
  struct GNUNET_PeerIdentity current_source;
 
  /**
   * The key we are looking for.
   */
  struct GNUNET_HashCode key;
  
  /* Get path. */

};


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
   * Successor of this finger value will be our finger peer.
   */
  uint64_t destination_finger;

  /**
   * Source peer which wants to setup the trail to one of its finger. 
   */
  struct GNUNET_PeerIdentity source_peer;
  
  /**
   * Peer to which this packet is forwarded.
   */
  struct GNUNET_PeerIdentity current_destination;
  
  /**
   * In case the packet is forwarded to an intermediate finger, then 
   * current_source contains the peer id whose finger is the intermediate
   * finger. In case the packet is forwarded to a friend, then it is NULL.
   * FIXME: check the usage of current_source and fix this comment. 
   */
  struct GNUNET_PeerIdentity current_source;
  
  /**
   * Index into finger peer map, in Network Byte Order. 
   */
  uint32_t finger_map_index;
  
  /**
   * Number of entries in trail list, in Network Byte Order.
   */
  uint32_t trail_length GNUNET_PACKED;
  
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
  
  /* Trail from destination_peer to finger_identity */
  
};


/**
 * P2P Trail Rejection Message. 
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
  uint64_t finger_identity_value;
  
  /**
   * Index in finger peer map of source peer.
   */
  uint32_t finger_map_index;
  
  /**
   * Total number of peers in the trail.
   */
  uint32_t trail_length;
  
  /* Trail_list from source_peer to peer which sent the message for trail setup
   * to congested peer.*/
};


/**
 * P2P Verify Successor message. 
 */
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
   * Total number of peers in trail to current successor.
   */
  uint32_t trail_length;
  
  /* Trail to reach to from source_peer to successor. */
};


/**
 * P2P Verify Successor Result message. 
 */
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
   * Total number of peers in trail.
   */
  uint32_t trail_length; 
  
  /* Trail to reach from destination_peer to its correct successor.
   * If source_successor is not destination peer, then trail is from destination_peer
   * to my_predecessor.
   * If source_successor is destination peer, then trail is from destination_peer
   * to source_successor. */
};


/**
 * P2P Notify New Successor message.
 */
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
  
  /**
   * Number of peers in trail from source_peer to new successor.
   */
  uint32_t trail_length;
  
  /* Trail to from source_peer to destination_peer. */
};

struct PeerTrailTearDownMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_DHT_P2P_TRAIL_TEARDOWN
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
  
  /**
   * Number of peers in trail from source_peer to new successor.
   */
  uint32_t trail_length;
  
  /* Trail to from source_peer to destination_peer. */
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
 * Linked List of peers which are part of trail to reach a particular Finger.
 */
struct TrailPeerList
{
   /**
    * Pointer to next item in the list
    */
   struct TrailPeerList *next;

   /**
    * Pointer to previous item in the list
    */
   struct TrailPeerList *prev;
   
   /**
    * An element in this trail list
    */
   struct GNUNET_PeerIdentity peer;
  
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
   * 1. used in select_random_friend(), in case the friend has trails_count > TRAILS_THROUGH_FRIEND,
   * then choose another friend.
   * 2. in case of find_successor(), if the number of trails going through the friend
   * has already crossed, then choose another friend. 
   * 3. in case of find_successor(), if we choose a finger, and if friend through
   * which we reach this finger has crossed the limit then choose another finger/friend.
   * 4. One way to implement in case of find_successor, is 1) you can have a global
   * array of the entries and only when an entry is added in finger table, friend table,
   * then you re calculate the array. In array while adding the element you check 
   * the threshold of the friend in case its friend, and in case of finger check
   * the threshold of the first friend in the trail. If crossed then don't add the
   * entries in the array. When the count goes down, then again set a flag and
   * recalculte the array. Store a field in Finger table also, which will be 
   * equal to number of trails going through the first friend. 
   * Number of trail of which this friend is the first hop.
   * 5.FIXME: understand where you need to use memcpy or direct assignment. 
   */
  unsigned int trails_count;
  
  /**
   * Count of outstanding messages for this friend.
   */
  unsigned int pending_count;
  
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
 * Entry in finger_peermap.
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
   * Number of trails to reach to this finger.
   */
  unsigned int trail_count;
  
  /**
   * Total number of entries in first trail from (me,finger)
   */
  unsigned int first_trail_length;
  
  /**
   * Total number of entries in second trail from (me,finger)
   */
  unsigned int second_trail_length;
  
  
  /**
   * Number of trail of which the first element to reach to this finger is
   * part of. 
   */
  unsigned int first_friend_trails_count;
  
  /**
   * Head of first trail to reach this finger.
   */
  struct TrailPeerList *first_trail_head;
  
  /**
   * Tail of first trail to reach this finger.
   */
  struct TrailPeerList *first_trail_tail;
  
  /**
   * Head of second trail to reach this finger.
   */
  struct TrailPeerList *second_trail_head;
  
  /**
   * Tail of second trail to reach this finger.
   */
  struct TrailPeerList *second_trail_tail;
  
};


/**
 * FIXME: The name is not correct. 
 * Used to specify the kind of value stored in the array all_known_peers. 
 */
enum current_destination_type
{
  FRIEND,
  FINGER,
  VALUE,
  MY_ID
};


/**
 * Data structure passed to sorting algorithm in find_successor().
 */
struct Sorting_List
{
  /**
   * 64 bit value of peer identity
   */
  uint64_t peer_id;
  
  /**
   * FIXME: think of a better name for both the struct and destination_type
   * Type : MY_ID, FINGER, FINGER, Value 
   */
  enum current_destination_type type;
  
  /**
   * Pointer to original data structure linked to peer id.
   */
  void *data;
};


/**
 * Task that sends FIND FINGER TRAIL requests. This task is started when we have
 * get our first friend. 
 */
static GNUNET_SCHEDULER_TaskIdentifier find_finger_trail_task;

/**
 * Task that periodically verifies my successor. This task is started when we
 * have found our successor. 
 */
static GNUNET_SCHEDULER_TaskIdentifier verify_successor;

/**
 * Identity of this peer.
 */
static struct GNUNET_PeerIdentity my_identity;

/**
 * Hash map of all the friends of a peer
 */
static struct GNUNET_CONTAINER_MultiPeerMap *friend_peermap;

/**
 * Hash map of all the fingers of a peer
 */
static struct GNUNET_CONTAINER_MultiPeerMap *finger_peermap;

/**
 * Handle to CORE.
 */
static struct GNUNET_CORE_Handle *core_api;

/**
 * Finger map index for predecessor entry in finger peermap. 
 */
#define PREDECESSOR_FINGER_ID 64

/**
 * Maximum number of trails allowed to go through a friend.
 * FIXME: Better name, Random value at the moment, need to be adjusted to maintain a balance
 * between performance and Sybil tolerance. 
 */
#define TRAIL_THROUGH_FRIEND_THRESHOLD 64

/**
 * Possible number of different trails to reach to a finger. (Redundant routing) 
 */
#define TRAIL_COUNT 2

/**
 * FIXME: better name.
 * Set to GNUNET_YES, when the number of trails going through all my friends 
 * have reached the TRAIL_THROUGH_FRIEND_THRESHOLD. 
 */
static unsigned int all_friends_trail_threshold;

/**
 * The current finger index that we have want to find trail to.
 */
static unsigned int current_search_finger_index;


/**
 * Iterate over trail and search your index location in the array. 
 * @param trail Trail which contains list of peers.
 * @param trail_length Number of peers in the trail.
 * @return Index in the array.
 *         #GNUNET_SYSERR, in case there is no entry which should not be the case ideally. 
 */
static int
search_my_index (const struct GNUNET_PeerIdentity *trail,
                int trail_length)
{
  int i = 0;
  
  while (i < trail_length)
  {
    if (0 == GNUNET_CRYPTO_cmp_peer_identity (&my_identity, &trail[i]))
    {
      return i;
    }
    i++;
  }
  return GNUNET_SYSERR;
}


/**
 * Invert the trail list. 
 * @param existing_trail Trail
 * @param trail_length Number of peers in the existing trail.
 * @return 
 */
static struct GNUNET_PeerIdentity *
invert_trail_list (struct GNUNET_PeerIdentity *existing_trail, 
                   unsigned int trail_length)
{
  int i;
  int j;
  struct GNUNET_PeerIdentity *new_trail;
  
  j = 0;
  new_trail = GNUNET_malloc (sizeof (struct GNUNET_PeerIdentity) * trail_length);
  
  if (trail_length > 1)
  {
    i = trail_length - 2;
    while (i >= 0 )
    {
      memcpy( &new_trail[j], &existing_trail[i], sizeof (struct GNUNET_PeerIdentity));
      i--;
      j++;
    }
  }
  return new_trail;
}


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
  
  /* FIXME: Are we correctly initializing importance and pending. */
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
 * Construct a trail message and forward it to a friend. 
 * @param source_peer Peer which wants to set up the trail to one of its finger.
 * @param destination_finger Peer identity closest to this value will be 
 *                           @a source_peer's finger.
 * @param current_destination Finger of the @a current_source, for which among 
 *                            its friends, its own identity and all fingers, this
 *                            finger is the closest to the @a destination_finger
 * @param current_source Peer for which @a current_destination is its finger.
 * @param target_friend Friend to which this message should be forwarded.
 * @param trail_length Numbers of peers in the trail found so far.
 * @param trail_peer_list Peers this request has traversed so far  
 * @param finger_map_index Index in finger peer map
 */
void
GDS_NEIGHBOURS_send_trail_setup (const struct GNUNET_PeerIdentity *source_peer,
                                 uint64_t destination_finger,
                                 struct GNUNET_PeerIdentity *current_destination,
                                 struct GNUNET_PeerIdentity *current_source,
                                 struct FriendInfo *target_friend,
                                 unsigned int trail_length,
                                 const struct GNUNET_PeerIdentity *trail_peer_list,
                                 unsigned int finger_map_index)
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
  memcpy (&(tsm->destination_finger), &destination_finger, sizeof (uint64_t));
  memcpy (&(tsm->source_peer), source_peer, sizeof (struct GNUNET_PeerIdentity));
  memcpy (&(tsm->current_destination), current_destination, sizeof (struct GNUNET_PeerIdentity));
  memcpy (&(tsm->current_source), current_source, sizeof (struct GNUNET_PeerIdentity));
  tsm->trail_length = htonl (trail_length); 
  tsm->finger_map_index = htonl (finger_map_index);
  
  if (trail_peer_list != NULL)
  {
    peer_list = (struct GNUNET_PeerIdentity *) &tsm[1];
    memcpy (peer_list, trail_peer_list, trail_length * sizeof(struct GNUNET_PeerIdentity));
  }

  GNUNET_CONTAINER_DLL_insert_tail (target_friend->head, target_friend->tail, pending);
  target_friend->pending_count++;
  process_friend_queue (target_friend);
  
}


/**
 * Construct a trail setup result message and forward it to a friend. 
 * @param destination_peer Peer which will get the trail to one of its finger.
 * @param source_finger Peer to which the trail has been setup to.
 * @param target_friend Friend to which this message should be forwarded.
 * @param trail_length Numbers of peers in the trail.
 * @param trail_peer_list Peers which are part of the trail from source to destination.
 * @param finger_map_index Index in finger peer map 
 */
void
GDS_NEIGHBOURS_send_trail_setup_result (const struct GNUNET_PeerIdentity *destination_peer,
                                        const struct GNUNET_PeerIdentity *source_finger,
                                        struct FriendInfo *target_friend,
                                        unsigned int trail_length,
                                        const struct GNUNET_PeerIdentity *trail_peer_list,
                                        unsigned int finger_map_index)
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
  memcpy (&(tsrm->destination_peer), destination_peer, sizeof (struct GNUNET_PeerIdentity));
  memcpy (&(tsrm->finger_identity), source_finger, sizeof (struct GNUNET_PeerIdentity));
  tsrm->trail_length = htonl (trail_length);
  tsrm->finger_map_index = htonl (finger_map_index);
 
  peer_list = (struct GNUNET_PeerIdentity *) &tsrm[1];
  if (trail_length > 0)
    memcpy (peer_list, trail_peer_list, trail_length * sizeof (struct GNUNET_PeerIdentity));
  
  /* Send the message to chosen friend. */
  GNUNET_CONTAINER_DLL_insert_tail (target_friend->head, target_friend->tail, pending);
  target_friend->pending_count++;
  process_friend_queue (target_friend);
}


/**
 * Construct a PeerVerifySuccessor message and send it to friend.
 * @param source_peer Peer which wants to verify its successor
 * @param successor Peer which is our current successor
 * @param target_friend Friend to which this message should be forwarded.
 * @param trail_peer_list Peer which are part of trail from source to destination
 * @param trail_length Number of peers in the trail list.
 */
void GDS_NEIGHBOURS_send_verify_successor(const struct GNUNET_PeerIdentity *source_peer,
                                          const struct GNUNET_PeerIdentity *successor,
                                          struct FriendInfo *target_friend,
                                          const struct GNUNET_PeerIdentity *trail_peer_list,
                                          unsigned int trail_length)
{
  struct PeerVerifySuccessorMessage *vsm;
  struct P2PPendingMessage *pending;
  struct GNUNET_PeerIdentity *peer_list;
  size_t msize;
  
  msize = sizeof (struct PeerVerifySuccessorMessage) + 
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
  pending->importance = 0;    /* FIXME */
  pending->timeout = GNUNET_TIME_relative_to_absolute (GET_TIMEOUT);
  vsm = (struct PeerVerifySuccessorMessage *) &pending[1];
  pending->msg = &vsm->header;
  vsm->header.size = htons (msize);
  vsm->header.type = htons (GNUNET_MESSAGE_TYPE_DHT_P2P_VERIFY_SUCCESSOR);
  memcpy (&(vsm->successor), successor, sizeof (struct GNUNET_PeerIdentity));
  memcpy (&(vsm->source_peer), source_peer, sizeof (struct GNUNET_PeerIdentity));
  vsm->trail_length = htonl (trail_length);
  peer_list = (struct GNUNET_PeerIdentity *) &vsm[1];
  memcpy (peer_list, trail_peer_list, trail_length * sizeof (struct GNUNET_PeerIdentity));
  
  /* Send the message to chosen friend. */
  GNUNET_CONTAINER_DLL_insert_tail (target_friend->head, target_friend->tail, pending);
  target_friend->pending_count++;
  process_friend_queue (target_friend);
  
}


/**
 * Construct a PeerVerifySuccessorResult message and send it to friend.
 * @param destination_peer Peer which sent verify successor message
 * @param source_successor Peer to which verify successor message was sent.
 * @param my_predecessor source_successor's predecessor.
 * @param target_friend Friend to which this message should be forwarded.
 * @param trail_peer_list Peers which are part of trail from source to destination
 * @param trail_length Number of peers in the trail list.
 */
void GDS_NEIGHBOURS_send_verify_successor_result (const struct GNUNET_PeerIdentity *destination_peer,
                                                  const struct GNUNET_PeerIdentity *source_successor,
                                                  const struct GNUNET_PeerIdentity *my_predecessor,
                                                  struct FriendInfo *target_friend,
                                                  const struct GNUNET_PeerIdentity *trail_peer_list,
                                                  unsigned int trail_length)
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
  memcpy (&(vsmr->destination_peer), destination_peer, sizeof (struct GNUNET_PeerIdentity));
  memcpy (&(vsmr->source_successor), source_successor, sizeof (struct GNUNET_PeerIdentity));
  memcpy (&(vsmr->my_predecessor), my_predecessor, sizeof (struct GNUNET_PeerIdentity));
  vsmr->trail_length = htonl (trail_length);  
  peer_list = (struct GNUNET_PeerIdentity *) &vsmr[1];
  memcpy (peer_list, trail_peer_list, trail_length * sizeof (struct GNUNET_PeerIdentity));
  
   /* Send the message to chosen friend. */
  GNUNET_CONTAINER_DLL_insert_tail (target_friend->head, target_friend->tail, pending);
  target_friend->pending_count++;
  process_friend_queue (target_friend);
}


/**
 * Construct a PeerNotifyNewSuccessor message and send it to friend.
 * @param source_peer Peer which is sending notify message to its new successor.
 * @param destination_peer Peer which is the new destination.
 * @param target_friend Next friend to pass this message to. 
 * @param peer_list List of peers in the trail to reach to destination_peer.
 * @param trail_length Total number of peers in peer list 
 */
void 
GDS_NEIGHBOURS_send_notify_new_successor (const struct GNUNET_PeerIdentity *source_peer,
                                          const struct GNUNET_PeerIdentity *destination_peer,
                                          struct FriendInfo *target_friend,
                                          const struct GNUNET_PeerIdentity *trail_peer_list,
                                          unsigned int trail_length)
{
  struct PeerNotifyNewSuccessorMessage *nsm;
  struct P2PPendingMessage *pending;
  struct GNUNET_PeerIdentity *peer_list;
  size_t msize;
  
  msize = sizeof (struct PeerNotifyNewSuccessorMessage) + 
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
  nsm = (struct PeerNotifyNewSuccessorMessage *) &pending[1];
  pending->msg = &nsm->header;
  nsm->header.size = htons (msize);
  nsm->header.type = htons (GNUNET_MESSAGE_TYPE_DHT_P2P_NOTIFY_NEW_SUCCESSOR);
  memcpy (&(nsm->source_peer), source_peer, sizeof (struct GNUNET_PeerIdentity));
  memcpy (&(nsm->destination_peer), destination_peer, sizeof (struct GNUNET_PeerIdentity));
  nsm->trail_length = htonl (trail_length);
  
  peer_list = (struct GNUNET_PeerIdentity *) &nsm[1];
  memcpy (peer_list, trail_peer_list, trail_length * sizeof (struct GNUNET_PeerIdentity));
  
   /* Send the message to chosen friend. */
  GNUNET_CONTAINER_DLL_insert_tail (target_friend->head, target_friend->tail, pending);
  target_friend->pending_count++;
  process_friend_queue (target_friend);
}

/**
 * Send a trail tear down message
 * @param source_peer Source of the trail.
 * @param destination_peer Destination of the trail. 
 * @param trail_list Peers in the trail from @a source_peer to @a destination_peer
 * @param trail_length Total number of peers in trail_list. 
 * @pararm target_peer Next peer to forward this message to. 
 */
void
GDS_NEIGHBOURS_send_trail_teardown (struct GNUNET_PeerIdentity *source_peer,
                                    const struct GNUNET_PeerIdentity *destination_peer,
                                    struct GNUNET_PeerIdentity *trail_peer_list,
                                    unsigned int trail_length,
                                    struct FriendInfo *target_friend)
{
  struct P2PPendingMessage *pending;
  struct PeerTrailTearDownMessage *ttdm;
  struct GNUNET_PeerIdentity *peer_list;
  size_t msize;
  
  msize = sizeof (struct PeerTrailTearDownMessage) + 
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
  ttdm = (struct PeerTrailTearDownMessage *) &pending[1];
  pending->msg = &ttdm->header;
  ttdm->header.size = htons (msize);
  ttdm->header.type = htons (GNUNET_MESSAGE_TYPE_DHT_P2P_TRAIL_TEARDOWN);
  memcpy (&(ttdm->source_peer), source_peer, sizeof (struct GNUNET_PeerIdentity));
  memcpy (&(ttdm->destination_peer), destination_peer, sizeof (struct GNUNET_PeerIdentity));
  ttdm->trail_length = htonl (trail_length);
  
  peer_list = (struct GNUNET_PeerIdentity *) &ttdm[1];
  memcpy (peer_list, trail_peer_list, trail_length * sizeof (struct GNUNET_PeerIdentity));
  
   /* Send the message to chosen friend. */
  GNUNET_CONTAINER_DLL_insert_tail (target_friend->head, target_friend->tail, pending);
  target_friend->pending_count++;
  process_friend_queue (target_friend);
}


/** 
 * FIXME: Handle congested peer - don't choose this friend, also don't choose
 * the friend if the link threshold has crossed. Not implemented yet. 
 * Randomly choose one of your friends from the friends_peer map
 * @return Friend
 */
static struct FriendInfo *
select_random_friend (struct GNUNET_PeerIdentity *congested_peer)
{  
  unsigned int current_size;
  unsigned int *index; 
  unsigned int j = 0;
  struct GNUNET_CONTAINER_MultiPeerMapIterator *iter;
  struct GNUNET_PeerIdentity key_ret;
  struct FriendInfo *friend;
  
  current_size = GNUNET_CONTAINER_multipeermap_size (friend_peermap);
  index = GNUNET_CRYPTO_random_permute (GNUNET_CRYPTO_QUALITY_WEAK, current_size);
  iter = GNUNET_CONTAINER_multipeermap_iterator_create (friend_peermap);
 
  while(j < (*index))
  {
    if(GNUNET_YES == GNUNET_CONTAINER_multipeermap_iterator_next (iter,NULL,NULL))
    {
      j++;
    }
    else 
      return NULL;
  }  

  if(GNUNET_YES == GNUNET_CONTAINER_multipeermap_iterator_next (iter,&key_ret,(const void **)&friend))
  {
    /* Possible number of trails that can go through this friend has been reached. */
    if (friend->trails_count > TRAIL_THROUGH_FRIEND_THRESHOLD)
    {
      /* FIXME: What should I do now, should I call this same function again and 
       remember the index, j so that call random function without j and find
       a new friend. Also, I need some way to make sure that if number of times
       I have called the function is equal to number of entries in friend peermap.
       then I should return NULL. but its much better to have a function which
       just eliminates looking at the entries with threshold crossed. URGENT: Whats
       the best way to handle this case? */
    }
    return friend;
  }
  else
    return NULL;
}


/**
 * Compute finger_identity to which we want to setup the trail
 * @return finger_identity 
 */
static uint64_t 
compute_finger_identity()
{
  uint64_t my_id64 ;

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


/**
 * Periodically ping your successor to ask its current predecessor
 * 
 * @param cls closure for this task
 * @param tc the context under which the task is running
 */
static void
send_verify_successor_message (void *cls,
                               const struct GNUNET_SCHEDULER_TaskContext *tc )
{
  struct GNUNET_TIME_Relative next_send_time;
  struct GNUNET_CONTAINER_MultiPeerMapIterator *finger_iter;
  struct GNUNET_PeerIdentity key_ret;
  struct FriendInfo *target_friend;
  struct GNUNET_PeerIdentity *next_hop;
  struct GNUNET_PeerIdentity *peer_list;
  struct FingerInfo *finger;
  unsigned int finger_index;
  unsigned int i;
  int flag = 0;
  
  /* Find the successor from the finger peermap.*/
  finger_iter = GNUNET_CONTAINER_multipeermap_iterator_create (finger_peermap);  
  for (finger_index = 0; finger_index < GNUNET_CONTAINER_multipeermap_size (finger_peermap); finger_index++)
  {
    if(GNUNET_YES == GNUNET_CONTAINER_multipeermap_iterator_next (finger_iter, &key_ret,
                                                                 (const void **)&finger)) 
    {
      if (0 == finger->finger_map_index)
      {
        flag = 1;
        break;
      }
    }
  }
  GNUNET_CONTAINER_multipeermap_iterator_destroy (finger_iter);
  
  if( flag == 0)
    goto send_new_request;
  
  peer_list = GNUNET_malloc (sizeof (struct GNUNET_PeerIdentity) * finger->first_trail_length);
 
  struct TrailPeerList *iterate;
  iterate = finger->first_trail_head;
  i = 0;
  while ( i < (finger->first_trail_length))
  {
    memcpy (&peer_list[i], &(iterate->peer), sizeof (struct GNUNET_PeerIdentity));
    iterate = iterate->next;
    i++;
  }
 
  next_hop = GNUNET_malloc (sizeof (struct GNUNET_PeerIdentity));
  memcpy (next_hop, &peer_list[0], sizeof (struct GNUNET_PeerIdentity));
  target_friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, next_hop);

  GDS_NEIGHBOURS_send_verify_successor (&my_identity,
                                        &(finger->finger_identity),
                                        target_friend,
                                        peer_list,
                                        finger->first_trail_length);
  
  
  /* FIXME: Understand what this function is actually doing here. */
  send_new_request:
  next_send_time.rel_value_us =
      DHT_FIND_FINGER_TRAIL_INTERVAL.rel_value_us +
      GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_WEAK,
                                DHT_FIND_FINGER_TRAIL_INTERVAL.rel_value_us);
 
  verify_successor =
      GNUNET_SCHEDULER_add_delayed (next_send_time, &send_verify_successor_message,
                                    NULL);
}


/**
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
  uint64_t finger_identity;
  unsigned int finger_map_index;
  
  next_send_time.rel_value_us =
      DHT_FIND_FINGER_TRAIL_INTERVAL.rel_value_us +
      GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_WEAK,
                                DHT_FIND_FINGER_TRAIL_INTERVAL.rel_value_us);
  
  /* FIXME; if all the friend have reached their threshold, then don't schedule
   * the task till the all_friends_trail_threshold gets reset. It will be
   * scheduled from there. So, in finger table when we remove an entry and the new
   * entry does not have the same friend as the first hop, then decrement the
   * threshold limit. and schedule this task. 
   IMPORTANT: reset the value some where. Better name */
  if (GNUNET_YES == all_friends_trail_threshold)
  {
    return;
  }

  find_finger_trail_task =
      GNUNET_SCHEDULER_add_delayed (next_send_time, &send_find_finger_trail_message,
                                    NULL);
  
  /* Friend peermap is empty but this task has already been started it failed.*/
  if (GNUNET_CONTAINER_multipeermap_size (friend_peermap) == 0)
  {
    GNUNET_break(0);
    return;
  }
  
  target_friend = select_random_friend (NULL);
 
  if (NULL == target_friend)
  {
     /* FIXME URGENT: Here we can get NULL all of the friends have reached their threshold.
      * At the moment, the code for select_random_friend, is not handling it. In such a
      * case I think we can set a flag, and only when any value for any friend gets
      * decremented,(which can happen only in finger table, when we remove an entry
      * from our finger table, and we are not part of the trail to reach to that
      * finger any more, t then reset the flag and schedule the code from there. */
    all_friends_trail_threshold = GNUNET_YES;
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
  
  /* URGENT :FIXME: In case the packet is not sent to a finger, then current_source is the
   * peer which sent the packet and current_destination which recevied it. Now
   * these fields are not always used. Think of some way to remove these variables.  */
  GDS_NEIGHBOURS_send_trail_setup (&my_identity, finger_identity, &(target_friend->id),
                                   &my_identity, target_friend, 0, NULL, finger_map_index);
}


/**
 * FIXME: How do I send back the updated trail.
 * Scan the trail to check if any on my own friend is part of trail. If yes
 * the shortcut the trail and update the finger_trail and trail_length. 
 * @param finger_trail
 * @param trail_length 
 * @return 
 */
static struct GNUNET_PeerIdentity *
scan_and_compress_trail (struct GNUNET_PeerIdentity *finger_trail, unsigned int trail_length,
            const struct GNUNET_PeerIdentity *finger)
{
  /* start from the second element as first element will always be your friend.
   In case trail_length = 2, and the last element is also your friend then you
   should delete the first element. In other cases go through the list and check
   if the trail */
  int i = trail_length - 1;
  
  while (i > 1)
  {
    if (NULL == GNUNET_CONTAINER_multipeermap_get (friend_peermap, &finger_trail[i]))
    {
      /* This element of trail is not my friend. */
      i--;
    }
    else
    {
      /* If for any i>1 we found a friend, then we can use this friend as the 
       first link and forget about all the peers behind it. But we need to first
       copy the peers behind it. send a trail tear down message along
       that line. */
      struct GNUNET_PeerIdentity *discarded_trail;
      struct FriendInfo *target_friend;
      /* FIXME: Create a new trail. to send back*/
      int discarded_trail_length = trail_length - i;
      int j = 0;
      discarded_trail = GNUNET_malloc (discarded_trail_length * sizeof (struct GNUNET_PeerIdentity));
      
      while (j < (discarded_trail_length + 1))
      {
        memcpy (&discarded_trail[j], &finger_trail[j], sizeof (struct GNUNET_PeerIdentity));
        j++;
      }
      
      target_friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, &finger_trail[0]);
      /* FIXME: THAT IN ROUTING TABLE SOURCE PEER IS INDEED THE SOURCE PEER.
       * should trail contain last element as finger or just the last element.? if
       * you can get some value then you should not keep at different places. 
       * remove finger as last element in the trail.  */
      GDS_NEIGHBOURS_send_trail_teardown (&my_identity, finger, discarded_trail,
                                          discarded_trail_length, target_friend);
      
      /* fixme: CHANGE IT TO NEW TRAIL */
      return NULL;
    }
  }
  return NULL;
}


/**
 * TODO:
 * To see the logic better, I guess it better that function calling
 * free_finger, decrement the count of the trail going through them 
 * reset all_friends_trail_threshold. In case you are removing an entry from 
 * finger table, and the new entry has the first friend different from the old
 * entry, then reset this all_friends_trail_threshold, if it is set to GNUNET_YES.
 * and also schedule send_find_finger_trail_message. 
 * Free finger and its trail.  
 * @param remove_finger Finger to be freed.
 */
static void
free_finger (struct FingerInfo *finger)
{
  struct TrailPeerList *peer;
  struct FriendInfo *first_trail_friend;
  struct FriendInfo *second_trail_friend;
  
  first_trail_friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, 
                                                          &(finger->first_trail_head->peer));
  second_trail_friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, 
                                                           &(finger->second_trail_head->peer));
  
  first_trail_friend->trails_count--;
  second_trail_friend->trails_count--;
  
  /* FIXME: Here we should reset the all_peers_trail_count to GNUNET_NO, and
   send_find_finger_trail_message. */
  while (NULL != (peer = finger->first_trail_head))
  {
    GNUNET_CONTAINER_DLL_remove (finger->first_trail_head, finger->first_trail_tail, peer);
    GNUNET_free (peer);
  }
 
  while (NULL != (peer = finger->second_trail_head))
  {
    GNUNET_CONTAINER_DLL_remove (finger->second_trail_head, finger->second_trail_tail, peer);
    GNUNET_free (peer);
  }
  GNUNET_free (finger);
}


/**
 * FIMXE: Change the function, here you need to invert the trail. 
 * @param existing_finger
 * @param new_finger
 * @param trail
 * @param trail_length
 * @return 
 */
static
int select_correct_predecessor (struct FingerInfo *existing_finger,
                                const struct GNUNET_PeerIdentity *new_finger,
                                struct GNUNET_PeerIdentity *trail,
                                unsigned int trail_length)
{
  int val = GNUNET_CRYPTO_cmp_peer_identity (&(existing_finger->finger_identity), new_finger);
  if (0 == val)
  {
    /* FIXME: if the new entry = old entry, then compare the trails, and see if the trails 
     are disjoint, then send GNUNET_YES, but don't free old finger. But first you
     * should collapse the trail and then do comparison. Also, if you are collapsing
     * for one case then you should do it for all the cases where you are sending
     * GNUNET_YES.  */
    /* Scan the trail for a friend and shorten if possible. */
    scan_and_compress_trail (trail, trail_length, new_finger);
    return GNUNET_YES;
  }
  else if (val < 0)
  {
    /* If the new entry is closest one, then free the old entry, send a trail_teardown message.*/
    struct GNUNET_PeerIdentity *peer_list; 
    struct FriendInfo *friend; 
    struct TrailPeerList *finger_trail;
    int existing_finger_trail_length = existing_finger->first_trail_length;
    int i = 0;
    
    finger_trail = existing_finger->first_trail_head;
    friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, &(finger_trail->peer)); 
    peer_list = GNUNET_malloc ( existing_finger_trail_length * sizeof (struct GNUNET_PeerIdentity));
    while (i < existing_finger->first_trail_length)
    {
      memcpy (&peer_list[i], &(finger_trail->peer), sizeof (struct GNUNET_PeerIdentity));
      finger_trail = finger_trail->next;
      i++;
    }
    
    GDS_NEIGHBOURS_send_trail_teardown (&my_identity, &(existing_finger->finger_identity),
                                        peer_list, existing_finger_trail_length, friend);
    
    free_finger (existing_finger);
    scan_and_compress_trail (trail, trail_length, new_finger);
    return GNUNET_YES;
  }
  else
  {
     /* If the old entry is closest then just return GNUNET_NO.*/
    return GNUNET_NO;
  }
  return GNUNET_SYSERR;
}


/**
 * Check if there is a predecessor in our finger peer map or not.
 * If no, then return GNUNET_YES
 * else compare existing predecessor and peer, and find the correct
 * predecessor. 
 * @param existing_predecessor
 * @param new_predecessor
 * @return #GNUNET_YES if new peer is predecessor
 *         #GNUNET_NO if new peer is not the predecessor. 
 */
static void
compare_and_update_predecessor (struct GNUNET_PeerIdentity *peer,
                                struct GNUNET_PeerIdentity *trail,
                                unsigned int trail_length)
{
  /* ! HAVE A PREDECESSOR || (source_peer closer than existing PREDECESOR) */
  struct FingerInfo *existing_finger;
  struct GNUNET_CONTAINER_MultiPeerMapIterator *finger_iter;
  struct FingerInfo *new_finger_entry;
  int i;
  int predecessor_flag = 0;
  
  finger_iter = GNUNET_CONTAINER_multipeermap_iterator_create (finger_peermap); 
  for (i= 0; i < GNUNET_CONTAINER_multipeermap_size (finger_peermap); i++)
  {
    if(GNUNET_YES == GNUNET_CONTAINER_multipeermap_iterator_next (finger_iter, NULL,
                                                                 (const void **)&existing_finger)) 
    {
      if (existing_finger->finger_map_index == PREDECESSOR_FINGER_ID)
      {
        predecessor_flag = 1;
        break;
      }
    }
  }
  
  if (predecessor_flag != 0)
  {
    /* There is a predecessor entry. Now we need to find out which one is
     * the closest one. If both are same then how to handle.  */
    if(select_correct_predecessor (existing_finger, peer, trail, trail_length) == GNUNET_NO)
      return;
  }
  else
  {
    scan_and_compress_trail (trail, trail_length, peer);
    invert_trail_list (trail, trail_length);
  }
  FPRINTF (stderr,_("\nSUPU %s, %s, %d"),__FILE__, __func__,__LINE__);
  memcpy (&(new_finger_entry->finger_identity), peer, sizeof (struct GNUNET_PeerIdentity));
  new_finger_entry->finger_map_index = PREDECESSOR_FINGER_ID;
  new_finger_entry->first_trail_length = trail_length;
  i = 0;
  while (i < trail_length)
  {
    struct TrailPeerList *element;
    element = GNUNET_malloc (sizeof (struct TrailPeerList));
    element->next = NULL;
    element->prev = NULL;
    
    memcpy (&(element->peer), &trail[i], sizeof(struct GNUNET_PeerIdentity));
    GNUNET_CONTAINER_DLL_insert_tail(new_finger_entry->first_trail_head, new_finger_entry->first_trail_tail, element);
    i++;
  }
  
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multipeermap_put (finger_peermap,
                                                    &(new_finger_entry->finger_identity),
                                                    &new_finger_entry,
                                                    GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE)); 
  
  return;
}


/**
 * FIXME: In this case first you should check which of the trail is longest and
 * the just discard it. Right now you are not checking it. 
 * In case there are already maximum number of possible trail to reach to a finger,
 * then check if the new trail can replace an existing one. If yes then replace.
 * @param existing_finger
 * @param trail
 * @param trail_length
 * @return #GNUNET_YES 
 *         #GNUNET_NO
 */
static 
void select_and_replace_trail (struct FingerInfo *existing_finger, 
                               struct GNUNET_PeerIdentity *trail,
                               unsigned int trail_length)
{
  if (trail_length < existing_finger->first_trail_length)
  {
    struct TrailPeerList *peer;
    int i = 0;
        
    while (NULL != (peer = existing_finger->first_trail_head))
    {
      GNUNET_CONTAINER_DLL_remove (existing_finger->first_trail_head, existing_finger->first_trail_tail, peer);
      GNUNET_free (peer);
    } 
        
    while (i < trail_length)
    {
      struct TrailPeerList *element;
      element = GNUNET_malloc (sizeof (struct TrailPeerList));
      element->next = NULL;
      element->prev = NULL;
    
      memcpy (&(element->peer), &trail[i], sizeof(struct GNUNET_PeerIdentity));
      GNUNET_CONTAINER_DLL_insert_tail(existing_finger->second_trail_head, existing_finger->second_trail_tail, element);
      i++;
    }
  }
  else if (trail_length < existing_finger->second_trail_length)
  {
    struct TrailPeerList *peer;
    int i = 0;
        
    while (NULL != (peer = existing_finger->second_trail_head))
    {
      GNUNET_CONTAINER_DLL_remove (existing_finger->second_trail_head, existing_finger->second_trail_tail, peer);
      GNUNET_free (peer);
    }
        
    while (i < trail_length)
    {
      struct TrailPeerList *element;
      element = GNUNET_malloc (sizeof (struct TrailPeerList));
      element->next = NULL;
      element->prev = NULL;
    
      memcpy (&(element->peer), &trail[i], sizeof(struct GNUNET_PeerIdentity));
      GNUNET_CONTAINER_DLL_insert_tail(existing_finger->second_trail_head, existing_finger->second_trail_tail, element);
      i++;
     }
  } 
}


/**
 * Add a new trail to reach an existing finger in finger peermap. 
 * @param existing_finger
 * @param trail
 * @param trail_length
 */
static
void add_new_trail (struct FingerInfo *existing_finger, 
                    struct GNUNET_PeerIdentity *trail,
                    unsigned int trail_length)
{
  int i;
  i = 0;
      
  if (existing_finger->second_trail_head != NULL)
  {
    while (i < trail_length)
    {
      struct TrailPeerList *element;
      element = GNUNET_malloc (sizeof (struct TrailPeerList));
      element->next = NULL;
      element->prev = NULL;
    
      memcpy (&(element->peer), &trail[i], sizeof(struct GNUNET_PeerIdentity));
      GNUNET_CONTAINER_DLL_insert_tail(existing_finger->second_trail_head, existing_finger->second_trail_tail, element);
      i++;
    }
  }
  else if (existing_finger->second_trail_head != NULL)
  {
    while (i < trail_length)
    {
      struct TrailPeerList *element;
      element = GNUNET_malloc (sizeof (struct TrailPeerList));
      element->next = NULL;
      element->prev = NULL;
    
      memcpy (&(element->peer), &trail[i], sizeof(struct GNUNET_PeerIdentity));
      GNUNET_CONTAINER_DLL_insert_tail(existing_finger->second_trail_head, existing_finger->second_trail_tail, element);
      i++;
    }
  }  
}


/**
 * * 1.* If you remove an entry from finger table, and if the finger is not your friend 
 * and the trail length > 1 for the finger that you removed, then you should send
 * a trail_teardown message along the trail. so that the peers which have an 
 * entry in their routing table for this trail can remove it from their routing
 * table. 
 * Better name
 * TODO: First check if both the trails are present if yes then send it
 * for both of them. 
 * @param existing_finger
 */
static
void send_trail_teardown (struct FingerInfo *existing_finger)
{
 struct GNUNET_PeerIdentity *peer_list; 
 struct FriendInfo *friend; 
 struct TrailPeerList *finger_trail;
 int existing_finger_trail_length = existing_finger->first_trail_length;
 int i = 0;
    
    
 finger_trail = existing_finger->first_trail_head;
 friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, &(finger_trail->peer)); 
 peer_list = GNUNET_malloc ( existing_finger_trail_length * sizeof (struct GNUNET_PeerIdentity));
 while (i < existing_finger->first_trail_length)
 {
   memcpy (&peer_list[i], &(finger_trail->peer), sizeof (struct GNUNET_PeerIdentity));
   finger_trail = finger_trail->next;
   i++;
 }
    
 GDS_NEIGHBOURS_send_trail_teardown (&my_identity, &(existing_finger->finger_identity),
                                        peer_list, existing_finger_trail_length, friend); 
}


/**TOD0.
 * Choose the closest successor from existing_finger and new_finger. In case new_finger
 * is choosen, then send a tear down message along the trail to reach existing_finger. 
 * @param existing_finger Existing entry in finger peer map
 * @param new_finger New finger 
 * @param trail Trail to reach to the new finger from me. 
 * @param trail_length Number of peers in the @a trail
 * @param finger_map_index If finger_map_index == PREDECESSOR_FINGER_INDEX,
 *                         then we use a different logic to find the closest 
 *                         predecessor. 
 * @return #GNUNET_YES In case we want to store the new entry.
 *         #GNUNET_NO In case we want the existing entry.
 *         #GNUNET_SYSERR Error. 
 */
static 
int select_closest_finger (struct FingerInfo *existing_finger,
                           const struct GNUNET_PeerIdentity *new_finger,
                           struct GNUNET_PeerIdentity *trail,
                           unsigned int trail_length)
{
  int val = GNUNET_CRYPTO_cmp_peer_identity (&(existing_finger->finger_identity), new_finger);
  
  if (0 == val)
  {
    /*FIXME: Check if this returns the compressed trail in the trail sent as parameter.
      Scan the trail for a friend and shorten if possible. */
    scan_and_compress_trail (trail, trail_length, new_finger);
    
    if (existing_finger->trail_count < TRAIL_COUNT)
    {
      add_new_trail (existing_finger, trail, trail_length);
      return GNUNET_NO;
    }
    else
    {
      /* If not then first check if this new trail is shorter than other trails,
         if yes then remove the old trail, and add this new trail. and send GNUNET_YES. */
      select_and_replace_trail (existing_finger, trail, trail_length);
      return GNUNET_NO;
    }
  }
  else if (val > 0)
  {
    /* If the new entry is closest one, then free the old entry, send a trail_teardown message.*/
    
    send_trail_teardown (existing_finger);
    free_finger (existing_finger);
    scan_and_compress_trail (trail, trail_length, new_finger);
    return GNUNET_YES;
  }
  else
  {
     /* If the old entry is closest then just return GNUNET_NO.*/
    return GNUNET_NO;
  }
  return GNUNET_SYSERR;
}


/**
 * FIXME: Better name, and make the code more cleaner.
 * Compare the new finger entry added and our successor. 
 * @return #GNUNET_YES if same.
 *         #GNUNET_NO if not. 
 */
static int
compare_new_entry_successor (const struct GNUNET_PeerIdentity *new_finger)
{
  int successor_flag = 0;
  struct FingerInfo *successor_finger;
  struct GNUNET_CONTAINER_MultiPeerMapIterator *finger_iter;
  int i;
  
  finger_iter = GNUNET_CONTAINER_multipeermap_iterator_create (finger_peermap); 
  for (i= 0; i < GNUNET_CONTAINER_multipeermap_size (finger_peermap); i++)
  {
    if(GNUNET_YES == GNUNET_CONTAINER_multipeermap_iterator_next (finger_iter, NULL,
                                                                 (const void **)&successor_finger)) 
    {
      if (successor_finger->finger_map_index == 0)
      {
        successor_flag = 1;
        break;
      }
    }
  }
  /* Ideally we should never reach here. */
  if (successor_flag == 0)
  {
    GNUNET_break (0);
    return GNUNET_NO;
  }
  
  if (0 == GNUNET_CRYPTO_cmp_peer_identity (new_finger, &(successor_finger->finger_identity)))
    return GNUNET_YES;
  else
    return GNUNET_NO;
}


/**
 * Add an entry in the finger table. If there is already an existing entry in
 * the finger peermap for given finger map index, then choose the closest one.
 * In case both the new entry and old entry are same, store both of them. (Redundant 
 * routing).
 * @param finger_identity
 * @param finger_trail
 * @param finger_trail_length
 * @param finger_map_index
 */
static
void finger_table_add (const struct GNUNET_PeerIdentity *finger_identity,
                       struct GNUNET_PeerIdentity *finger_trail,
                       uint32_t finger_trail_length,
                       uint32_t finger_map_index)
{
  struct FingerInfo new_finger_entry;
  struct FingerInfo *existing_finger;
  struct FriendInfo *first_friend_trail;
  struct GNUNET_CONTAINER_MultiPeerMapIterator *finger_iter;
  int i;
  
  /* If you are your own finger, then exit. */
  if (0 == GNUNET_CRYPTO_cmp_peer_identity (&my_identity, finger_identity))
  {
    /* SUPU: We don't store this trail in case of trail_setup_result, if
     source and destination of the message are same. */
    return;
  }
  
  /* Check if there is already an entry for the finger map index in the finger peer map. */
  finger_iter = GNUNET_CONTAINER_multipeermap_iterator_create (finger_peermap); 
  for (i= 0; i < GNUNET_CONTAINER_multipeermap_size (finger_peermap); i++)
  {
    if(GNUNET_YES == GNUNET_CONTAINER_multipeermap_iterator_next (finger_iter, NULL,
                                                                 (const void **)&existing_finger)) 
    {
      if (existing_finger->finger_map_index == finger_map_index)
      {
        /* If existing finger is closest or both the new finger and existing finger
         are same, then just update current_search_finger_index. We are not
         adding a new entry just updating the existing entry or doing nothing. */
        if ( GNUNET_NO == select_closest_finger (existing_finger, finger_identity, 
                                                finger_trail, finger_trail_length)) 
          goto update_current_search_finger_index;
        else
          break;
      }
    } 
  }
  
  /* Add the new entry. */
  memcpy (&(new_finger_entry.finger_identity), finger_identity, sizeof (struct GNUNET_PeerIdentity));
  new_finger_entry.finger_map_index = finger_map_index;
  new_finger_entry.first_trail_length = finger_trail_length;
  
  if (finger_trail_length > 0)   
  {
    first_friend_trail = GNUNET_CONTAINER_multipeermap_get (friend_peermap, &finger_trail[0]);
    first_friend_trail->trails_count++;
  }
  else
  {
    /* It means the finger is my friend. */
    first_friend_trail = GNUNET_CONTAINER_multipeermap_get (friend_peermap, finger_identity);
    first_friend_trail->trails_count++;
  }
  
  
  new_finger_entry.first_friend_trails_count = first_friend_trail->trails_count;  
  i = 0;
  while (i < finger_trail_length)
  {
    struct TrailPeerList *element;
    element = GNUNET_malloc (sizeof (struct TrailPeerList));
    element->next = NULL;
    element->prev = NULL;
    
    memcpy (&(element->peer), &finger_trail[i], sizeof(struct GNUNET_PeerIdentity));
    GNUNET_CONTAINER_DLL_insert_tail(new_finger_entry.first_trail_head, new_finger_entry.first_trail_tail, element);
    i++;
  }
  
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multipeermap_put (finger_peermap,
                                                    &(new_finger_entry.finger_identity),
                                                    &new_finger_entry,
                                                    GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE));   
  
  /* Set the value of current_search_finger_index. */
  update_current_search_finger_index:
  if (0 == finger_map_index)
  {
    verify_successor = GNUNET_SCHEDULER_add_now (&send_verify_successor_message, NULL);
    current_search_finger_index = PREDECESSOR_FINGER_ID;
    return;
  }
  else if (GNUNET_YES == compare_new_entry_successor (finger_identity))
  {
    /* If the new entry is same as our successor, then reset the current_search_finger_index to 0*/
    current_search_finger_index = 0;
    return;
  }
  else 
  {
    current_search_finger_index = current_search_finger_index - 1;
    return;
  }
}
 

/**
 * Compare two peer identities.
 * @param p1 Peer identity
 * @param p2 Peer identity
 * @return 1 if p1 > p2, -1 if p1 < p2 and 0 if p1 == p2. 
 */
static int
compare_peer_id (const void *p1, const void *p2)
{
  struct Sorting_List *p11;
  struct Sorting_List *p22;
  int ret;
  p11 = GNUNET_malloc (sizeof (struct Sorting_List));
  p22 = GNUNET_malloc (sizeof (struct Sorting_List));
  p11 = (struct Sorting_List *)p1;
  p22 = (struct Sorting_List *)p2;
  ret = ( (p11->peer_id) > (p22->peer_id) ) ? 1 : 
          ( (p11->peer_id) == (p22->peer_id) ) ? 0 : -1;
  return ret;
}

  
/**
 * Return the successor of value in all_known_peers.
 * @param all_known_peers list of all the peers
 * @param value value we have to search in the all_known_peers.
 * @return 
 */
static struct Sorting_List *
find_closest_successor(struct Sorting_List *all_known_peers, uint64_t value,
                       unsigned int size)
{
  int first;
  int last;
  int middle;
  
  first = 0;
  last = size - 1;
  middle = (first + last)/2;
  
  while(first <= last)
  {
    if(all_known_peers[middle].peer_id < value)
    {
      first = middle + 1; 
    }
    else if(all_known_peers[middle].peer_id == value)
    {
      if(middle == (size -1))
      {
        return &all_known_peers[0];
      }
      else
      {
        return &all_known_peers[middle+1];
      }
    }
    else
    {
       last = middle - 1;
    }
  
    middle = (first + last)/2;  
  }
  return NULL;
}


/**
 * Find closest successor for the value.
 * @param value Value for which we are looking for successor
 * @param[out] current_destination set to the end of the finger to traverse next 
 * @param[out] current_source set to my_identity.
 * @param congested_peer Peer not to be considered when looking for
 *                       successor. FIXME: IMPLEMENT IT. 
 * @return Peer identity of next hop, NULL if we are the 
 *   ultimate destination 
 */
static struct GNUNET_PeerIdentity *
find_successor (uint64_t value, struct GNUNET_PeerIdentity *current_destination,
               struct GNUNET_PeerIdentity *current_source,
               struct GNUNET_PeerIdentity *congested_peer)
{
  struct GNUNET_CONTAINER_MultiPeerMapIterator *friend_iter;
  struct GNUNET_CONTAINER_MultiPeerMapIterator *finger_iter;
  struct GNUNET_PeerIdentity key_ret;
  struct FriendInfo *friend;
  struct FingerInfo *finger;
  unsigned int finger_index;
  unsigned int friend_index;
  struct Sorting_List *successor;
  unsigned int size;
  int j;
  
  /* 2 is added in size for my_identity and value which will part of all_known_peers. */
  size = GNUNET_CONTAINER_multipeermap_size (friend_peermap)+
         GNUNET_CONTAINER_multipeermap_size (finger_peermap)+
         2;
  
  struct Sorting_List all_known_peers[size];
  
  int k;
  for (k = 0; k < size; k++)
    all_known_peers[k].peer_id = 0;
  
  /* Copy your identity at 0th index in all_known_peers. */
  j = 0;
  memcpy (&(all_known_peers[j].peer_id), &my_identity, sizeof (uint64_t));
  all_known_peers[j].type = MY_ID;
  all_known_peers[j].data = 0;
  j++;
  
  /* Copy value */
  all_known_peers[j].peer_id = value;
  all_known_peers[j].type = VALUE;
  all_known_peers[j].data = 0;
  j++;
  
  /* Iterate over friend peer map and copy all the elements into array. */
  friend_iter = GNUNET_CONTAINER_multipeermap_iterator_create (friend_peermap); 
  for (friend_index = 0; friend_index < GNUNET_CONTAINER_multipeermap_size (friend_peermap); friend_index++)
  {
    if(GNUNET_YES == GNUNET_CONTAINER_multipeermap_iterator_next(friend_iter,&key_ret,(const void **)&friend)) 
    {
      memcpy (&(all_known_peers[j].peer_id), &(friend->id), sizeof (uint64_t));
      all_known_peers[j].type = FRIEND;
      all_known_peers[j].data = friend;
      j++;
    }
  }
  
  /* Iterate over finger map and copy all the entries into all_known_peers array. */
  finger_iter = GNUNET_CONTAINER_multipeermap_iterator_create (finger_peermap);  
  for (finger_index = 0; finger_index < GNUNET_CONTAINER_multipeermap_size (finger_peermap); finger_index++)
  {
    if(GNUNET_YES == GNUNET_CONTAINER_multipeermap_iterator_next(finger_iter,&key_ret,(const void **)&finger)) 
    {
      memcpy (&(all_known_peers[j].peer_id), &(finger->finger_identity), sizeof (uint64_t));
      all_known_peers[j].type = FINGER;
      all_known_peers[j].data = finger;
      j++;
    }
  }
  
  GNUNET_CONTAINER_multipeermap_iterator_destroy (finger_iter);
  GNUNET_CONTAINER_multipeermap_iterator_destroy (friend_iter);   
  
  qsort (&all_known_peers, size, sizeof (struct Sorting_List), &compare_peer_id);
  
  /* search value in all_known_peers array. */
  successor = find_closest_successor (all_known_peers, value, size);
  
  if (successor->type == MY_ID)
  {
    /* FIXME: make sure everywhere you are using current_destination to check if 
     I am the final destination. */
    memcpy (current_destination, &my_identity, sizeof (struct GNUNET_PeerIdentity));
    return NULL;
  }
  else if (successor->type == FRIEND)
  {
    struct FriendInfo *target_friend;
    target_friend = (struct FriendInfo *)successor->data;
    memcpy (current_destination, &(target_friend->id), sizeof (struct GNUNET_PeerIdentity));
    memcpy (current_source, &my_identity, sizeof (struct GNUNET_PeerIdentity));
    return current_destination;
  }
  else if (successor->type == FINGER)
  {
    struct GNUNET_PeerIdentity *next_hop;
    struct FingerInfo *finger;
    struct TrailPeerList *iterator;
    iterator = GNUNET_malloc (sizeof (struct TrailPeerList));
    finger = successor->data;
    iterator = finger->first_trail_head;
    next_hop = GNUNET_malloc (sizeof (struct GNUNET_PeerIdentity));
    memcpy (next_hop, &(iterator->peer), sizeof (struct GNUNET_PeerIdentity));
    memcpy (current_destination, &(finger->finger_identity), sizeof (struct GNUNET_PeerIdentity));
    memcpy (current_source, &my_identity, sizeof (struct GNUNET_PeerIdentity));
    return next_hop;
  }
  else
  {
    /* FIXME: This is returned when congested peer is the only peer or the only
     finger that we have is reachable through this congested peer. */
    GNUNET_assert (0);
    return NULL;
  }
}


/** FIXME: by default I keep current_source, and destination as my own id.
 * in case we find a finger then we update current_source in the 
 * find_successor message. 
 * Construct a Put message and send it to target_peer. 
 * @param key Key for the content  
 * @param data Content to store
 * @param data_size Size of content @a data in bytes
 * @param block_type Type of the block
 * @param options Routing options
 * @param desired_replication_level Desired replication count
 * @param expiration_time When does the content expire
 * @param current_destination 
 * @param current_source 
 * @param target_peer Peer to which this message will be forwarded.
 * @param hop_count Number of hops traversed so far.
 * @param put_path_length Total number of peers in @a put_path
 * @param put_path Number of peers traversed so far 
 */
void
GDS_NEIGHBOURS_send_put (const struct GNUNET_HashCode *key,
                         const void *data, size_t data_size,
                         enum GNUNET_BLOCK_Type block_type,
                         enum GNUNET_DHT_RouteOption options,
                         uint32_t desired_replication_level,
                         struct GNUNET_TIME_Absolute expiration_time,
                         struct GNUNET_PeerIdentity current_destination,
                         struct GNUNET_PeerIdentity current_source,
                         struct GNUNET_PeerIdentity *target_peer,
                         uint32_t hop_count,
                         uint32_t put_path_length,
                         struct GNUNET_PeerIdentity *put_path)
{
  struct PeerPutMessage *ppm;
  struct P2PPendingMessage *pending;
  struct FriendInfo *target_friend;
  struct GNUNET_PeerIdentity *pp;
  size_t msize;
  
  msize = put_path_length * sizeof (struct GNUNET_PeerIdentity) + data_size +
          sizeof (struct PeerPutMessage);
  
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
  
  /* This is the first call made from clients file. So, we should search for the
     target_friend. */
  if (NULL == target_peer)
  {
    uint64_t key_value;
    struct GNUNET_PeerIdentity *next_hop;
    
    memcpy (&key_value, key, sizeof (uint64_t));
    struct GNUNET_PeerIdentity curr_dest;
    struct GNUNET_PeerIdentity curr_src;
    memcpy (&curr_dest, &current_destination, sizeof (struct GNUNET_PeerIdentity));
    memcpy (&curr_src, &current_source, sizeof (struct GNUNET_PeerIdentity));
    next_hop = find_successor (key_value, &curr_dest, &curr_src, NULL);
    /* FIXME: I am copying back current_destination and current_source. but I am not 
     sure, if its correct. I am doing so just to remove the code from client file.*/
    memcpy (&current_destination, &curr_dest, sizeof (struct GNUNET_PeerIdentity));
    memcpy (&current_source, &curr_src, sizeof (struct GNUNET_PeerIdentity));
    
    if (NULL == next_hop) /* I am the destination do datacache_put */
    {
      GDS_DATACACHE_handle_put (expiration_time, key, put_path_length, put_path,
                                block_type, data_size, data);
      return;
    }
    else
      target_friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, next_hop);   
  }
  
  pending = GNUNET_malloc (sizeof (struct P2PPendingMessage) + msize);
  pending->timeout = expiration_time;
  ppm = (struct PeerPutMessage *) &pending[1];
  pending->msg = &ppm->header;
  ppm->header.size = htons (msize);
  ppm->header.type = htons (GNUNET_MESSAGE_TYPE_DHT_P2P_PUT);
  ppm->options = htonl (options);
  ppm->block_type = htonl (block_type);
  ppm->hop_count = htonl (hop_count + 1);
  ppm->desired_replication_level = htonl (desired_replication_level);
  ppm->put_path_length = htonl (put_path_length);
  ppm->expiration_time = GNUNET_TIME_absolute_hton (expiration_time);
  ppm->key = *key;
  ppm->current_destination = current_destination;
  ppm->current_source = current_source;
 
  pp = (struct GNUNET_PeerIdentity *) &ppm[1];
  if (put_path_length != 0)
  {
    memcpy (pp, put_path,
            sizeof (struct GNUNET_PeerIdentity) * put_path_length);
  }
  memcpy (&pp[put_path_length], data, data_size);
  GNUNET_CONTAINER_DLL_insert_tail (target_friend->head, target_friend->tail, pending);
  target_friend->pending_count++;
  process_friend_queue (target_friend);
}



/** FIXME: by default I keep current_source, and destination as my own id.
 * in case we find a finger then we update current_source in the 
 * find_successor message. 
 * Construct a Get message and send it to target_peer. 
 * @param key Key for the content  
 * @param block_type Type of the block
 * @param options Routing options
 * @param desired_replication_level Desired replication count
 * @param expiration_time When does the content expire
 * @param current_destination 
 * @param current_source 
 * @param target_peer Peer to which this message will be forwarded.
 * @param hop_count Number of hops traversed so far.
 * @param put_path_length Total number of peers in @a put_path
 * @param put_path Number of peers traversed so far 
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
  struct PeerGetMessage *pgm;
  struct P2PPendingMessage *pending;
  struct FriendInfo *target_friend;
  struct GNUNET_PeerIdentity *gp;
  size_t msize;
  
  msize = sizeof (struct PeerGetMessage) + 
          (get_path_length * sizeof (struct GNUNET_PeerIdentity));
  
  if (msize >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    return;
  }
  
  if (NULL == target_peer)
  {
    /* This is the first call from client file, we need to search for next_hop*/
    struct GNUNET_PeerIdentity *next_hop;
    uint64_t key_value;
    struct GNUNET_PeerIdentity curr_dest;
    struct GNUNET_PeerIdentity curr_src;
    memcpy (&curr_dest, &current_destination, sizeof (struct GNUNET_PeerIdentity));
    memcpy (&curr_src, &current_source, sizeof (struct GNUNET_PeerIdentity));
    memcpy (&key_value, key, sizeof (uint64_t));
    next_hop = find_successor (key_value, &curr_dest, &curr_src, NULL);
    /* FIXME: Again I am copying back value of current_destination, current_source,
     Think of a better solution. */
    memcpy (&current_destination, &curr_dest, sizeof (struct GNUNET_PeerIdentity));
    memcpy (&current_source, &curr_src, sizeof (struct GNUNET_PeerIdentity));
    if (NULL == next_hop) /* I am the destination do datacache_put */
    {
      GDS_DATACACHE_handle_get (key,block_type, NULL, 0, 
                                NULL, 0, 1, &my_identity, NULL,&my_identity);
      return;
    }
    else
    {
      target_friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, next_hop);
    }
  }
  
  pending = GNUNET_malloc (sizeof (struct P2PPendingMessage) + msize);
  pending->importance = 0;    /* FIXME */
  pgm = (struct PeerGetMessage *) &pending[1];
  pending->msg = &pgm->header;
  pgm->header.size = htons (msize);
  pgm->header.type = htons (GNUNET_MESSAGE_TYPE_DHT_P2P_GET);
  pgm->get_path_length = htonl (get_path_length);
  pgm->key = *key;
  pgm->current_destination = current_destination;
  pgm->current_source = current_source;
  pgm->hop_count = htonl (hop_count + 1);
  
  gp = (struct GNUNET_PeerIdentity *) &pgm[1];
  memcpy (gp, get_path, get_path_length * sizeof (struct GNUNET_PeerIdentity));
  GNUNET_CONTAINER_DLL_insert_tail (target_friend->head, target_friend->tail, pending);
  target_friend->pending_count++;
  process_friend_queue (target_friend);
}


/**
 * Send the get result to requesting client.
 * @param expiration When will this result expire?
 * @param key Key of the requested data.
 * @param put_path_length Number of peers in @a put_path
 * @param put_path Path taken to put the data at its stored location.
 * @param type Block type
 * @param data_size Size of the @a data 
 * @param data Payload to store
 * @param get_path Path taken to reach to the location of the key.
 * @param get_path_length Number of peers in @a get_path
 * @param next_hop Next peer to forward the message to. 
 * @param source_peer Peer which has the data for the key.
 */
void 
GDS_NEIGHBOURS_send_get_result (struct GNUNET_TIME_Absolute expiration,
                                const struct GNUNET_HashCode *key,
                                unsigned int put_path_length,
                                const struct GNUNET_PeerIdentity *put_path,
                                enum GNUNET_BLOCK_Type type, size_t data_size,
                                const void *data,
                                struct GNUNET_PeerIdentity *get_path,
                                unsigned int get_path_length,
                                struct GNUNET_PeerIdentity *next_hop,
                                struct GNUNET_PeerIdentity *source_peer)
{
  struct PeerGetResultMessage *get_result;
  struct GNUNET_PeerIdentity *get_result_path;
  struct GNUNET_PeerIdentity *pp;
  struct P2PPendingMessage *pending;
  struct FriendInfo *target_friend;
  int current_path_index;
  size_t msize;
  
  msize = get_path_length * sizeof (struct GNUNET_PeerIdentity) + data_size +
          sizeof (struct PeerPutMessage);
 
  if (msize >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    return;
  }
  
  current_path_index = search_my_index(get_path, get_path_length);
  /* FIXME: handle the case when current_path_index = GNUNET_SYSERR;*/
  if (0 == current_path_index)
  {
    GDS_CLIENTS_handle_reply (expiration, key, get_path_length, get_path, put_path_length,
                              put_path, type, data_size, data);
    return;
  }
  pending = GNUNET_malloc (sizeof (struct P2PPendingMessage) + msize);
  pending->importance = 0;   
  get_result = (struct PeerGetResultMessage *)&pending[1];
  pending->msg = &get_result->header;
  get_result->header.size = htons (msize);
  get_result->header.type = htons (GNUNET_MESSAGE_TYPE_DHT_P2P_GET_RESULT);
  get_result->key = *key;
  memcpy (&(get_result->source_peer), source_peer, sizeof (struct GNUNET_PeerIdentity));
  get_result->expiration_time = expiration;
  
  get_result_path = (struct GNUNET_PeerIdentity *)&get_result[1];
  memcpy (get_result_path, get_path,
          sizeof (struct GNUNET_PeerIdentity) * get_path_length);
  memcpy (&get_result_path[get_path_length], data, data_size);
  /* FIXME: Is this correct? */
  pp = (struct GNUNET_PeerIdentity *)&get_result_path[1];
  memcpy (pp, put_path,sizeof (struct GNUNET_PeerIdentity) * put_path_length);
  
  target_friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, next_hop);
  GNUNET_CONTAINER_DLL_insert_tail (target_friend->head, target_friend->tail, pending);
  target_friend->pending_count++;
  process_friend_queue (target_friend);
}


/**
 * Send tral rejection message to the peer which sent me a trail setup message. 
 * @param source_peer Source peer which wants to set up the trail.
 * @param finger_identity Value whose successor will be the finger of @a source_peer.
 * @param congested_peer Peer which has send trail rejection message.
 * @param next_hop Peer to which this message should be forwarded.
 * @param finger_map_index Index in @a source_peer finger peermap.
 * @param trail_peer_list Trail followed to reach from @a source_peer to next_hop,
 *                        NULL, in case the @a congested_peer was the first peer 
 *                        to which trail setup message was forwarded.
 * @param trail_length Number of peers in trail_peer_list. 
 */
void
GDS_NEIGHBOURS_send_trail_rejection (struct GNUNET_PeerIdentity *source_peer,
                                     uint64_t finger_identity,
                                     struct GNUNET_PeerIdentity *congested_peer,
                                     const struct GNUNET_PeerIdentity *next_hop,
                                     unsigned int finger_map_index,
                                     struct GNUNET_PeerIdentity *trail_peer_list,
                                     unsigned int trail_length)
{
  struct PeerTrailRejectionMessage *trail_rejection;
  struct GNUNET_PeerIdentity *trail_list;
  struct P2PPendingMessage *pending;
  struct FriendInfo *target_friend;
  size_t msize;
  
  msize = trail_length * sizeof(struct GNUNET_PeerIdentity) +
          sizeof (struct PeerTrailRejectionMessage);
  
  if (msize >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    return;
  }
  
  pending = GNUNET_malloc (sizeof (struct P2PPendingMessage) + msize); 
  pending->importance = 0;    
  pending->timeout = GNUNET_TIME_relative_to_absolute (GET_TIMEOUT);
  trail_rejection = (struct PeerTrailRejectionMessage *) &pending[1]; 
  pending->msg = &trail_rejection->header;
  trail_rejection->header.size = htons (msize);
  trail_rejection->header.type = htons (GNUNET_MESSAGE_TYPE_DHT_P2P_TRAIL_SETUP);
  memcpy (&(trail_rejection->source_peer), source_peer, sizeof (struct GNUNET_PeerIdentity));
  memcpy (&(trail_rejection->congested_peer), congested_peer, sizeof (struct GNUNET_PeerIdentity));
  memcpy (&(trail_rejection->finger_identity_value), &finger_identity, sizeof (uint64_t));
  trail_rejection->finger_map_index = htonl(finger_map_index);
  trail_rejection->trail_length = htonl (trail_length);
  
  trail_list = (struct GNUNET_PeerIdentity *)&trail_rejection[1];
  if (trail_length != 0)
    memcpy (trail_list, trail_peer_list, trail_length * sizeof (struct GNUNET_PeerIdentity));
  
  target_friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, next_hop);
  GNUNET_CONTAINER_DLL_insert_tail (target_friend->head, target_friend->tail, pending);
  target_friend->pending_count++;
  process_friend_queue (target_friend);
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
  struct PeerPutMessage *put;
  struct GNUNET_PeerIdentity *put_path;
  struct GNUNET_HashCode test_key;
  enum GNUNET_DHT_RouteOption options;
  struct GNUNET_PeerIdentity current_destination;
  struct GNUNET_PeerIdentity current_source;
  struct GNUNET_PeerIdentity *next_hop;
  void *payload;
  size_t msize;
  uint32_t putlen;
  size_t payload_size;
  uint64_t key_value;
  
  msize = ntohs (message->size);
  if (msize < sizeof (struct PeerPutMessage))
  {
    GNUNET_break_op (0);
    return GNUNET_YES;
  }
  
  put = (struct PeerPutMessage *) message;
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
  
  current_destination = put->current_destination;
  current_source = put->current_source;
  put_path = (struct GNUNET_PeerIdentity *) &put[1];
  payload = &put_path[putlen];
  options = ntohl (put->options);
  payload_size = msize - (sizeof (struct PeerPutMessage) + 
                          putlen * sizeof (struct GNUNET_PeerIdentity));
  
  switch (GNUNET_BLOCK_get_key (GDS_block_context, ntohl (put->block_type),
                                payload, payload_size, &test_key))
  {
    case GNUNET_YES:
      if (0 != memcmp (&test_key, &put->key, sizeof (struct GNUNET_HashCode)))
      {
        char *put_s = GNUNET_strdup (GNUNET_h2s_full (&put->key));
        GNUNET_break_op (0);
        GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                    "PUT with key `%s' for block with key %s\n",
                     put_s, GNUNET_h2s_full (&test_key));
        GNUNET_free (put_s);
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
  
   if (ntohl (put->block_type) == GNUNET_BLOCK_TYPE_REGEX) /* FIXME: do for all tpyes */
  {
    switch (GNUNET_BLOCK_evaluate (GDS_block_context,
                                   ntohl (put->block_type),
                                   NULL,    /* query */
                                   NULL, 0, /* bloom filer */
                                   NULL, 0, /* xquery */
                                   payload, payload_size))
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
      return GNUNET_OK;
    }
  }
  
   struct GNUNET_PeerIdentity pp[putlen + 1];
  /* extend 'put path' by sender */
  /* FIXME: Check what are we doing here? */
  if (0 != (options & GNUNET_DHT_RO_RECORD_ROUTE))
  {
    memcpy (pp, put_path, putlen * sizeof (struct GNUNET_PeerIdentity));
    pp[putlen] = *peer;
    putlen++;
  }
  else
    putlen = 0;
  
  memcpy (&key_value, &(put->key), sizeof (uint64_t));
  if (0 != (GNUNET_CRYPTO_cmp_peer_identity (&current_destination, &my_identity)))
  {
     next_hop = GDS_ROUTING_search (&current_source, &current_destination, peer);
     if (next_hop == NULL)
     {
       /* refer to handle_dht_p2p_trail_setup. */
     }
  }
  else
  {
    next_hop = find_successor (key_value, &current_destination, &current_source, NULL); 
  }
  
  if (NULL == next_hop) /* I am the final destination */
  {
    GDS_DATACACHE_handle_put (GNUNET_TIME_absolute_ntoh (put->expiration_time),
                              &(put->key),putlen, pp, ntohl (put->block_type), 
                              payload_size, payload);
     return GNUNET_YES;
  }
  else
  {
    GDS_CLIENTS_process_put (options,
                              ntohl (put->block_type),
                              ntohl (put->hop_count),
                              ntohl (put->desired_replication_level),
                              putlen, pp,
                              GNUNET_TIME_absolute_ntoh (put->expiration_time),
                              &put->key,
                              payload,
                              payload_size);
    
    GDS_NEIGHBOURS_send_put (&put->key, payload, payload_size, 
                             ntohl (put->block_type),ntohl (put->options),
                             ntohl (put->desired_replication_level),
                             GNUNET_TIME_absolute_ntoh (put->expiration_time),
                             current_destination, current_source, next_hop,
                             ntohl (put->hop_count), putlen, pp);
 
     return GNUNET_YES;
  }
  return GNUNET_SYSERR;
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
  struct PeerGetMessage *get;
  struct GNUNET_PeerIdentity *get_path;
  struct GNUNET_PeerIdentity current_destination;
  struct GNUNET_PeerIdentity current_source;
  struct GNUNET_PeerIdentity *next_hop;
  uint32_t get_length;
  uint64_t key_value;
  size_t msize;
  
  msize = ntohs (message->size);
  if (msize < sizeof (struct PeerGetMessage))
  {
    GNUNET_break_op (0);
    return GNUNET_YES;
  }
  
  get = (struct PeerGetMessage *)message;
  get_length = ntohl (get->get_path_length);
  get_path = (struct GNUNET_PeerIdentity *)&get[1];
  current_destination = get->current_destination;
  current_source = get->current_source;
  
  if ((msize <
       sizeof (struct PeerGetMessage) +
       get_length * sizeof (struct GNUNET_PeerIdentity)) ||
       (get_length >
        GNUNET_SERVER_MAX_MESSAGE_SIZE / sizeof (struct GNUNET_PeerIdentity)))
  {
    GNUNET_break_op (0);
    return GNUNET_YES; 
  }
  
  /* Add sender to get path */
  struct GNUNET_PeerIdentity gp[get_length + 1];
  memcpy (gp, get_path, get_length * sizeof (struct GNUNET_PeerIdentity));
  gp[get_length + 1] = *peer;
  get_length = get_length + 1;
  
  memcpy (&key_value, &(get->key), sizeof (uint64_t));
  if (0 != (GNUNET_CRYPTO_cmp_peer_identity (&current_destination, &my_identity)))
  {
     next_hop = GDS_ROUTING_search (&current_source, &current_destination, peer);
     if (next_hop == NULL)
     {
       /* refer to handle_dht_p2p_trail_setup. */
     }
  }
  else
  {
    next_hop = find_successor (key_value, &current_destination, &current_source, NULL); 
  }
  
  if (NULL == next_hop)
  {
    /* FIXME: Try to make this code also short and remove useless variables. */
    struct GNUNET_PeerIdentity final_get_path[get_length+1];
    memcpy (final_get_path, gp, get_length * sizeof (struct GNUNET_PeerIdentity));
    memcpy (&final_get_path[get_length+1], &my_identity, sizeof (struct GNUNET_PeerIdentity));
    get_length = get_length + 1;
    struct GNUNET_PeerIdentity *next_hop;
    next_hop = GNUNET_malloc (sizeof (struct GNUNET_PeerIdentity));
    memcpy (next_hop, &final_get_path[get_length-2], sizeof (struct GNUNET_PeerIdentity));
    GDS_DATACACHE_handle_get (&(get->key),(get->block_type), NULL, 0, NULL, 0,
                              get_length, final_get_path,next_hop, &my_identity);

    return GNUNET_YES;
  }
  else
  {
    GDS_NEIGHBOURS_send_get (&(get->key), get->block_type, get->options, 
                             get->desired_replication_level,current_destination,
                             current_source, next_hop, 0,
                             get_length, gp);
  }
  return GNUNET_SYSERR;
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
  /* If you are the source, go back to the client file and there search for
   the requesting client and send back the result. */
  struct PeerGetResultMessage *get_result;
  struct GNUNET_PeerIdentity *get_path;
  struct GNUNET_PeerIdentity *put_path;
  void *payload;
  size_t payload_size;
  size_t msize;
  unsigned int getlen;
  unsigned int putlen;
  int current_path_index;
  
  msize = ntohs (message->size);
  if (msize < sizeof (struct PeerGetResultMessage))
  {
    GNUNET_break_op (0);
    return GNUNET_YES;
  }
  
  get_result = (struct PeerGetResultMessage *)message;
  getlen = ntohl (get_result->get_path_length);
  putlen = ntohl (get_result->put_path_length);
  
  if ((msize <
       sizeof (struct PeerGetResultMessage) +
       getlen * sizeof (struct GNUNET_PeerIdentity) + 
       putlen * sizeof (struct GNUNET_PeerIdentity)) ||
      (getlen >
       GNUNET_SERVER_MAX_MESSAGE_SIZE / sizeof (struct GNUNET_PeerIdentity) ||
      (putlen >
         GNUNET_SERVER_MAX_MESSAGE_SIZE / sizeof (struct GNUNET_PeerIdentity))))
  {
    GNUNET_break_op (0);
    return GNUNET_YES;
  }
  
  get_path = (struct GNUNET_PeerIdentity *) &get_result[1];
  payload = &get_path[getlen];
  payload_size = msize - (sizeof (struct PeerGetResultMessage) + 
                          getlen * sizeof (struct GNUNET_PeerIdentity));
  /* FIXME: Check if its correct or not. */

  if (putlen > 0)
    put_path = &get_path[1];
  else
    put_path = NULL;
  
  if (0 == (GNUNET_CRYPTO_cmp_peer_identity (&my_identity, &(get_path[0]))))
  {
    //GDS_CLIENTS_process_get_result();
    GDS_CLIENTS_handle_reply (get_result->expiration_time, &(get_result->key), 
                              getlen, get_path, putlen,
                              put_path, get_result->type, payload_size, payload);
    return GNUNET_YES;
  }
  else
  {
    struct GNUNET_PeerIdentity *next_hop;
    next_hop = GNUNET_malloc (sizeof (struct GNUNET_PeerIdentity));
    /* FIXME: handle the case when current_path_index = GNUNET_SYSERR;*/
    current_path_index = search_my_index (get_path, getlen);
    /* FIXME: First check if you are adding yourself to the get path or not.
     if yes then don't check if current_path_index == 0, if not then check 
     and next_hop == source_peer. */
    memcpy (next_hop, &get_path[current_path_index - 1], sizeof (struct GNUNET_PeerIdentity));
  
    GDS_NEIGHBOURS_send_get_result (get_result->expiration_time, &(get_result->key),
                                     putlen, put_path,
                                     get_result->type, payload_size,payload,
                                     get_path, getlen,
                                     next_hop, &(get_result->source_peer));
    return GNUNET_YES;
  }  
  return GNUNET_SYSERR;
}


/** 
 * Core handle for PeerTrailSetupMessage. 
 * @param cls closure
 * @param message message
 * @param peer peer identity this notification is about
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static int
handle_dht_p2p_trail_setup (void *cls, const struct GNUNET_PeerIdentity *peer,
                            const struct GNUNET_MessageHeader *message)
{
  const struct PeerTrailSetupMessage *trail_setup; 
  struct GNUNET_PeerIdentity current_destination;
  struct GNUNET_PeerIdentity current_source;
  struct GNUNET_PeerIdentity source;
  struct GNUNET_PeerIdentity *next_hop;
  struct GNUNET_PeerIdentity next_peer;
  struct GNUNET_PeerIdentity *trail_peer_list;
  struct FriendInfo *target_friend;
  uint64_t destination_finger_value;
  uint32_t trail_length;
  uint32_t finger_map_index;
  size_t msize;

  msize = ntohs (message->size);
  if (msize < sizeof (struct PeerTrailSetupMessage))
  {
    GNUNET_break_op (0);
    return GNUNET_YES;
  }
  
  trail_setup = (const struct PeerTrailSetupMessage *) message; 
  trail_length = ntohl (trail_setup->trail_length); 
  
  if ((msize < sizeof (struct PeerTrailSetupMessage) +
       trail_length * sizeof (struct GNUNET_PeerIdentity)) ||
       (trail_length >
        GNUNET_SERVER_MAX_MESSAGE_SIZE / sizeof (struct GNUNET_PeerIdentity)))
  {
    GNUNET_break_op (0);
    return GNUNET_OK; 
  }
  
  trail_peer_list = (struct GNUNET_PeerIdentity *)&trail_setup[1];
  current_destination = trail_setup->current_destination;
  current_source = trail_setup->current_source;
  source = trail_setup->source_peer;
  finger_map_index = ntohl (trail_setup->finger_map_index);
  destination_finger_value = ntohl (trail_setup->destination_finger);
  
  /* My routing state size has crossed the threshold, I can not be part of any more
   * trails. */
  if(GDS_ROUTING_check_threshold())
  {
    /* No more trails possible through me. send a trail rejection message. */
    GDS_NEIGHBOURS_send_trail_rejection (&source, destination_finger_value, &my_identity,
                                         peer,finger_map_index, trail_peer_list,trail_length);
    return GNUNET_OK;
  }
  
  /* Check if you are current_destination or not. */
  if (0 != (GNUNET_CRYPTO_cmp_peer_identity (&current_destination, &my_identity)))
  {
    next_hop = GDS_ROUTING_search (&current_source, &current_destination, peer);
    /* ADDNOW: OPTIMIZATION: do find_successor also and get a better path if possible. */
    
    if (next_hop == NULL)
    {
      /* FIXME  next_hop is NULL, in a case when next_hop was a friend which got disconnected
       * and we removed the trail from our routing trail. So, I can send the message
       * to other peer or can drop the message. VERIFY which will be the correct
       * thing to do. next_hop to NULL, 1. statistics update, drop the message. 
       * 2. complain to sender with new message: trail lost */
      return GNUNET_OK;
    }
  }
  else
  {
    next_hop = find_successor (destination_finger_value, &current_destination, &current_source, NULL); 
  }
  
  if (0 == (GNUNET_CRYPTO_cmp_peer_identity (&current_destination, &my_identity))) /* This means I am the final destination */
  {
    /* SUPU: trail length is 0, when I am the friend of the source peer. */
    if (trail_length == 0)
    {
      memcpy (&next_peer, &source, sizeof (struct GNUNET_PeerIdentity));
    }
    else
    {
      memcpy (&next_peer, &trail_peer_list[trail_length-1], sizeof (struct GNUNET_PeerIdentity));
    }
  
    target_friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, &next_peer);
    /* ! HAVE A PREDECESSOR || (source_peer closer than existing PREDECESOR) */
    compare_and_update_predecessor (&source, trail_peer_list, trail_length );
    
    GDS_NEIGHBOURS_send_trail_setup_result (&source,
                                            &(my_identity),
                                            target_friend, trail_length,
                                            trail_peer_list,
                                            finger_map_index);
    return GNUNET_OK;
  }
  else
  {
    /* Now add yourself to the trail. */
    struct GNUNET_PeerIdentity peer_list[trail_length + 1];
    memcpy (peer_list, trail_peer_list, trail_length * sizeof (struct GNUNET_PeerIdentity));
    peer_list[trail_length] = my_identity;
    trail_length++;
    
    target_friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, next_hop);
    GDS_NEIGHBOURS_send_trail_setup (&source,
                                     destination_finger_value,
                                     &current_destination, &current_source,
                                     target_friend, trail_length, peer_list, 
                                     finger_map_index);
    return GNUNET_OK;
  }
  return GNUNET_SYSERR;
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
  const struct PeerTrailSetupResultMessage *trail_result;
  struct GNUNET_PeerIdentity *trail_peer_list;
  uint32_t trail_length;
  uint32_t finger_map_index;
  size_t msize;
  
  msize = ntohs (message->size);
  if (msize < sizeof (struct PeerTrailSetupResultMessage))
  {
    GNUNET_break_op (0);
    return GNUNET_YES;
  }
  
  trail_result = (const struct PeerTrailSetupResultMessage *) message; 
  trail_length = ntohl (trail_result->trail_length); 
  
  if ((msize <
       sizeof (struct PeerTrailSetupResultMessage) +
       trail_length * sizeof (struct GNUNET_PeerIdentity)) ||
       (trail_length >
        GNUNET_SERVER_MAX_MESSAGE_SIZE / sizeof (struct GNUNET_PeerIdentity)))
  {
    GNUNET_break_op (0);
    return GNUNET_YES;
  }
  
  finger_map_index = htonl (trail_result->finger_map_index);
  trail_peer_list = (struct GNUNET_PeerIdentity *) &trail_result[1];
  
  if (0 == (GNUNET_CRYPTO_cmp_peer_identity (&(trail_result->destination_peer),
                                             &my_identity)))
  {
      finger_table_add (&(trail_result->finger_identity), trail_peer_list, trail_length, 
                       finger_map_index);
      return GNUNET_YES;
  }
  else
  {
    struct GNUNET_PeerIdentity next_hop;
    struct FriendInfo *target_friend;
    int my_index;
    
    /* FIXME: handle the case when current_path_index = GNUNET_SYSERR;*/
    /* FIXME: Make sure you are passing the current length */
    my_index =  search_my_index (trail_peer_list, trail_length);
    if (my_index == 0)
    {
      next_hop = trail_result->destination_peer;
    }
    else
      next_hop = trail_peer_list[my_index - 1];
    
    /* Finger table of destination peer will not contain any trail for the case
     * where destination peer is its own finger identity. */
    if (0 != (GNUNET_CRYPTO_cmp_peer_identity (&(trail_result->destination_peer),
                                               &(trail_result->finger_identity))))
    {
      GDS_ROUTING_add (&(trail_result->destination_peer), &(trail_result->finger_identity),
                       peer, &next_hop); 
    }
    
    target_friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, &next_hop);
    GDS_NEIGHBOURS_send_trail_setup_result (&(trail_result->destination_peer),
                                            &(trail_result->finger_identity),
                                            target_friend, trail_length,
                                            trail_peer_list,
                                            finger_map_index);
    return GNUNET_YES;
  }
  return GNUNET_SYSERR;
}


/**
 * FIXME: Use flag in the case finger peer map does not contain predcessor
 * then its NULL. Ideally it should never happen. Some one sent you are verify
 * successor and you don't have any predecessor, then ideally you should 
 * GNUNET_break_op(0).
 * Get my current predecessor from the finger peer map
 * @return Current predecessor.
 */
static struct FingerInfo *
get_predecessor()
{
  struct GNUNET_CONTAINER_MultiPeerMapIterator *finger_iter;
  struct GNUNET_PeerIdentity key_ret;
  unsigned int finger_index;
  struct FingerInfo *my_predecessor;
 
  /* Iterate over finger peer map and extract your predecessor. */
  finger_iter = GNUNET_CONTAINER_multipeermap_iterator_create (finger_peermap);  
  for (finger_index = 0; finger_index < GNUNET_CONTAINER_multipeermap_size (finger_peermap); finger_index++)
  {
    if(GNUNET_YES == GNUNET_CONTAINER_multipeermap_iterator_next 
                       (finger_iter,&key_ret,(const void **)&my_predecessor)) 
    {
      if(1 == my_predecessor->finger_map_index)
      {
        break;
      }
    }
  }
  GNUNET_CONTAINER_multipeermap_iterator_destroy (finger_iter);
  return my_predecessor;
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
  const struct PeerVerifySuccessorMessage *vsm;
  const struct GNUNET_PeerIdentity *trail_peer_list;
  struct GNUNET_PeerIdentity source_peer;
  struct GNUNET_PeerIdentity next_hop;
  struct FriendInfo *target_friend;
  size_t msize;
  uint32_t trail_length;
   
  msize = ntohs (message->size);
  if (msize < sizeof (struct PeerVerifySuccessorMessage))
  {
    GNUNET_break_op (0);
    return GNUNET_YES;
  }
  
  vsm = (struct PeerVerifySuccessorMessage *) message;
  trail_length = ntohl (vsm->trail_length);
  
  if ((msize < sizeof (struct PeerVerifySuccessorMessage) +
               trail_length * sizeof (struct GNUNET_PeerIdentity)) ||
      (trail_length > GNUNET_SERVER_MAX_MESSAGE_SIZE / sizeof (struct GNUNET_PeerIdentity)))
  {
    GNUNET_break_op (0);
    return GNUNET_YES;
  }
   
  trail_peer_list = (const struct GNUNET_PeerIdentity *)&vsm[1];
  memcpy (&source_peer, &(vsm->source_peer), sizeof(struct GNUNET_PeerIdentity));
  if(0 == (GNUNET_CRYPTO_cmp_peer_identity (&(vsm->successor),&my_identity)))
  {
    struct FingerInfo *my_predecessor;
    
    if (trail_length == 0)
      memcpy (&next_hop, &source_peer, sizeof (struct GNUNET_PeerIdentity));
    else
    {
      int current_trail_index;
      current_trail_index = search_my_index (trail_peer_list, trail_length);
      memcpy (&next_hop, &trail_peer_list[current_trail_index-1], sizeof (struct GNUNET_PeerIdentity));
    }
    target_friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, &next_hop);
    
    my_predecessor = get_predecessor();
    if (0 == (GNUNET_CRYPTO_cmp_peer_identity (&source_peer,
                                               &(my_predecessor->finger_identity))))
    {
      
      GDS_NEIGHBOURS_send_verify_successor_result (&source_peer,
                                                   &(my_identity),
                                                   &(my_predecessor->finger_identity),
                                                   target_friend,
                                                   trail_peer_list,
                                                   trail_length);
    }
    else
    {
      struct GNUNET_PeerIdentity *new_successor_trail;
      struct TrailPeerList *iterator;
      int new_trail_length;
      int i;
      
      new_trail_length = trail_length + my_predecessor->first_trail_length + 1;
      new_successor_trail = GNUNET_malloc (sizeof (struct GNUNET_PeerIdentity) * new_trail_length);
      memcpy (new_successor_trail, trail_peer_list, (trail_length) * sizeof (struct GNUNET_PeerIdentity));
      memcpy (&new_successor_trail[trail_length], &my_identity, sizeof (struct GNUNET_PeerIdentity));
      
      iterator = GNUNET_malloc (sizeof (struct TrailPeerList));
      iterator = my_predecessor->first_trail_head; 
      i = trail_length + 1;
      while (i < new_trail_length)
      {
        memcpy (&new_successor_trail[i], &(iterator->peer), sizeof (struct GNUNET_PeerIdentity));
        iterator = iterator->next;
        i++;
      }
 
      GDS_NEIGHBOURS_send_verify_successor_result (&source_peer,
                                                   &(my_identity),
                                                   &(my_predecessor->finger_identity),
                                                   target_friend,
                                                   new_successor_trail,
                                                   new_trail_length); 
    }      
    
  }
  else
  {
   int my_index;
    /* FIXME: handle the case when current_path_index = GNUNET_SYSERR;*/
    /* FIXME: make sure you are passing the correct trail length */
   my_index = search_my_index (trail_peer_list, trail_length);
   memcpy (&next_hop, &trail_peer_list[my_index + 1], sizeof (struct GNUNET_PeerIdentity));
   target_friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, &next_hop);
      
   GDS_NEIGHBOURS_send_verify_successor (&(vsm->source_peer), &(vsm->successor),target_friend,
                                          trail_peer_list, trail_length); 
  }
  return GNUNET_SYSERR;
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
  const struct PeerVerifySuccessorResultMessage *vsrm;
  struct GNUNET_PeerIdentity *trail_peer_list;
  struct GNUNET_PeerIdentity next_hop;
  struct FriendInfo *target_friend;
  size_t msize;
  uint32_t trail_length;
  
  msize = ntohs (message->size);
  if (msize < sizeof (struct PeerVerifySuccessorResultMessage))
  {
    GNUNET_break_op (0);
    return GNUNET_YES;
  }
  
  vsrm = (const struct PeerVerifySuccessorResultMessage *) message;
  trail_length = ntohl (vsrm->trail_length); 
  
  if ((msize <
       sizeof (struct PeerVerifySuccessorResultMessage) +
       trail_length * sizeof (struct GNUNET_PeerIdentity)) ||
       (trail_length >
       GNUNET_SERVER_MAX_MESSAGE_SIZE / sizeof (struct GNUNET_PeerIdentity)))
  {
    GNUNET_break_op (0);
    return GNUNET_YES;
  }
  
  trail_peer_list = (struct GNUNET_PeerIdentity *) &vsrm[1];
  
  if(0 == (GNUNET_CRYPTO_cmp_peer_identity (&(vsrm->destination_peer), &(my_identity))))
  {
    if(0 != (GNUNET_CRYPTO_cmp_peer_identity (&(vsrm->my_predecessor), &(my_identity))))
    {
      finger_table_add (&(vsrm->my_predecessor), trail_peer_list, trail_length, 0);
      memcpy (&next_hop, &trail_peer_list[0], sizeof (struct GNUNET_PeerIdentity));
      target_friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, &next_hop);
      GDS_NEIGHBOURS_send_notify_new_successor (&my_identity, &(vsrm->my_predecessor),
                                                target_friend, trail_peer_list,
                                                trail_length);
      return GNUNET_OK;
    }
  }
  else
  {
    int my_index;
    /* FIXME: handle the case when current_path_index = GNUNET_SYSERR;*/
    /* FIXME: make sure you are passing the correct trail length */
    my_index = search_my_index (trail_peer_list, trail_length);
    if (my_index == 1)
      memcpy (&next_hop, &(vsrm->destination_peer), sizeof (struct GNUNET_PeerIdentity));
    else
      memcpy (&next_hop, &trail_peer_list[my_index-1], sizeof (struct GNUNET_PeerIdentity));
    target_friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, &next_hop); 
    GDS_NEIGHBOURS_send_verify_successor_result (&(vsrm->destination_peer),
                                                 &(vsrm->source_successor),
                                                 &(vsrm->my_predecessor),
                                                 target_friend,
                                                 trail_peer_list,
                                                 trail_length); 
    return GNUNET_OK;
  }
  return GNUNET_SYSERR;
}


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
  const struct PeerNotifyNewSuccessorMessage *nsm;
  struct GNUNET_PeerIdentity *trail_peer_list;
  size_t msize;
  uint32_t trail_length;
  
  msize = ntohs (message->size);
  if (msize < sizeof (struct PeerNotifyNewSuccessorMessage))
  {
    GNUNET_break_op (0);
    return GNUNET_YES;
  }
  
  nsm = (const struct PeerNotifyNewSuccessorMessage *) message;
  trail_length = ntohl (nsm->trail_length);
  
  if ((msize < sizeof (struct PeerNotifyNewSuccessorMessage) +
               trail_length * sizeof (struct GNUNET_PeerIdentity)) ||
      (trail_length >
       GNUNET_SERVER_MAX_MESSAGE_SIZE / sizeof (struct GNUNET_PeerIdentity)))
  {
    GNUNET_break_op (0);
    return GNUNET_YES;
  }
  
  trail_peer_list = (struct GNUNET_PeerIdentity *) &nsm[1];
  
  if(0 == (GNUNET_CRYPTO_cmp_peer_identity (&(nsm->destination_peer), &my_identity)))
  {
    //update_predecessor (&(nsm->destination_peer), trail_peer_list);
    return GNUNET_OK;
  }
  else
  {
    struct FriendInfo *target_friend;
    struct GNUNET_PeerIdentity next_hop;
    int my_index;
    
    /* FIXME: handle the case when current_path_index = GNUNET_SYSERR;*/
    /* FIXME: check that trail length is correct. */
    my_index = search_my_index (trail_peer_list, trail_length);
    memcpy (&next_hop, &trail_peer_list[my_index+1], sizeof (struct GNUNET_PeerIdentity));
    target_friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, &next_hop);
    GDS_NEIGHBOURS_send_notify_new_successor (&(nsm->source_peer), 
                                              &(nsm->destination_peer),
                                              target_friend, trail_peer_list,
                                              trail_length);
    return GNUNET_OK;
  }
  return GNUNET_SYSERR;
}


/**
 * Core handler for P2P trail rejection message 
 * @param cls closure
 * @param message message
 * @param peer peer identity this notification is about
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static
int handle_dht_p2p_trail_rejection(void *cls, const struct GNUNET_PeerIdentity *peer,
                                   const struct GNUNET_MessageHeader *message)
{
  /* Here you have recevied the message it means that the peer next to you have
   failed to setup the trail to the finger identity value. now you should call 
   find_successor and make sure that you don't choose the peer as next hop
   in order to do so, you need to pass a new parameter to find successor,
   congested peer - a peer which you should ignore. once you have found this
   peer then just send a trail setup message to that peer. In case you are
   also congested then remove yourself from the trail as this message
   reached to as you are part of the trail. and then send the message to
   element before you. Ideally you should be the last element in the trail as
   all the the elements before you have rejected you. In case you are source,
   then you should call select_random_Friend(congested_peer). in case you don't
   find any peer because congested peer then set flag that all friends are busy
   and leave. */
  const struct PeerTrailRejectionMessage *trail_rejection;
  struct GNUNET_PeerIdentity *trail_peer_list;
  struct GNUNET_PeerIdentity source_peer;
  struct GNUNET_PeerIdentity congested_peer;
  struct FriendInfo *target_friend;
  struct GNUNET_PeerIdentity next_peer;
  struct GNUNET_PeerIdentity *next_hop;
  struct GNUNET_PeerIdentity current_source;
  struct GNUNET_PeerIdentity current_destination;
  size_t msize;
  uint32_t trail_length;
  uint32_t finger_map_index;
  uint64_t destination_finger_value;
  
  msize = ntohs (message->size);
  if (msize < sizeof (struct PeerTrailRejectionMessage))
  {
    GNUNET_break_op (0);
    return GNUNET_YES;
  }
  
  trail_rejection = (struct PeerTrailRejectionMessage *) message;
  trail_length = ntohl (trail_rejection->trail_length);
  
  if ((msize < sizeof (struct PeerTrailRejectionMessage) +
               trail_length * sizeof (struct GNUNET_PeerIdentity)) ||
      (trail_length >
       GNUNET_SERVER_MAX_MESSAGE_SIZE / sizeof (struct GNUNET_PeerIdentity)))
  {
    GNUNET_break_op (0);
    return GNUNET_YES;
  }
  trail_peer_list = (struct GNUNET_PeerIdentity *)&trail_rejection[1];
  finger_map_index = ntohl (trail_rejection->finger_map_index);
  memcpy (&source_peer, &(trail_rejection->source_peer), sizeof(struct GNUNET_PeerIdentity));
  memcpy (&destination_finger_value, &(trail_rejection->finger_identity_value), sizeof (uint64_t));
  memcpy (&congested_peer, &(trail_rejection->congested_peer), sizeof (struct GNUNET_PeerIdentity));
  
  /* If I am the source of the original trail setup message, then again select
   a random friend and send a new trail setup message to this finger identity
   value. */
  if(0 == (GNUNET_CRYPTO_cmp_peer_identity (&my_identity, &source_peer)))
  {
    /* If friend peer map is empty, or all the friends trail threshold has been crossed,
     * then return. */
    if ((GNUNET_CONTAINER_multipeermap_size (friend_peermap) == 0) ||
        (all_friends_trail_threshold == GNUNET_YES))
    {
      GNUNET_break(0);
      return GNUNET_SYSERR;
    }
    
    /* Select any random friend except congested peer. */
    target_friend = select_random_friend (&congested_peer);
    
    if (NULL == target_friend)
    {
      all_friends_trail_threshold = GNUNET_YES;
      return GNUNET_SYSERR;
    }
    
    GDS_NEIGHBOURS_send_trail_setup (&my_identity, destination_finger_value, &(target_friend->id),
                                     &my_identity, target_friend, 0, NULL, finger_map_index);
    return GNUNET_YES;
  }
  
  /* My routing state size has crossed the threshold, I can not be part of any more
   * trails. */
  if(GDS_ROUTING_check_threshold())
  {
    struct GNUNET_PeerIdentity *new_trail;
   
    if (trail_length == 1)
    {
      memcpy (&next_peer, &source_peer, sizeof (struct GNUNET_PeerIdentity));
    }
    else
    {
      memcpy (&next_peer, &trail_peer_list[trail_length - 2], sizeof (struct GNUNET_PeerIdentity));
    }
    
    /* Remove myself from the trail. */
    new_trail = GNUNET_malloc ((trail_length -1) * sizeof (struct GNUNET_PeerIdentity));
    memcpy (new_trail, trail_peer_list, (trail_length -1) * sizeof (struct GNUNET_PeerIdentity));
    
    /* No more trails possible through me. send a trail rejection message to next hop. */
    GDS_NEIGHBOURS_send_trail_rejection (&source_peer, destination_finger_value, &my_identity,
                                         &next_peer,finger_map_index, new_trail,trail_length - 1);
    return GNUNET_YES;
  }
  
  /* FIXME: In this case I have just written my_identity as current_destination 
   and current source need ot think more of better values anad if needed or not.
   Also, i am adding a new parameter to funciton find_successor so that this peer
   is not considered as next hop congested_peer is not being used. FIXME. */
  memcpy (&current_destination, &my_identity, sizeof (struct GNUNET_PeerIdentity));
  memcpy (&current_source, &my_identity, sizeof (struct GNUNET_PeerIdentity));
  next_hop = find_successor (destination_finger_value, &current_destination, &current_source, &congested_peer); 
  
  /* FIXME: WE NEED ANOTHER CASE as it may happend that congested peer is the only
   friend, and find_successor finds nothig, so check something else
   here like if current_destination is me, it means that i am destination
   or if current_destination = NULL, then it means found nothing. URGENT. */
  if (NULL == next_hop) /* This means I am the final destination */
  {
    /* SUPU: trail length is 1, when I am the friend of the srouce peer. */
    if (trail_length == 1)
    {
      memcpy (&next_peer, &source_peer, sizeof (struct GNUNET_PeerIdentity));
    }
    else
    {
      memcpy (&next_peer, &trail_peer_list[trail_length-1], sizeof (struct GNUNET_PeerIdentity));
    }
  
    target_friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, &next_peer);
    compare_and_update_predecessor (&source_peer, trail_peer_list, trail_length);
    
    GDS_NEIGHBOURS_send_trail_setup_result (&source_peer,
                                            &(my_identity),
                                            target_friend, trail_length,
                                            trail_peer_list,
                                            finger_map_index);
    return GNUNET_OK;
  }
  else
  {
    /* Now add yourself to the trail. */
    struct GNUNET_PeerIdentity peer_list[trail_length + 1];
    memcpy (peer_list, trail_peer_list, trail_length * sizeof (struct GNUNET_PeerIdentity));
    peer_list[trail_length] = my_identity;
    trail_length++;
    
    target_friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, next_hop);
    GDS_NEIGHBOURS_send_trail_setup (&source_peer,
                                     destination_finger_value,
                                     &current_destination, &current_source,
                                     target_friend, trail_length, peer_list, 
                                     finger_map_index);
    return GNUNET_OK;
  }
  return GNUNET_SYSERR;
}


/**
 * Core handle for p2p trail tear down messages.
 * @param cls closure
 * @param message message
 * @param peer peer identity this notification is about
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
static
int handle_dht_p2p_trail_treadown (void *cls, const struct GNUNET_PeerIdentity *peer,
                                   const struct GNUNET_MessageHeader *message)
{
  /* Call is made to this function when the source peer removes an existing 
   finger entry and it need to inform the peers which are part of the trail to remove
   the trail from their routing table. So, this peer should first
   get the next hop and then delete the entry. */
  struct PeerTrailTearDownMessage *trail_teardown;
  struct GNUNET_PeerIdentity *trail_peer_list;
  struct GNUNET_PeerIdentity next_hop;
  struct FriendInfo *target_friend;
  uint32_t trail_length;
  size_t msize;
  int my_index;
  
  msize = ntohs (message->size);
  if (msize < sizeof (struct PeerTrailTearDownMessage))
  {
    GNUNET_break_op (0);
    return GNUNET_YES;
  }
  
  trail_teardown = (struct PeerTrailTearDownMessage *) message;
  trail_length = ntohl (trail_teardown->trail_length);
  
  if ((msize < sizeof (struct PeerTrailTearDownMessage) +
               trail_length * sizeof (struct GNUNET_PeerIdentity)) ||
      (trail_length >
       GNUNET_SERVER_MAX_MESSAGE_SIZE / sizeof (struct GNUNET_PeerIdentity)))
  {
    GNUNET_break_op (0);
    return GNUNET_YES;
  }
  
  trail_peer_list = (struct GNUNET_PeerIdentity *) &trail_teardown[1];
  
  if(0 == (GNUNET_CRYPTO_cmp_peer_identity (&(trail_teardown->destination_peer), &my_identity)))
  {
    /* We have reached destination then just return. May be if the peer before this
     destination, does not forward the packet to destination. So, this case should never
     occur. */
    GNUNET_break (0);
    return GNUNET_YES;
  }
  
  my_index = search_my_index (trail_peer_list, trail_length);
  if (GNUNET_NO == GDS_ROUTING_remove_trail (&(trail_teardown->source_peer),
                                             &(trail_teardown->destination_peer),peer))
  {
    /* Here we get GNUNET_NO, only if there is no matching entry found in routing
     table. */
    GNUNET_break (0);
    return GNUNET_YES;
  }
  
  if (my_index == (trail_length - 2))
    return GNUNET_SYSERR;
    
  memcpy (&next_hop, &trail_peer_list[my_index + 1], sizeof (struct GNUNET_PeerIdentity));
  target_friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, &next_hop); 
  
  GDS_NEIGHBOURS_send_trail_teardown (&(trail_teardown->source_peer), 
                                      &(trail_teardown->destination_peer),
                                      trail_peer_list, trail_length, target_friend);
  return GNUNET_YES;
}

/**
 * Iterate over finger_peermap, and remove entries with peer as the first element
 * of their trail.  
 * @param cls closure
 * @param key current public key
 * @param value value in the hash map
 * @return #GNUNET_YES if we should continue to
 *         iterate,
 *         #GNUNET_NO if not.
 */
static int
remove_matching_finger (void *cls,
                        const struct GNUNET_PeerIdentity *key,
                        void *value)
{
  struct FingerInfo *remove_finger = value;
  const struct GNUNET_PeerIdentity *disconnected_peer = cls;
  
  if (0 == GNUNET_CRYPTO_cmp_peer_identity (&remove_finger->first_trail_head->peer, disconnected_peer))
  {
    GNUNET_assert (GNUNET_YES ==
                   GNUNET_CONTAINER_multipeermap_remove (finger_peermap,
                                                         key, 
                                                         remove_finger));
    free_finger (remove_finger);
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
  
  /* Check for self message. */
  if (0 == memcmp (&my_identity, peer, sizeof (struct GNUNET_PeerIdentity)))
    return;
  
  /* Search for peer to remove in your friend_peermap. */
  remove_friend =
      GNUNET_CONTAINER_multipeermap_get (friend_peermap, peer);
  
  if (NULL == remove_friend)
  {
    GNUNET_break (0);
    return;
  }
  
  /* Remove fingers for which this peer is the first element in the trail. */
  GNUNET_CONTAINER_multipeermap_iterate (finger_peermap,
                                         &remove_matching_finger, (void *)peer);
  
  /* Remove routing trails of which this peer is a part. */
  GDS_ROUTING_remove_entry (peer);
  
  /* Remove the peer from friend_peermap. */
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
    
  if (GNUNET_SCHEDULER_NO_TASK != verify_successor)
  {
      GNUNET_SCHEDULER_cancel (verify_successor);
      verify_successor = GNUNET_SCHEDULER_NO_TASK;
  }
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
  friend->trails_count = 0;
  
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
    {&handle_dht_p2p_trail_treadown, GNUNET_MESSAGE_TYPE_DHT_P2P_TRAIL_TEARDOWN, 0}, 
    {NULL, 0, 0}
  };
  
  core_api =
    GNUNET_CORE_connect (GDS_cfg, NULL, &core_init, &handle_core_connect,
                         &handle_core_disconnect, NULL, GNUNET_NO, NULL,
                         GNUNET_NO, core_handlers);
  if (NULL == core_api)
    return GNUNET_SYSERR;
  
  friend_peermap = GNUNET_CONTAINER_multipeermap_create (256, GNUNET_NO);
  finger_peermap = GNUNET_CONTAINER_multipeermap_create (MAX_FINGERS * 4/3, GNUNET_NO);
  
  all_friends_trail_threshold = GNUNET_NO;
  
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
  
  GNUNET_assert (0 == GNUNET_CONTAINER_multipeermap_size (finger_peermap));
  GNUNET_CONTAINER_multipeermap_destroy (finger_peermap);
  finger_peermap = NULL;

  /* FIXME: Here I have added GNUNET_break(0) as ideally if friend_peermap 
   is already zero, then we really don't need to cancel it again. If this 
   condition happens it mean we might have missed some corner case. */
  if (GNUNET_SCHEDULER_NO_TASK != find_finger_trail_task)
  {
    GNUNET_break (0);
    GNUNET_SCHEDULER_cancel (find_finger_trail_task);
    find_finger_trail_task = GNUNET_SCHEDULER_NO_TASK;
  }
  
  if (GNUNET_SCHEDULER_NO_TASK != verify_successor)
  {
    GNUNET_break (0);
    GNUNET_SCHEDULER_cancel (verify_successor);
    verify_successor = GNUNET_SCHEDULER_NO_TASK;
  }
}


/**
 * FIXME: Here I want to send only the value not the address. Initially
 * I wanted to make it const struct * so that no other function can change it.
 * then in client file, i make a copy and send that copy. now I have made this
 * as only struct. 
 * Get my identity
 *
 * @return my identity
 */
struct GNUNET_PeerIdentity 
GDS_NEIGHBOURS_get_my_id (void)
{
  return my_identity;
}


/* end of gnunet-service-xdht_neighbours.c */
