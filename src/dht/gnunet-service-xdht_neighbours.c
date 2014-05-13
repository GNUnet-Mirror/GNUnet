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
 1. to randomly choose one of the routes in case there are multiple
    routes to reach to the finger. 
 2. Use a global array of all known peers in find_successor, Only when 
    a new peer is added in finger or friend peer map, then re calculate
    the array. Or else use the old one. The benefit of having this list is something
    I am not sure. only when the code is complete and working I will do this part. 
 3. Structure alignment.
 4. Check where do you set all_friends_trail_threshold? In select_random_friend?
 5. In put, we don't have anything like put result. so we are not adding anything
    in the routing table. 
*/

/**
 * Maximum possible fingers of a peer.
 */
#define MAX_FINGERS 66

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
 * Return the predecessor of value in all_known_peers.
 * @param all_known_peers list of all the peers
 * @param value value we have to search in the all_known_peers.
 * @param size Total numbers of elements
 * @return Predecessor
 */
static struct Sorting_List *
find_closest_predecessor(struct Sorting_List *all_known_peers, uint64_t value,
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
      if(middle == (0))
      {
        return &all_known_peers[size - 1];
      }
      else
      {
        return &all_known_peers[middle - 1];
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
 * Return the successor of value in all_known_peers.
 * @param all_known_peers list of all the peers
 * @param value value we have to search in the all_known_peers.
 * @param size Total numbers of elements
 * @return Successor
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
  {
    memcpy (peer_list, trail_peer_list, trail_length * sizeof (struct GNUNET_PeerIdentity));
  }
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
  
  if (trail_length > 0)
  {
    peer_list = (struct GNUNET_PeerIdentity *) &vsm[1];
    memcpy (peer_list, trail_peer_list, trail_length * sizeof (struct GNUNET_PeerIdentity));
  }
  
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
  if (trail_length > 0)
  {
    peer_list = (struct GNUNET_PeerIdentity *) &vsmr[1];
    memcpy (peer_list, trail_peer_list, trail_length * sizeof (struct GNUNET_PeerIdentity));
  }
  
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
  /* FIXME: Here I am not checking the trail length, as I am assuming that for new
   successor our old successor is a part of trail, so trail length > 1. */
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
 * FIMXE: Change the return value, to handle the case where all friends
 * are congested. 
 * FIXME: Handle congested peer - don't choose this friend, also don't choose
 * the friend if the link threshold has crossed. Not implemented yet. 
 * Randomly choose one of your friends from the friends_peer map
 * @return Friend
 */
static struct FriendInfo *
select_random_friend ()
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
 * Ping your successor to verify if it is still your successor or not. 
 */
static void
send_verify_successor_message()
{
  struct GNUNET_CONTAINER_MultiPeerMapIterator *finger_iter;
  struct GNUNET_PeerIdentity key_ret;
  struct FriendInfo *target_friend;
  struct GNUNET_PeerIdentity next_hop;
  struct GNUNET_PeerIdentity *peer_list;
  struct FingerInfo *finger;
  unsigned int finger_index;
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
  
  /* Either you don't have a successor or you are your own successor, then don't
   send a successor message. */
  if(( flag == 0) ||
    (0 == GNUNET_CRYPTO_cmp_peer_identity(&my_identity, &(finger->finger_identity))))
  {
    return;
  }

  if (finger->first_trail_length > 0)
  {
    struct TrailPeerList *iterate;
    int i = 0;
    peer_list = GNUNET_malloc (sizeof (struct GNUNET_PeerIdentity) * finger->first_trail_length);
    iterate = finger->first_trail_head;

    while ( i < (finger->first_trail_length))
    {
      
      memcpy (&peer_list[i], &(iterate->peer), sizeof (struct GNUNET_PeerIdentity));
      iterate = iterate->next;
      i++;
    }
    memcpy (&next_hop, &peer_list[0], sizeof (struct GNUNET_PeerIdentity));
    target_friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, &next_hop);
  }
  else
  {
    /* If trail length = 0, then our successor is our friend. */
    peer_list = NULL;
    target_friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap,
                                                      &(finger->finger_identity));
  }
   
  GDS_NEIGHBOURS_send_verify_successor (&my_identity,
                                        &(finger->finger_identity),
                                        target_friend,
                                        peer_list,
                                        finger->first_trail_length);  
}


/**
 * FIXME: 
 * 1. Need to handle the case where all friends are either congested or
 * have reached their threshold. 
 * 2. If we need all_friends_trail_threshold
 * 3. do we need to check if friend peermap is empty or not. 
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
  find_finger_trail_task =
      GNUNET_SCHEDULER_add_delayed (next_send_time, &send_find_finger_trail_message,
                                    NULL);
  
  if (GNUNET_YES == all_friends_trail_threshold)
  {
     /* All friends in friend peer map, have reached their trail threshold. No
      more new trail can be created. */
    return;
  }
  
  target_friend = select_random_friend (); 
  if (NULL == target_friend)
  {
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
  GDS_NEIGHBOURS_send_trail_setup (&my_identity, finger_identity, &(target_friend->id),
                                   &my_identity, target_friend, 0, NULL, finger_map_index);
}




/* In this function, we want to return the compressed trail and the trail length.
 We can send back a new trail and update the trail length value as we get as 
 parameter to our function. There are many cases where we don't need to call 
 this function. Move that logic to calling function. */
/**
 * Scan the trail to check if any of my own friend is part of trail. If yes
 * then shortcut the trail, update trail length and send back the new trail.
 * @param trail[Out] Current trail to reach to @a finger, will be updated
 *                          in case we compress the trail. 
 * @param trail_length[Out] Number of peers in @a finger_trail, will be updated
 *                          in case we compress the trail. 
 * @param finger Finger identity 
 */
static void
scan_and_compress_trail (struct GNUNET_PeerIdentity *trail,
                         unsigned int *trail_length,
                         const struct GNUNET_PeerIdentity *finger)
{
  int i;

  /* If finger is my friend, then set trail_length = 0;*/
  if (GNUNET_CONTAINER_multipeermap_get (friend_peermap, finger))
  {
    /* supu' delete entry from the thrail. */
    trail_length = 0;
    trail = NULL;
    return;
  }
  
  i = *trail_length - 1;
  while (i > 1)
  {
    if (NULL == GNUNET_CONTAINER_multipeermap_get (friend_peermap, &trail[i]))
    {
      /* This element of trail is not my friend. */
      i--;
    }
    else
    {
      /* A --> B(friend 1) --> C(friend 2)--> D ---> E, then we can rewrite the trail as
       * C --> D --> E,
       * Now, we should remove the entry from A's routing table, B's routing table
       * and update the entry in C's routing table. Rest everything will be same.
       * C's routing table should have source peer as the prev.hop. 
       * In case we found a friend not at i = 0, then we can discard all the 
       peers before it in the trail and short cut the path. We need to send 
       trail teardown message also but not to all the peers in the trail. only
       the peer just behind me and also update the routing table of the friend,
       to prev hop as the source peer ie my_identity.  */
      struct GNUNET_PeerIdentity *discarded_trail;
      struct FriendInfo *target_friend;
      int discarded_trail_length;
      int j = 0;
      /* Here I am adding the friend (C) found to the discarded trail also, as we
       need to update its routing table also. */
      discarded_trail_length = i;
      discarded_trail = GNUNET_malloc (discarded_trail_length * sizeof (struct GNUNET_PeerIdentity));
      memcpy (discarded_trail, trail, discarded_trail_length * sizeof (struct GNUNET_PeerIdentity));
      target_friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, &trail[0]);
      /* send_update_routing_table(friend). so that it removes prev hop 
       and update it to source for given finger. */
      /* FIXME: Modify trail_teardown function to handle such cases. In case
       the last element of the trail update the routing table, in case it
       is trail compression. But teardown is called from various places so 
       need to differentiate these two cases. URGENT*/
      GDS_NEIGHBOURS_send_trail_teardown (&my_identity, finger, discarded_trail,
                                         discarded_trail_length, target_friend);
     
      /* Copy the trail from index i to index trail_length -1 and change
       trail length and return */
      while (i < *trail_length)
      {
        memcpy (&trail[j], &trail[i], sizeof(struct GNUNET_PeerIdentity));
        j++;
        i++;
      }
      *trail_length = j+1;
      return;
    }
  }
  return;
}


/**
 * FIXME: Is this correct? Here I am using dll_remove and its documentation
 * reads something else. Verify. Urgent. 
 * Free finger and its trail.  
 * @param finger Finger to be freed.
 */
static void
free_finger (struct FingerInfo *finger)
{
  struct TrailPeerList *peer;
 
  if(finger->first_trail_head != NULL)
  {
    while (NULL != (peer = finger->first_trail_head))
    {
      GNUNET_CONTAINER_DLL_remove (finger->first_trail_head, finger->first_trail_tail, peer);
      GNUNET_free (peer);
    }
  }
  
  if (finger->second_trail_head != NULL)
  {
    while (NULL != (peer = finger->second_trail_head))
    {
      GNUNET_CONTAINER_DLL_remove (finger->second_trail_head, finger->second_trail_tail, peer);
      GNUNET_free (peer);
    }
    GNUNET_free (finger);
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

 
 if (existing_finger->first_trail_length == 0)
    return;
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
  existing_finger->trail_count++;
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
 * FIXME: If we remove a finger which is our friend, then do we need to handle it 
 * differentlty in regard to trail count. 
 * Decrement the trail count for the first friend to reach to the finger. 
 * @param finger
 */
static void
decrement_friend_trail_count (struct FingerInfo *finger)
{
  struct FriendInfo *first_trail_friend;
  struct FriendInfo *second_trail_friend;
  
  if(finger->first_trail_head != NULL)
  {
    first_trail_friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, 
                                                          &(finger->first_trail_head->peer));
    first_trail_friend->trails_count--;
  }
    
  if(finger->second_trail_head != NULL)
  {
    second_trail_friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, 
                                                           &(finger->second_trail_head->peer));
    second_trail_friend->trails_count--;
  }
  
  if (GNUNET_YES == all_friends_trail_threshold)
  {
    all_friends_trail_threshold = GNUNET_NO;
    /* FIXME; Here you should reschedule the send_find_finger_task here. or
     make a call.*/
  }
}


/**
 * FIXME: consider the case where my_id = 2, and we are in circle from 0 to 7.
 * my current_predecessor is 6, and now the new finger 1. Here we are checking
 * if existing_finger < new_entry then new_entry is predecessor. This holds
 * true in case where lets say existing_finger = 5, new_entry= 6. But in the case
 * above, 6 > 1 but still 1 is correct predecessor. We have not handled it here.
 * We can put all the three values in an array and then the peer just before me
 * will be mine predecessor. 
 * FIXME: Currently I am using struct Sorting_list to compare the values,
 * will create a new ds if needed. 
 * @param existing_finger
 * @param new_finger
 * @return 
 */
static 
int select_finger (struct FingerInfo *existing_finger,
                   const struct GNUNET_PeerIdentity *new_finger,
                   unsigned int finger_map_index)
{
  struct Sorting_List peers[3]; /* 3 for existing_finger, new_finger, my_identity */
  struct Sorting_List *closest_finger; 
  uint64_t value;
  int k;
  
  for (k = 0; k < 3; k++)
    peers[k].data = 0;
  
  memcpy (&peers[0], &my_identity, sizeof (uint64_t));
  peers[0].type = MY_ID;
  peers[0].data = NULL;
  
  memcpy (&peers[1], &(existing_finger->finger_identity), sizeof (uint64_t));
  peers[1].type = FINGER;
  peers[1].data = existing_finger;
  
  memcpy (&peers[2], &new_finger, sizeof (uint64_t));
  peers[2].type = VALUE;
  peers[2].data = NULL;
  
  memcpy (&value, &my_identity, sizeof (uint64_t));
  
  
  qsort (&peers, 3, sizeof (struct Sorting_List), &compare_peer_id);
  
  if (PREDECESSOR_FINGER_ID == finger_map_index)
    closest_finger = find_closest_predecessor (peers, value, 3);
  else
    closest_finger = find_closest_successor (peers, value, 3);
  
  if (closest_finger->type  == FINGER)
  {
    return GNUNET_NO;
  }
  else if (closest_finger->type == VALUE)
  {
    return GNUNET_YES;
  }
  else if (closest_finger->type == MY_ID);
  {
    return GNUNET_SYSERR;  
  }
}


/**
 * Choose the closest finger between existing_finger and new_finger. In case new_finger
 * is closest and finger_map_index != PREDCESSOR_FINGER_ID,
 * then send a tear down message along the trail to reach existing_finger. 
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
                           unsigned int trail_length,
                           unsigned int finger_map_index)
{
  if (0 == GNUNET_CRYPTO_cmp_peer_identity (&(existing_finger->finger_identity), new_finger))
  {
    /* Both the new entry and existing entry are same. */
    if (0 == GNUNET_CRYPTO_cmp_peer_identity (&(existing_finger->finger_identity), &my_identity))
    {
      /* If both are same then exit. You already have that entry in your finger table,
       then you don't need to add it again. */
      return GNUNET_NO;
    }
    if (trail_length > 1)
    {
      scan_and_compress_trail (trail, &trail_length, new_finger);
    }
    if (existing_finger->trail_count < TRAIL_COUNT)
    {
      add_new_trail (existing_finger, trail, trail_length);
      return GNUNET_NO;
    }
    else
    {
      select_and_replace_trail (existing_finger, trail, trail_length);
      return GNUNET_NO;
    }  
  }
  else if (GNUNET_YES == select_finger (existing_finger, new_finger, finger_map_index))
  {
    /* Here in case finger_map_index was Predecessor_finger then also you don't 
     need to send trail teardown and in case its successor then you found it in
     trail_setup and then you don't need to send trail teardown. FIXME: check if
     its true for every call made to finger_table_add. Also, if we have an entry
     which is not my identity should I replace it with my identity or not? */
    if (0 == GNUNET_CRYPTO_cmp_peer_identity (&my_identity, new_finger))
    {
      return GNUNET_NO; /* FIXME: In case I have a peer id which is not my id then
                         * should I keep it as finger */
             
    }
    /* new_finger is the correct finger. */
    if (PREDECESSOR_FINGER_ID != finger_map_index)
      send_trail_teardown (existing_finger);
    
    decrement_friend_trail_count (existing_finger);
    free_finger (existing_finger);
    if (trail_length > 1)
      scan_and_compress_trail (trail, &trail_length, new_finger);
    return GNUNET_YES;
  }
  else if (GNUNET_NO == select_finger (existing_finger, new_finger,finger_map_index))
  {
    /* existing_finger is the correct finger. */
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
static int
compare_and_update_predecessor (const struct GNUNET_PeerIdentity *peer,
                                struct GNUNET_PeerIdentity *trail,
                                unsigned int trail_length)
{
  /* ! HAVE A PREDECESSOR || (source_peer closer than existing PREDECESOR) */
  struct FingerInfo *existing_finger;
  struct GNUNET_CONTAINER_MultiPeerMapIterator *finger_iter;
  struct FingerInfo *new_finger_entry;
  struct FriendInfo *first_friend_trail;
  int i;
  
  finger_iter = GNUNET_CONTAINER_multipeermap_iterator_create (finger_peermap); 
  for (i= 0; i < GNUNET_CONTAINER_multipeermap_size (finger_peermap); i++)
  {
    if(GNUNET_YES == GNUNET_CONTAINER_multipeermap_iterator_next (finger_iter, NULL,
                                                                 (const void **)&existing_finger)) 
    {
      if (PREDECESSOR_FINGER_ID == existing_finger->finger_map_index)
      {
        if( GNUNET_NO == select_closest_finger (existing_finger, peer, trail, 
                                                trail_length,PREDECESSOR_FINGER_ID))
          return GNUNET_NO;
        else
          break;
      }
    }
  }
  GNUNET_CONTAINER_multipeermap_iterator_destroy (finger_iter);
  
  new_finger_entry = GNUNET_malloc (sizeof (struct FingerInfo));
  memcpy (&(new_finger_entry->finger_identity), peer, sizeof (struct GNUNET_PeerIdentity));
  new_finger_entry->finger_map_index = PREDECESSOR_FINGER_ID;
  new_finger_entry->first_trail_length = trail_length;
  
  if (trail != NULL) /* finger_trail is NULL in case I am my own finger identity. */
  {
    /* FIXME: Currently we are not handling the second trail. In that case, finger
     trail count = min (first_friend, second_friend) trail count. */
    /* Incrementing the friend trails count. */
    if (trail_length > 0)   
    {
      first_friend_trail = GNUNET_CONTAINER_multipeermap_get (friend_peermap, &trail[0]);
      first_friend_trail->trails_count++;
    }
    else
    {
      /* It means the finger is my friend. */
      first_friend_trail = GNUNET_CONTAINER_multipeermap_get (friend_peermap, peer);
      first_friend_trail->trails_count++;
    }
    new_finger_entry->first_friend_trails_count = first_friend_trail->trails_count; 
 
    if (trail_length != 0)
    { 
      i = trail_length - 1;
      while (i > 0)
      {
        struct TrailPeerList *element;
        element = GNUNET_malloc (sizeof (struct TrailPeerList));
        element->next = NULL;
        element->prev = NULL;
    
        memcpy (&(element->peer), &trail[i], sizeof(struct GNUNET_PeerIdentity)); 
        GNUNET_CONTAINER_DLL_insert_tail(new_finger_entry->first_trail_head, new_finger_entry->first_trail_tail, element);
        i--;
      }
      struct TrailPeerList *element;
      element = GNUNET_malloc (sizeof (struct TrailPeerList));
      element->next = NULL;
      element->prev = NULL;
      memcpy (&(element->peer), &trail[i], sizeof(struct GNUNET_PeerIdentity)); 
      GNUNET_CONTAINER_DLL_insert_tail(new_finger_entry->first_trail_head, new_finger_entry->first_trail_tail, element);
    }
  }
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multipeermap_put (finger_peermap,
                                                    &(new_finger_entry->finger_identity),
                                                    new_finger_entry,
                                                    GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE)); 
  
  return GNUNET_YES;
}


/**
 * FIXME: Better name, and make the code more cleaner.
 * Compare the new finger entry added and our successor. 
 * @return #GNUNET_YES if same.
 *         #GNUNET_NO if not. 
 */
static int
compare_new_entry_and_successor (const struct GNUNET_PeerIdentity *new_finger,
                                 int finger_map_index)
{
  int successor_flag = 0;
  struct FingerInfo *successor_finger;
  struct GNUNET_CONTAINER_MultiPeerMapIterator *finger_iter;
  int i;

  if (PREDECESSOR_FINGER_ID == finger_map_index)
    return GNUNET_NO;
  
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
  GNUNET_CONTAINER_multipeermap_iterator_destroy (finger_iter);
  
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
 * Add a new entry in finger table. 
 * @param finger_identity PeerIdentity of the new finger
 * @param finger_trail Trail to reach to the finger, can be NULL in case I am my own
 *                     finger.
 * @param finger_trail_length Number of peers in the trail, can be 0 in case finger
 *                            is a friend or I am my own finger.
 * @param finger_map_index Index in finger map. 
 */
static int
add_new_entry (const struct GNUNET_PeerIdentity *finger_identity,
               struct GNUNET_PeerIdentity *finger_trail,
               uint32_t finger_trail_length,
               uint32_t finger_map_index)
{
  struct FriendInfo *first_friend_trail;
  struct FingerInfo *new_finger_entry;
  int i;
  
  /* Add a new entry. */
  new_finger_entry = GNUNET_malloc (sizeof (struct FingerInfo));
  memcpy (&(new_finger_entry->finger_identity), finger_identity, sizeof (struct GNUNET_PeerIdentity));
  new_finger_entry->finger_map_index = finger_map_index;
  new_finger_entry->first_trail_length = finger_trail_length;
  new_finger_entry->trail_count = 1;
  
  if (finger_trail != NULL) /* finger_trail is NULL in case I am my own finger identity. */
  {
    /* Incrementing the friend trails count. */
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
    new_finger_entry->first_friend_trails_count = first_friend_trail->trails_count; 
    
    /* Copy the trail. */
    i = 0;
    while (i < finger_trail_length)
    {
      struct TrailPeerList *element;
      element = GNUNET_malloc (sizeof (struct TrailPeerList));
      element->next = NULL;
      element->prev = NULL;
    
      memcpy (&(element->peer), &finger_trail[i], sizeof(struct GNUNET_PeerIdentity));
      GNUNET_CONTAINER_DLL_insert_tail(new_finger_entry->first_trail_head, new_finger_entry->first_trail_tail, element);
      i++;
    }
  }
 
  return  GNUNET_CONTAINER_multipeermap_put (finger_peermap,
                                             &(new_finger_entry->finger_identity),
                                             new_finger_entry,
                                             GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);    
}


/**
 * 1. removed predecessor_finger_id check as in select_closest_finger we check it
 * and handle it accordingly.
 * 2. you don't handle the second trail here as in new entry you will have only
 * one trail to reach to the finger. 
 * 3. check how do you handle the return value of this function. 
 * FIXME: Functions calling finger_table_add will not check if finger identity
 * and my identity are same, it should be done in this function.
 * Add an entry in the finger table. If there is already an existing entry in
 * the finger peermap for given finger map index, then choose the closest one.
 * In case both the new entry and old entry are same, store both of them. (Redundant 
 * routing).
 * @param finger_identity
 * @param finger_trail
 * @param finger_trail_length
 * @param finger_map_index
 * @return #GNUNET_YES if the new entry is added.
 *         #GNUNET_NO if the new entry is discarded.
 */
static
int finger_table_add (const struct GNUNET_PeerIdentity *finger_identity,
                      struct GNUNET_PeerIdentity *finger_trail,
                      uint32_t finger_trail_length,
                      uint32_t finger_map_index)
{
  struct FingerInfo *existing_finger;
  struct GNUNET_CONTAINER_MultiPeerMapIterator *finger_iter;
  int i;
  int new_entry_added = GNUNET_NO;
   
  /* Check if there is already an entry for the finger map index in the finger peer map. */
  finger_iter = GNUNET_CONTAINER_multipeermap_iterator_create (finger_peermap); 
  for (i= 0; i < GNUNET_CONTAINER_multipeermap_size (finger_peermap); i++)
  {
    if(GNUNET_YES == GNUNET_CONTAINER_multipeermap_iterator_next (finger_iter, NULL,
                                                                 (const void **)&existing_finger)) 
    {
      if (existing_finger->finger_map_index == finger_map_index)
      {
        if ( GNUNET_NO == select_closest_finger (existing_finger, finger_identity, 
                                                finger_trail, finger_trail_length,finger_map_index)) 
          goto update_current_search_finger_index;
        else
          break;
      }
    } 
  }
  GNUNET_CONTAINER_multipeermap_iterator_destroy (finger_iter);
  
  if(GNUNET_OK == add_new_entry (finger_identity,finger_trail,finger_trail_length, finger_map_index))
    new_entry_added = GNUNET_YES;
  else
    return GNUNET_NO;
  
  update_current_search_finger_index:
  if (0 == finger_map_index)
  {
    current_search_finger_index = PREDECESSOR_FINGER_ID;
    if (0 != GNUNET_CRYPTO_cmp_peer_identity (&my_identity,finger_identity))
      send_verify_successor_message();
  }
  else if (GNUNET_YES == compare_new_entry_and_successor (finger_identity,finger_map_index))
  {
    /* If the new entry is same as our successor, then reset the current_search_finger_index to 0*/
    current_search_finger_index = 0;
  }
  else 
  {
    current_search_finger_index = current_search_finger_index - 1;
  }
  
  return new_entry_added;
}
 

/**
 * FIXME: In case a friend is either congested or has crossed its trail threshold,
 * then don't consider it as next successor, In case of finger if its first
 * friend has crossed the threshold then don't consider it. In case no finger
 * or friend is found, then return NULL.
 * Find closest successor for the value.
 * @param value Value for which we are looking for successor
 * @param[out] current_destination set to my_identity in case I am the final destination,
 *                                 set to friend identity in case friend is final destination,
 *                                 set to first friend to reach to finger, in case finger
 *                                 is final destination. 
 * @param[out] current_source set to my_identity.
 * @return Peer identity of next hop to send trail setup message to,
 *         NULL in case all the friends are either congested or have crossed
 *              their trail threshold.
 */
static struct GNUNET_PeerIdentity *
find_successor (uint64_t value, struct GNUNET_PeerIdentity *current_destination,
               struct GNUNET_PeerIdentity *current_source)
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
    memcpy (current_destination, &my_identity, sizeof (struct GNUNET_PeerIdentity));
    return &my_identity;
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
    finger = successor->data;
    next_hop = GNUNET_malloc (sizeof (struct GNUNET_PeerIdentity));
    
    if (finger->first_trail_length > 0)
    {
      struct TrailPeerList *iterator;
      iterator = GNUNET_malloc (sizeof (struct TrailPeerList));
      iterator = finger->first_trail_head;
      memcpy (next_hop, &(iterator->peer), sizeof (struct GNUNET_PeerIdentity));
    }
    else /* This means finger is our friend. */
      memcpy (next_hop, &(finger->finger_identity), sizeof(struct GNUNET_PeerIdentity));
    
    memcpy (current_destination, &(finger->finger_identity), sizeof (struct GNUNET_PeerIdentity));
    memcpy (current_source, &my_identity, sizeof (struct GNUNET_PeerIdentity));
    return next_hop;
  }
  else
  {
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
    next_hop = find_successor (key_value, &curr_dest, &curr_src);
    /* FIXME: I am copying back current_destination and current_source. but I am not 
     sure, if its correct. I am doing so just to remove the code from client file.*/
    memcpy (&current_destination, &curr_dest, sizeof (struct GNUNET_PeerIdentity));
    memcpy (&current_source, &curr_src, sizeof (struct GNUNET_PeerIdentity));
    
    if (0 == GNUNET_CRYPTO_cmp_peer_identity(&my_identity,&current_destination)) /* I am the destination do datacache_put */
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
	// FIXME: endianess of key_value!?
    next_hop = find_successor (key_value, &curr_dest, &curr_src);
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
 * Send trail rejection message to the peer which sent me a trail setup message. 
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
  
  if (trail_length != 0)
  {
    trail_list = (struct GNUNET_PeerIdentity *)&trail_rejection[1];
    memcpy (trail_list, trail_peer_list, trail_length * sizeof (struct GNUNET_PeerIdentity));
  }
  
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
    next_hop = find_successor (key_value, &current_destination, &current_source); 
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
    next_hop = find_successor (key_value, &current_destination, &current_source); 
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
 * FIXME: In case of trail, we don't have source and destination part of the trail,
 * Check if we follow the same in case of get/put/get_result. Also, in case of 
 * put should we do a routing table add.
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
 * FIXME: Is all trails threshold and routing table has some link. 
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
  
  if (trail_length > 0)
    trail_peer_list = (struct GNUNET_PeerIdentity *)&trail_setup[1];
  memcpy (&current_destination, &(trail_setup->current_destination), sizeof (struct GNUNET_PeerIdentity));
  memcpy (&current_source,&(trail_setup->current_source), sizeof (struct GNUNET_PeerIdentity));
  memcpy (&source, &(trail_setup->source_peer), sizeof (struct GNUNET_PeerIdentity));
  finger_map_index = ntohl (trail_setup->finger_map_index);
  destination_finger_value = ntohl (trail_setup->destination_finger);
  
#if 0
   /* FIXME: Here we need to check 3 things
    * 1. if my routing table is all full
    * 2. if all my friends are congested
    * 3. if trail threshold of my friends have crossed. 
    * In all these cases we need to send back trail rejection message.  */
  if ( (GNUNET_YES == all_friends_trail_threshold)
      || (GNUNET_YES == GDS_ROUTING_check_threshold()))
  {
    /* If all the friends have reached their trail threshold or if there is no
   more space in routing table to store more trails, then reject. */
    GDS_NEIGHBOURS_send_trail_rejection (&source, destination_finger_value, &my_identity,
                                         peer,finger_map_index, trail_peer_list,trail_length);
    return GNUNET_OK;
  }
#endif  
  
  
  /* Check if you are current_destination or not. */
  if (0 != (GNUNET_CRYPTO_cmp_peer_identity (&current_destination, &my_identity)))
  {
    next_hop = GDS_ROUTING_search (&current_source, &current_destination, peer);
    /* OPTIMIZATION: Choose a peer from find_successor and choose the closest one.
     In case the closest one is from routing table and it is NULL, then update
     statistics. */
    if (next_hop == NULL)
    {
      /* FIXME: Should we inform the peer before us. If not then it may continue
       to send us request. But in case we want to inform we need to have a 
       different kind of message. */
      GNUNET_STATISTICS_update (GDS_stats,
                                gettext_noop ("# Trail not found in routing table during"
                                "trail setup request, packet dropped."),
                                1, GNUNET_NO);
      return GNUNET_OK;
    }
  }
  else
  {
    next_hop = find_successor (destination_finger_value, &current_destination, &current_source); 
  } 
  
  if (NULL == next_hop)
  {
    return GNUNET_SYSERR;
  }
  else if (0 == (GNUNET_CRYPTO_cmp_peer_identity (next_hop, &my_identity)))/* This means I am the final destination */
  {
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
    if (PREDECESSOR_FINGER_ID != finger_map_index)
    {
       /* FIXME: Is this correct assumption? A peer which think I am its predecessor,
          then I am not its predecessor. */
       compare_and_update_predecessor (&source, trail_peer_list, trail_length );
    }
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
    if (trail_length != 0)
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
    
    my_index =  search_my_index (trail_peer_list, trail_length);
    if (my_index == GNUNET_SYSERR)
      return GNUNET_SYSERR;
    
    if (my_index == 0)
    {
      next_hop = trail_result->destination_peer;
    }
    else
      next_hop = trail_peer_list[my_index - 1];
  
    /* Finger table of destination peer will not contain any trail for the case
     * where destination peer is its own finger identity.*/
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
  int flag = 0;
 
  /* Iterate over finger peer map and extract your predecessor. */
  finger_iter = GNUNET_CONTAINER_multipeermap_iterator_create (finger_peermap);  
  for (finger_index = 0; finger_index < GNUNET_CONTAINER_multipeermap_size (finger_peermap); finger_index++)
  {
    if(GNUNET_YES == GNUNET_CONTAINER_multipeermap_iterator_next 
                       (finger_iter,&key_ret,(const void **)&my_predecessor)) 
    {
      if(PREDECESSOR_FINGER_ID == my_predecessor->finger_map_index)
      {
        flag = 1;
        break;
      }
    }
  }
  GNUNET_CONTAINER_multipeermap_iterator_destroy (finger_iter);
  
  if (0 == flag)
    return NULL;
  else
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
    {
      /* SUPU: If I am friend of source_peer, then trail_length == 0. */
      memcpy (&next_hop, &source_peer, sizeof (struct GNUNET_PeerIdentity));
    }
    else
    {
      /* SUPU: Here I am the final destination successor, and trail does not contain
       destination. So, the next hop is the last element in the trail. */
      memcpy (&next_hop, &trail_peer_list[trail_length-1], sizeof (struct GNUNET_PeerIdentity));
    }
    target_friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, &next_hop);
    
    my_predecessor = get_predecessor();
    if (NULL == my_predecessor)
    {
      GNUNET_break(0);
      return GNUNET_SYSERR;
    }
    
    if (0 == (GNUNET_CRYPTO_cmp_peer_identity (&source_peer,
                                               &(my_predecessor->finger_identity))))
    {
      /* Source peer and my predecessor, both are same. */
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
      if (trail_length > 0)
        memcpy (new_successor_trail, trail_peer_list, (trail_length) * sizeof (struct GNUNET_PeerIdentity));
      
      memcpy (&new_successor_trail[trail_length], &my_identity, sizeof (struct GNUNET_PeerIdentity));
     
      if (my_predecessor->first_trail_length)
      {
        iterator = GNUNET_malloc (sizeof (struct TrailPeerList));
        iterator = my_predecessor->first_trail_head; 
        i = trail_length + 1;
        while (i < new_trail_length)
        {
          memcpy (&new_successor_trail[i], &(iterator->peer), sizeof (struct GNUNET_PeerIdentity));
          iterator = iterator->next;
          i++;
        }
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
   
   my_index = search_my_index (trail_peer_list, trail_length);
   if (my_index == GNUNET_SYSERR)
   {
     GNUNET_break (0);
     return GNUNET_SYSERR;
   }
   if (my_index == (trail_length - 1))
   {
      target_friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, &(vsm->successor));
   }
   else
   {
     memcpy (&next_hop, &trail_peer_list[my_index + 1], sizeof (struct GNUNET_PeerIdentity));
     target_friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, &next_hop);
   }   

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
  /* FIXME: URGENT: What happens when trail length = 0. */
  
  trail_peer_list = (struct GNUNET_PeerIdentity *) &vsrm[1];
  
  if(0 == (GNUNET_CRYPTO_cmp_peer_identity (&(vsrm->destination_peer), &(my_identity))))
  {
    if(0 != (GNUNET_CRYPTO_cmp_peer_identity (&(vsrm->my_predecessor), &(my_identity))))
    {
      /* FIXME: Here we have got a new successor. But it may happen that our logic
       * says that this is not correct successor. so in finger table add it
       * failed to update the successor and we are still sending a notify
       * new successor. Here trail_length will be atleast 1, in case we have a new
       * successor because in that case our old successor is part of trail.
       * Could it be possible that our identity and my_predecessor is same. Check it.  */
      if (GNUNET_YES == finger_table_add (&(vsrm->my_predecessor), trail_peer_list, trail_length, 0))
      {
        memcpy (&next_hop, &trail_peer_list[0], sizeof (struct GNUNET_PeerIdentity));
        target_friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, &next_hop);
        GDS_NEIGHBOURS_send_notify_new_successor (&my_identity, &(vsrm->my_predecessor),
                                                  target_friend, trail_peer_list,
                                                  trail_length);
        return GNUNET_OK;
      }
      /*else
      {
        
        GNUNET_break (0);
        return GNUNET_SYSERR;
      }*/
    }
  }
  else
  {
    int my_index;
    
    my_index = search_my_index (trail_peer_list, trail_length);
    if (GNUNET_SYSERR == my_index)
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    
    if (my_index == 0)
    {
      /* Source is not part of trail, so if I am the last one then my index
       should be 0. */
      memcpy (&next_hop, &(vsrm->destination_peer), sizeof (struct GNUNET_PeerIdentity));
    }
    else
    {
      memcpy (&next_hop, &trail_peer_list[my_index-1], sizeof (struct GNUNET_PeerIdentity));
    }
    
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
    /* I am the new successor. */
    struct GNUNET_PeerIdentity new_predecessor;
    memcpy (&new_predecessor, &(nsm->source_peer), sizeof (struct GNUNET_PeerIdentity));
    if (GNUNET_NO == compare_and_update_predecessor (&new_predecessor, trail_peer_list,
                                                     trail_length))
    {
      /* Someone claims to be my predecessor but its not closest predecessor
       the break. */
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
      return GNUNET_OK;
  }
  else
  {
    struct FriendInfo *target_friend;
    struct GNUNET_PeerIdentity next_hop;
    int my_index;
    
    my_index = search_my_index (trail_peer_list, trail_length);
    if (GNUNET_SYSERR == my_index)
    {
      GNUNET_break(0);
      return GNUNET_SYSERR;
    }
    
    if (my_index == (trail_length - 1))
    {
      target_friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, &(nsm->destination_peer));
    }
    else
    {
      memcpy (&next_hop, &trail_peer_list[my_index+1], sizeof (struct GNUNET_PeerIdentity));
      target_friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, &next_hop);
    }
    GDS_NEIGHBOURS_send_notify_new_successor (&(nsm->source_peer), 
                                              &(nsm->destination_peer),
                                              target_friend, trail_peer_list,
                                              trail_length);
    return GNUNET_OK;
  }
  return GNUNET_SYSERR;
}


/**
 * FIXME; Should we call select_random_friend from here in case I am the source 
 * of the message or should I just return and in next iteration by default
 * we will call select random friend from send_find_finger_trail. But in that
 * case we should maintain a list of congested peer which failed to setup the
 * trail. and then in select random friend we should ignore them. this list
 * should have an expiration time and we should garbage collect it periodically. 
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
  
  if(0 == (GNUNET_CRYPTO_cmp_peer_identity (&my_identity, &source_peer)))
  {
    /* I am the source of original trail setup message. Do nothing and exit. */
    /* In current implementation, when we don't get the result of a trail setup,
     then no entry is added to finger table and hence, by default a trail setup for 
     the same finger map index is sent. so we don't need to send it here. */
    return GNUNET_YES;
  }
  
  if(GDS_ROUTING_check_threshold())
  {
    /* My routing state size has crossed the threshold, I can not be part of any more
     * trails. */
    struct GNUNET_PeerIdentity *new_trail;
   
    if (trail_length == 1)
    {
      memcpy (&next_peer, &source_peer, sizeof (struct GNUNET_PeerIdentity));
    }
    else
    {
      /* FIXME: Here if I got the trail rejection message then I am the last element
       in the trail. So, I should choose trail_length-2.*/
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
  
  memcpy (&current_destination, &my_identity, sizeof (struct GNUNET_PeerIdentity));
  memcpy (&current_source, &my_identity, sizeof (struct GNUNET_PeerIdentity));
  /* FIXME: After adding a new field in struct FriendInfo congested, then call
   find successor then it will never consider that friend by default. */
  next_hop = find_successor (destination_finger_value, &current_destination, &current_source); 
  
  if (0 == (GNUNET_CRYPTO_cmp_peer_identity (&my_identity, &current_destination))) /* This means I am the final destination */
  {
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
  else if (NULL == next_hop)
  {
    /* No peer found. Send a trail rejection message to previous peer in the trail. */
  
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
 * FIXME: we don't send trail teardown to finger for which the trail was setup.
 * Trail teardown only aim is to remove entries from the routing table. Destination
 * finger does not have any entry in its routing table. So, it does not need 
 * a trail teardown. 
 * Core handle for p2p trail tear down messages.
 * @param cls closure
 * @param message message
 * @param peer peer identity this notification is about
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
static
int handle_dht_p2p_trail_teardown (void *cls, const struct GNUNET_PeerIdentity *peer,
                                   const struct GNUNET_MessageHeader *message)
{
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
    /* I am the destination of the trail, but I am not part of trail. I don't
     need to remove any entry from my routing table. So, I should not get this
     message. */
    GNUNET_break (0);
    return GNUNET_YES;
  }
  
  my_index = search_my_index (trail_peer_list, trail_length);
  if(GNUNET_SYSERR == my_index)
    return GNUNET_SYSERR;
  
  if (GNUNET_NO == GDS_ROUTING_remove_trail (&(trail_teardown->source_peer),
                                             &(trail_teardown->destination_peer),peer))
  {
    /* Here we get GNUNET_NO, only if there is no matching entry found in routing
     table. */
    GNUNET_break (0);
    return GNUNET_YES;
  }
  
  /* I am the last element of the trail. */
  if(my_index == trail_length - 1)
    return GNUNET_YES;
    
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
  
  if (0 == GNUNET_CRYPTO_cmp_peer_identity (&remove_finger->first_trail_head->peer, disconnected_peer)
      || (0 == GNUNET_CRYPTO_cmp_peer_identity (&(remove_finger->finger_identity), disconnected_peer)))
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

  /* Remove fingers for which this peer is the first element in the trail or if
   * the friend is a finger.  */
  GNUNET_CONTAINER_multipeermap_iterate (finger_peermap,
                                         &remove_matching_finger, (void *)peer);
  
  /* Remove routing trails of which this peer is a part.
   * FIXME: Here do we only remove the entry from our own routing table
   * or do we also inform other peers which are part of trail. It seems to be
   * too much of messages exchanged. */
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
    {&handle_dht_p2p_trail_teardown, GNUNET_MESSAGE_TYPE_DHT_P2P_TRAIL_TEARDOWN, 0}, 
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
   condition happens it mean we might have missed some corner case. But we
   cancel the task only in handle_core_disconnect. it may happen that this 
   function is called but not handle_core_disconnect, In that case GNUNET_break(0)
   is not needed. */
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


/* end of gnunet-service-xdht_neighbours.c */
