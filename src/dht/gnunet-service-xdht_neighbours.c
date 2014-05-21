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
#define TRAILS_COUNT 2

/**
 * Used to distinguish put/get request use of find_successor() from others 
 */
#define PUT_GET_REQUEST 65


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
   * Number of peers recorded in the outgoing path from source to the
   * stored location of this message.
   */
  uint32_t put_path_length GNUNET_PACKED;
  
  /**
   * Length of the GET path that follows (if tracked).
   */
  uint32_t get_path_length GNUNET_PACKED;
  
  /**
   * Peer which will receive the get result message. 
   */
  struct GNUNET_PeerIdentity source_peer;
  
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
   * Peer closest to this value will be our finger. 
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
  
  /**
   * Relative time for which congested_peer will remain congested. 
   */
  struct GNUNET_TIME_Relative congestion_time;
  
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
   * Old successor of source peer. 
   */
  struct GNUNET_PeerIdentity old_successor;
  
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
   * Source peer of this trail.  
   */
  struct GNUNET_PeerIdentity source_peer;
  
  /**
   * Destination peer of this trail. 
   */
  struct GNUNET_PeerIdentity destination_peer;
  
  /**
   * Trail from source_peer to destination_peer compressed such that 
   * new_first_friend is the first hop in the trail from source to 
   * destination. 
   */
  struct GNUNET_PeerIdentity new_first_friend;
  /**
   * Number of peers in trail from source_peer to new first friend.
   */
  uint32_t trail_length;
  
  /* Trail from source_peer to new first friend. */
};


struct PeerAddTrailMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_DHT_P2P_ADD_TRAIL
   */
  struct GNUNET_MessageHeader header;
  
  /**
   * Source peer of the routing trail. 
   */
  struct GNUNET_PeerIdentity source_peer;
  
  /**
   * Destination peer of the routing trail. 
   */
  struct GNUNET_PeerIdentity destination_peer;
  
  /**
   * Total number of peers from source peer to destination peer. 
   */
  unsigned int trail_length;
  
  /* Trail from source peer to destination peer. */
  
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
 * FIXME: for congested peer just define a relative time as #define.
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
      if(middle == 0)
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
 * Construct a trail setup message and forward it to a friend. 
 * @param source_peer Peer which wants to set up the trail to one of its finger.
 * @param destination_finger Peer identity closest to this value will be 
 *                           @a source_peer's finger.
 * @param current_destination next destination corresponding to @a current_source,
 *                            can be either a finger or a friend of @a current_source. 
 * @param current_source Peer for which @a current_destination is its finger/friend.
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
                                          const struct GNUNET_PeerIdentity *old_successor,
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
  memcpy (&(nsm->old_successor), old_successor, sizeof (struct GNUNET_PeerIdentity));
  nsm->trail_length = htonl (trail_length);

  if (trail_length > 0)
  {
    peer_list = (struct GNUNET_PeerIdentity *) &nsm[1];
    memcpy (peer_list, trail_peer_list, trail_length * sizeof (struct GNUNET_PeerIdentity));
  }
   /* Send the message to chosen friend. */
  GNUNET_CONTAINER_DLL_insert_tail (target_friend->head, target_friend->tail, pending);
  target_friend->pending_count++;
  process_friend_queue (target_friend);
}


/**
 * Send a trail tear down message
 * @param source_peer Source of the trail.
 * @param destination_peer Destination of the trail. 
 * @param discarded_trail Discarded trail from source to destination. 
 * @param discarded_trail_length Total number of peers in trail_list. 
 * @pararm target_peer Next peer to forward this message to. 
 * @param new_first_friend The new first hop in the new trail from source to destination
 *                         peer.
 */
void
GDS_NEIGHBOURS_send_trail_teardown (const struct GNUNET_PeerIdentity *source_peer,
                                    const struct GNUNET_PeerIdentity *destination_peer,
                                    const struct GNUNET_PeerIdentity *discarded_trail,
                                    unsigned int discarded_trail_length,
                                    struct FriendInfo *target_friend,
                                    const struct GNUNET_PeerIdentity *new_first_friend)
{
  struct P2PPendingMessage *pending;
  struct PeerTrailTearDownMessage *ttdm;
  struct GNUNET_PeerIdentity *peer_list;
  size_t msize;
  
  msize = sizeof (struct PeerTrailTearDownMessage) + 
          (discarded_trail_length * sizeof(struct GNUNET_PeerIdentity));
  
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
  memcpy (&(ttdm->new_first_friend),new_first_friend, sizeof (struct GNUNET_PeerIdentity));
  ttdm->trail_length = htonl (discarded_trail_length);
  
  if (discarded_trail_length > 0)
  {
    peer_list = (struct GNUNET_PeerIdentity *) &ttdm[1];
    memcpy (peer_list, discarded_trail, discarded_trail_length * sizeof (struct GNUNET_PeerIdentity));
  }
   /* Send the message to chosen friend. */
  GNUNET_CONTAINER_DLL_insert_tail (target_friend->head, target_friend->tail, pending);
  target_friend->pending_count++;
  process_friend_queue (target_friend);
}


/**
 * Construct an add_trail_message and send it to target_friend
 * @param source_peer Source of the trail to be added
 * @param destination_peer Destination of the trail to be added
 * @param trail Trail from source to destination
 * @param trail_length Total number of peers in the trail
 * @param target_friend Friend to forward this message. 
 */
void
GDS_NEIGHBOURS_send_add_trail_message (struct GNUNET_PeerIdentity *source_peer,
                                       struct GNUNET_PeerIdentity *destination_peer,
                                       struct GNUNET_PeerIdentity *trail,
                                       unsigned int trail_length,
                                       struct FriendInfo *target_friend)
{
  struct P2PPendingMessage *pending;
  struct PeerAddTrailMessage *adm;
  struct GNUNET_PeerIdentity *peer_list;
  size_t msize;
  
  msize = sizeof (struct PeerAddTrailMessage) + 
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
  adm = (struct PeerAddTrailMessage *) &pending[1];
  pending->msg = &adm->header;
  adm->header.size = htons (msize);
  adm->header.type = htons (GNUNET_MESSAGE_TYPE_DHT_P2P_ADD_TRAIL);
  memcpy (&(adm->source_peer), source_peer, sizeof (struct GNUNET_PeerIdentity));
  memcpy (&(adm->destination_peer), destination_peer, sizeof (struct GNUNET_PeerIdentity));
  adm->trail_length = htonl (trail_length);
  
  if (trail_length > 0)
  {
    peer_list = (struct GNUNET_PeerIdentity *)&adm[1];
    memcpy (peer_list, trail, sizeof (struct GNUNET_PeerIdentity) * trail_length);
  }
  
  /* Send the message to chosen friend. */
  GNUNET_CONTAINER_DLL_insert_tail (target_friend->head, target_friend->tail, pending);
  target_friend->pending_count++;
  process_friend_queue (target_friend);
}


/**
 * FIXME: CONGESTION: check the code once basic code is all correct. s
 * FIXME: call GNUNET_CONTAINER_multipeermap_iterator_destroy (iter);
 * In case the friend chosen in select_random_friend() is congested or
 * has crossed trail_threshold, then get next friend which is not congested or 
 * has not crossed trail threshold from friend peermap. 
 * @param current_index Index in finger peermap chosen randomly
 * @param friend_peermap_size Total number of entries in friend peermap.
 * @param count Total number of time this function has been called, in case
 *              count == sizeof(friend_peermap) - 1, it means none of the friends are free. 
 * @return Friend Friend found.
 *         NULL in case all the friends are congested or have crossed trail threshold.
 */
static struct FriendInfo *
get_next_friend (unsigned int current_index, 
                 unsigned int friend_peermap_size,
                 unsigned int count)
{
  struct GNUNET_CONTAINER_MultiPeerMapIterator *iter;
  struct GNUNET_PeerIdentity key_ret;
  struct FriendInfo *friend;
  int j = 0;
  
  current_index = (current_index + 1) % friend_peermap_size;
  iter = GNUNET_CONTAINER_multipeermap_iterator_create (friend_peermap);
  while(j < (current_index))
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
    if ((friend->trails_count > TRAIL_THROUGH_FRIEND_THRESHOLD) ||
        (0 != GNUNET_TIME_absolute_get_remaining (friend->congestion_duration).rel_value_us))
    {
      count++;
      if (count == (friend_peermap_size -1))
        return NULL;
      else
        return get_next_friend (j,friend_peermap_size,count);
    }
    return friend;
  }
  else
    return NULL;
}


/** 
 * FIXME: CONGESTION: check the code once basic code is all correct. 
 * FIXME: call GNUNET_CONTAINER_multipeermap_iterator_destroy (iter);
 * Randomly choose one of your friends from the friends_peer map
 * @return Friend Randomly chosen friend. 
 *         NULL in case friend peermap is empty, or all the friends are either
 *              congested or have crossed trail threshold. 
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
  if (0 == current_size)
    return NULL;
  
  index = GNUNET_CRYPTO_random_permute (GNUNET_CRYPTO_QUALITY_WEAK, current_size);
  iter = GNUNET_CONTAINER_multipeermap_iterator_create (friend_peermap);
 
  while(j < (*index))
  {
    if(GNUNET_YES == GNUNET_CONTAINER_multipeermap_iterator_next (iter,NULL,NULL))
    {
      j++;
    }
    else 
    {
      return NULL;
    }
  }  

  if(GNUNET_YES == GNUNET_CONTAINER_multipeermap_iterator_next (iter,&key_ret,(const void **)&friend))
  {
    if ((TRAIL_THROUGH_FRIEND_THRESHOLD == friend->trails_count) ||
        (0 != GNUNET_TIME_absolute_get_remaining (friend->congestion_duration).rel_value_us))
    {
      return get_next_friend (*index, current_size, 1);
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
  GDS_NEIGHBOURS_send_trail_setup (&my_identity, finger_identity, &(target_friend->id),
                                   &my_identity, target_friend, 0, NULL, finger_map_index);
}


/**
 * FIXME: TRAIL_LIST URGENT. Send trail teardown message along each of the trail. 
 * Scan the trail to check if any of my own friend is part of trail. If yes
 * then shortcut the trail, send a trail teardown for the discarded trail,
 * update trail list and trail_length. 
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
  struct FriendInfo *target_friend;
   
  if (0 == GNUNET_CRYPTO_cmp_peer_identity (&my_identity,finger))
  {
    /* Here you don't send a trail teardown as no one added this in their
     routing table. */
    *trail_length = 0;
    trail = NULL;
    return;    
  }
  if (GNUNET_CONTAINER_multipeermap_get (friend_peermap, finger))
  {
    int discarded_trail_length = *trail_length;
    target_friend = GNUNET_CONTAINER_multipeermap_get(friend_peermap, &trail[0]);
    GDS_NEIGHBOURS_send_trail_teardown (&my_identity, finger, trail,
                                        discarded_trail_length, target_friend, finger);
    *trail_length = 0;
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
       */
      struct GNUNET_PeerIdentity *discarded_trail;
      struct FriendInfo *target_friend;
      int discarded_trail_length;
      int j = 0;

      discarded_trail_length = i - 1;
      discarded_trail = GNUNET_malloc (discarded_trail_length * sizeof (struct GNUNET_PeerIdentity));
      memcpy (discarded_trail, trail, discarded_trail_length * sizeof (struct GNUNET_PeerIdentity));
      target_friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, &trail[0]);
      GDS_NEIGHBOURS_send_trail_teardown (&my_identity, finger, discarded_trail,
                                         discarded_trail_length, target_friend,
                                         &trail[i]);
     
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
 * FIXME: URGENT:Adapt the code for List of trails. 
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
 * FIXME: URGENT: TRAIL_LIST First check if both the trails are present if yes 
 * then send it for both of them. Currently sending it only for one trail.
 * Send a trail teardown message for the trail of removed finger from the finger
 * peermap. 
 * @param existing_finger Finger to removed from the finger peermap.
 */
static
void send_trail_teardown (struct FingerInfo *removed_finger)
{
 struct GNUNET_PeerIdentity *peer_list; 
 struct FriendInfo *friend; 
 struct TrailPeerList *finger_trail;
 int removed_finger_trail_length = removed_finger->first_trail_length;
 int i = 0;

 if (removed_finger->first_trail_length == 0)
    return;
 
 finger_trail = removed_finger->first_trail_head;
 friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, &(finger_trail->peer)); 
 peer_list = GNUNET_malloc ( removed_finger_trail_length * sizeof (struct GNUNET_PeerIdentity));
 while (i < removed_finger->first_trail_length)
 {
   memcpy (&peer_list[i], &(finger_trail->peer), sizeof (struct GNUNET_PeerIdentity));
   finger_trail = finger_trail->next;
   i++;
 }

 GDS_NEIGHBOURS_send_trail_teardown (&my_identity, &(removed_finger->finger_identity),
                                     peer_list, removed_finger_trail_length, friend,
                                     &(removed_finger->finger_identity)); 
}


/**
 * FIXME: URGENT Adapt it to trail list. 
 * Add a new trail to reach an existing finger in finger peermap and increment
 * the count of number of trails to reach to this finger. 
 * @param existing_finger Finger 
 * @param trail New trail to be added
 * @param trail_length Total number of peers in the trail. 
 */
static
void add_new_trail (struct FingerInfo *existing_finger, 
                    struct GNUNET_PeerIdentity *trail,
                    unsigned int trail_length)
{
  int i;
  i = 0;
  /* FIXME: Here you need to understand which trail is there and which not. 
   In case first_trail_head != NULL, then that trail is present 
   so you should add the second one. Need to verify this logic. */    
  if (existing_finger->first_trail_head != NULL)
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
      GNUNET_CONTAINER_DLL_insert_tail(existing_finger->first_trail_head, existing_finger->first_trail_tail, element);
      i++;
    }
  }  
  existing_finger->trail_count++;
}


/**
 * FIXME: URGENT: adapt it to TRAIL LIST. 
 * In case there are already maximum number of possible trail to reach to a finger,
 * then check if the new trail's length is lesser than any of the existing trails.
 * If yes then replace that old trail by new trail.
 * Note: Here we are taking length as a parameter to choose the best possible trail,
 * but there could be other parameters also like - 1. duration of existence of a
 * trail - older the better. 2. if the new trail is completely disjoint than the 
 * other trails, then may be choosing it is better. 
 * @param existing_finger
 * @param trail
 * @param trail_length
 * @return #GNUNET_YES 
 *         #GNUNET_NO
 */
static 
void select_and_replace_trail (struct FingerInfo *existing_finger, 
                               struct GNUNET_PeerIdentity *new_trail,
                               unsigned int new_trail_length)
{
  if (existing_finger->first_trail_length == existing_finger->second_trail_length)
  {
    if (new_trail_length < existing_finger->first_trail_length)
    {
      /* Randomly choose one of the trail. FIXME:currently I am just replacing the
       first trail.*/
      struct TrailPeerList *peer;
      int i = 0;
        
      while (NULL != (peer = existing_finger->first_trail_head))
      {
        GNUNET_CONTAINER_DLL_remove (existing_finger->first_trail_head, existing_finger->first_trail_tail, peer);
        GNUNET_free (peer);
      } 
        
      while (i < new_trail_length)
      {
        struct TrailPeerList *element;
        element = GNUNET_malloc (sizeof (struct TrailPeerList));
        element->next = NULL;
        element->prev = NULL;
    
        memcpy (&(element->peer), &new_trail[i], sizeof(struct GNUNET_PeerIdentity));
        GNUNET_CONTAINER_DLL_insert_tail(existing_finger->second_trail_head, existing_finger->second_trail_tail, element);
        i++;
      }
    }
  }
  else if ((new_trail_length < existing_finger->second_trail_length) && 
          (existing_finger->second_trail_length < existing_finger->first_trail_length))
  {
    /* Replace the first trail by the new trail. */
    struct TrailPeerList *peer;
    int i = 0;
        
    while (NULL != (peer = existing_finger->first_trail_head))
    {
      GNUNET_CONTAINER_DLL_remove (existing_finger->first_trail_head, existing_finger->first_trail_tail, peer);
      GNUNET_free (peer);
    } 
        
    while (i < new_trail_length)
    {
      struct TrailPeerList *element;
      element = GNUNET_malloc (sizeof (struct TrailPeerList));
      element->next = NULL;
      element->prev = NULL;
    
      memcpy (&(element->peer), &new_trail[i], sizeof(struct GNUNET_PeerIdentity));
      GNUNET_CONTAINER_DLL_insert_tail(existing_finger->second_trail_head, existing_finger->second_trail_tail, element);
      i++;
    }
  }
  else if ( (new_trail_length < existing_finger->first_trail_length) &&
           (existing_finger->first_trail_length < existing_finger->second_trail_length))
  {
    /* Replace the second trail by the new trail. */
    struct TrailPeerList *peer;
    int i = 0;
        
    while (NULL != (peer = existing_finger->second_trail_head))
    {
      GNUNET_CONTAINER_DLL_remove (existing_finger->second_trail_head, existing_finger->second_trail_tail, peer);
      GNUNET_free (peer);
    }
        
    while (i < new_trail_length)
    {
      struct TrailPeerList *element;
      element = GNUNET_malloc (sizeof (struct TrailPeerList));
      element->next = NULL;
      element->prev = NULL;
    
      memcpy (&(element->peer), &new_trail[i], sizeof(struct GNUNET_PeerIdentity));
      GNUNET_CONTAINER_DLL_insert_tail(existing_finger->second_trail_head, existing_finger->second_trail_tail, element);
      i++;
     }
  } 
}


/**
 * FIXME: URGENT: Adapat it for trail list. 
 * FIXME: If we remove a finger which is our friend, then how should we handle it. 
 * Ideally only in case if the trail_length > 0,we increment the trail count
 * of the first friend in the trail to reach to the finger. in case finger is
 * our friend then trail length = 0, and hence, we have never incremented the
 * trail count associated with that friend. 
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
  
#if 0
  /* We will not need this variable any more, all_friends_trail_threshold,
   FIXME: REMOVE IT. */
  if (GNUNET_YES == all_friends_trail_threshold)
  {
    all_friends_trail_threshold = GNUNET_NO;
    /* FIXME; Here you should reschedule the send_find_finger_task here. or
     make a call.*/
  }
#endif
}


/**
 * FIXME: create a different data structure for storing the peer ids here. 
 * Select the closest finger. Used for both predecessor and other fingers..
 * But internally calls different functions for predecessor and other fingers.
 * @param existing_finger Finger in finger peermap. 
 * @param new_finger New finger identity
 * @param finger_map_index Index in finger peermap where @a existing_finger is stored.
 * @return #GNUNET_YES if the new finger is closest.
 *         #GNUNET_NO if the old finger is closest.
 *         #GNUNET_SYSERR in case our own identity is closest (should never happen).
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
  
  /* Add your entry to peers. */
  memcpy (&peers[0], &my_identity, sizeof (uint64_t));
  peers[0].type = MY_ID;
  peers[0].data = NULL;
  
  /* Add existing_finger identity to the peers. */
  memcpy (&peers[1], &(existing_finger->finger_identity), sizeof (uint64_t));
  peers[1].type = FINGER;
  peers[1].data = existing_finger;
  
  /* Add new_finger identity to the peers. s*/
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
 * FIXME: URGENT: Adapat it for trail list. 
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
  
  if (0 != GNUNET_CRYPTO_cmp_peer_identity (&my_identity,finger_identity)) /* finger_trail is NULL in case I am my own finger identity. */
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
 
  return GNUNET_CONTAINER_multipeermap_put (finger_peermap,
                                            &(new_finger_entry->finger_identity),
                                            new_finger_entry,
                                            GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);    
}


/**
 * Choose the closest finger between existing finger and new finger.
 * If the new finger is closest, then send a trail_teardown message along 
 * existing_finger's trail. In case both the id's are same, and there is a place
 * to add more trails, then store both of them. In case there is no space to 
 * store any more trail, then choose the best trail (best - depends on length in
 * current_implementation) and discard the others. 
 * @param existing_finger
 * @param new_finger Existing finger in finger_peermap for @a finger_map_index
 * @param trail Trail to reach from me to @a new_finger
 * @param trail_length Total number of peers in @a trail.
 * @param finger_map_index Index in finger peermap. 
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
    /* New entry and existing entry are same. */
    if (0 == GNUNET_CRYPTO_cmp_peer_identity (&(existing_finger->finger_identity), &my_identity))
    {
      /* If existing_finger is my_identity then trail_length = 0, trail = NULL. In
       this case you don't need to check the trails. Exit. */
      return GNUNET_NO;
    }
    if (trail_length > 0)
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
    /* New finger is the closest finger. */
    if (0 == GNUNET_CRYPTO_cmp_peer_identity (&my_identity, new_finger))
    {
      /* FIXME: Here in case the new finger is my_identity and old entry is not,
       should we keep the old entry even if the old entry is not the closest? */
      return GNUNET_NO;    
    }
    send_trail_teardown (existing_finger);
    decrement_friend_trail_count (existing_finger);
    free_finger (existing_finger);
    
    if (trail_length > 0)
    {
      scan_and_compress_trail (trail, &trail_length, new_finger);
    }
    return GNUNET_YES;
  }
  else if (GNUNET_NO == select_finger (existing_finger, new_finger,finger_map_index))
  {
    /* existing_finger is the closest finger. */
    return GNUNET_NO;
  }
  return GNUNET_SYSERR;
}


/**
 * FIXME: TRAIL LIST urgent. 
 * Check if there is already an entry for finger map index in finger table.
 * If yes then choose the closest finger. 
 * @param finger_identity Peer Identity of finger. 
 * @param finger_trail Trail to reach from me to @a finger_identity
 * @param finger_trail_length Total number of peers in finger_trail.
 * @param finger_map_index Index in finger_peermap.
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
  int old_entry_found = GNUNET_NO;
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
        old_entry_found = GNUNET_YES;
        if ( GNUNET_NO == select_closest_finger (existing_finger, finger_identity, 
                                                 finger_trail, finger_trail_length,
                                                 finger_map_index)) 
          goto update_current_search_finger_index;
        else
          break;
      }
    } 
  }
  GNUNET_CONTAINER_multipeermap_iterator_destroy (finger_iter);
  
  if (GNUNET_NO == old_entry_found)
  {
    if (finger_trail_length > 0)
    {
      scan_and_compress_trail (finger_trail, &finger_trail_length, finger_identity);
    }
  }
  
  /* FIXME: handle the case when addition in peer map failed. */
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
    current_search_finger_index = 0;
  }
  else 
  {
    current_search_finger_index = current_search_finger_index - 1;
  }
  
  return new_entry_added;
}


/**
 * FIXME: URGNET: adapt it for trail list. 
 * Check if the successor chosen is congested or has crossed trail threshold. 
 * @param successor Successor to be checked.
 * @return #GNUNET_YES in case its is either congested or has crossed trail threshold.
 *         #GNUNET_NO if its good to go. 
 */
static int
check_friend_threshold_and_congestion (struct Sorting_List *successor)
{  
  struct FriendInfo *friend;
  
  if (successor->type == FRIEND)
  {
    friend = successor->data;
  }
  else if (successor->type == FINGER)
  {
    struct FingerInfo *finger = successor->data;
    if (finger->first_trail_length > 0)
    {
      friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, 
                                                  &(finger->first_trail_head->peer));
    }
    else
    {
      if (0 != GNUNET_CRYPTO_cmp_peer_identity(&my_identity, &finger->finger_identity))
       friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, &(finger->finger_identity));
      else
        return GNUNET_YES;
    }
  }
  
  if ((friend->trails_count == TRAIL_THROUGH_FRIEND_THRESHOLD)||
      ((0 != GNUNET_TIME_absolute_get_remaining (friend->congestion_duration).rel_value_us)))
  {
    return GNUNET_YES;
  }
  else
    return GNUNET_NO;
}


/**
 * Find the next successor for key_value as the earlier selected successor is either
 * congested or have crossed trail threshold. 
 * @param all_known_peers Array that contains my_identity, value, friends and fingers.
 * @param array_size Total number of entries in @a all_known_peers.
 * @param start_index Index at which original successor is located. 
 * @param search_index Index at which our possible current successor is located.
 * @param count Number of times this function has been called. 
 * @return successor, in case found.
 *         NULL, in case of error.  
 */
static struct Sorting_List *
get_next_successor (struct Sorting_List *all_known_peers,
                    unsigned int array_size, int start_index,
                    int search_index, int count)
{
  struct Sorting_List *next_peer;
  
  if (search_index == start_index)
    return NULL;
  next_peer = GNUNET_malloc (sizeof (struct Sorting_List));
  memcpy (next_peer, &all_known_peers[search_index], sizeof (struct Sorting_List));
  
  if (next_peer->type == MY_ID)
    return next_peer;
  
  if ((next_peer->type == VALUE) || 
     (GNUNET_YES == check_friend_threshold_and_congestion (next_peer)))
  {
    search_index = (search_index + 1) % array_size;
    count++;
    return get_next_successor (all_known_peers, array_size, start_index, search_index, count);
  }
  else 
    return next_peer;
}


/**
 * Search the current location of successor in all_known_peers array.
 * @param all_known_peers Array which contains my_id, key value, friends and fingers.
 * @param array_size Total number of entries in @a all_known_peers
 * @param search_value 64 bit value of successor. 
 * @return Index of array at which value is stored,
 *         #GNUNET_SYSERR in case of error.
 */
static int
get_successor_location (struct Sorting_List *all_known_peers, size_t array_size,
                     uint64_t search_value)
{
  int k;
  
  while (0 != memcmp (&all_known_peers[k].data, &search_value, sizeof (uint64_t)))
  {
    k++;
  }
  if (k == array_size)
    return GNUNET_SYSERR;
  else 
    return k;
}


/**
 * Initialize all_known_peers with my_id, value, friends and fingers. 
 * @param all_known_peers Empty all_known_peers
 * @param size Total number of elements in all_known_peers
 */
static void
init_all_known_peers (struct Sorting_List *all_known_peers, int size, uint64_t value)
{
  struct GNUNET_CONTAINER_MultiPeerMapIterator *friend_iter;
  struct GNUNET_CONTAINER_MultiPeerMapIterator *finger_iter;
  struct GNUNET_PeerIdentity key_ret;
  struct FriendInfo *friend;
  struct FingerInfo *finger;
  unsigned int finger_index;
  unsigned int friend_index;
  int k;
  int j; 
  
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
}


/** 
 * FIXME: 1. In case all the peers are congested/threshold then by default my_id is
 * chosen. There is no limit on number of peers which can keep me as their finger.
 * Should there be limit? If yes then we need to keep a counter of number of peers
 * that keep me as fingers. This counter may/may not give the correct value as
 * that peer may have found a better finger. So should reset the limit at some
 * interval. 
 * 2. Change the finger code, TRAIL_LIST. URGENT
 * Find closest successor for the value.
 * @param value Value for which we are looking for successor
 * @param[out] current_destination set to my_identity in case I am the final destination,
 *                                 set to friend identity in case friend is final destination,
 *                                 set to first friend to reach to finger, in case finger
 *                                 is final destination. 
 * @param[out] current_source set to my_identity.
 * @param finger_map_index Index in finger peer map. 
 * @return Peer identity of next hop to send trail setup message to 
 */
static struct GNUNET_PeerIdentity *
find_successor (uint64_t value, struct GNUNET_PeerIdentity *current_destination,
               struct GNUNET_PeerIdentity *current_source, unsigned int finger_map_index)
{
  struct Sorting_List *successor;
  unsigned int size;
  
  size = GNUNET_CONTAINER_multipeermap_size (friend_peermap)+
         GNUNET_CONTAINER_multipeermap_size (finger_peermap)+
         2;
  
  struct Sorting_List all_known_peers[size];
  init_all_known_peers (all_known_peers, size, value);
  qsort (&all_known_peers, size, sizeof (struct Sorting_List), &compare_peer_id);
  
  if (PREDECESSOR_FINGER_ID == finger_map_index)
    successor = find_closest_predecessor (all_known_peers, value, size);
  else
    successor = find_closest_successor (all_known_peers, value, size);
  
  if ((successor->type != MY_ID) && (successor->type != VALUE))
  {
    if (GNUNET_YES == check_friend_threshold_and_congestion (successor))
    {
      int search_index = get_successor_location (all_known_peers, size, successor->peer_id);
      successor = get_next_successor (all_known_peers, size, search_index, search_index + 1, 0);
    }
  }
  
  if (successor->type == MY_ID)
  {
    memcpy (current_destination, &my_identity, sizeof (struct GNUNET_PeerIdentity));
    return &my_identity;
  }
  else if (successor->type == FRIEND)
  {
    struct FriendInfo *target_friend = successor->data;
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
    return NULL;
  }
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
    next_hop = find_successor (key_value, &current_destination, &current_source,PUT_GET_REQUEST);
    if (0 == GNUNET_CRYPTO_cmp_peer_identity(next_hop, &my_identity)) 
    {
      /* I am the destination but we have already done datacache_put in client file.  */
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
    struct GNUNET_PeerIdentity *next_hop;
    uint64_t key_value;
    
    memcpy (&key_value, key, sizeof (uint64_t));
	// FIXME: endianess of key_value!?
    next_hop = find_successor (key_value, &current_destination, &current_source, PUT_GET_REQUEST);
    if (0 == GNUNET_CRYPTO_cmp_peer_identity(&my_identity,next_hop)) 
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
  
  if (get_path != 0)
  {
    gp = (struct GNUNET_PeerIdentity *) &pgm[1];
    memcpy (gp, get_path, get_path_length * sizeof (struct GNUNET_PeerIdentity));
  }
  GNUNET_CONTAINER_DLL_insert_tail (target_friend->head, target_friend->tail, pending);
  target_friend->pending_count++;
  process_friend_queue (target_friend);
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
                                struct GNUNET_PeerIdentity *next_hop,
                                struct GNUNET_PeerIdentity *source_peer,
                                unsigned int put_path_length,
                                const struct GNUNET_PeerIdentity *put_path,
                                unsigned int get_path_length,
                                struct GNUNET_PeerIdentity *get_path,
                                struct GNUNET_TIME_Absolute expiration,
                                const void *data, size_t data_size)
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
  
  if(get_path_length > 0)
  {
    current_path_index = search_my_index(get_path, get_path_length);
    if (GNUNET_SYSERR == current_path_index)
    {
      GNUNET_break (0);
      return;
    }
  }
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
  
  if (get_path_length != 0)
  {
    get_result_path = (struct GNUNET_PeerIdentity *)&get_result[1];
    memcpy (get_result_path, get_path,
            sizeof (struct GNUNET_PeerIdentity) * get_path_length);
  }
  memcpy (&get_result_path[get_path_length], data, data_size);
  
  /* FIXME: Is this correct? */
  if (put_path_length != 0)
  {
    pp = (struct GNUNET_PeerIdentity *)&get_result_path[1];
    memcpy (pp, put_path,sizeof (struct GNUNET_PeerIdentity) * put_path_length);
  }
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
 * @param congestion_timeout Time duration for which @a congested peer will be
 *                           congested. 
 */
void
GDS_NEIGHBOURS_send_trail_rejection (const struct GNUNET_PeerIdentity *source_peer,
                                     uint64_t finger_identity,
                                     const struct GNUNET_PeerIdentity *congested_peer,
                                     const struct GNUNET_PeerIdentity *next_hop,
                                     unsigned int finger_map_index,
                                     struct GNUNET_PeerIdentity *trail_peer_list,
                                     unsigned int trail_length,
                                     struct GNUNET_TIME_Relative congestion_timeout)
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
  trail_rejection->finger_map_index = htonl (finger_map_index);
  trail_rejection->trail_length = htonl (trail_length);
  trail_rejection->congestion_time = congestion_timeout;
  
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
  
  /* extend 'put path' by sender */
  struct GNUNET_PeerIdentity pp[putlen + 1];
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
  }
  else
  {
    next_hop = find_successor (key_value, &current_destination, &current_source,PUT_GET_REQUEST); 
  }
  
  if (NULL == next_hop)
  {
    GNUNET_STATISTICS_update (GDS_stats,
                              gettext_noop ("# Next hop to forward the packet not found "
                              "trail setup request, packet dropped."),
                              1, GNUNET_NO);
    return GNUNET_SYSERR;
  }
  
  GDS_CLIENTS_process_put (options,
                           ntohl (put->block_type),
                           ntohl (put->hop_count),
                           ntohl (put->desired_replication_level),
                           putlen, pp,
                           GNUNET_TIME_absolute_ntoh (put->expiration_time),
                           &put->key,
                           payload,
                           payload_size);
  
  if (0 == GNUNET_CRYPTO_cmp_peer_identity(&my_identity, next_hop)) /* I am the final destination */
  {
    GDS_DATACACHE_handle_put (GNUNET_TIME_absolute_ntoh (put->expiration_time),
                              &(put->key),putlen, pp, ntohl (put->block_type), 
                              payload_size, payload);
    return GNUNET_YES;
  }
  else
  {
    GDS_NEIGHBOURS_send_put (&put->key,  
                             ntohl (put->block_type),ntohl (put->options),
                             ntohl (put->desired_replication_level),
                             current_destination, current_source, next_hop,
                             ntohl (put->hop_count), putlen, pp,
                             GNUNET_TIME_absolute_ntoh (put->expiration_time),
                             payload, payload_size);
 
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
  current_destination = get->current_destination;
  current_source = get->current_source;
  if (get_length > 0)
    get_path = (struct GNUNET_PeerIdentity *)&get[1];
  
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
  }
  else
  {
    next_hop = find_successor (key_value, &current_destination, &current_source,PUT_GET_REQUEST);  
  }
  
  if (NULL == next_hop)
  {
    GNUNET_STATISTICS_update (GDS_stats,
                              gettext_noop ("# Next hop to forward the packet not found "
                              "trail setup request, packet dropped."),
                              1, GNUNET_NO);
    return GNUNET_SYSERR;
  }
  if (0 == GNUNET_CRYPTO_cmp_peer_identity(&my_identity, next_hop))
  {
    /* I am the destination.*/
    struct GNUNET_PeerIdentity final_get_path[get_length+1];
    struct GNUNET_PeerIdentity next_hop;

    memcpy (final_get_path, gp, get_length * sizeof (struct GNUNET_PeerIdentity));
    memcpy (&final_get_path[get_length+1], &my_identity, sizeof (struct GNUNET_PeerIdentity));
    get_length = get_length + 1;
    memcpy (&next_hop, &final_get_path[get_length-2], sizeof (struct GNUNET_PeerIdentity));
    GDS_DATACACHE_handle_get (&(get->key),(get->block_type), NULL, 0, NULL, 0,
                              get_length, final_get_path,&next_hop, &my_identity);
    
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
  
  if (getlen > 0)
   get_path = (struct GNUNET_PeerIdentity *) &get_result[1];
  payload = &get_path[getlen];
  payload_size = msize - (sizeof (struct PeerGetResultMessage) + 
                          getlen * sizeof (struct GNUNET_PeerIdentity));
  
  if (putlen > 0)
    put_path = &get_path[1];
  else
    put_path = NULL;
  
  if (0 == (GNUNET_CRYPTO_cmp_peer_identity (&my_identity, &(get_path[0]))))
  {
    GDS_CLIENTS_handle_reply (get_result->expiration_time, &(get_result->key), 
                              getlen, get_path, putlen,
                              put_path, get_result->type, payload_size, payload);
    return GNUNET_YES;
  }
  else
  {
    current_path_index = search_my_index (get_path, getlen);
    if (GNUNET_SYSERR == current_path_index )
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    GDS_NEIGHBOURS_send_get_result (&(get_result->key), get_result->type,
                                    &get_path[current_path_index - 1],
                                    &(get_result->source_peer), putlen, put_path,
                                    getlen, get_path, get_result->expiration_time,
                                    payload, payload_size);
    return GNUNET_YES;
  }  
  return GNUNET_SYSERR;
}
 

/**
 * Select the closest peer between peer returned from routing table and from
 * find_successor()
 * @param prev_hop Peer which sent the trail setup message.
 * @param current_destination[out] Next peer which will receive this message.
 * @param current_source[out] Source of the @a current_destination. 
 * @param value Key value to which the peer should be closest.
 * @para finger_map_index Index in finger map. 
 * @return Peer which is closest, in case of error NULL.
 */
struct GNUNET_PeerIdentity *
select_closest_peer (const struct GNUNET_PeerIdentity *prev_hop,
                     struct GNUNET_PeerIdentity *current_destination,
                     struct GNUNET_PeerIdentity *current_source,
                     uint64_t value,
                     unsigned int finger_map_index)
{
  struct GNUNET_PeerIdentity *peer1;
  struct GNUNET_PeerIdentity *peer2;
  struct Sorting_List peers[3];
  struct Sorting_List *closest_finger;
  struct GNUNET_PeerIdentity current_dest;
  struct GNUNET_PeerIdentity current_src;
  
  peer1 = GDS_ROUTING_search (current_source, current_destination, prev_hop);
  peer2 = find_successor (value, &current_dest, &current_src,finger_map_index);

  if( (peer1 != NULL) && (peer2 != NULL))
  {
    memcpy (&peers[0], &peer1, sizeof (uint64_t));
    peers[0].type = FRIEND;
    peers[0].data = NULL;
    
    memcpy (&peers[1], &value, sizeof (uint64_t));
    peers[1].type = VALUE;
    peers[1].data = NULL;
    
    memcpy (&peers[2], &peer2, sizeof (uint64_t));
    peers[2].type = FINGER;
    peers[1].data = NULL;
  
    qsort (&peers, 3, sizeof (struct Sorting_List), &compare_peer_id);
    if (PREDECESSOR_FINGER_ID == finger_map_index)
      closest_finger = find_closest_predecessor (peers, value, 3);
    else
      closest_finger = find_closest_successor (peers, value, 3);

    if (closest_finger->type == FINGER)
    {
      memcpy (current_destination, &current_dest, sizeof (struct GNUNET_PeerIdentity));
      memcpy (current_source, &current_src, sizeof (struct GNUNET_PeerIdentity));
      return peer2;
    }
    else if (closest_finger->type == VALUE)
    { 
      return NULL;
    }
    else if (closest_finger->type == FRIEND);
    {
      return peer1;  
    }
  }
  else if ((peer1 == NULL) && (peer2 == NULL))
  {
    return NULL;
  }
  else if (peer1 == NULL)
  {
    return peer2;
  }
  else if (peer2 == NULL)
  {
    return peer1;
  }
  return NULL;
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
  
  if (trail_length > 0)
    trail_peer_list = (struct GNUNET_PeerIdentity *)&trail_setup[1];
  memcpy (&current_destination, &(trail_setup->current_destination), sizeof (struct GNUNET_PeerIdentity));
  memcpy (&current_source,&(trail_setup->current_source), sizeof (struct GNUNET_PeerIdentity));
  memcpy (&source, &(trail_setup->source_peer), sizeof (struct GNUNET_PeerIdentity));
  finger_map_index = ntohl (trail_setup->finger_map_index);
  destination_finger_value = ntohl (trail_setup->destination_finger);
  
  /* Check your routing table size, and if you can handle any more trails through you. */
  if (GNUNET_YES == GDS_ROUTING_check_threshold())
  {
    GDS_NEIGHBOURS_send_trail_rejection (&source, destination_finger_value, &my_identity,
                                         peer, finger_map_index, trail_peer_list, trail_length,
                                         CONGESTION_TIMEOUT);
    return GNUNET_OK;
  }
  
   /* Check if you are current_destination or not. */
  if (0 != (GNUNET_CRYPTO_cmp_peer_identity (&current_destination, &my_identity)))
  {
    next_hop = select_closest_peer (peer, &current_destination, &current_source,
                                    destination_finger_value, finger_map_index);
  }
  else
  {
    next_hop = find_successor (destination_finger_value, &current_destination, 
                               &current_source,finger_map_index); 
  } 
  
  if (NULL == next_hop)
  {
    GNUNET_STATISTICS_update (GDS_stats,
                                gettext_noop ("# Next hop to forward the packet not found "
                                "trail setup request, packet dropped."),
                                1, GNUNET_NO);
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
  struct GNUNET_PeerIdentity destination_peer;
  struct GNUNET_PeerIdentity finger_identity;    
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
  memcpy (&destination_peer, &(trail_result->destination_peer), sizeof (struct GNUNET_PeerIdentity));
  memcpy (&finger_identity, &(trail_result->finger_identity), sizeof (struct GNUNET_PeerIdentity));
  
  if (trail_length > 0)
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
      next_hop = trail_result->destination_peer;
    else
      next_hop = trail_peer_list[my_index - 1];
  
    if (0 != (GNUNET_CRYPTO_cmp_peer_identity (&(trail_result->destination_peer),
                                               &(trail_result->finger_identity))))
    {
      struct GNUNET_PeerIdentity *routing_next_hop;

      routing_next_hop = GDS_ROUTING_search (&destination_peer,&finger_identity,
                                             peer);
      if ((NULL == routing_next_hop) || 
          (0 != GNUNET_CRYPTO_cmp_peer_identity(routing_next_hop, &next_hop)))
      {
        GDS_ROUTING_add (&(trail_result->destination_peer), &(trail_result->finger_identity),
                         peer, &next_hop);
      }
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
  if (trail_length > 0)
    trail_peer_list = (const struct GNUNET_PeerIdentity *)&vsm[1];
  memcpy (&source_peer, &(vsm->source_peer), sizeof(struct GNUNET_PeerIdentity));
  
  if(0 == (GNUNET_CRYPTO_cmp_peer_identity (&(vsm->successor),&my_identity)))
  {
    struct FingerInfo *my_predecessor;
    
    my_predecessor = get_predecessor();
    if (NULL == my_predecessor)
    {
      /* FIXME: should we just return. */
      return GNUNET_OK;
    }
    
    if (trail_length == 0)
    {
      memcpy (&next_hop, &source_peer, sizeof (struct GNUNET_PeerIdentity));
    }
    else
    {
      memcpy (&next_hop, &trail_peer_list[trail_length-1], sizeof (struct GNUNET_PeerIdentity));
    }
    target_friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, &next_hop);
    
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
  
  if (trail_length > 0)
    trail_peer_list = (struct GNUNET_PeerIdentity *) &vsrm[1];
  
  if(0 == (GNUNET_CRYPTO_cmp_peer_identity (&(vsrm->destination_peer), &(my_identity))))
  {
    if(0 != (GNUNET_CRYPTO_cmp_peer_identity (&(vsrm->my_predecessor), &(my_identity))))
    {
      if (GNUNET_YES == finger_table_add (&(vsrm->my_predecessor), trail_peer_list, trail_length, 0))
      {
        memcpy (&next_hop, &trail_peer_list[0], sizeof (struct GNUNET_PeerIdentity));
        target_friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, &next_hop);
        scan_and_compress_trail (trail_peer_list, &trail_length, &(vsrm->my_predecessor));
        GDS_NEIGHBOURS_send_notify_new_successor (&my_identity, &(vsrm->my_predecessor),
                                                  &(vsrm->source_successor),
                                                  target_friend, trail_peer_list,
                                                  trail_length);
      }
      return GNUNET_OK;
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
  struct GNUNET_PeerIdentity source_peer;
  struct GNUNET_PeerIdentity old_successor;
  struct GNUNET_PeerIdentity new_successor;
  struct FriendInfo *target_friend;
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
  
  if( trail_length > 0)
    trail_peer_list = (struct GNUNET_PeerIdentity *) &nsm[1];
  memcpy (&source_peer, &(nsm->source_peer), sizeof (struct GNUNET_PeerIdentity));
  memcpy (&old_successor, &(nsm->old_successor), sizeof (struct GNUNET_PeerIdentity));
  memcpy (&new_successor, &(nsm->destination_peer), sizeof (struct GNUNET_PeerIdentity));
  
  if(0 == (GNUNET_CRYPTO_cmp_peer_identity (&new_successor, &my_identity)))
  {
    /* I am the new successor. */
    struct GNUNET_PeerIdentity *new_predecessor;
   
    new_predecessor = GNUNET_new (struct GNUNET_PeerIdentity);
    memcpy (new_predecessor, &(nsm->source_peer), sizeof (struct GNUNET_PeerIdentity));
    if (GNUNET_YES == finger_table_add (new_predecessor, trail_peer_list, trail_length, PREDECESSOR_FINGER_ID))
    {
      if (trail_length > 0)
       target_friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, &(trail_peer_list[trail_length - 1]));
      else 
        target_friend = NULL;
      GDS_NEIGHBOURS_send_add_trail_message (&my_identity, new_predecessor, 
                                             trail_peer_list, trail_length, target_friend);  
    }
    return GNUNET_OK;
  }
  else
  {
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
    GDS_ROUTING_remove_trail (&source_peer, &old_successor, peer);
    GDS_ROUTING_add (&(nsm->source_peer), &(nsm->destination_peer), &next_hop, peer);
    GDS_NEIGHBOURS_send_notify_new_successor (&(nsm->source_peer), 
                                              &(nsm->destination_peer),
                                              &(nsm->old_successor),
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
  const struct PeerTrailRejectionMessage *trail_rejection;
  struct GNUNET_PeerIdentity *trail_peer_list;
  struct FriendInfo *target_friend;
  struct GNUNET_PeerIdentity next_hop;
  struct GNUNET_PeerIdentity *next_peer;
  struct GNUNET_PeerIdentity source;
  struct GNUNET_PeerIdentity current_destination;
  struct GNUNET_PeerIdentity current_source;
  uint32_t trail_length;
  uint32_t finger_map_index;
  uint64_t destination_finger_value;
  struct GNUNET_TIME_Relative congestion_timeout;
  size_t msize;
  
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
  
  if (trail_length > 0)
    trail_peer_list = (struct GNUNET_PeerIdentity *)&trail_rejection[1];
  finger_map_index = ntohl (trail_rejection->finger_map_index);
  memcpy (&destination_finger_value, &(trail_rejection->finger_identity_value), sizeof (uint64_t));
  memcpy (&source, &(trail_rejection->source_peer), sizeof (struct GNUNET_PeerIdentity));
  congestion_timeout = trail_rejection->congestion_time;
  
  /* First set the congestion time of the friend that sent you this message. */
  target_friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, peer);
  target_friend->congestion_duration = GNUNET_TIME_absolute_add (GNUNET_TIME_absolute_get(),
                                                                 congestion_timeout);
  
  if(0 == (GNUNET_CRYPTO_cmp_peer_identity (&my_identity, &(trail_rejection->source_peer))))
  {
    return GNUNET_OK;
  }
  
  if(GNUNET_YES == GDS_ROUTING_check_threshold())
  {
    struct GNUNET_PeerIdentity *new_trail;
    unsigned int new_trail_length;
    
    if (trail_length == 1)
    {
      new_trail = NULL;
      new_trail_length = 0;
      memcpy (&next_hop, &(trail_rejection->source_peer), sizeof (struct GNUNET_PeerIdentity));
    }
    else 
    {
      memcpy (&next_hop, &trail_peer_list[trail_length - 2], sizeof (struct GNUNET_PeerIdentity));
      /* Remove myself from the trail. */
      new_trail_length = trail_length -1;
      new_trail = GNUNET_malloc (new_trail_length * sizeof (struct GNUNET_PeerIdentity));
      memcpy (new_trail, trail_peer_list, new_trail_length * sizeof (struct GNUNET_PeerIdentity));
    }
    GDS_NEIGHBOURS_send_trail_rejection (&(trail_rejection->source_peer), 
                                         destination_finger_value,
                                         &my_identity, &next_hop,finger_map_index,
                                         new_trail,new_trail_length, CONGESTION_TIMEOUT);
    return GNUNET_YES;
  }
  
  {
  memcpy (&current_destination, &my_identity, sizeof (struct GNUNET_PeerIdentity));
  memcpy (&current_source, &my_identity, sizeof (struct GNUNET_PeerIdentity));
  next_peer = find_successor (destination_finger_value,&current_destination,
                             &current_source, finger_map_index);
  if (NULL == next_peer)
  {
    GNUNET_STATISTICS_update (GDS_stats,
                                gettext_noop ("# Next hop not found"
                                "trail setup request, packet dropped."),
                                1, GNUNET_NO);
    return GNUNET_SYSERR;
  }
  else if (0 == (GNUNET_CRYPTO_cmp_peer_identity (next_peer, &my_identity)))/* This means I am the final destination */
  {
    memcpy (&next_hop, &trail_peer_list[trail_length-1], sizeof (struct GNUNET_PeerIdentity));
    target_friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, &next_hop);
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
    target_friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, &next_hop);
    GDS_NEIGHBOURS_send_trail_setup (&source,
                                     destination_finger_value,
                                     &current_destination, &current_source,
                                     target_friend, trail_length, peer_list, 
                                     finger_map_index);
     return GNUNET_OK;
  }
  }
  
}


/*
 * Core handle for p2p trail tear down messages.
 * @param cls closure
 * @param message message
 * @param peer peer identity this notification is about
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static
int handle_dht_p2p_trail_teardown (void *cls, const struct GNUNET_PeerIdentity *peer,
                                   const struct GNUNET_MessageHeader *message)
{
  struct PeerTrailTearDownMessage *trail_teardown;
  struct GNUNET_PeerIdentity *discarded_trail;
  struct GNUNET_PeerIdentity next_hop;
  struct FriendInfo *target_friend;
  uint32_t discarded_trail_length;
  size_t msize;
  int my_index;
  
  msize = ntohs (message->size);
  if (msize < sizeof (struct PeerTrailTearDownMessage))
  {
    GNUNET_break_op (0);
    return GNUNET_OK;
  }
  
  trail_teardown = (struct PeerTrailTearDownMessage *) message;
  discarded_trail_length = ntohl (trail_teardown->trail_length);
  
  if ((msize < sizeof (struct PeerTrailTearDownMessage) +
               discarded_trail_length * sizeof (struct GNUNET_PeerIdentity)) ||
      (discarded_trail_length >
       GNUNET_SERVER_MAX_MESSAGE_SIZE / sizeof (struct GNUNET_PeerIdentity)))
  {
    GNUNET_break_op (0);
    return GNUNET_OK;
  }
  
  if (discarded_trail_length > 0)
    discarded_trail = (struct GNUNET_PeerIdentity *) &trail_teardown[1];
  
  if (0 == (GNUNET_CRYPTO_cmp_peer_identity (&(trail_teardown->new_first_friend),
                                             &my_identity)))
  {
     if(0 == (GNUNET_CRYPTO_cmp_peer_identity (&(trail_teardown->destination_peer), 
                                               &my_identity)))
     {
       return GNUNET_OK;
     }
     else
     {
       return GDS_ROUTING_trail_update (&(trail_teardown->source_peer),
                                        &(trail_teardown->destination_peer), peer);
     }
  }
  else
  {
    my_index = search_my_index (discarded_trail, discarded_trail_length);
    if(GNUNET_SYSERR == my_index)
        return GNUNET_SYSERR;
    
    if (GNUNET_NO == GDS_ROUTING_remove_trail (&(trail_teardown->source_peer),
                                               &(trail_teardown->destination_peer),peer))
    { 
      GNUNET_break (0); /* no matching entry found. Should not happen */
      return GNUNET_SYSERR;
    }  
    
    if (my_index == (discarded_trail_length - 1))
      return GNUNET_OK;
    
    memcpy (&next_hop, &discarded_trail[my_index + 1], sizeof (struct GNUNET_PeerIdentity));
    target_friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, &next_hop); 
    GDS_NEIGHBOURS_send_trail_teardown (&(trail_teardown->source_peer), 
                                        &(trail_teardown->destination_peer),
                                        discarded_trail, discarded_trail_length, 
                                        target_friend, &(trail_teardown->new_first_friend));
    return GNUNET_YES;
  }
  return GNUNET_SYSERR;
}


/**
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
  struct PeerAddTrailMessage *add_trail;
  struct GNUNET_PeerIdentity *trail;
  struct GNUNET_PeerIdentity next_hop;
  struct FriendInfo *target_friend;
  size_t msize;
  uint32_t trail_length;
  int my_index;
  
  msize = ntohs (message->size);
  if (msize < sizeof (struct PeerAddTrailMessage))
  {
    GNUNET_break_op (0);
    return GNUNET_OK;
  }
  
  add_trail = (struct PeerAddTrailMessage *) message;
  trail_length = ntohl (add_trail->trail_length);
  
  if ((msize < sizeof (struct PeerAddTrailMessage) +
               trail_length * sizeof (struct GNUNET_PeerIdentity)) ||
      (trail_length >
       GNUNET_SERVER_MAX_MESSAGE_SIZE / sizeof (struct GNUNET_PeerIdentity)))
  {
    GNUNET_break_op (0);
    return GNUNET_OK;
  }
  
  if (trail_length > 0)
    trail = (struct GNUNET_PeerIdentity *)&add_trail[1];
  
  my_index = search_my_index (trail, trail_length);
  if (GNUNET_SYSERR == my_index)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  
  if (GNUNET_YES == GDS_ROUTING_add (&(add_trail->source_peer), &(add_trail->destination_peer),
                                     peer,&next_hop))
  {
    if (my_index != 0)
    {
      memcpy (&next_hop, &trail[my_index - 1], sizeof (struct GNUNET_PeerIdentity));  
      target_friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, &next_hop); 
      GDS_NEIGHBOURS_send_add_trail_message (&(add_trail->source_peer), 
                                             &(add_trail->destination_peer),
                                             trail, trail_length,target_friend);
    }
    return GNUNET_OK;
  }
  else
  {
    /* No space left in my routing table. How should we handle this case? */
    return GNUNET_SYSERR;
  }
}


/**
 * FIXME: Adapt the code for List of trails. 
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
  
  if (remove_finger->first_trail_length > 0)
  {
    if (0 == GNUNET_CRYPTO_cmp_peer_identity (&remove_finger->first_trail_head->peer, disconnected_peer))
    {
      GNUNET_assert (GNUNET_YES ==
                   GNUNET_CONTAINER_multipeermap_remove (finger_peermap,
                                                         key, 
                                                         remove_finger));
      free_finger (remove_finger);
    }
  }
  else if (0 == GNUNET_CRYPTO_cmp_peer_identity (&(remove_finger->finger_identity), 
                                                 disconnected_peer))
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
  finger_peermap = GNUNET_CONTAINER_multipeermap_create (MAX_FINGERS * 4/3, GNUNET_NO);
  
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