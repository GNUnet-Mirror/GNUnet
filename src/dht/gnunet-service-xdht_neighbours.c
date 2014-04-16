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
 the array. Or else use the old one.*/

/**
 * Maximum possible fingers of a peer.
 */
#define MAX_FINGERS 63

/**
 * Maximum allowed number of pending messages per friend peer.
 */
#define MAXIMUM_PENDING_PER_FRIEND 64

/**
 * How long at least to wait before sending another find finger trail request,
 * at most we wait twice this long.
 */
#define DHT_FIND_FINGER_TRAIL_INTERVAL GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 30)

/**
 * How long at most to wait for transmission of a GET request to another peer?
 */
#define GET_TIMEOUT GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MINUTES, 2)

/**
 * Maximum number of trails allowed to go through a friend.
 */
#define LINK_THRESHOLD 64


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
 * FIXME: Check the alignment in all the struct  
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
   */
  struct GNUNET_PeerIdentity current_source;
  
  /**
   * Index into finger peer map, in NBO. 
   */
  uint32_t finger_map_index;
  
  /**
   * Number of entries in trail list, in NBO.
   */
  uint32_t trail_length GNUNET_PACKED;
  
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
   * Index into finger peer map
   */
  uint32_t finger_map_index;
  
  /**
   * Number of entries in trail list.
   */
  uint32_t trail_length GNUNET_PACKED;
  
};

/**
 *
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
   * Finger identity value. 
   */
  uint64_t finger_identity;
  
  /**
   * Index in finger peer map of source peer.
   */
  uint32_t finger_map_index;
  
  /**
   * Total number of peers in the trail.
   */
  uint32_t trail_length;
  
  /* trail_list */
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
   * If source_successor is not destination peer, then trail is from destination_peer
   * to my_predecessor.
   * If source_successor is destination peer, then trail is from destination_peer
   * to source_successor.
   */
  uint32_t trail_length; 
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
   * Number of trail of which this friend is the first hop.
   */
  unsigned int trail_links;
  
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
   * Total number of entries in trail from (me,finger] 
   */
  unsigned int trail_length;
  
  /**
   * Head of trail to reach this finger.
   */
  struct TrailPeerList *head;
  
  /**
   * Tail of trail to reach this finger.
   */
  struct TrailPeerList *tail;
  
};

enum current_destination_type
{
  FRIEND,
  FINGER,
  VALUE,
  MY_ID
};

/**
 * FIXME: Think of a better name. 
 * Data structure passed to sorting algorithm in find_successor.
 */
struct Sorting_List
{
  /**
   * 64 bit value of peer identity
   */
  uint64_t peer_id;
  
  /**
   * Type : MY_ID, FINGER, FINGER, Value 
   */
  enum current_destination_type type;
  
  /**
   * Pointer to original data structure linked to peer id.
   */
  void *data;
};


/**
 * FIXME: Think of better comments.
 * An entry in Failed_Trail_List
 */
struct FailedTrail
{
  /**
   * Source peer which was trying to setup up the trail to @a destination_finger_value
   */
  struct GNUNET_PeerIdentity source_peer;
  
  /**
   * Value to which we were trying to find the closest successor.
   */
  uint64_t destination_finger_value;
  
  /**
   * Peer which has crossed the threshold limit on its routing table size.
   */
  struct GNUNET_PeerIdentity congested_peer;
  
};


/**
 * Task that sends FIND FINGER TRAIL requests.
 */
static GNUNET_SCHEDULER_TaskIdentifier find_finger_trail_task;

/**
 * 
 * Task that periodically verifies my successor. 
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
 * Hash maps of all the trail which failed due to a congested peer. 
 */
static struct GNUNET_CONTAINER_MultiPeerMap *failed_trail_list;

/**
 * Handle to CORE.
 */
static struct GNUNET_CORE_Handle *core_api;

/**
 * Finger map index for predecessor entry in finger peermap. 
 */
#define PREDECESSOR_FINGER_ID 64

/**
 * The current finger index that we have found trail to.
 */
static unsigned int current_finger_index;

/**
 * Iterate over trail and search your index location in the array. 
 * @param trail Trail which contains list of peers.
 * @return Index in the array.
 */
static int
search_my_index (const struct GNUNET_PeerIdentity *trail)
{
  return 0;
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
 * FIXME: In this function using const, does it affect only here right? not in 
 * the struct P2PTrailSetupMessage as their fields are not defined as const. 
 * Also, I changed current_destination and current_source from const to not, 
 * because when we make a call from handle_dht_p2p_trail_setup, then we are 
 * passing struct for current_destination and not current_source, as we are writing
 * to these variables and we can not decalre them as const. 
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
    /* SUPU: Its important to have such statistics as you need to keep track of
     the packets lost due to full queue. */
    GNUNET_STATISTICS_update (GDS_stats, gettext_noop ("# P2P messages dropped due to full queue"),
				1, GNUNET_NO);
  }
  
  pending = GNUNET_malloc (sizeof (struct P2PPendingMessage) + msize); 
  pending->timeout = GNUNET_TIME_relative_to_absolute (GET_TIMEOUT);
  tsm = (struct PeerTrailSetupMessage *) &pending[1]; 
  pending->msg = &tsm->header;
  tsm->header.size = htons (msize);
  tsm->header.type = htons (GNUNET_MESSAGE_TYPE_DHT_P2P_TRAIL_SETUP);
  /* FIXME: understand where you need to use memcpy or direct assignment. */
  memcpy (&(tsm->destination_finger), &destination_finger, sizeof (uint64_t));
  memcpy (&(tsm->source_peer), source_peer, sizeof (struct GNUNET_PeerIdentity));
  memcpy (&(tsm->current_destination), current_destination, sizeof (struct GNUNET_PeerIdentity));
  memcpy (&(tsm->current_source), current_source, sizeof (struct GNUNET_PeerIdentity));
  tsm->trail_length = htonl (trail_length); 
  tsm->finger_map_index = htonl (finger_map_index);
  
  /* SUPU: here i guess its okay to have it as NULL as it is added at the end of 
   the struct but in case of current_destination and current_source, it is part
   of the struct. thats why the confusion. */
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
 * FIXME: Optimizaiton Once the basic code is running. Add the optimization
 * where you check if the threshold on number of links that should go through
 * a particular friend has crossed. If yes then again choose a different
 * friend. Important that the new friend chosen should be different. How to 
 * ensure this? This is an important optimization as without this one x-vine
 * is actually not a sybil tolerant DHT.
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
 
  if (GNUNET_CONTAINER_multipeermap_size (friend_peermap) == 0)
  {
    /* FIXME: It may happen that there is not friend in friend peermap but
     as this task has already been started it failed.*/
    GNUNET_break(0);
    return NULL;
  }
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
    /* TODO: Here you have chosen a random friend. Now you should check the size
     of its routing table size, and if its more than threshold, then check which
     of the entries has trail length greater than trail length threshold. we
     should without checking the routing table size also we should check the
     trail with trail length greater than threshold. then 
     you should try to find a new route through this new node that has joined in
     only for those finger entries whose trail length is greater than threshold. 
     But I don't want the new node to wait for this process to get over. so
     should i declare a function which will be called after some interval.*/
    return friend;
  }
  else
    return NULL;
}


/**
 * FIMXE: pass current_finger_index as argument.
 * Compute finger_identity to which we want to setup the trail
 * @return finger_identity 
 */
static uint64_t 
compute_finger_identity()
{
  uint64_t my_id64 ;

  memcpy (&my_id64, &my_identity, sizeof (uint64_t));
  my_id64 = GNUNET_ntohll (my_id64);
  /*FIXME: Do we need a mod finger = ((my_id + pow(2, finger_index)) mod (pow (2, MAX_FINGERS))*/
  return (my_id64 + (unsigned long) pow (2, current_finger_index));
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
  
  peer_list = GNUNET_malloc (sizeof (struct GNUNET_PeerIdentity) * finger->trail_length);
 
  struct TrailPeerList *iterate;
  iterate = finger->head;
  i = 0;
  while ( i < (finger->trail_length))
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
                                        finger->trail_length);
  
  
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
 * FIXME - the main logic of handling the finger map index has changed.
 * first we start with finger index = 64, that index is reserved for the
 * predecessor always. Then we start going backwards, finger_index = 63 to 0
 * and once its 0 we again go back to 64. now, when you start looking for the finger
 * then your successor is always the finger with lowest finger index. in finger_table_add
 * whenever you do an entry you check for predecessor , if the new finger identity
 * is greater than existing one, then that should be your predecessor. In case of 
 * other fingers also, if the new entry is smaller than existing one. If yes
 * then that is correct finger for that finger index. Also, the lowest finger index and
 * its corresponding finger identity is your successor.
 * 
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
  
  /* FIXME: understand how does this scheduling of processes take place? */
  next_send_time.rel_value_us =
      DHT_FIND_FINGER_TRAIL_INTERVAL.rel_value_us +
      GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_WEAK,
                                DHT_FIND_FINGER_TRAIL_INTERVAL.rel_value_us);
  /* FIXME: here we are just adding the process to the scheduling list. only
   when this function is executed, it may get scheduled. */
  find_finger_trail_task =
      GNUNET_SCHEDULER_add_delayed (next_send_time, &send_find_finger_trail_message,
                                    NULL);
  target_friend = select_random_friend (NULL);
 
  if (NULL == target_friend)
  {
     /* SUPU: Here we can get NULL in the case there is no friend in the peer map
   or all of the friends have reached their threshold. The first case should ideally
   never happen because in handle_core_disconnect we have already canceled the task
   but it may happen if we already started the process and we reached here and 
   we cancelled the next task. So, it can return NULL in that case also. Should
   we handle both cases in same way or not? */
    return;
  }
  
  /* FIXME: start with current_finger_index = 64, */
  if (PREDECESSOR_FINGER_ID == current_finger_index)
  {
    /* FIXME: Where do we set the value back to PREDECESSR_FINGER_ID? Only
     when current_finger_index = 0, do we set it back to PREDECESSOR_FINGER_ID,
     in finger_table_add? Or is there any other possible condition, where we 
     may need to set it to PREDECESSOR_FINGER_ID*/
    finger_identity = compute_predecessor_identity();  
  }
  else
  {
    finger_identity = compute_finger_identity();
  }
  finger_map_index = current_finger_index;
  
  /* FIXME: verify if its correct to set current_destination and current_source
   as my identity. */
  GDS_NEIGHBOURS_send_trail_setup (&my_identity, finger_identity, &(target_friend->id),
                                   &(target_friend->id), target_friend, 0, NULL, finger_map_index);
}


/**
 * 
 * @param destination_peer
 * @param existing_trail
 * @param trail_length
 * @return 
 */
static struct GNUNET_PeerIdentity *
invert_trail_list (struct GNUNET_PeerIdentity *destination_peer,
                   struct GNUNET_PeerIdentity *existing_trail, 
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
  memcpy (&new_trail[j], destination_peer, sizeof(struct GNUNET_PeerIdentity));
 
  return new_trail;
}


#if 0
/**
 * 
 * @param existing_finger
 * @param new_finger
 * @return 
 */
static int
compare_finger_identity (struct GNUNET_PeerIdentity *existing_finger,
                         struct GNUNET_PeerIdentity *new_finger)
{
  int ret;
  ret = (existing_finger > new_finger) ? 1 : 
          (existing_finger == new_finger) ? 0 : -1;
  return ret;
}
#endif


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
compare_predecessor(struct GNUNET_PeerIdentity *peer)
{
  /* FIXME: here you should first check if you already have an entry in the 
   finger peer map for finger index = 64, if yes then compare it with peer
   if not then just add the peer. */
  return GNUNET_YES;
}

/**
 * 
 * @return 
 */
static struct GNUNET_PeerIdentity *
check_for_successor ()
{
  return NULL;
}
/**
 * Scan the trail, check if there is a friend in the trail, then shortcut
 * the trail and return the new trail and trail length. 
 * FIXME: How to send the trail length? Should I create a new array and copy into
 * it or modify the existing trail. also, how can it be done optimally? 
 * @param finger_trail
 * @return 
 */
#if 0
static struct GNUNET_PeerIdentity *
scan_trail (struct GNUNET_PeerIdentity *finger_trail)
{
  return NULL;
}
#endif

/**
 * Add an entry in finger table. Before adding, check if there is already an 
 * entry in finger peermap for the same index, if yes then choose the closest one.
 * In case both the existing identity and new identity are same, keep both the trail
 * only if the trails are different (Redundant routing). Also, a peer stored at index,i
 * if its same as peer stored index, i+1, and 'i' is the lowest finger map index 
 * seen so far, then that peer is the successor. In case finger_map_index is PREDECESSOR_INDEX,
 * then simply add it as handle rest of the cases for it in a different function. 
 * Also while adding an entry check the trail, scan the trail and check if there 
 * is a friend in between, then shortcut the path. 
 * @param finger_identity
 * @param finger_trail
 * @param finger_trail_length
 * @param finger_map_index
 */
static
void finger_table_add (const struct GNUNET_PeerIdentity *finger_identity,
                       const struct GNUNET_PeerIdentity *finger_trail,
                       uint32_t finger_trail_length,
                       uint32_t finger_map_index)
{
  struct FingerInfo new_finger_entry;
  int i;
  
  /* If I am my own finger, then return. */
  if (0 == GNUNET_CRYPTO_cmp_peer_identity (&my_identity, finger_identity))
  {
    GNUNET_break (0); /* SUPU: Its here because I need to see when it happens. */
    return;
  }
  
  if (finger_map_index == PREDECESSOR_FINGER_ID)
    goto add_new_entry;
  
  /* For rest of current_finger_index, choose the correct finger and correct trail. */
  /* SUPU: Here I want to iterate over all the entries and see if there is already
   an entry for the finger map index. if yes then check if finger identity are same
   if yes then check the trail. if I use gnuent_container_multipeermap_iterate,
   i should stop after I found the finger map index, and just return the 
   struct finger info. then I should call another function which takes care of
   finding the closest peer*/
  
  add_new_entry:
  memcpy (&(new_finger_entry.finger_identity), finger_identity, sizeof (struct GNUNET_PeerIdentity));
  new_finger_entry.finger_map_index = finger_map_index;
  /* FIXME: How do I get the length as well as the trail. 
   * scan_trail (finger_trail);
   */
  new_finger_entry.trail_length = finger_trail_length;
 
  i = 0;
  while (i < finger_trail_length)
  {
    struct TrailPeerList *element;
    element = GNUNET_malloc (sizeof (struct TrailPeerList));
    element->next = NULL;
    element->prev = NULL;
    
    memcpy (&(element->peer), &finger_trail[i], sizeof(struct GNUNET_PeerIdentity));
    GNUNET_CONTAINER_DLL_insert_tail(new_finger_entry.head, new_finger_entry.tail, element);
    i++;
  }
  
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multipeermap_put (finger_peermap,
                                                    &(new_finger_entry.finger_identity),
                                                    &new_finger_entry,
                                                    GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE));   
  
  /* FIXME: after adding an entry, I want to check if there is a successor, if yes
   then this function will return it and then we should schedule a verify successor 
   task */
  if (NULL != check_for_successor())
  {
    verify_successor = GNUNET_SCHEDULER_add_now (&send_verify_successor_message, NULL);
    /* FIXME: Is it safe to set the finger index to predecessor_finger_id here? */
    current_finger_index = PREDECESSOR_FINGER_ID;
    return;
  }
  
  /* FIXME: Not sure if this is the correct place to set the values. Look into
   send_find_finger_trail_message and check. */
  if(current_finger_index == 0)
    current_finger_index = PREDECESSOR_FINGER_ID;
  else
    current_finger_index = current_finger_index - 1;
}


#if 0
/*FIXME: Here you need to set the correct value of finger_map_index,
 * in case it is 0, then you set it back to 64, and in case it is x,
 * then you set it back to x-1. current_finger_index = ( current_finger_index - 1) % MAX_FINGERS
 * we also need to change the logic of starting the process to look for a successor. 
 * when you add an entry then go through whole trail and check if there is an entry
 * which is your friend, if yes then just collapse the trail. if you are not doing it 
 * here then you need to do it in handle_core_disconnect where you will have to search
 * through whole trail find peer and then delete the finger. 
 * Add an entry in finger table. 
 * @param finger_identity Peer identity of finger
 * @param finger_trail Trail to reach the finger
 * @param trail_length Number of peers in the trail. 
 * @param finger_map_index Index in finger peer map.
 */
static
void finger_table_add (const struct GNUNET_PeerIdentity *finger_identity,
                       const struct GNUNET_PeerIdentity *finger_trail,
                       unsigned int trail_length,
                       const unsigned int finger_map_index)
{
  struct FingerInfo *new_finger_entry;
  //struct GNUNET_PeerIdentity key_ret;
  int i;
  //struct GNUNET_CONTAINER_MultiPeerMapIterator *finger_iter;
  //struct FingerInfo *existing_finger;
  //int finger_index;

  /* SUPU Here we trying to check if we already have an entry. If yes then we
   can keep two trails for redundant routing. if they are different then we
   need to choose the closest one. and remove the other one. */
#if 0
  finger_iter = GNUNET_CONTAINER_multipeermap_iterator_create (finger_peermap); 

  for (finger_index = 0; finger_index < GNUNET_CONTAINER_multipeermap_size (finger_peermap); finger_index++)
  {
    if(GNUNET_YES == GNUNET_CONTAINER_multipeermap_iterator_next (finger_iter, &key_ret,
                                                                 (const void **)&existing_finger)) 
    {
      if ((finger_map_index == existing_finger->finger_map_index))
      {
        if (0 == GNUNET_CRYPTO_cmp_peer_identity (&(existing_finger->finger_identity),finger_identity))
        {
          /* FIXME: Here you should check if the trail is same. If yes then don't add the entry. it
           seems to be very suboptimal. */
          if ((existing_finger->trail_length) == trail_length)
          {
            struct TrailPeerList *iterate;
            iterate = existing_finger->head;
            int k;
            k = 0;
            while (k < trail_length)
            {
              if (0 == GNUNET_CRYPTO_cmp_peer_identity (&(iterate->peer), &finger_trail[k]))
              {
                k++;
                iterate = iterate->next;
              }
            }
            if (k == trail_length)
              return;
            else
              goto add_new_entry;
          }
          goto add_new_entry;
        }
        else
        {
          int ret;
          if (finger_map_index == 1)
          {
            ret = compare_predecessor (&(existing_finger->finger_identity),
                                       finger_identity);
            goto add_new_entry;
          }
          else
          {
            ret = compare_finger_identity (&(existing_finger->finger_identity),
                                          finger_identity);
          }
          if (ret > 0)
          {
            GNUNET_assert (GNUNET_YES ==
                       GNUNET_CONTAINER_multipeermap_remove (finger_peermap,
                                                             &(existing_finger->finger_identity),
                                                             existing_finger));
            goto add_new_entry;
          }
          else
          {
            return;
          }
        }
      }
    }
  }

  add_new_entry:
#endif
  new_finger_entry = GNUNET_malloc (sizeof (struct FingerInfo));
  memcpy (&(new_finger_entry->finger_identity), finger_identity, sizeof (struct GNUNET_PeerIdentity));
  new_finger_entry->finger_map_index = finger_map_index;
  
  if (0 == GNUNET_CRYPTO_cmp_peer_identity (&my_identity, finger_identity))
  {
    /* I am the finger */
    new_finger_entry->trail_length = 0;
    /* FIXME: If I am the finger then why do we even do an entry.  don't add any
     * field because it is of no use. you may just send a message to yourself
     * when another peer send you a trail setup or put request. */
  }
  else
  {
    i = 0;
    while (i < trail_length)
    {
      struct TrailPeerList *element;
      element = GNUNET_malloc (sizeof (struct TrailPeerList));
      element->next = NULL;
      element->prev = NULL;
    
      memcpy (&(element->peer), &finger_trail[i], sizeof(struct GNUNET_PeerIdentity));
      GNUNET_CONTAINER_DLL_insert_tail(new_finger_entry->head, new_finger_entry->tail, element);
      i++;
    }
    new_finger_entry->trail_length = trail_length;
  }
  
  /* FIXME: Here we are keeping multiple hashmap option so that there are
   multiple routes to reach to same finger, redundant routing.
   * Also same peers could be our fingers for different finger map index
   * Should we handle the case where we have same fingers at the different
   * finger index but with different trail to reach.  */
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multipeermap_put (finger_peermap,
                                                    &(new_finger_entry->finger_identity),
                                                    new_finger_entry,
                                                    GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE)); 
  
  if (1 == GNUNET_CONTAINER_multipeermap_size (finger_peermap)
      && (new_finger_entry->finger_map_index!= 1))
  {
    verify_successor = GNUNET_SCHEDULER_add_now (&send_verify_successor_message, NULL);
  }
}
#endif  

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
 * here you should set the current source instead of destination type.
 * so current_source is actual source till we don't find another current_source
 * but is it good. why are we wasting space in case current_Destination is just us. 
 * also in many case current_destination is just me. so again it does not seem
 * so smart.  
 * Find closest successor for the value.
 * @param value Value for which we are looking for successor
 * FIXME: pass the correct value for current_destination 
 * @param[out] current_destination set to the end of the finger to traverse next 
 * @param type Next destination type
 * @return Peer identity of next hop, NULL if we are the 
 *   ultimate destination 
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
    return NULL;
  }
  else if (successor->type == FRIEND)
  {
    struct FriendInfo *target_friend;
    target_friend = (struct FriendInfo *)successor->data;
    memcpy (current_destination, &(target_friend->id), sizeof (struct GNUNET_PeerIdentity));
    return current_destination;
  }
  else if (successor->type == FINGER)
  {
    struct GNUNET_PeerIdentity *next_hop;
    struct FingerInfo *finger;
    struct TrailPeerList *iterator;
    iterator = GNUNET_malloc (sizeof (struct TrailPeerList));
    finger = successor->data;
    iterator = finger->head;
    next_hop = GNUNET_malloc (sizeof (struct GNUNET_PeerIdentity));
    memcpy (next_hop, &(iterator->peer), sizeof (struct GNUNET_PeerIdentity));
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
                         struct GNUNET_PeerIdentity *current_destination,
                         struct GNUNET_PeerIdentity *current_source,
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
    next_hop = find_successor (key_value, current_destination, current_source);
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
  ppm->current_destination = *current_destination;
  ppm->current_source = *current_source;
 
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
                         struct GNUNET_PeerIdentity *current_destination,
                         struct GNUNET_PeerIdentity *current_source,
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
    
    memcpy (&key_value, key, sizeof (struct GNUNET_PeerIdentity));
    next_hop = find_successor (key_value, current_destination, current_source);
    if (NULL == next_hop) /* I am the destination do datacache_put */
    {
      GDS_DATACACHE_handle_get (key,block_type, NULL, 0, 
                                NULL, 0, 1, &my_identity, NULL,&my_identity);
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
  pgm->current_destination = *current_destination;
  pgm->current_source = *current_source;
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
  
  current_path_index = search_my_index(get_path);
  if (0 == current_path_index)
  {
    FPRINTF (stderr,_("\nSUPU %s, %s, %d"),__FILE__, __func__,__LINE__);
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
 * Send tral rejection message
 * @param source_peer Source peer which wants to set up the trail.
 * @param finger_identity Finger identity to which it want to setup the trail.
 * @param congested_peer Peer which has send trail rejection message
 * @param next_hop Peer to which this message should be forwarded.
 * @param finger_map_index
 * @param trail_peer_list
 * @param trail_length
 */
void
GDS_NEIGHBOURS_send_trail_rejection_message(struct GNUNET_PeerIdentity *source_peer,
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
  
  msize =  sizeof (struct PeerTrailRejectionMessage);
  
  pending = GNUNET_malloc (sizeof (struct P2PPendingMessage) + msize); 
  pending->importance = 0;    /* FIXME */
  pending->timeout = GNUNET_TIME_relative_to_absolute (GET_TIMEOUT);
  trail_rejection = (struct PeerTrailRejectionMessage *) &pending[1]; 
  pending->msg = &trail_rejection->header;
  trail_rejection->header.size = htons (msize);
  trail_rejection->header.type = htons (GNUNET_MESSAGE_TYPE_DHT_P2P_TRAIL_SETUP);
  memcpy (&(trail_rejection->source_peer), source_peer, sizeof (struct GNUNET_PeerIdentity));
  memcpy (&(trail_rejection->congested_peer), congested_peer, sizeof (struct GNUNET_PeerIdentity));
  memcpy (&(trail_rejection->finger_identity), &finger_identity, sizeof (uint64_t));
  trail_rejection->finger_map_index = htonl(finger_map_index);
  trail_rejection->trail_length = htonl (trail_length);
  
  trail_list = (struct GNUNET_PeerIdentity *)&trail_rejection[1];
  memcpy (trail_list, trail_peer_list, trail_length * sizeof (struct GNUNET_PeerIdentity));
  
  target_friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, next_hop);
  GNUNET_CONTAINER_DLL_insert_tail (target_friend->head, target_friend->tail, pending);
  target_friend->pending_count++;
  process_friend_queue (target_friend);
}


/**
 * 
 * @param cls
 * @param peer
 * @param message
 * @return 
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
                             &current_destination, &current_source, next_hop,
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
                             get->desired_replication_level,&current_destination,
                             &current_source, next_hop, 0,
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
    current_path_index = search_my_index (get_path);
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
 * Handle a PeerTrailSetupMessage. 
 * @param cls closure
 * @param message message
 * @param peer peer identity this notification is about
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static int
handle_dht_p2p_trail_setup(void *cls, const struct GNUNET_PeerIdentity *peer,
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
  
  /* Check if you are part of the trail or current destination, and accordingly
   * find the next peer to send the message to. */
  if (0 != (GNUNET_CRYPTO_cmp_peer_identity (&current_destination, &my_identity)))
  {
    next_hop = GDS_ROUTING_search (&current_source, &current_destination, peer);
    /* OPTIMIZATION: do find_successor also and get a better path if possible. */
    if (next_hop == NULL)
    {
      /* FIXME next_hop to NULL, 1. statistics update, drop the message. 
         2. complain to sender with new message: trail lost */
        return GNUNET_OK;
    }
  }
  else
  {
    next_hop = find_successor (destination_finger_value, &current_destination, &current_source); 
  }
  
  /* Now add yourself to the trail. */
  struct GNUNET_PeerIdentity peer_list[trail_length + 1];
  memcpy (peer_list, trail_peer_list, trail_length * sizeof (struct GNUNET_PeerIdentity));
  peer_list[trail_length] = my_identity;
  trail_length++;
  
  /* Check next_hop type and make the judgment what to do next. */
  if (NULL == next_hop) /* This means I am the final destination */
  {
    if (trail_length == 1)
    {
      memcpy (&next_peer, &source, sizeof (struct GNUNET_PeerIdentity));
    }
    else
    {
      memcpy (&next_peer, &trail_peer_list[trail_length-2], sizeof (struct GNUNET_PeerIdentity));
    }
    
    target_friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, &next_peer);
    /* FIXME: URGENT change it to handle the change in current_finger_index. 
       compare  to your own predecessor */
    if (compare_predecessor (&source) /* ! HAVE A PREDECESSOR || (source_peer closer than existing PREDECESOR) */)
    {
      struct GNUNET_PeerIdentity *new_trail_list;
      new_trail_list = invert_trail_list (&source, peer_list, trail_length);
      finger_table_add (&source, new_trail_list, trail_length, PREDECESSOR_FINGER_ID);
    }
    GDS_NEIGHBOURS_send_trail_setup_result (&source,
                                            &(my_identity),
                                            target_friend, trail_length,
                                            peer_list,
                                            finger_map_index);
    return GNUNET_OK;
  }
  else
  {
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
  const struct GNUNET_PeerIdentity *trail_peer_list;
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
  trail_peer_list = (const struct GNUNET_PeerIdentity *) &trail_result[1];
  
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
    
    my_index =  search_my_index (trail_peer_list);
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

#if 0
/**
 * FIXME: Use flag in the case finger peer map does not contain predcessor
 * then its NULL. Ideally it should never happen. 
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
#endif

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
   if(0 == (GNUNET_CRYPTO_cmp_peer_identity (&(vsm->successor),&my_identity)))
   {
     /*FIXME:URGENT:IMPLEMENT Here you are the successor, here you should check your predecessor
      and if there is no predecessor then just add this peer and send result
      if there is some other predecessor, then construct a new trial and then
      send back the list to requesting peer. */
   }
   else
   {
    int my_index;
    
    my_index = search_my_index (trail_peer_list);
    memcpy (&next_hop, &trail_peer_list[my_index], sizeof (struct GNUNET_PeerIdentity));
    target_friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, &next_hop);
      
    GDS_NEIGHBOURS_send_verify_successor (&(vsm->source_peer), &(vsm->successor),target_friend,
                                          trail_peer_list, trail_length); 
   }
   return GNUNET_SYSERR;
}

#if 0
/**
 * Core handle for p2p verify successor messages.
 * @param cls closure
 * @param message message
 * @param peer peer identity this notification is about
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
static int
handle_dht_p2p_verify_successor(void *cls, const struct GNUNET_PeerIdentity *peer,
                                const struct GNUNET_MessageHeader *message)
{
  struct PeerVerifySuccessorMessage *vsm;
  struct GNUNET_PeerIdentity *trail_peer_list;
  struct FriendInfo *target_friend;
  struct GNUNET_PeerIdentity *next_hop;
  struct GNUNET_PeerIdentity *source_peer;
  unsigned int trail_length;
  size_t msize;
  
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
  
  trail_peer_list = (struct GNUNET_PeerIdentity *) &vsm[1];
  source_peer = GNUNET_malloc (sizeof (struct GNUNET_PeerIdentity));
  memcpy (source_peer, &(vsm->source_peer), sizeof (struct GNUNET_PeerIdentity));
  
  next_hop = GNUNET_malloc (sizeof (struct GNUNET_PeerIdentity));
  
  if(0 == (GNUNET_CRYPTO_cmp_peer_identity (&(vsm->successor),&my_identity)))
  {
    struct FingerInfo *my_predecessor;
    if (trail_length == 1)
      memcpy (next_hop, source_peer, sizeof (struct GNUNET_PeerIdentity));
    else
    {
      int current_trail_index;
      current_trail_index = search_my_index (trail_peer_list);
      memcpy (next_hop, &trail_peer_list[current_trail_index-1], sizeof (struct GNUNET_PeerIdentity));
    }
    target_friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, next_hop);
    GNUNET_free (next_hop);
    
    my_predecessor = get_predecessor();
    if (0 == (GNUNET_CRYPTO_cmp_peer_identity (source_peer,
                                               &(my_predecessor->finger_identity))))
    {
      GDS_NEIGHBOURS_send_verify_successor_result (source_peer,
                                                   &(my_identity),
                                                   &(my_predecessor->finger_identity),
                                                   target_friend,
                                                   trail_peer_list,
                                                   trail_length);
    }
    else
    {
      struct GNUNET_PeerIdentity *new_successor_trail;
      int new_trail_length;
      int i;
      
      new_trail_length = trail_length + my_predecessor->trail_length;
      new_successor_trail = GNUNET_malloc (sizeof (struct GNUNET_PeerIdentity) * new_trail_length);
      memcpy (new_successor_trail, trail_peer_list, (trail_length) * sizeof (struct GNUNET_PeerIdentity));
      struct TrailPeerList *iterator;
      iterator = GNUNET_malloc (sizeof (struct TrailPeerList));
      iterator = my_predecessor->head; 
      i = trail_length;
      while (i < new_trail_length)
      {
        memcpy (&new_successor_trail[i], &(iterator->peer), sizeof (struct GNUNET_PeerIdentity));
        iterator = iterator->next;
        i++;
      }
 
      GDS_NEIGHBOURS_send_verify_successor_result (source_peer,
                                                   &(my_identity),
                                                   &(my_predecessor->finger_identity),
                                                   target_friend,
                                                   new_successor_trail,
                                                   new_trail_length); 
    }      
   
  }
  else
  {
    unsigned int current_trail_index;
    current_trail_index = search_my_index (trail_peer_list);
    memcpy (next_hop, &trail_peer_list[current_trail_index], sizeof (struct GNUNET_PeerIdentity));
    target_friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, next_hop);
    GNUNET_free (next_hop);
        
    GDS_NEIGHBOURS_send_verify_successor (source_peer, &(vsm->successor),target_friend,
                                          trail_peer_list, trail_length); 
  }
  return GNUNET_YES;
}
#endif

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
  const struct GNUNET_PeerIdentity *trail_peer_list;
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
  
  trail_peer_list = (const struct GNUNET_PeerIdentity *) &vsrm[1];
  
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
    
    my_index = search_my_index (trail_peer_list);
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
 * Check if there is already an entry in finger_peermap for predecessor,
 * If not then add peer as your predecessor.
 * Else compare existing entry and peer, and choose the closest one as predecessor.
 * @param peer Peer identity
 * @param trail_peer_list Trail to reach from @a peer to me. 
 */
static void
update_predecessor (const struct GNUNET_PeerIdentity *peer,
                    const struct GNUNET_PeerIdentity *trail_peer_list)
{
   /*FIXME: URGENT: Here you should first check if there is already an entry for predecessor
     field or not. if not then add peer. else compare existing entry and peer,
     and choose the closest one as predecessor. I am confused should I call a
     function which just checks if this peer can be predecessor or not, and then 
     call another function to add it. Or call a single function which checks
     it all and add the entry. we are never going to communicate with the peer
     if it is my predecessor or not. so, we don't care about the result. */
  
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
  const struct GNUNET_PeerIdentity *trail_peer_list;
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
  
  trail_peer_list = (const struct GNUNET_PeerIdentity *) &nsm[1];
  
  if(0 == (GNUNET_CRYPTO_cmp_peer_identity (&(nsm->destination_peer), &my_identity)))
  {
    update_predecessor (&(nsm->destination_peer), trail_peer_list);
    return GNUNET_OK;
  }
  else
  {
    struct FriendInfo *target_friend;
    struct GNUNET_PeerIdentity next_hop;
    int my_index;
    
    my_index = search_my_index (trail_peer_list);
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
 * FIXME: I am not sure if this is correct or not. once I am done with 
 * basic implementation then will handle threshold limits.  
 * Does it matter if the packet was going to a finger or friend?
 * Core handle for p2p trail rejection messages.
 * @param cls closure
 * @param message message
 * @param peer peer identity this notification is about
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
static
int handle_dht_p2p_trail_rejection(void *cls, const struct GNUNET_PeerIdentity *peer,
                                   const struct GNUNET_MessageHeader *message)
{
  struct PeerTrailRejectionMessage *trail_rejection;
  struct FailedTrail *trail_fail;
  struct FriendInfo *target_friend;
  struct GNUNET_PeerIdentity *trail_peer_list;
  unsigned int finger_map_index;
  size_t msize;
  
  msize = ntohs (message->size);
  if (msize < sizeof (struct PeerTrailRejectionMessage))
  {
    GNUNET_break_op (0);
    return GNUNET_YES;
  }
  
  trail_rejection = (struct PeerTrailRejectionMessage *) message;
  trail_peer_list = (struct GNUNET_PeerIdentity *)&trail_rejection[1];
  finger_map_index = ntohl (trail_rejection->finger_map_index);
  trail_fail = GNUNET_malloc (sizeof (struct FailedTrail));
  memcpy (&(trail_fail->source_peer), &(trail_rejection->source_peer), sizeof (struct GNUNET_PeerIdentity));
  memcpy (&(trail_fail->congested_peer), &(trail_rejection->congested_peer), sizeof (struct GNUNET_PeerIdentity));
  memcpy (&(trail_fail->destination_finger_value), &(trail_rejection->finger_identity), sizeof (uint64_t));
  
  GNUNET_assert (GNUNET_OK ==
  GNUNET_CONTAINER_multipeermap_put (failed_trail_list, &(trail_fail->source_peer),
                                     trail_fail, GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE));
   
  /* FIXME: Is it okay if I pass the struct as parameter. */
  target_friend = select_random_friend (&(trail_fail->congested_peer));
  
  if(NULL != target_friend)
  { 
    GDS_NEIGHBOURS_send_trail_setup (&(trail_fail->source_peer), 
                                     trail_fail->destination_finger_value,
                                     &(target_friend->id),
                                     NULL, target_friend, ntohl (trail_rejection->trail_length),
                                     trail_peer_list, 
                                     finger_map_index);
    return GNUNET_YES;
  }
  return GNUNET_SYSERR;
}


/**
 * FIXME: free_finger(remove_finger); Call this function at finger_table_add,
           when you replace an existing entry 
 * Free finger and its trail.  
 * @param remove_finger Finger to be freed.
 */
static void
free_finger (struct FingerInfo *finger)
{
  struct TrailPeerList *peer;
  
  while (NULL != (peer = finger->head))
  {
    GNUNET_CONTAINER_DLL_remove (finger->head, finger->tail, peer);
    GNUNET_free (peer);
  }
  
  GNUNET_free (finger);
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
  
  if (0 == GNUNET_CRYPTO_cmp_peer_identity (&remove_finger->head->peer, disconnected_peer))
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
    {NULL, 0, 0}
  };
  
  core_api =
    GNUNET_CORE_connect (GDS_cfg, NULL, &core_init, &handle_core_connect,
                         &handle_core_disconnect, NULL, GNUNET_NO, NULL,
                         GNUNET_NO, core_handlers);
  if (NULL == core_api)
    return GNUNET_SYSERR;
  
  /* Initialize the current index in the finger map. */
  current_finger_index = PREDECESSOR_FINGER_ID;
  
  friend_peermap = GNUNET_CONTAINER_multipeermap_create (256, GNUNET_NO);
  finger_peermap = GNUNET_CONTAINER_multipeermap_create (MAX_FINGERS * 4/3, GNUNET_NO);
  /* FIXME: Not sure if this value is correct for this data structure. also 
   * not sure if we actually need any such data structure. Once done with other functions,
   * will revisit this part.  */
  failed_trail_list = GNUNET_CONTAINER_multipeermap_create (LINK_THRESHOLD * 4/3, GNUNET_NO);
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
 * Get my identity
 *
 * @return my identity
 */
const struct GNUNET_PeerIdentity *
GDS_NEIGHBOURS_get_my_id (void)
{
  return &my_identity;
}


/* end of gnunet-service-xdht_neighbours.c */
