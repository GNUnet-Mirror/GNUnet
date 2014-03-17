/*
     This file is part of GNUnet.
     (C) 2009-2013 Christian Grothoff (and other contributing authors)

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
#include "gnunet_nse_service.h"
#include "gnunet_ats_service.h"
#include "gnunet_core_service.h"
#include "gnunet_datacache_lib.h"
#include "gnunet_transport_service.h"
#include "gnunet_hello_lib.h"
#include "gnunet_dht_service.h"
#include "gnunet_statistics_service.h"
#include "gnunet-service-xdht.h"
#include "gnunet-service-xdht_clients.h"
#include "gnunet-service-xdht_datacache.h"
#include "gnunet-service-xdht_hello.h"
#include "gnunet-service-xdht_neighbours.h"
#include "gnunet-service-xdht_nse.h"
#include "gnunet-service-xdht_routing.h"
#include <fenv.h>
#include "dht.h"

/**
 * Maximum possible fingers of a peer.
 */
#define MAX_FINGERS 64

/**
 * Maximum allowed number of pending messages per friend peer.
 */
#define MAXIMUM_PENDING_PER_FRIEND 64

/**
 * How long at least to wait before sending another find finger trail request.
 */
#define DHT_MINIMUM_FIND_FINGER_TRAIL_INTERVAL GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 30)

/**
 * How long at most to wait before sending another find finger trail request.
 */
#define DHT_MAXIMUM_FIND_FINGER_TRAIL_INTERVAL GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 10)

/**
 * How long at most to wait for transmission of a GET request to another peer?
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
  uint32_t type GNUNET_PACKED;

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
   * When does the content expire?
   */
  struct GNUNET_TIME_AbsoluteNBO expiration_time;

  /**
   * Bloomfilter (for peer identities) to stop circular routes
   */
  char bloomfilter[DHT_BLOOM_SIZE];

  /**
   * The key we are storing under.
   */
  struct GNUNET_HashCode key;

  /* put path (if tracked) */

  /* Payload */

};


/**
 * P2P Result message
 */
struct PeerResultMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_DHT_P2P_RESULT
   */
  struct GNUNET_MessageHeader header;

  /**
   * Content type.
   */
  uint32_t type GNUNET_PACKED;

  /**
   * Length of the PUT path that follows (if tracked).
   */
  uint32_t put_path_length GNUNET_PACKED;

  /**
   * Length of the GET path that follows (if tracked).
   */
  uint32_t get_path_length GNUNET_PACKED;

  /**
   * When does the content expire?
   */
  struct GNUNET_TIME_AbsoluteNBO expiration_time;

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
  uint32_t type GNUNET_PACKED;

  /**
   * Hop count
   */
  uint32_t hop_count GNUNET_PACKED;

  /**
   * Desired replication level for this request.
   */
  uint32_t desired_replication_level GNUNET_PACKED;

  /**
   * Size of the extended query.
   */
  uint32_t xquery_size;

  /**
   * Bloomfilter mutator.
   */
  uint32_t bf_mutator;

  /**
   * Bloomfilter (for peer identities) to stop circular routes
   */
  char bloomfilter[DHT_BLOOM_SIZE];

  /**
   * The key we are looking for.
   */
  struct GNUNET_HashCode key;

};


/**
 * A destination can be either a friend, finger or me.
 * Used in trail setup to understand if the message is sent to an intermediate
 * finger or a friend.
 */
enum current_destination_type
{
  FRIEND ,
  FINGER ,
  MY_ID        
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
   * Source peer which wants to setup the trail to one of its finger. 
   */
  struct GNUNET_PeerIdentity source_peer;

  /**
   * Finger id to which we want to set up the trail to. 
   */
  uint64_t destination_finger;
  
  /**
   * If set to 1, then we are looking for trail to our immediate successor. 
   */
  unsigned int successor_flag;
  
  /**
   * If set to 1, then we are looking for trail to our immediate predecessor. 
   */
  unsigned int predecessor_flag;
  
  /**
   * Peer which gets this message can be either an intermediate finger or friend. 
   */
  enum current_destination_type current_destination_type;
  
  /**
   * Peer to which this packet is forwarded.
   */
  struct GNUNET_PeerIdentity current_destination;
  
  /**
   * Index into finger peer map. 
   */
  unsigned int finger_map_index;
  
  /**
   * Number of entries in trail list.
   */
  uint32_t trail_length GNUNET_PACKED;
  
};


/**
 * P2P Trail setup Result message
 */
struct PeerTrailSetupResultMessage
{
  
  /**
   * Type: #GNUNET_MESSAGE_TYPE_DHT_P2P_TRAIL_RESULT_SETUP
   */
  struct GNUNET_MessageHeader header;
  
  /**
   * Finger to which we have found the path. 
   */
  struct GNUNET_PeerIdentity finger;

  /**
   * Peer which was looking for the trail to finger. 
   */
  struct GNUNET_PeerIdentity destination_peer;

  /**
   * Peer to which this packet is forwarded next.
   */
  struct GNUNET_PeerIdentity current_destination;
  
  /**
   * Index at which peer list should be accessed. 
   */
  unsigned int current_index;
  
  /**
   * If set to 1, then this trail is the trail to our successor. 
   */
  unsigned int successor_flag;
  
  /**
   * If set to 1, then this trail is the trail to our predecessor. 
   */
  unsigned int predecessor_flag;
  
  /**
   * Index into finger peer map
   */
  unsigned int finger_map_index;
  
  /**
   * Number of entries in trail list.
   */
  uint32_t trail_length GNUNET_PACKED;
  
};


/**
 * P2P verify successor message. 
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
  unsigned int trail_length;
  
  /**
   * Index in trail which points to next destination to send this message.
   */
  unsigned int current_trail_index;
  
};


/**
 * P2P verify successor result message. 
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
  unsigned int trail_length;
  
  /**
   * Index in trail which points to next destination to send this message.
   */
  unsigned int current_index;
  
};

/**
 * P2P notify new successor message.
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
  unsigned int trail_length;
  
  /**
   * Index in trail which points to next destination to send this message.
   */
  unsigned int current_index;
  
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
   * When does this message time out?
   */
  struct GNUNET_TIME_Absolute timeout;

   /**
   * Message importance level.  FIXME: used? useful?
   */
  unsigned int importance;

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
   * If 1, then this finger entry is my first finger(successor).
   */
  unsigned int successor;
  
  /**
   * If 1, then this finger entry is my first predecessor.
   */
  unsigned int predecessor;
  
  /**
   * Index in finger peer map
   */
  unsigned int finger_map_index;
  
  /**
   * Total number of entries in trail from me to finger. 
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


/**
 * Task that sends FIND FINGER TRAIL requests.
 */
static GNUNET_SCHEDULER_TaskIdentifier find_finger_trail_task;

/**
 * 
 * Task that periodically checks for who is my successor. 
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
 * Handle to ATS.
 */
static struct GNUNET_ATS_PerformanceHandle *atsAPI;

/**
 * Handle to CORE.
 */
static struct GNUNET_CORE_Handle *core_api;

/**
 * FIXME: Is it safe to assume its initialized to 0 by default.
 * The current finger index that we have found trail to.
 */
static unsigned int current_finger_index;


/**
 * Called when core is ready to send a message we asked for
 * out to the destination.
 *
 * @param cls the 'struct PeerInfo' of the target peer
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
 * Setup the trail message and forward it to a friend. 
 * @param source_peer Peer which wants to set up the trail to one of its finger.
 * @param destination_finger Peer to which we want to set up the trail to.
 * @param target_friend Current friend to which this message should be forwarded.
 * @param trail_length Numbers of peers in the trail.
 * @param trail_peer_list peers this request has traversed so far
 * @param successor_flag If 1 then we are looking for trail to our successor.
 * @param predecessor_flag If 1, then we are looking for trail to our predecessor.  
 * @param current_finger_index Finger index in finger peer map 
 */
void
GDS_NEIGHBOURS_handle_trail_setup (struct GNUNET_PeerIdentity *source_peer,
                                  uint64_t *destination_finger,
                                  struct FriendInfo *target_friend,
                                  unsigned int trail_length,
                                  struct GNUNET_PeerIdentity *trail_peer_list,
                                  unsigned int successor_flag,
                                  unsigned int predecessor_flag,
                                  unsigned int current_finger_index)
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
  pending->importance = 0;    /* FIXME */
  pending->timeout = GNUNET_TIME_relative_to_absolute (GET_TIMEOUT);
  tsm = (struct PeerTrailSetupMessage *) &pending[1]; 
  pending->msg = &tsm->header;
  tsm->header.size = htons (msize);
  tsm->header.type = htons (GNUNET_MESSAGE_TYPE_DHT_P2P_TRAIL_SETUP);
  memcpy (&(tsm->destination_finger), destination_finger, sizeof (uint64_t)); /* FIXME: Wrong value of finger identity goes to the target peer in 
                                                                               * handle_dht_p2p_trail_setup */
  memcpy (&(tsm->source_peer), source_peer, sizeof (struct GNUNET_PeerIdentity));
  memcpy (&(tsm->current_destination), &(target_friend->id), 
          sizeof (struct GNUNET_PeerIdentity));
  tsm->current_destination_type = htonl (FRIEND); 
  tsm->trail_length = htonl (trail_length); 
  tsm->finger_map_index = htonl (current_finger_index);
  if(1 == successor_flag)
  {
    tsm->successor_flag = htonl(1);
    tsm->predecessor_flag = htonl (0);
  }
  else if (1 == predecessor_flag)
  {
    tsm->predecessor_flag = htonl(1);
    tsm->successor_flag = htonl(0);
  }
  else
  {
    tsm->successor_flag = htonl(0);
    tsm->predecessor_flag = htonl(0);
  }
  peer_list = (struct GNUNET_PeerIdentity *) &tsm[1];
  memcpy (peer_list, trail_peer_list, trail_length * sizeof(struct GNUNET_PeerIdentity));
  GNUNET_CONTAINER_DLL_insert_tail (target_friend->head, target_friend->tail, pending);
  target_friend->pending_count++;
  process_friend_queue (target_friend);
  
}


/**
 * Handle a tail setup result message. 
 * @param destination_peer Peer which will get the trail to one of its finger.
 * @param source_finger Peer to which the trail has been setup to.
 * @param target_friend Friend to which this message should be forwarded.
 * @param trail_length Numbers of peers in the trail.
 * @param trail_peer_list Peers which are part of the trail from source to destination.
 * @param current_trail_index Index in trail_peer_list. 
 * @param successor_flag If 1, then this is the trail to our successor.
 * @param predecessor_flag If 1, then this is the trail to our predecessor.  
 * @param finger_map_index Finger index in finger peer map 
 */
void
GDS_NEIGHBOURS_handle_trail_setup_result (struct GNUNET_PeerIdentity *destination_peer,
                                          struct GNUNET_PeerIdentity *source_finger,
                                          struct FriendInfo *target_friend,
                                          unsigned int trail_length,
                                          struct GNUNET_PeerIdentity *trail_peer_list,
                                          unsigned int current_trail_index,
                                          unsigned int successor_flag,
                                          unsigned int predecessor_flag,
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
  memcpy (&(tsrm->current_destination), &(target_friend->id), sizeof (struct GNUNET_PeerIdentity));
  memcpy (&(tsrm->destination_peer), destination_peer, sizeof (struct GNUNET_PeerIdentity));
  memcpy (&(tsrm->finger), source_finger, sizeof (struct GNUNET_PeerIdentity));
  tsrm->trail_length = htonl (trail_length);
  tsrm->current_index = htonl (current_trail_index);
  tsrm->successor_flag = htonl (successor_flag);
  tsrm->predecessor_flag = htonl (predecessor_flag);
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
 * @param current_trail_index Index in the trial list at which receiving peer should
 *                            get the next element.
 */
void GDS_NEIGHBOURS_handle_verify_successor(struct GNUNET_PeerIdentity *source_peer,
                                            struct GNUNET_PeerIdentity *successor,
                                            struct FriendInfo *target_friend,
                                            struct GNUNET_PeerIdentity *trail_peer_list,
                                            unsigned int trail_length,
                                            unsigned int current_trail_index)
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
  vsm->current_trail_index = htonl (current_trail_index);
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
 * @param my_predecessor source_successor predecessor.
 * @param target_friend Friend to which this message should be forwarded.
 * @param trail_peer_list Peer which are part of trail from source to destination
 * @param trail_length Number of peers in the trail list.
 * @param current_trail_index Index in the trial list at which receiving peer should
 *                            get the next element.
 */
void GDS_NEIGHBOURS_handle_verify_successor_result (struct GNUNET_PeerIdentity *destination_peer,
                                                    struct GNUNET_PeerIdentity *source_successor,
                                                    struct GNUNET_PeerIdentity *my_predecessor,
                                                    struct FriendInfo *target_friend,
                                                    struct GNUNET_PeerIdentity *trail_peer_list,
                                                    unsigned int trail_length,
                                                    unsigned int current_trail_index)
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
  vsmr->current_index = htonl (current_trail_index);
  
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
 * @param current_trail_index Index of peer_list for next target friend position. 
 * @param trail_length Total number of peers in peer list 
 */
void 
GDS_NEIGHBOURS_notify_new_successor (struct GNUNET_PeerIdentity *source_peer,
                                     struct GNUNET_PeerIdentity *destination_peer,
                                     struct FriendInfo *target_friend,
                                     struct GNUNET_PeerIdentity *trail_peer_list,
                                     unsigned int trail_length,
                                     unsigned int current_trail_index)
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
  nsm->current_index = htonl (current_trail_index);
  
  peer_list = (struct GNUNET_PeerIdentity *) &nsm[1];
  memcpy (peer_list, trail_peer_list, trail_length * sizeof (struct GNUNET_PeerIdentity));
  
   /* Send the message to chosen friend. */
  GNUNET_CONTAINER_DLL_insert_tail (target_friend->head, target_friend->tail, pending);
  target_friend->pending_count++;
  process_friend_queue (target_friend);
}


/**FIXME: Old implementation just to remove error
 * TODO: Modify this function to handle our get request. 
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
 * @param reply_bf bloomfilter to filter duplicates
 * @param reply_bf_mutator mutator for @a reply_bf
 * @param peer_bf filter for peers not to select (again)
 */
void
GDS_NEIGHBOURS_handle_get (enum GNUNET_BLOCK_Type type,
                           enum GNUNET_DHT_RouteOption options,
                           uint32_t desired_replication_level,
                           uint32_t hop_count, const struct GNUNET_HashCode * key,
                           const void *xquery, size_t xquery_size,
                           const struct GNUNET_CONTAINER_BloomFilter *reply_bf,
                           uint32_t reply_bf_mutator,
                           struct GNUNET_CONTAINER_BloomFilter *peer_bf)
{

  /*
   1. take the key, get the 64 bit value of the key.
   2. call find_successor to get the successor of the key.
   3. successor can be either a friend or finger.
   4. update the field in get message to reflect if its a friend or finger table
   5. add the put message to pending message and send it. 
   */
  
}

/**FIXME: Old implementation just to remove error.
 * TODO: Modify this function to handle our put request. 
 * Perform a PUT operation.   Forwards the given request to other
 * peers.   Does not store the data locally.  Does not give the
 * data to local clients.  May do nothing if this is the only
 * peer in the network (or if we are the closest peer in the
 * network).
 *
 * @param type type of the block
 * @param options routing options
 * @param desired_replication_level desired replication count
 * @param expiration_time when does the content expire
 * @param hop_count how many hops has this message traversed so far
 * @param bf Bloom filter of peers this PUT has already traversed
 * @param key key for the content
 * @param put_path_length number of entries in @a put_path
 * @param put_path peers this request has traversed so far (if tracked)
 * @param data payload to store
 * @param data_size number of bytes in @a data
 */
void
GDS_NEIGHBOURS_handle_put (enum GNUNET_BLOCK_Type type,
                           enum GNUNET_DHT_RouteOption options,
                           uint32_t desired_replication_level,
                           struct GNUNET_TIME_Absolute expiration_time,
                           uint32_t hop_count,
                           struct GNUNET_CONTAINER_BloomFilter *bf,
                           const struct GNUNET_HashCode *key,
                           unsigned int put_path_length,
                           struct GNUNET_PeerIdentity *put_path,
                           const void *data, size_t data_size)
{

   /*
   1. take the key, get the 64 bit value of the key.
   2. call find_successor to get the successor of the key.
   3. successor can be either a friend or finger.
   4. update the field in put message to reflect if its a friend or finger table
   5. add the put message to pending message and send it. 
   */
  /* SUPU: Call is made to this function from client. It does not seem to be
   waiting for a confirmation So, once we got the request, we use the key and
   try to find the closest successor, but in this case when we reach to the
   closest successor in handle_dht_p2p_put, then just do datacache_put. As the calling 
   function does not need any confirmation, we don't need the result back. */
}


/** 
 * Randomly choose one of your friends from the friends_peer map
 * @return Friend
 */
static struct FriendInfo *
select_random_friend()
{  
  unsigned int current_size;
  unsigned int *index; 
  unsigned int j = 0;
  struct GNUNET_CONTAINER_MultiPeerMapIterator *iter;
  struct GNUNET_PeerIdentity key_ret;
  struct FriendInfo *friend;
  
  current_size = GNUNET_CONTAINER_multipeermap_size (friend_peermap);
  
  /* Element stored at this index in friend_peermap should be selected friend. */
  index = GNUNET_CRYPTO_random_permute (GNUNET_CRYPTO_QUALITY_WEAK, current_size);
  
  /* Create an iterator for friend_peermap. */
  iter = GNUNET_CONTAINER_multipeermap_iterator_create (friend_peermap);
  
  /* Set the position of iterator to index. */
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
    return friend;
  }

  return NULL;
}


/**
 * Compute finger_identity to which we want to setup the trail
 * @return finger_identity 
 */
static uint64_t *
compute_finger_identity()
{
  uint64_t *my_id64 ;
  uint64_t *finger_identity64;
  
  my_id64 = GNUNET_malloc (sizeof (uint64_t));
  finger_identity64 = GNUNET_malloc (sizeof (uint64_t));

  memcpy (my_id64, &(my_identity.public_key.q_y), sizeof (uint64_t));
  *finger_identity64 = fmod ((*my_id64 + pow (2,current_finger_index)),( (pow (2,MAX_FINGERS))));
  
  return finger_identity64;
}


/**
 * Compute immediate predecessor identity in the network.
 * @return peer identity of immediate predecessor.
 */
static uint64_t *
compute_predecessor_identity()
{
  uint64_t *my_id ;
  uint64_t *predecessor;
  
  my_id = GNUNET_malloc (sizeof (uint64_t));
  predecessor = GNUNET_malloc (sizeof (uint64_t));
  
  memcpy (my_id, &(my_identity.public_key.q_y), sizeof (uint64_t));
  *predecessor = fmod ((*my_id -1), (pow (2,MAX_FINGERS)));
          
  return predecessor;
}


/**
 * SUPU: You should pass the trail index from where next peer should read. read
 * position should be set and after you read you should update the read position
 * for next peer in the trail list. 
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
  unsigned int finger_trail_current_index;
  struct FingerInfo *finger;
  unsigned int finger_index;
  unsigned int i;
  
  finger_iter = GNUNET_CONTAINER_multipeermap_iterator_create (finger_peermap);  
  for (finger_index = 0; finger_index < GNUNET_CONTAINER_multipeermap_size (finger_peermap); finger_index++)
  {
    if(GNUNET_YES == GNUNET_CONTAINER_multipeermap_iterator_next (finger_iter, &key_ret,
                                                                 (const void **)&finger)) 
    {
      if (1 == finger->successor)
        break;
    }
  }
  GNUNET_CONTAINER_multipeermap_iterator_destroy (finger_iter);
 
  peer_list = GNUNET_malloc (sizeof (struct GNUNET_PeerIdentity) * finger->trail_length);
  
  /* Iterate over your linked list of trail and copy it into peer_list. */
  struct TrailPeerList *iterate;
  iterate = finger->head;
  i = 0;
  while ( i < (finger->trail_length))
  {
    memcpy (&peer_list[i], &(iterate->peer), sizeof (struct GNUNET_PeerIdentity));
    iterate = iterate->next;
    i++;
  }
 
  /* element stored at location 0 is my own identity. element stored at location 1
   is the next hop. */
   next_hop = GNUNET_malloc (sizeof (struct GNUNET_PeerIdentity));
   memcpy (next_hop, &peer_list[1], sizeof (struct GNUNET_PeerIdentity));

  
  /* Find the friend corresponding to this next hop. */
  target_friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, next_hop);
  finger_trail_current_index = 2; 
  GDS_NEIGHBOURS_handle_verify_successor (&my_identity,
                                          &(finger->finger_identity),
                                          target_friend,
                                          peer_list,
                                          finger->trail_length,
                                          finger_trail_current_index);
  
  
  /* FIXME: Use a random value so that this message is send not at the same
   interval as send_find_finger_trail_message. */
  next_send_time.rel_value_us =
      DHT_MINIMUM_FIND_FINGER_TRAIL_INTERVAL.rel_value_us +
      GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_WEAK,
                                DHT_MAXIMUM_FIND_FINGER_TRAIL_INTERVAL.rel_value_us /
                                (current_finger_index + 1));
 
  verify_successor =
      GNUNET_SCHEDULER_add_delayed (next_send_time, &send_verify_successor_message,
                                    NULL);
}


/**
 * Task to send a find finger trail message. We attempt to find trail
 * to our fingers, successor and predecessor in the network.
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
  struct GNUNET_PeerIdentity *peer_list;
  unsigned int successor_flag;
  unsigned int predecessor_flag;
  uint64_t *finger_identity;
  unsigned int finger_index;
  
  /* Initialize flag values */
  predecessor_flag = 0;
  successor_flag = 0;
  
  if (1 == current_finger_index)
  {
    /* We have started the process to find the successor. We should search 
     for our predecessor. */
    finger_identity = compute_predecessor_identity();  
    predecessor_flag = 1; 
    goto select_friend;
  }
  else
  {
    finger_identity = compute_finger_identity();
  }
  
  if(0 == current_finger_index)
  {
    /* We are searching for our successor in the network. */
    successor_flag = 1;
  }
  
  select_friend:
  finger_index = current_finger_index;
  current_finger_index = ( current_finger_index + 1) % MAX_FINGERS;
  
  target_friend = select_random_friend();
 
  /* We found a friend.*/
  if(NULL != target_friend)
  { 
    /* Add yourself and selected friend in the trail list. */
    unsigned int trail_length = 2;
    peer_list = GNUNET_malloc (sizeof (struct GNUNET_PeerIdentity) * trail_length);
    memcpy (&peer_list[0], &(my_identity), sizeof (struct GNUNET_PeerIdentity)); 
    memcpy (&peer_list[1], &(target_friend->id), sizeof (struct GNUNET_PeerIdentity)); 
    
    GDS_NEIGHBOURS_handle_trail_setup (&my_identity, finger_identity, 
                                       target_friend, trail_length, peer_list,
                                       successor_flag, predecessor_flag, 
                                       finger_index);
  }
  
  /* FIXME: Should we be using current_finger_index to generate random interval.*/
  next_send_time.rel_value_us =
      DHT_MINIMUM_FIND_FINGER_TRAIL_INTERVAL.rel_value_us +
      GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_WEAK,
                                DHT_MAXIMUM_FIND_FINGER_TRAIL_INTERVAL.rel_value_us /
                                (current_finger_index + 1));
 
  find_finger_trail_task =
      GNUNET_SCHEDULER_add_delayed (next_send_time, &send_find_finger_trail_message,
                                    NULL);
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
  if (1 == GNUNET_CONTAINER_multipeermap_size (friend_peermap))
    find_finger_trail_task = GNUNET_SCHEDULER_add_now (&send_find_finger_trail_message, NULL);
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
  
  /* Remove the friend from friend_peermap. */
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multipeermap_remove (friend_peermap,
                                                       peer,
                                                       remove_friend));
  
  /* If the peer is removed then all the trail which goes through this
   peer also becomes invalid. */
  /* FIXME: Iterate over finger peermap, get the trail index and find all the
   finger whose trail's first peer was this peer. and remove them from finger
   peermap. Assumption that in send_find_finger_trail we will eventually reach
   to this finger and we will setup up the new trail. 
   So, we need a threshold on number of trail thats can go through a node 
   so that if that nodes go away then also our system is up and runnning. 
   Where can we specify that threshold.*/
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
 * Core handler for p2p put requests.
 *
 * @param cls closure
 * @param peer sender of the request
 * @param message message
 * @param peer peer identity this notification is about
 * @return #GNUNET_OK to keep the connection open,
 *         #GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_dht_p2p_put (void *cls,
		    const struct GNUNET_PeerIdentity *peer,
                    const struct GNUNET_MessageHeader *message)
{
    /**
    1. Check if destination is friend or finger.
    2. If finger then get the next hop from routing table and 
     * call GDS_NEGIHBOURS_handle_get.
    3. If friend then call find_successor to get the next hop and again
     * call GDS_NEIGHBOURS_handle_get to send to chosen hop.
     4. If you are the destination then do datacache_store.
     */
  return 0;
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
  /**
    1. Check if destination is friend or finger.
    2. If finger then get the next hop from routing table and 
     * call GDS_NEGIHBOURS_handle_get.
    3. If friend then call find_successor to get the next hop and again
     * call GDS_NEIGHBOURS_handle_get to send to chosen hop.
     4. If you are the destination then send the data back to source peer
   * Assuming we have trail setup we can
   * either store the whole trail or again do the search process..
     */
  return 0;
}


/**
 * Compare two peer identities.
 * @param p1 Peer identity
 * @param p2 Peer identity
 * @return 1 if p1 > p2, -1 if p1 < p2 and 0 if p1 == p2. 
 */
#if 0
static int
compare_peer_id (const void *p1, const void *p2)
{
  return memcmp (p1, p2, sizeof (uint64_t));;
}
#endif

/**
 * Returns the previous element of value in all_known_peers.
 * @param all_known_peers list of all the peers
 * @param value value we have to search in the all_known_peers.
 * @return 
 */
#if 0
static struct GNUNET_PeerIdentity *
binary_search(struct GNUNET_PeerIdentity *all_known_peers, uint64_t *value,
              unsigned int size)
{
  int first;
  int last;
  int middle;
  struct GNUNET_PeerIdentity *successor;
  successor = GNUNET_malloc (sizeof (struct GNUNET_PeerIdentity));
  
  first = 0;
  last = size - 1;
  middle = (first + last)/2;
  
  while(first <= last)
  {
    if(compare_peer_id(&all_known_peers[middle], &value) > 0)
    {
      first = middle + 1;
    }
    else if(0 == compare_peer_id(&all_known_peers[middle], &value))
    {
      if(middle == 0)
      {
        memcpy (successor, &(all_known_peers[size - 1]), sizeof (struct GNUNET_PeerIdentity));
      }
      else
      {
        memcpy (successor, &(all_known_peers[middle-1]), sizeof (struct GNUNET_PeerIdentity));
      }
    }
    else
    {
       last = middle - 1;
    }
  
    middle = (first + last)/2;  
  }

  return successor;
}
#endif

/**
 * Find closest successor for the value.
 * @param value Value for which we are looking for successor
 * @param current_destination NULL if my_identity is successor else finger/friend 
 * identity 
 * @param type Next destination type
 * @return Peer identity of next destination i.e. successor of value. 
 */
static struct GNUNET_PeerIdentity *
find_successor(uint64_t *value, struct GNUNET_PeerIdentity *current_destination,
               enum current_destination_type *type)
{
#if 0
  struct GNUNET_CONTAINER_MultiPeerMapIterator *friend_iter;
  struct GNUNET_CONTAINER_MultiPeerMapIterator *finger_iter;
  struct GNUNET_PeerIdentity key_ret;
  struct FriendInfo *friend;
  struct FingerInfo *finger;
  unsigned int finger_index;
  unsigned int friend_index;
  struct GNUNET_PeerIdentity *all_known_peers;
  struct GNUNET_PeerIdentity *successor;
  unsigned int size;
  unsigned int j;
  
  /* 2 is added in size for my_identity and value which will part of all_known_peers. */
  size = GNUNET_CONTAINER_multipeermap_size (friend_peermap)+
         GNUNET_CONTAINER_multipeermap_size (finger_peermap)+
         2;
  
  all_known_peers = GNUNET_malloc (sizeof (struct GNUNET_PeerIdentity) * size);
  
  /* Copy your identity at 0th index in all_known_peers. */
  j = 0;
  memcpy (&all_known_peers[j], &(my_identity), sizeof (struct GNUNET_PeerIdentity));
  
  /* Copy the value that you are searching at index 1 in all_known_peers. */
  j++;
  memcpy (&all_known_peers[j], value, sizeof(uint64_t));
  
  /* Iterate over friend peer map and copy all the elements into array. */
  friend_iter = GNUNET_CONTAINER_multipeermap_iterator_create (friend_peermap); 
  for (friend_index = 0; friend_index < GNUNET_CONTAINER_multipeermap_size (friend_peermap); friend_index++)
  {
    if(GNUNET_YES == GNUNET_CONTAINER_multipeermap_iterator_next(friend_iter,&key_ret,(const void **)&friend)) 
    {
      memcpy (&all_known_peers[j], &(friend->id), sizeof (struct GNUNET_PeerIdentity));
      j++;
    }
  }
  
  /* Iterate over finger map and copy all the entries into all_known_peers array. */
  finger_iter = GNUNET_CONTAINER_multipeermap_iterator_create (finger_peermap);  
  for (finger_index = 0; finger_index < GNUNET_CONTAINER_multipeermap_size (finger_peermap); finger_index++)
  {
    /* FIXME: I don't think we are actually iterating.
     Read about how to iterate over the multi peer map. */
    if(GNUNET_YES == GNUNET_CONTAINER_multipeermap_iterator_next(finger_iter,&key_ret,(const void **)&finger)) 
    {
      memcpy (&all_known_peers[j], &(finger->finger_identity), sizeof (struct GNUNET_PeerIdentity));
      j++;
    }
  }
  
  GNUNET_CONTAINER_multipeermap_iterator_destroy (finger_iter);
  GNUNET_CONTAINER_multipeermap_iterator_destroy (friend_iter);   

  /* FIMXE : Should we not sort it for 64 bits. */
  qsort (all_known_peers, size, sizeof (uint64_t), &compare_peer_id);
  
  /* search value in all_known_peers array. */
  successor = binary_search (all_known_peers, value, size);
 
  /* compare successor with my_identity, finger and friend */
  if(0 == GNUNET_CRYPTO_cmp_peer_identity(&(my_identity), successor))
  {
    FPRINTF (stderr,_("\nSUPU %s, %s, %d"),    __FILE__, __func__,__LINE__);
    *type = MY_ID;
    return NULL;
  }
  else if (GNUNET_YES == GNUNET_CONTAINER_multipeermap_contains (friend_peermap,
                                              successor))
  {
    FPRINTF (stderr,_("\nSUPU %s, %s, %d"),    __FILE__, __func__,__LINE__);
    *type = FRIEND;
    memcpy (current_destination, successor, sizeof (struct GNUNET_PeerIdentity));
    return successor;
  }
  else if (GNUNET_YES == GNUNET_CONTAINER_multipeermap_contains (finger_peermap,
                                              successor))
  {
    FPRINTF (stderr,_("\nSUPU %s, %s, %d"),    __FILE__, __func__,__LINE__);
    *type = FINGER;
    memcpy (current_destination, successor, sizeof (struct GNUNET_PeerIdentity));
    /* get the corresponding finger for succcesor and read the first element from
     the trail list and return that element. */
    struct FingerInfo *successor_finger;
    struct GNUNET_PeerIdentity *next_hop;
    next_hop = GNUNET_malloc (sizeof (struct GNUNET_PeerIdentity));
    successor_finger = GNUNET_CONTAINER_multipeermap_get (finger_peermap, successor);
    //memcpy (next_hop, &(successor_finger->trail_peer_list[0]), sizeof (struct GNUNET_PeerIdentity));
    return next_hop;
  }
  FPRINTF (stderr,_("\nSUPU %s, %s, %d"),    __FILE__, __func__,__LINE__);
  return NULL;
#endif
  *type = MY_ID;
  return &my_identity;
}


/**
 * SUPU: The first element in the trail setup message is your identity.
 * in this function you should increment the trail length. 
 * Handle a PeerTrailSetupMessage. 
 * @param cls closure
 * @param message message
 * @param peer peer identity this notification is about
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
static int
handle_dht_p2p_trail_setup(void *cls, const struct GNUNET_PeerIdentity *peer,
                    const struct GNUNET_MessageHeader *message)
{
  struct PeerTrailSetupMessage *trail_setup; 
  struct GNUNET_PeerIdentity *next_hop; 
  struct FriendInfo *target_friend;
  size_t msize;
  uint32_t trail_length;
  enum current_destination_type peer_type;
  struct GNUNET_PeerIdentity *trail_peer_list; 
  uint32_t current_trail_index;
  unsigned int finger_map_index;
  struct GNUNET_PeerIdentity *next_peer;
  unsigned int successor_flag;
  unsigned int predecessor_flag;
 
  /* parse and validate message. */
  msize = ntohs (message->size);
  if (msize < sizeof (struct PeerTrailSetupMessage))
  {
    GNUNET_break_op (0);
    return GNUNET_YES;
  }
  
  
  trail_setup = (struct PeerTrailSetupMessage *) message; 
  trail_length = ntohl (trail_setup->trail_length); 
  peer_type = ntohl (trail_setup->current_destination_type);
  finger_map_index = ntohl (trail_setup->finger_map_index);
  successor_flag = ntohl (trail_setup->successor_flag);
  predecessor_flag = ntohl (trail_setup->predecessor_flag);

  trail_peer_list = (struct GNUNET_PeerIdentity *) &trail_setup[1];
  
  if ((msize <
       sizeof (struct PeerTrailSetupMessage) +
       trail_length * sizeof (struct GNUNET_PeerIdentity)) ||
      (trail_length >
       GNUNET_SERVER_MAX_MESSAGE_SIZE / sizeof (struct GNUNET_PeerIdentity)))
  {
    GNUNET_break_op (0);
    return GNUNET_YES; 
  }
  
  GNUNET_STATISTICS_update (GDS_stats,
                            gettext_noop ("# TRAIL SETUP requests received"), 1,
                            GNUNET_NO);
  GNUNET_STATISTICS_update (GDS_stats,
                            gettext_noop ("# TRAIL SETUP bytes received"), msize,
                            GNUNET_NO);
  
  if (peer_type == FRIEND)
  {
    if (0 == (GNUNET_CRYPTO_cmp_peer_identity (&(trail_setup->current_destination),
                                               &my_identity)))
    {
      next_hop = find_successor (&(trail_setup->destination_finger),
                                 &(trail_setup->current_destination),
                                 &(peer_type));
    }
    else
      return GNUNET_SYSERR; 
  }
  else if (peer_type == FINGER)
  {
    if (0 != (GNUNET_CRYPTO_cmp_peer_identity (&(trail_setup->current_destination),
                                               &my_identity)))
    {
      next_hop = GDS_ROUTING_search (&(trail_setup->source_peer),
                                     &(trail_setup->current_destination));
      
      #if 0
      /* This is an optimization. Uncomment when basic code is running first. */
      /* I am part of trail.*/
      struct GNUNET_PeerIdentity *next_peer_routing_table;
      next_peer_routing_table = GNUNET_malloc (sizeof (struct GNUNET_PeerIdentity));
      next_peer_routing_table = GDS_ROUTING_search (&(trail_setup->source_peer),
                                     &(trail_setup->current_destination));
      
      struct GNUNET_PeerIdentity *next_peer_find_successor;
      next_peer_find_successor = find_successor (&(trail_setup->destination_finger),
                                           &(trail_setup->current_destination),
                                           &(peer_type));
      
      next_hop = GNUNET_malloc (sizeof (struct GNUNET_PeerIdentity));
      next_hop = find_closest_destination (next_peer_routing_table, 
                                           next_peer_find_successor,
                                           &(trail_setup->destination_finger) );
      #endif
    } 
    else
    {
      /* I am the current_destination finger */
      next_hop = find_successor (&(trail_setup->destination_finger),
                                 &(trail_setup->current_destination), &(peer_type));
    }
  }
  
  /* If you are the next hop, then you are the final destination */
  if (peer_type == MY_ID)
  {
    /*SUPU:
     1. You were the destination of this message which means you were already added
     in the peer list by previous calling function. 
     2. current_trail_index should point to the trail element at which the peer
     which receives this message should look for the next peer to forward the packet
     to. */
    current_trail_index = trail_length - 2;
    next_peer = GNUNET_malloc (sizeof (struct GNUNET_PeerIdentity)); 
    memcpy (next_peer, &trail_peer_list[current_trail_index], sizeof (struct GNUNET_PeerIdentity));
    target_friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, next_peer);
    GNUNET_free (next_peer);
    
    if(current_trail_index != 0)
      current_trail_index = current_trail_index - 1; 
    
    GDS_NEIGHBOURS_handle_trail_setup_result (&(trail_setup->source_peer),
                                              &(my_identity),
                                              target_friend, trail_length,
                                              trail_peer_list, current_trail_index,
                                              successor_flag, 
                                              predecessor_flag,
                                              finger_map_index);
  
    return GNUNET_YES;
  }
  
  /* Add next hop to list of peers. */
  struct GNUNET_PeerIdentity *peer_list;
  peer_list = GNUNET_malloc (sizeof (struct GNUNET_PeerIdentity) * (trail_length + 1));
  memcpy (peer_list, trail_peer_list, trail_length * sizeof (struct GNUNET_PeerIdentity));
  memcpy (&peer_list[trail_length], next_hop, sizeof (struct GNUNET_PeerIdentity));
  trail_length++;
  
  target_friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, next_hop);
  
  if(peer_type == FINGER)
  {
    GDS_ROUTING_add (&(trail_setup->source_peer), 
                     &(trail_setup->current_destination),
                     next_hop);
  }
  
  GDS_NEIGHBOURS_handle_trail_setup (&(trail_setup->source_peer),
                                     &(trail_setup->destination_finger),
                                     target_friend,
                                     trail_setup->trail_length,
                                     peer_list,trail_setup->successor_flag,
                                     trail_setup->predecessor_flag,
                                     finger_map_index);

return GNUNET_YES;
}


/**
 * FIXME: For redundant routing, we may start looking for different
 * paths to reach to same finger. So, in send_find_finger, we are starting
 * the search for trail to a finger, even if we already have found trail to
 * reach to it. There are several reasons for doing so
 * 1. We may reach to a closer successor than we have at the moment. So, we
 * should keep looking for the successor.
 * 2. We may reach to the same successor but through a shorter path.
 * 3. As I don't know how keys are distributed and how put/get will react 
 * because of this, I have to think further before implementing it. 
 * Add an entry in finger table. 
 * @param finger Finger to be added to finger table
 * @param peer_list peers this request has traversed so far
 * @param trail_length Numbers of peers in the trail.
 */
static 
void finger_table_add (struct GNUNET_PeerIdentity *finger,
                       struct GNUNET_PeerIdentity *peer_list,
                       unsigned int trail_length,
                       unsigned int successor_flag,
                       unsigned int predecessor_flag,
                       unsigned int finger_map_index)
{
  struct FingerInfo *new_finger_entry;
  unsigned int i = 0;
 /** SUPU: when we add an entry then we should look if
  * we already have an entry for that index. If yes, then
  * 1) if both the finger identity are same, and same first friend, then choose
  * the one with shorter trail length.
  * 2) if the finger identity is different, then keep the one which is closest.*/
 
  new_finger_entry = GNUNET_malloc (sizeof (struct FingerInfo));
  memcpy (&(new_finger_entry->finger_identity), finger, sizeof (struct GNUNET_PeerIdentity));
 

  /* Insert elements of peer_list into TrailPeerList. */
  i = 0;
  while (i < trail_length)
  {
    struct TrailPeerList *element;
    element = GNUNET_malloc (sizeof (struct TrailPeerList));
    element->next = NULL;
    element->prev = NULL;
    
    memcpy (&(element->peer), &peer_list[i], sizeof(struct GNUNET_PeerIdentity));
    GNUNET_CONTAINER_DLL_insert_tail(new_finger_entry->head, new_finger_entry->tail, element);
    i++;
  }
  
  
  new_finger_entry->successor = successor_flag;
  new_finger_entry->predecessor = predecessor_flag;
  new_finger_entry->finger_map_index = finger_map_index;
  new_finger_entry->trail_length = trail_length;
  
  
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multipeermap_put (finger_peermap,
                                                    &(new_finger_entry->finger_identity),
                                                    new_finger_entry,
                                                    GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  
  /*FIXME: Is it really a good time to call verify successor message. */
  if (1 == GNUNET_CONTAINER_multipeermap_size (finger_peermap))
  {
    verify_successor = GNUNET_SCHEDULER_add_now (&send_verify_successor_message, NULL);
  }
}


/**
 * Core handle for p2p trail construction result messages.
 * @param cls closure
 * @param message message
 * @param peer peer identity this notification is about
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
static int
handle_dht_p2p_trail_setup_result(void *cls, const struct GNUNET_PeerIdentity *peer,
                    const struct GNUNET_MessageHeader *message)
{
  struct PeerTrailSetupResultMessage *trail_result;
  size_t msize;
  unsigned int trail_length;
  struct GNUNET_PeerIdentity *trail_peer_list;
  unsigned int current_trail_index;
  struct GNUNET_PeerIdentity *next_peer;
  struct FriendInfo *target_friend;
  unsigned int finger_map_index;
  unsigned int successor_flag;
  unsigned int predecessor_flag;
  
  msize = ntohs (message->size);
  if (msize < sizeof (struct PeerTrailSetupMessage))
  {
    GNUNET_break_op (0);
    return GNUNET_YES;
  }
  
  trail_result = (struct PeerTrailSetupResultMessage *) message; 
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
  
  current_trail_index = ntohl (trail_result->current_index);
  successor_flag = ntohl (trail_result->successor_flag);
  predecessor_flag = ntohl (trail_result->predecessor_flag);
  finger_map_index = ntohl (trail_result->finger_map_index);
  
  trail_peer_list = (struct GNUNET_PeerIdentity *) &trail_result[1];
  
  if (0 == (GNUNET_CRYPTO_cmp_peer_identity (&(trail_result->current_destination),
                                             &my_identity)))
  {
    if ( 0 == (GNUNET_CRYPTO_cmp_peer_identity (&(trail_result->destination_peer),
                                                &my_identity)))
    {
      #if 0
      /* SUPU: Here I have removed myself from the trail before storing it in
       th finger table - to save space, but in case of verify successor result
       the result trail does not contain me, and I will never get the message back.
       So, keeping myself in the trail list. Think of better solution.*/
      struct GNUNET_PeerIdentity *finger_trail;
      finger_trail = GNUNET_malloc (sizeof (struct GNUNET_PeerIdentity) * (trail_length - 1));
      
      /* Copy the whole trail_peer_list except the first element into trail */
      unsigned int i;
      i = trail_length - 1;
      while (i > 0)
      {
        memcpy (&finger_trail[i], &trail_peer_list[i], sizeof (struct GNUNET_PeerIdentity));
        i--;
      }
      trail_length = trail_length -1 ; SUPU: As you removed yourself from the trail.*/
      #endif
      
      finger_table_add (&(trail_result->finger), trail_peer_list, trail_length, 
                        successor_flag, predecessor_flag,
                        finger_map_index);
      
      return GNUNET_YES;
    }
    else
    {
      next_peer = GNUNET_malloc (sizeof (struct GNUNET_PeerIdentity));
      memcpy (next_peer, &(trail_peer_list[current_trail_index]), 
              sizeof (struct GNUNET_PeerIdentity));
      /* SUPU: here current trail index will always be greater than 0.
       so no need for this check here. trail index = 0, contains the final
       destination, and if we are in this loop we have not yet reached the
       final destination. */
      current_trail_index = current_trail_index - 1;
      
      target_friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, next_peer);
      GNUNET_free (next_peer);
      
      GDS_NEIGHBOURS_handle_trail_setup_result (&(trail_result->destination_peer),
                                                &(trail_result->finger),
                                                target_friend, trail_length,
                                                trail_peer_list,current_trail_index,
                                                trail_result->successor_flag,
                                                trail_result->predecessor_flag,
                                                finger_map_index);
      return GNUNET_YES;
    }
  }
  else
    return GNUNET_SYSERR;
}


/**
 * SUPU: In this function you don't do anything with trail length
 * You increment the current trail index so that you find the correct
 * peer to send the packet forward.
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
  size_t msize;
  unsigned int trail_length;
  struct GNUNET_PeerIdentity *trail_peer_list;
  unsigned int current_trail_index;
  struct FriendInfo *target_friend;
  struct GNUNET_PeerIdentity *next_hop;
   
  msize = ntohs (message->size);
  if (msize < sizeof (struct PeerVerifySuccessorMessage))
  {
    GNUNET_break_op (0);
    return GNUNET_YES;
  }
  
  vsm = (struct PeerVerifySuccessorMessage *) message;
  trail_length = ntohl (vsm->trail_length);
  
  if ((msize <
       sizeof (struct PeerVerifySuccessorMessage) +
       trail_length * sizeof (struct GNUNET_PeerIdentity)) ||
       (trail_length >
       GNUNET_SERVER_MAX_MESSAGE_SIZE / sizeof (struct GNUNET_PeerIdentity)))
       {
         GNUNET_break_op (0);
         return GNUNET_YES;
       }
  
  current_trail_index = ntohl (vsm->current_trail_index);
          
  trail_peer_list = (struct GNUNET_PeerIdentity *) &vsm[1];
  
  next_hop = GNUNET_malloc (sizeof (struct GNUNET_PeerIdentity));
  
  if(0 == (GNUNET_CRYPTO_cmp_peer_identity (&(vsm->successor),
                                            &my_identity)))
  {
    /* I am the successor, check who is my predecessor. If my predecessor is not
      same as source peer then update the trail and send back to calling function. 
    */
    struct GNUNET_CONTAINER_MultiPeerMapIterator *finger_iter;
    struct GNUNET_PeerIdentity key_ret;
    unsigned int finger_index;
    struct FingerInfo *my_predecessor;
    struct GNUNET_PeerIdentity *destination_peer;
 
    /* Iterate over finger peer map and extract your predecessor. */
    finger_iter = GNUNET_CONTAINER_multipeermap_iterator_create (finger_peermap);  
    for (finger_index = 0; finger_index < GNUNET_CONTAINER_multipeermap_size (finger_peermap); finger_index++)
    {
      if(GNUNET_YES == GNUNET_CONTAINER_multipeermap_iterator_next 
                       (finger_iter,&key_ret,(const void **)&my_predecessor)) 
      {
        if(1 == my_predecessor->predecessor)
          break; 
      }
    }

    GNUNET_CONTAINER_multipeermap_iterator_destroy (finger_iter);
    destination_peer = GNUNET_malloc (sizeof (struct GNUNET_PeerIdentity));
    memcpy (destination_peer, &(vsm->source_peer), sizeof (struct GNUNET_PeerIdentity));
    current_trail_index = trail_length - 2; /*SUPU: I am the last element in the trail.*/
    memcpy (next_hop, &trail_peer_list[current_trail_index], sizeof (struct GNUNET_PeerIdentity));
    target_friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, next_hop);
    GNUNET_free (next_hop);
    
    if (current_trail_index != 0)
    current_trail_index = current_trail_index - 1;
    
    /* FIXME: Here we should check if our predecessor is source peer or not. 
     If not then, we can send an updated trail that goes through us. Instead of
     looking for a new trail to reach to the new successor, source peer
     can just use this trail. It may not be an optimal route. */
    if (0 != (GNUNET_CRYPTO_cmp_peer_identity (&(vsm->source_peer),
                                               &(my_predecessor->finger_identity))))
    {
      /*If we have a new predecessor, then create a new trail to reach from 
       vsm source peer to this new successor of source peer. */
      struct GNUNET_PeerIdentity *new_successor_trail;
      unsigned int my_predecessor_trail_length;
      unsigned int new_trail_length;
      unsigned int i;
     
      /* SUPU: The trail that we store corresponding to each finger contains
       * me as the first element. So, we are included twice when we join the
       * two trails. */
      my_predecessor_trail_length = (my_predecessor->trail_length) - 1; /*SUPU: Removing myself from the trail */
      new_trail_length = trail_length + my_predecessor_trail_length;
      
      new_successor_trail = GNUNET_malloc (sizeof (struct GNUNET_PeerIdentity)
                                           * new_trail_length);
      memcpy (new_successor_trail, trail_peer_list, 
              trail_length * sizeof (struct GNUNET_PeerIdentity));
      
      struct TrailPeerList *iterator;
      iterator = my_predecessor->head->next; /* FIXME: Check if you are removing yourself */
      i = trail_length;
      while (i < new_trail_length)
      {
        memcpy (&new_successor_trail[i], &(iterator->peer), sizeof (struct GNUNET_PeerIdentity));
        iterator = iterator->next;
        i++;
      }
      
      
      GDS_NEIGHBOURS_handle_verify_successor_result (destination_peer,
                                                     &(my_identity),
                                                     &(my_predecessor->finger_identity),
                                                     target_friend,
                                                     new_successor_trail,
                                                     new_trail_length,
                                                     current_trail_index); 
    }
    
    GDS_NEIGHBOURS_handle_verify_successor_result (destination_peer,
                                                   &(my_identity),
                                                   &(my_predecessor->finger_identity),
                                                   target_friend,
                                                   trail_peer_list,
                                                   trail_length,
                                                   current_trail_index);      
   
  }
  else
  {
    memcpy (next_hop, &trail_peer_list[current_trail_index], sizeof (struct GNUNET_PeerIdentity));
    target_friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, next_hop);
    GNUNET_free (next_hop);
    
    current_trail_index = current_trail_index + 1; 
    
    GDS_NEIGHBOURS_handle_verify_successor(&(vsm->source_peer),
                                           &(vsm->successor),
                                           target_friend,
                                           trail_peer_list,
                                           trail_length,
                                           current_trail_index); 
  }
  return GNUNET_YES;
}


/**
 * Update successor field in finger table with new successor.
 * @param successor New successor which is the predecessor my old successor.
 * @param peer_list Trail list to reach to new successor = trail to reach old
 *                  successor + trail to reach to new successor from that old successor. 
 * @param trail_length Number of peers to reach to the new successor.
 */
static void
update_successor (struct GNUNET_PeerIdentity *successor_identity,
                  struct GNUNET_PeerIdentity *peer_list,
                  unsigned int trail_length)
{
  struct FingerInfo *new_finger_entry;
  unsigned int i;
  
  new_finger_entry = GNUNET_malloc (sizeof (struct FingerInfo));
  new_finger_entry->predecessor = 0;
  new_finger_entry->successor = 1;
  new_finger_entry->trail_length = trail_length;
  new_finger_entry->finger_map_index = 0;
  memcpy (&(new_finger_entry->finger_identity), successor_identity, sizeof (struct GNUNET_PeerIdentity));
  
  i = 0;
  while (i < trail_length)
  {
    struct TrailPeerList *element;
    element = GNUNET_malloc (sizeof (struct TrailPeerList));
    element->next = NULL;
    element->prev = NULL;
    
    memcpy (&(element->peer), &peer_list[i], sizeof(struct GNUNET_PeerIdentity));
    GNUNET_CONTAINER_DLL_insert_tail(new_finger_entry->head, new_finger_entry->tail, element);
    i++;
  }
}


/**
 * FIXME: Also copy the trail list in reverse direction that is the path to
 * reach to your predecessor. 
 * Replace your predecessor with new predecessor.
 * @param predecessor My new predecessor
 * @param peer_list Trail list to reach to my new predecessor
 * @param trail_length Number of peers in the trail.
 */
static void
update_predecessor (struct GNUNET_PeerIdentity *predecessor,
                    struct GNUNET_PeerIdentity *peer_list,
                    unsigned int trail_length)
{
  struct GNUNET_PeerIdentity *trail_peer_list;
  struct FingerInfo *new_finger_entry;
  unsigned int i;
  unsigned int j;
  
  i = trail_length - 1;
  j = 0;
  trail_peer_list = GNUNET_malloc (sizeof (struct GNUNET_PeerIdentity) * 
                                   trail_length);
  while (i > 0)
  {
    memcpy( &trail_peer_list[j], &peer_list[i], sizeof (struct GNUNET_PeerIdentity));
    i--;
    j++;
  }
  memcpy (&trail_peer_list[j], &peer_list[i], sizeof(struct GNUNET_PeerIdentity));
  
  new_finger_entry = GNUNET_malloc (sizeof (struct FingerInfo));
  memcpy (&(new_finger_entry->finger_identity), predecessor, sizeof (struct GNUNET_PeerIdentity));
  new_finger_entry->finger_map_index = 1;
  new_finger_entry->predecessor = 1;
  new_finger_entry->successor = 0;
  
  i = 0;
  while (i < trail_length)
  {
    struct TrailPeerList *element;
    element = GNUNET_malloc (sizeof (struct TrailPeerList));
    element->next = NULL;
    element->prev = NULL;
    
    memcpy (&(element->peer), &trail_peer_list[i], sizeof(struct GNUNET_PeerIdentity));
    GNUNET_CONTAINER_DLL_insert_tail(new_finger_entry->head, new_finger_entry->tail, element);
    i++;
  }
}


/**
 * Core handle for p2p notify new successor messages.
 * @param cls closure
 * @param message message
 * @param peer peer identity this notification is about
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
static int
handle_dht_p2p_notify_new_successor(void *cls, const struct GNUNET_PeerIdentity *peer,
                                    const struct GNUNET_MessageHeader *message)
{
  struct PeerNotifyNewSuccessorMessage *nsm;
  size_t msize;
  unsigned int trail_length;
  struct GNUNET_PeerIdentity *trail_peer_list;
  unsigned int current_trail_index;
 
  msize = ntohs (message->size);
  if (msize < sizeof (struct PeerNotifyNewSuccessorMessage))
  {
    GNUNET_break_op (0);
    return GNUNET_YES;
  }
  
  /* Again in the function you have the whole trail to reach to the destination. */
  nsm = (struct PeerNotifyNewSuccessorMessage *) message;
  trail_length = ntohl (nsm->trail_length);
  
  if ((msize <
       sizeof (struct PeerNotifyNewSuccessorMessage) +
       trail_length * sizeof (struct GNUNET_PeerIdentity)) ||
       (trail_length >
       GNUNET_SERVER_MAX_MESSAGE_SIZE / sizeof (struct GNUNET_PeerIdentity)))
  {
    GNUNET_break_op (0);
    return GNUNET_YES;
  }
  
  current_trail_index = ntohl (nsm->current_index);
  trail_peer_list = (struct GNUNET_PeerIdentity *) &nsm[1];
  
  if(0 == (GNUNET_CRYPTO_cmp_peer_identity (&(nsm->destination_peer),
                                             &my_identity)))
  {
    update_predecessor (&(nsm->source_peer),
                        trail_peer_list,
                        trail_length);
    return GNUNET_YES;
  }
  else
  {
    struct FriendInfo *target_friend;
    target_friend = GNUNET_malloc (sizeof (struct FriendInfo));
    struct GNUNET_PeerIdentity *next_hop;
    next_hop = GNUNET_malloc (sizeof (struct GNUNET_PeerIdentity));
    memcpy (next_hop, &trail_peer_list[current_trail_index], sizeof (struct GNUNET_PeerIdentity)); 
    target_friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, next_hop);
    GNUNET_free (next_hop);
    current_trail_index = current_trail_index + 1;
    
    GDS_NEIGHBOURS_notify_new_successor (&(nsm->source_peer), 
                                         &(nsm->destination_peer),
                                         target_friend, trail_peer_list, trail_length, 
                                         current_trail_index);
  }
  return GNUNET_YES;
}


/**
 * Core handle for p2p verify successor result messages.
 * @param cls closure
 * @param message message
 * @param peer peer identity this notification is about
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
static int
handle_dht_p2p_verify_successor_result(void *cls, const struct GNUNET_PeerIdentity *peer,
                                       const struct GNUNET_MessageHeader *message)
{
  struct PeerVerifySuccessorResultMessage *vsrm;
  size_t msize;
  struct FriendInfo *target_friend;
  unsigned int current_trail_index;
  struct GNUNET_PeerIdentity *trail_peer_list;
  struct GNUNET_PeerIdentity *next_hop;
  unsigned int trail_length;
  
  msize = ntohs (message->size);
  if (msize < sizeof (struct PeerVerifySuccessorResultMessage))
  {
    GNUNET_break_op (0);
    return GNUNET_YES;
  }
 
  /* Again in the function you have the whole trail to reach to the destination. */
  vsrm = (struct PeerVerifySuccessorResultMessage *) message;
  current_trail_index = ntohl (vsrm->current_index);
  trail_length = ntohl (vsrm->trail_length); 

  trail_peer_list = (struct GNUNET_PeerIdentity *) &vsrm[1];
  
  if ((msize <
       sizeof (struct PeerVerifySuccessorResultMessage) +
       trail_length * sizeof (struct GNUNET_PeerIdentity)) ||
       (trail_length >
       GNUNET_SERVER_MAX_MESSAGE_SIZE / sizeof (struct GNUNET_PeerIdentity)))
  {
    GNUNET_break_op (0);
    return GNUNET_YES;
  }
  
  if(0 == (GNUNET_CRYPTO_cmp_peer_identity (&(vsrm->destination_peer),
                                            &(my_identity))))
  {
    if(0 != (GNUNET_CRYPTO_cmp_peer_identity (&(vsrm->my_predecessor),
                                              &(my_identity))))
    {
      update_successor (&(vsrm->my_predecessor), trail_peer_list, trail_length);
      
      next_hop = GNUNET_malloc (sizeof (struct GNUNET_PeerIdentity));
      /* FIXME: Assuming that I am also in trail list and I am the first peer. */
      memcpy (next_hop, &trail_peer_list[1], sizeof (struct GNUNET_PeerIdentity));
      target_friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, next_hop);
      GNUNET_free (next_hop);
      
      GDS_NEIGHBOURS_notify_new_successor (&my_identity, &(vsrm->my_predecessor),
                                           target_friend, trail_peer_list,
                                           trail_length, current_trail_index);
    }
  }
  else
  {
    /* Read the peer trail list and find out the next destination to forward this
     packet to. */
    next_hop = GNUNET_malloc (sizeof (struct GNUNET_PeerIdentity));
    
    /* FIXME: Assuming that I am also in trail list and I am the first peer. */
    memcpy (next_hop, &trail_peer_list[current_trail_index], sizeof (struct GNUNET_PeerIdentity));
    target_friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, next_hop);
    GNUNET_free (next_hop);
    current_trail_index = current_trail_index - 1;
    
    GDS_NEIGHBOURS_handle_verify_successor_result (&(vsrm->destination_peer),
                                                   &(vsrm->source_successor),
                                                   &(vsrm->my_predecessor),
                                                   target_friend,
                                                   trail_peer_list,
                                                   trail_length,
                                                   current_trail_index); 
  }
  return GNUNET_YES;
}


/**
 * Initialize neighbours subsystem.
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GDS_NEIGHBOURS_init()
{
  static struct GNUNET_CORE_MessageHandler core_handlers[] = {
    {&handle_dht_p2p_get, GNUNET_MESSAGE_TYPE_DHT_P2P_GET, 0},
    {&handle_dht_p2p_put, GNUNET_MESSAGE_TYPE_DHT_P2P_PUT, 0},
    {&handle_dht_p2p_trail_setup, GNUNET_MESSAGE_TYPE_DHT_P2P_TRAIL_SETUP, 0},
    {&handle_dht_p2p_trail_setup_result, GNUNET_MESSAGE_TYPE_DHT_P2P_TRAIL_SETUP_RESULT, 0},
    {&handle_dht_p2p_verify_successor, GNUNET_MESSAGE_TYPE_DHT_P2P_VERIFY_SUCCESSOR, 0},
    {&handle_dht_p2p_verify_successor_result, GNUNET_MESSAGE_TYPE_DHT_P2P_VERIFY_SUCCESSOR_RESULT, 0},
    {&handle_dht_p2p_notify_new_successor, GNUNET_MESSAGE_TYPE_DHT_P2P_NOTIFY_NEW_SUCCESSOR, 0},
    {NULL, 0, 0}
  };


  /*TODO: What is ATS? Why do we need it? */
  atsAPI = GNUNET_ATS_performance_init (GDS_cfg, NULL, NULL);
  core_api =
    GNUNET_CORE_connect (GDS_cfg, NULL, &core_init, &handle_core_connect,
                         &handle_core_disconnect, NULL, GNUNET_NO, NULL,
                         GNUNET_NO, core_handlers);
  if (NULL == core_api)
    return GNUNET_SYSERR;

  friend_peermap = GNUNET_CONTAINER_multipeermap_create (256, GNUNET_NO);
  finger_peermap = GNUNET_CONTAINER_multipeermap_create (MAX_FINGERS, GNUNET_NO); 
 
  return GNUNET_OK;
}


/**
 * Shutdown neighbours subsystem.
 */
void
GDS_NEIGHBOURS_done ()
{
  if (NULL == core_api)
    return;
  
  GNUNET_CORE_disconnect (core_api);
  core_api = NULL;
  GNUNET_ATS_performance_done (atsAPI);
  atsAPI = NULL;

  /* FIXME: In case of friends, every time we are disconnected from a friend
   we remove it from friend table. So, this assertion works for friend.
   But in case of finger_peermap, we never remove any entry from our
   finger peermap. So, either when we remove the friend from friend peermap,then
   I remove all the finger for which that friend was the first trail and leave
   it on send_find_finger_trail to eventually find path to that finger. In that
   case may be assertion for finger peermap will also succed. Or else if 
   peermap are not empty check it and empty it and then destroy because
   multipeermpa_destroy does not free individual entries. */
  GNUNET_assert (0 == GNUNET_CONTAINER_multipeermap_size (friend_peermap));
  GNUNET_CONTAINER_multipeermap_destroy (friend_peermap);
  friend_peermap = NULL;

  GNUNET_assert (0 == GNUNET_CONTAINER_multipeermap_size (finger_peermap));
  GNUNET_CONTAINER_multipeermap_destroy (finger_peermap);
  finger_peermap = NULL;

  if (GNUNET_SCHEDULER_NO_TASK != find_finger_trail_task)
  {
    GNUNET_SCHEDULER_cancel (find_finger_trail_task);
    find_finger_trail_task = GNUNET_SCHEDULER_NO_TASK;
  }
 
  if (GNUNET_SCHEDULER_NO_TASK != verify_successor)
  {
    GNUNET_SCHEDULER_cancel (verify_successor);
    verify_successor = GNUNET_SCHEDULER_NO_TASK;
  }
  
}


/**
 * Get the ID of the local node.
 *
 * @return identity of the local node
 */
struct GNUNET_PeerIdentity *
GDS_NEIGHBOURS_get_id ()
{
  return &my_identity;
}


/* end of gnunet-service-xdht_neighbours.c */