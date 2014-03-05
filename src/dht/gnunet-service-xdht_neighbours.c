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


/* FIXME:
 *SUPU: Lets assume that while adding entries in the multipeermap
     we are adding it in sorted way. 
 1. Add content and route replication later. 
 *2. Algorithm to shorten the trail length - one possible solution could be
 * when we are in trail seutp result part. each peer in the trail check if any of
 * the corresponding peers is its friend list. Then it can shortcut the path.
 * But this will have O(n) run time at each peer, where n = trail_length.\
 * or rather O(n)+O(n-1)+..O(1) =O(n). 
 * 3. Add a new field finger index to keep track of which finger respongs to which
 * entry. 
 * 4. As we start looking for finger from i = 0, using this parameter to 
 * generate random value does not look smart in send_find_finger_trail_message. 
 * 5. Need to store the interval in finger and friend table which will be used
 * to find the correct successor.
 * 6. Need to add a new task, fix fingers. For node join/leave, we need to 
 * upgrade our finger table periodically. So, we should call fix_fingers 
 * and change our finger table. 
 * 7. Should we look for fingers one by one in send_find_finger_trail_setup
 * 8. Change the message is gnunet_protocols.h 
 */


/**
 * Maximum possible fingers of a peer.
 * FIXME: Should it be 64 as we are doing all the operation on 64 bit numbers now? 
 */
#define MAX_FINGERS 64

/**
 * Maximum allowed number of pending messages per friend peer.
 */
#define MAXIMUM_PENDING_PER_FRIEND 64

/**
 * How long at least to wait before sending another find finger trail request.
 */
#define DHT_MINIMUM_FIND_FINGER_TRAIL_INTERVAL GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 30)

/**
 * How long at most to wait before sending another find finger trail request.
 */
#define DHT_MAXIMUM_FIND_FINGER_TRAIL_INTERVAL GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MINUTES, 10)

/**
 * FIXME: Currently used in GDS_NEIGHBOURS_handle_trail_setup.
 * I have just copied it from gnunet-service-dht_neighbours. Will it work here? 
 * How long at most to wait for transmission of a GET request to another peer?
 */
#define GET_TIMEOUT GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MINUTES, 2)

GNUNET_NETWORK_STRUCT_BEGIN

/* FIXME:
 * 1) Bloomfilter is not required for X-Vine.
 * Keep the field now but remove it when implementing PUT/GET.
 * 2) also, check the field of put/get/result if all are required for
 * x-vine or not. */
  
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
 * A destination can be either a friend or finger.
 */
enum current_destination_type
{
  /* Friend */
  FRIEND ,
  
  /* Finger */
  FINGER ,

  /* My own identity */
  MY_ID        
};

/**
 * P2P Trail setup message
 * TODO: Take reference from put_path and get_path to understand how to use size of trail list.  
 */
struct PeerTrailSetupMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_DHT_P2P_TRAIL_SETUP
   */
  struct GNUNET_MessageHeader header;

  /**
   * Source peer which wants to find trail to one of its finger. 
   */
  struct GNUNET_PeerIdentity source_peer;

  /**
   * As we are not sending any hello messages to this destination
   * finger, we are only searching for it, we can just send 64 bit. 
   * Finger id to which we want to set up the trail to. 
   *
  struct GNUNET_PeerIdentity destination_finger; */

  /**
   * Finger id to which we want to set up the trail to. 
   */
  uint64_t destination_finger;
  
  /**
   * If the message is forwarded to finger or friend. 
   */
  enum current_destination_type current_destination_type;
  
  /**
   * This field contains the peer to which this packet is forwarded.
   */
  struct GNUNET_PeerIdentity current_destination;
 
  /**
   * Number of entries in trail list.
   * FIXME: Is this data type correct?
   * FIMXE: Is usage of GNUNET_PACKED correct?
   */
  uint32_t trail_length GNUNET_PACKED;
  
  /* FIXME: Add this field later. 
   * The finger index in finger map. 
  unsigned int finger_index;*/
  
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
   * This field contains the peer to which this packet is forwarded.
   */
  struct GNUNET_PeerIdentity current_destination;
  
  /**
   * FIXME: Temporary field used to remember at which index we should read
   * to get our next peer. 
   */
  unsigned int current_index;
  
  /**
   * Number of entries in trail list.
   * FIXME: Is this data type correct?
   * FIXME: Is usage of GNUNET_PACKED correct?
   */
  uint32_t trail_length GNUNET_PACKED;
  
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
   * What is the identity of the peer?
   */
  struct GNUNET_PeerIdentity id;

  /**
   * Count of outstanding messages for peer.
   */
  unsigned int pending_count;

  /**
   * Start of interval friend[i].start
   */
  uint64_t interval_start;
  
  /**
   * Start of interval friend[i+1].start
   */
  uint64_t interval_end;
  
  /**
   * Successor of this finger.
   */
  struct GNUNET_PeerIdentity successor_identity;
  
  /**
   * Predecessor of this finger.
   */
  struct GNUNET_PeerIdentity predecessor_identity;
  
  /**
   * Head of pending messages to be sent to this peer.
   */
 struct P2PPendingMessage *head;

 /**
  * Tail of pending messages to be sent to this peer.
  */
 struct P2PPendingMessage *tail;
 
 /**
  * TODO - How and where to use this?
  * Core handle for sending messages to this peer.
  */
 struct GNUNET_CORE_TransmitHandle *th;

};


/**
 * FIXME: Should we use another PeerIdentity which is smaller
 * than 256 bits while storing. 
 * SUPU
 * finger_identity is the actual finger that we were looking for.
 * successor is the peer id which is our finger in place of finger_identity
 * that we were actually looking for. It may happen that finger_identity
 * was not in the network and we found the successor closest to that
 * finger_identity.
 * Predcessor is needed in case of node join/fail. 
 * Entry in finger_peermap.
 */
struct FingerInfo
{
  /**
   * Index in finger_peermap.
   */
  unsigned int index;
  
  /**
   * Finger identity.
   */
  struct GNUNET_PeerIdentity finger_identity;
  
  /**
   * Start of interval finger[i].start 
   */
  uint64_t interval_start;
  
  /**
   * Start of interval finger[i+1].start 
   */
  uint64_t interval_end;
  
  /**
   * Successor of this finger.
   */
  struct GNUNET_PeerIdentity successor_identity;
  
  /**
   * Predecessor of this finger.
   */
  struct GNUNET_PeerIdentity predecessor_identity;
  
  /**
   * List of peers in the trail.
   */
  const struct GNUNET_PeerIdentity *trail_peer_list;
};

/**
 * Task that sends FIND FINGER TRAIL requests.
 */
static GNUNET_SCHEDULER_TaskIdentifier find_finger_trail_task;

/**
 * FIXME: As we should check for our immediate successor
 * in case of node join/fail, the immediate successor will change. 
 * Hence we define a process which will be scheduled in regular interval.
 * But you should schedule this process once you have found your successor.
 * so, in finger_table_add_entry, when finger_peermap is size 1 then start
 * this task, and periodically call it within it self like find_finger_trail_setup
 * 
 * Task that periodically checks for the immediate successor. 
 */
static GNUNET_SCHEDULER_TaskIdentifier verify_immediate_successor;

/**
 * Identity of this peer.
 */
static struct GNUNET_PeerIdentity my_identity;

/**
 * FIXME: Not used anywhere in the code yet. 
 * Hash of the identity of this peer.
 */
static struct GNUNET_HashCode my_identity_hash;

/**
 * Hash map of all the friends of a peer
 */
static struct GNUNET_CONTAINER_MultiPeerMap *friend_peermap;

/**
 * Hash map of all the fingers of a peer
 */
static struct GNUNET_CONTAINER_MultiPeerMap *finger_peermap;

/**
 * TODO: Ask whats the use of ATS.
 * Handle to ATS.
 */
static struct GNUNET_ATS_PerformanceHandle *atsAPI;

/**
 * Handle to CORE.
 */
static struct GNUNET_CORE_Handle *core_api;

/**
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
 * SUPU:
 * We add the next destination i.e. friend to which we are sending the packet
 * to our peer list in the calling function and we also increment trail_length
 * in calling function i.e. send_find_finger_trail and handle_dht_p2p_trail_setup.
 * Here we only copy the whole trail into our peer_list. 
 * Setup the trail message and forward it to a friend. 
 * @param source_peer Peer which wants to set up the trail to one of its finger.
 * @param destination_finger Peer to which we want to set up the trail to.
 * @param current_destination Current peer to which this message should be forwarded.
 * @param trail_length Numbers of peers in the trail.
 * @param trail_peer_list peers this request has traversed so far 
 */
void
GDS_NEIGHBOURS_handle_trail_setup(struct GNUNET_PeerIdentity *source_peer,
                                  uint64_t *destination_finger,
                                  struct FriendInfo *current_destination,
                                  unsigned int trail_length,
                                  struct GNUNET_PeerIdentity *trail_peer_list)
{
  struct P2PPendingMessage *pending;
  struct PeerTrailSetupMessage *tsm;
  struct GNUNET_PeerIdentity *peer_list;
  size_t msize;
  
  msize = sizeof(struct PeerTrailSetupMessage) + 
          (trail_length * sizeof(struct GNUNET_PeerIdentity));
  
  if (msize >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    return;
  }
  
  if (current_destination->pending_count >= MAXIMUM_PENDING_PER_FRIEND)
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
  memcpy(&(tsm->destination_finger), destination_finger, sizeof (uint64_t)); //FIXME: Is this copy correct?
  memcpy(&(tsm->source_peer), source_peer, sizeof (struct GNUNET_PeerIdentity));
  memcpy(&(tsm->current_destination),&(current_destination->id), sizeof (struct GNUNET_PeerIdentity));
  tsm->current_destination_type = htonl(FRIEND); 
  tsm->trail_length = htonl(trail_length); 
  peer_list = GNUNET_malloc (sizeof (struct GNUNET_PeerIdentity) * trail_length); 
  peer_list = (struct GNUNET_PeerIdentity *) &tsm[1];
  memcpy(peer_list, trail_peer_list, trail_length * sizeof(struct GNUNET_PeerIdentity));
  
  GNUNET_CONTAINER_DLL_insert_tail (current_destination->head, current_destination->tail, pending);
  current_destination->pending_count++;
  process_friend_queue (current_destination);
  
}

/**
 * Handle a tail setup result message. 
 * @param destination_peer Peer which will get the trail to one of its finger.
 * @param source_finger Peer to which the trail has been setup to.
 * @param current_destination Current peer to which this message should be forwarded.
 * @param trail_length Numbers of peers in the trail.
 * @param trail_peer_list peers this request has traversed so far 
 * @param current_trail_index Index in trail_peer_list. 
 */
void
GDS_NEIGHBOURS_handle_trail_setup_result(struct GNUNET_PeerIdentity *destination_peer,
                                  struct GNUNET_PeerIdentity *source_finger,
                                  struct FriendInfo *current_destination,
                                  unsigned int trail_length,
                                  const struct GNUNET_PeerIdentity *trail_peer_list,
                                  unsigned int current_trial_index)
{
  struct P2PPendingMessage *pending;
  struct PeerTrailSetupResultMessage *tsrm;
  struct GNUNET_PeerIdentity *peer_list;
  size_t msize;
  
  msize = sizeof(struct PeerTrailSetupMessage) + 
          (trail_length * sizeof(struct GNUNET_PeerIdentity));
  
  if (msize >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    return;
  }
  
  if (current_destination->pending_count >= MAXIMUM_PENDING_PER_FRIEND)
  {  
    GNUNET_STATISTICS_update (GDS_stats, gettext_noop ("# P2P messages dropped due to full queue"),
				1, GNUNET_NO);
  }

  pending = GNUNET_malloc (sizeof (struct P2PPendingMessage) + msize); 
  pending->importance = 0;    /* FIXME */
  pending->timeout = GNUNET_TIME_relative_to_absolute (GET_TIMEOUT);
  tsrm = (struct PeerTrailSetupResultMessage *) &pending[1]; 
  pending->msg = &tsrm->header;
  tsrm->header.size = htons (msize);
  tsrm->header.type = htons (GNUNET_MESSAGE_TYPE_DHT_P2P_TRAIL_SETUP_RESULT);
  memcpy(&(tsrm->current_destination), &(current_destination->id), sizeof(struct GNUNET_PeerIdentity));
  memcpy(&(tsrm->destination_peer), destination_peer, sizeof(struct GNUNET_PeerIdentity));
  memcpy(&(tsrm->finger), source_finger, sizeof(struct GNUNET_PeerIdentity));
  tsrm->trail_length = htonl(trail_length);
  tsrm->current_index = htonl(current_trial_index);
  peer_list = (struct GNUNET_PeerIdentity *) &tsrm[1];
  memcpy(peer_list, trail_peer_list, trail_length * sizeof(struct GNUNET_PeerIdentity));
  
  /* Send the message to chosen friend. */
  GNUNET_CONTAINER_DLL_insert_tail (current_destination->head, current_destination->tail, pending);
  current_destination->pending_count++;
  process_friend_queue (current_destination);
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
  
  current_size = GNUNET_CONTAINER_multipeermap_size(friend_peermap);
  
  /* Element stored at this index in friend_peermap should be selected friend. */
  index = GNUNET_CRYPTO_random_permute (GNUNET_CRYPTO_QUALITY_WEAK, current_size);
  
  /* Create an iterator for friend_peermap. */
  iter = GNUNET_CONTAINER_multipeermap_iterator_create(friend_peermap);
  
  /* Set the position of iterator to index. */
  while(j < (*index))
  {
    if(GNUNET_YES == GNUNET_CONTAINER_multipeermap_iterator_next(iter,NULL,NULL))
      j++;
    else 
      return NULL;
  }  
  
  if(GNUNET_YES == GNUNET_CONTAINER_multipeermap_iterator_next(iter,&key_ret,(const void **)&friend))
  {
    return friend;
  }

  return NULL;
}


/**
 * Compute finger_identity to which we want to setup the trail
 * FIXME: If we maintain a index that is value of current_finger_index
 * to which a particular entry in finger map corresponds then should we first
 * check if there is already an entry for that index. If yes then don't
 * search for trail to that finger. 
 * @return finger_identity 
 */
static uint64_t *
compute_finger_identity()
{
  uint64_t *my_id64 ;
  uint64_t *finger_identity64;
  
  my_id64 = GNUNET_malloc (sizeof (uint64_t));
  finger_identity64 = GNUNET_malloc (sizeof (uint64_t));
  
  memcpy(my_id64, &(my_identity.public_key.q_y), sizeof (uint64_t));
  *finger_identity64 = fmod ((*my_id64 + pow (2,current_finger_index)),( (pow (2,MAX_FINGERS))));
  current_finger_index = current_finger_index + 1;
  
  return finger_identity64;
}


/**
 * TODO: Implement after testing friend/finger map.
 * TODO: Handle the case when we already have a trail to our predecessor in
 * the network. 
 * This function will be needed when we are handling node joins/fails
 * to maintain correct pointer to our predecessor and successor in the network. 
 * Find immediate predecessor in the network.
 * @param me my own identity
 * @return peer identity of immediate predecessor.
 */
static uint64_t *
find_immediate_predecessor()
{
  /* Using your own peer identity, calculate your predecessor
   * in the network. Try to setup path to this predecessor using
   * the same logic as used for other fingers. 
   * If we already have a trail to our predecessor then send NULL and 
   * calling function should be able to handle that case.
  */
  /* FIXME: O could be a valid peer id, return something else. */
  return 0;
}


/**
 * Periodically verify your own immediate successor and 
 * tell your successor about yourself. 
 * 
 * @param cls closure for this task
 * @param tc the context under which the task is running
 */
static void
stabilize(void *cls,
          const struct GNUNET_SCHEDULER_TaskContext *tc )
{
  /* 
   * FIXME:
   * Should we have a new message type
   * 1. like who is your predecessor.
   * 2. notify
   In this function
   1. ask your immediate successor ( its stored in your finger table with 
   field that notes that its immediate successor) who is its predecessor.
   2. Then after getting the reply, check if its you.
   3. If not then update the new successor and your successor
   and notify the new successor that you are its new predecessor.
   */
  struct GNUNET_TIME_Relative next_send_time;

  next_send_time.rel_value_us =
      DHT_MINIMUM_FIND_FINGER_TRAIL_INTERVAL.rel_value_us +
      GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_WEAK,
                                DHT_MAXIMUM_FIND_FINGER_TRAIL_INTERVAL.rel_value_us /
                                (current_finger_index + 1));
 
  verify_immediate_successor =
      GNUNET_SCHEDULER_add_delayed (next_send_time, &stabilize,
                                    NULL);
}


/**
 * Task to send a find finger trail message. We attempt to find trail
 * to our finger and successor in the network.
 *
 * @param cls closure for this task
 * @param tc the context under which the task is running
 */
static void
send_find_finger_trail_message (void *cls,
                        const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct FriendInfo *friend;
  struct GNUNET_TIME_Relative next_send_time;
  uint64_t *finger_identity; /* FIXME: Better variable name */ 
  struct GNUNET_PeerIdentity *peer_list;
  
  /* We already have found trail to each of our possible fingers in the network. */
  if (GNUNET_CONTAINER_multipeermap_size (finger_peermap) == MAX_FINGERS)
  {
    /* FIXME: I call find_immediate_predecessor when I have found trail to 
     * all the possible fingers in the network. But we need to find immediate
     * predecessor when there is a node failure/join. It may happen before.
     * Think of a better strategy to decide when to call this function. 
     * We can find trail to our immediate predecessor in the network.
     * I think its better to call this after we have trail to our successor set up.
     */  
    finger_identity = find_immediate_predecessor();  
    
    if(NULL == finger_identity)
    {
      /* We already have a trail to reach to immediate predecessor. */
      goto new_find_finger_trail_request;
    }
  }
  else
  {
    finger_identity = compute_finger_identity();
   
    if(finger_identity == NULL)
    {
      goto new_find_finger_trail_request;
    }
  }
  
  friend = GNUNET_malloc (sizeof (struct FriendInfo));
  friend = select_random_friend();
 
  /* We found a friend.*/
  if(NULL != friend)
  { 
    /* SUPU: Verify if its correct or not.  */
    unsigned int trail_length = 2;
    peer_list = GNUNET_malloc (sizeof (struct GNUNET_PeerIdentity) * trail_length);
    memcpy(&peer_list[0], &(my_identity), sizeof (struct GNUNET_PeerIdentity)); 
    memcpy(&peer_list[1], &(friend->id), sizeof (struct GNUNET_PeerIdentity)); 
    GDS_NEIGHBOURS_handle_trail_setup(&my_identity, finger_identity, 
                                      friend, trail_length, peer_list);
  }
  
  /* FIXME: Should we be using current_finger_index to generate random interval.*/
  new_find_finger_trail_request:
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
 * @param peer peer identity this notification is about
 */
static void
handle_core_connect (void *cls, const struct GNUNET_PeerIdentity *peer)
{
  struct FriendInfo *ret;
  
  /* Check for connect to self message */
  if (0 == memcmp (&my_identity, peer, sizeof (struct GNUNET_PeerIdentity)))
    return;
  
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Connected to %s\n",
              GNUNET_i2s (peer));
  
  /* If peer already exists in our friend_peermap, then exit. */
  if (GNUNET_YES ==
      GNUNET_CONTAINER_multipeermap_contains (friend_peermap,
                                              peer))
  {
    GNUNET_break (0);
    return;
  }

  GNUNET_STATISTICS_update (GDS_stats, gettext_noop ("# peers connected"), 1,
                            GNUNET_NO);

  /* FIXME: Whenever you add an entry into your finger peermap,
   first add everything in sorted way and interval field should also
   be updated. */
  ret = GNUNET_new (struct FriendInfo);
  ret->id = *peer;

  
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multipeermap_put (friend_peermap,
                                                    peer, ret,
                                                    GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));

  
  /* got a first connection, good time to start with FIND FINGER TRAIL requests... */
  if (1 == GNUNET_CONTAINER_multipeermap_size (friend_peermap))
    find_finger_trail_task = GNUNET_SCHEDULER_add_now (&send_find_finger_trail_message, NULL);
}


/**
 * FIXME: Implement after testing finger/friend table setup.
 * Method called whenever a peer disconnects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 */
static void
handle_core_disconnect (void *cls,
			const struct GNUNET_PeerIdentity *peer)
{
  /**
   * 1. remove the friend from the friend map.
   * 2. remove the trail for the fingers for which this peer was the first hop.
   * 3. start send_find_finger_trail for these fingers to find a new trail 
   * in the network.
   * 4. Also when a node gets disconnected, how should we update pointers of its
   * immediate successor and predecessor in the network ?
   * 5. Also how do we distribute the keys in the network?
   * 6. Here is case where we started put operation but a peer got disconnected and 
      we removed the entry from the table. How to handle such a case. 
   */
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
  GNUNET_CRYPTO_hash (identity,
		      sizeof (struct GNUNET_PeerIdentity),
		      &my_identity_hash);
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
 * FIXME: Use some optimal way to do the operations.
 * FIXME: Check if this function can be used as such for put/get
 * 1.assumption that when ever we insert a value into friend or
 * finger map, we sort it and also update the interval correctly,
 * 2. all the comparison are done on 64 bit values. so in last part when 
 * you compare finger , friend and your own identity then also you need to 
 * have the values in 64 bit format and get the correct successor. 
 * At this point the algorithm does not look very smart. 
 * Finds successor of the identifier 
 * @param id Identifier for which we are trying to find the successor
 * @return 
 */
static struct GNUNET_PeerIdentity *
find_successor(uint64_t id, 
               struct GNUNET_PeerIdentity *current_destination,
               enum current_destination_type *type)
{
  /* 1. Iterate over friend map and find the closest peer.
     2. Iterate over finger map and find the closest peer.
     3. Sort my_identity, friend successor and finger successor.
     4. Choose the closest peer among the three. 
  */
  struct GNUNET_CONTAINER_MultiPeerMapIterator *friend_iter;
  struct GNUNET_CONTAINER_MultiPeerMapIterator *finger_iter;
  struct FriendInfo *friend;
  struct FingerInfo *finger;
  struct GNUNET_PeerIdentity key_ret;
  unsigned int finger_index;
  unsigned int friend_index;
  struct FriendInfo *successor_friend;
  struct FingerInfo *successor_finger;
  uint64_t friend_id;
  uint64_t finger_id;
  uint64_t my_id;
  
  successor_friend = GNUNET_malloc (sizeof (struct FriendInfo ));
  successor_finger = GNUNET_malloc (sizeof (struct FingerInfo ));
  
  /* Iterate over friend map. */
  friend_iter = GNUNET_CONTAINER_multipeermap_iterator_create (friend_peermap); 
  for (friend_index = 0; friend_index < GNUNET_CONTAINER_multipeermap_size (friend_peermap); friend_index++)
  {
    /* SUPU: check if you are using iterator_next correctly */
    if(GNUNET_YES == GNUNET_CONTAINER_multipeermap_iterator_next(friend_iter,&key_ret,(const void **)&friend)) 
    {
      if(((friend->interval_start <= id) && (id < friend->interval_end))
         || (((friend->interval_start) > (friend->interval_end)) 
             && ((friend->interval_start <= id) && (id < friend->interval_end))))
      {
        /* SUPU: Here I am copying friend into successor_friend as when among 
         three ids i.e. friend, finger and my_id, one is chosen then I should
         be able to identify which one was chosen. */
        memcpy(successor_friend, friend, sizeof (struct FriendInfo)); 
        break; /*FIXME: Will it come out of outer for loop */
      }
    }
  }
  
  finger_iter = GNUNET_CONTAINER_multipeermap_iterator_create (finger_peermap);  
  /* iterate over finger map till you reach a peer id such that destination <= peer id */ 
  for (finger_index = 0; finger_index < GNUNET_CONTAINER_multipeermap_size (finger_peermap); finger_index++)
  {
    if(GNUNET_YES == GNUNET_CONTAINER_multipeermap_iterator_next(finger_iter,&key_ret,(const void **)&finger)) 
    {
      if(((finger->interval_start <= id) && (id < finger->interval_end))
         || (((finger->interval_start) > (finger->interval_end)) 
             && ((finger->interval_start <= id) && (id < finger->interval_end))))
      {
        memcpy(successor_finger, finger, sizeof (struct FingerInfo)); 
        break; /*FIXME: Will it come out of outer for loop */
      }
    }
  }
  
  /* Here you have two values from friend and finger map. 
     Now sort the my_identity, friend and finger and
     choose the closest peer. Also update the closest successor type
     correctly to finger/friend/me. and update the current_destination value. */
  memcpy (&my_id, &(my_identity.public_key.q_y), sizeof (uint64_t));
  memcpy (&friend_id, (successor_friend->id.public_key.q_y), sizeof (uint64_t));
  memcpy (&finger_id, (successor_finger->finger_identity.public_key.q_y), sizeof (uint64_t));
  
  /* if finger_id is selected, then set type = FINGER, current_destination = finger
   and next_hop = first peer in trail list. 
   if friend id is selected, then set type = FRIEND, current_destination = friend
   and return friend. */
  /* You need some function to compare which three of them is successor to 
   id that we are looking for. 
   1. Sort three of them.
   2. Set up the new interval.
   3. Check in which interval id lies. 
   * You should set the type proprly. Need to add a new type to handle
   * my_idenity.
   This is very suboptimal.
   Once you found the correct successor you should just return the 
   correct PeerIdentity.
   so basic logic is:
   lets say that 
   my_id = 3 [3,5)
   friend_id = 5 [5,7)
   finger_id = 7 [7,3)
   and we are looking for 1.  */
  return &(successor_friend->id); /* FIXME: remove this, added just to remove 
                            * warning */
}


/**
 * Handle a P2PTrailSetupMessage. 
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
  struct GNUNET_PeerIdentity *next_peer;

  
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
  trail_peer_list = (struct GNUNET_PeerIdentity *) &trail_setup[1];
  
  if ((msize <
       sizeof (struct PeerTrailSetupMessage) +
       trail_length * sizeof (struct GNUNET_PeerIdentity)) ||
      (trail_length >
       GNUNET_SERVER_MAX_MESSAGE_SIZE / sizeof (struct GNUNET_PeerIdentity)))
  {
    GNUNET_break_op (0);
    return GNUNET_YES; /*TODO: Why do we send GNUNET_YES here? */
  }
 
  
  GNUNET_STATISTICS_update (GDS_stats,
                            gettext_noop ("# TRAIL SETUP requests received"), 1,
                            GNUNET_NO);
  GNUNET_STATISTICS_update (GDS_stats,
                            gettext_noop ("# TRAIL SETUP bytes received"), msize,
                            GNUNET_NO);
  
  if(peer_type == FRIEND)
  {
    if(0 == (GNUNET_CRYPTO_cmp_peer_identity(&(trail_setup->current_destination),&my_identity)))
    {
      next_hop = find_successor((trail_setup->destination_finger),&(trail_setup->current_destination),&(peer_type));
    }
    else
      return GNUNET_SYSERR; /*TODO: Should we handle this case differently? */
  }
  else if(peer_type == FINGER)
  {
    if(0 != (GNUNET_CRYPTO_cmp_peer_identity(&(trail_setup->current_destination),&my_identity)))
    {
      /* I am part of trail. 
       SUPU: So, I should ask for next hop to reach the current_destination which is the finger
       for which this packet has been sent. */
      next_hop = GDS_ROUTING_search(&(trail_setup->source_peer),&(trail_setup->current_destination));
      
      /*TODO: 
       call find_successor and compare the two peer ids 
       and choose whichever is closest to the destination finger. */
    } 
    else
    {
      /* I am the current_destination finger
       FIXME: Why are we sending current_destination to find_successor. 
       In this case, is it safe to assume current_Destination = my_identity.
       I guess we are sending current_destination so that we update it with new
       current_destination, if could either me, friend or finger.*/
      next_hop = find_successor((trail_setup->destination_finger),&(trail_setup->current_destination),&(peer_type));
    }
  }
   
  /* If you are the next hop */
  if(peer_type == MY_ID)
  {
    /* FIXME: Verify if its allowed here to definer peer_list and define it
       again in the next block below? */
      struct GNUNET_PeerIdentity *peer_list;
      peer_list = GNUNET_malloc (sizeof (struct GNUNET_PeerIdentity) * (trail_length));
      memcpy(peer_list, trail_peer_list, trail_length * sizeof (struct GNUNET_PeerIdentity));
      current_trail_index = trail_length - 2;
      next_peer = GNUNET_malloc (sizeof (struct GNUNET_PeerIdentity)); //FIXME: Do we need to allocate the memory?
      memcpy(next_peer, &peer_list[current_trail_index], sizeof (struct GNUNET_PeerIdentity));
      
      target_friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, next_peer);
     
      /* FIXME: It does not find a friend. Could be possible error in find_successor 
       function. Change the logic in find_successor and change it again. */
   
      /* FIXME: Here as destination_finger is 64 bit instead of struct
       GNUNET_PeerIdentity, but you need destination_peer id. If you calling the 
       function handle_Trail_setup_result from here, it means you are the
       destination. So, you can send your own identity. */
      GDS_NEIGHBOURS_handle_trail_setup_result(&(trail_setup->source_peer),
                                               &(my_identity),
                                               target_friend, trail_length,
                                               peer_list,current_trail_index);
  
    return GNUNET_YES;
  }
  
  /* Add next_hop to list of peers that trail setup message have traversed so far
   and increment trail length. */
  struct GNUNET_PeerIdentity *peer_list;
  peer_list = GNUNET_malloc (sizeof (struct GNUNET_PeerIdentity) * (trail_length + 1));
  memcpy(peer_list, trail_peer_list, trail_length * sizeof (struct GNUNET_PeerIdentity));
  memcpy(&peer_list[trail_length], next_hop, sizeof (struct GNUNET_PeerIdentity));
  trail_length++;
  
  target_friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, next_hop);
  
  if(peer_type == FINGER)
  {
    GDS_ROUTING_add(&(trail_setup->source_peer),&(trail_setup->current_destination),next_hop);
  }
  
  GDS_NEIGHBOURS_handle_trail_setup(&(trail_setup->source_peer),
                                    &(trail_setup->destination_finger),
                                    target_friend,
                                    trail_setup->trail_length,
                                    peer_list);
return GNUNET_YES;
}


/**
 * FIXME : Add interval field. 
 * When adding successor or predeccsor, update a field to
 * specify that this entry is not a finger but immediate
 * successor or predeccesor. 
 * Add an entry in finger table. 
 * @param finger Finger to be added to finger table
 * @param peer_list peers this request has traversed so far
 * @param trail_length Numbers of peers in the trail.
 */
static 
void finger_table_add(struct GNUNET_PeerIdentity *finger,
                      const struct GNUNET_PeerIdentity *peer_list,
                      unsigned int trail_length)
{
  struct FingerInfo *finger_entry;
  finger_entry = GNUNET_malloc(sizeof(struct GNUNET_PeerIdentity));
  memcpy(&(finger_entry->finger_identity), finger, sizeof(struct GNUNET_PeerIdentity));
  memcpy(&(finger_entry->trail_peer_list), peer_list, sizeof(struct GNUNET_PeerIdentity)
                                                      * trail_length);
  /*FIXME: When you add an entry into your finger table, then 
   you should add it in sorted way. Also, once sorted update the finger table 
   entry. As we will be using sorting and updating the interval in finger and friend 
   table and also in find_successor, we need this functionality see if you can 
   define a common function which can be used in all the three functions. 
   Also, you should then insert that entry into your finger_peermap.
   It seems to be too much of complexity but I need a working copy but i will
   ask bart first. */
  
  if (1 == GNUNET_CONTAINER_multipeermap_size (finger_peermap))
    verify_immediate_successor = GNUNET_SCHEDULER_add_now (&stabilize, NULL);
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
  uint32_t trail_length;
  const struct GNUNET_PeerIdentity *trail_peer_list;
  uint32_t current_trail_index;
  struct GNUNET_PeerIdentity *next_peer;
  struct FriendInfo *target_friend;
  
  msize = ntohs (message->size);
  if (msize < sizeof (struct PeerTrailSetupMessage))
  {
    GNUNET_break_op (0);
    return GNUNET_YES;
  }
  
  trail_result = (struct PeerTrailSetupResultMessage *) message; 
  trail_length = ntohl (trail_result->trail_length); 
  current_trail_index = ntohl(trail_result->current_index);
  trail_peer_list = (struct GNUNET_PeerIdentity *) &trail_result[1];
  
  if ((msize <
       sizeof (struct PeerTrailSetupResultMessage) +
       trail_length * sizeof (struct GNUNET_PeerIdentity)) ||
      (trail_length >
       GNUNET_SERVER_MAX_MESSAGE_SIZE / sizeof (struct GNUNET_PeerIdentity)))
  {
    GNUNET_break_op (0);
    return GNUNET_YES;
  }
 
  if(0 == (GNUNET_CRYPTO_cmp_peer_identity (&(trail_result->current_destination), &my_identity)))
  {
    /* Am I the destination? */
    if( 0 == (GNUNET_CRYPTO_cmp_peer_identity(&(trail_result->destination_peer), &my_identity)))
    {
      finger_table_add(&(trail_result->finger), trail_peer_list,trail_length);
      return GNUNET_YES;
    }
    else
    {
      next_peer = GNUNET_malloc (sizeof (struct GNUNET_PeerIdentity));
      current_trail_index = current_trail_index - 1;
      memcpy(next_peer, &(trail_peer_list[trail_length-1]), sizeof (struct GNUNET_PeerIdentity));
      target_friend = GNUNET_CONTAINER_multipeermap_get (friend_peermap, next_peer);
    
      GDS_NEIGHBOURS_handle_trail_setup_result(&(trail_result->destination_peer),
                                               &(trail_result->finger),
                                               target_friend, trail_length,
                                               trail_peer_list,current_trail_index);
      return GNUNET_YES;
    }
  }
  else
    return GNUNET_SYSERR;
}


/**
 * Core handle for p2p verify successor messages.
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
static int
handle_dht_p2p_verify_successor()
{
  /*
   * In this function you have received the message verify successor,
   * Now, either you are the destination or just part of the trail.
   * As we already know the whole path find out the next destination
   * and pass the packet forward.
   * If you are the final destination, check who is your predecessor.  
   * and send your predecessor back to calling function. 
   * FIXME: Should we have a different handler function for it. 
   */
  return GNUNET_YES;
}

/**
 * Core handle for p2p notify successor messages.
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
static int
handle_dht_p2p_notify_successor()
{
  /*
   * So, if you are the destination you should update your
   * predecessor field with peer id of source peer of this message.
   * If you are not the destination peer, then just check your routing
   * table and pass on the message. 
   */
  return GNUNET_YES;
}

/**
 * Core handle for p2p verify successor result messages.
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
static int
handle_dht_p2p_verify_successor_result()
{
  /*
   * In this function you have received the message verify successor result,
   If you are not the destination, just pass this message forward
   * if you are destination,
   * then check if immediate predecessor of this peer is you or someone else.
   * If its you, then don't do anything.
   * If its some one else, then call notify method to let your new successor
   * know that you are its predecessor. 
   */
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
    {&handle_dht_p2p_notify_successor, GNUNET_MESSAGE_TYPE_DHT_P2P_NOTIFY_SUCCESSOR, 0},
    {&handle_dht_p2p_verify_successor_result, GNUNET_MESSAGE_TYPE_DHT_P2P_VERIFY_SUCCESSOR_RESULT, 0},
    {NULL, 0, 0}
  };

  /*TODO: What is ATS? Why do we need it? */
  atsAPI = GNUNET_ATS_performance_init (GDS_cfg, NULL, NULL);
  core_api =
    GNUNET_CORE_connect (GDS_cfg, NULL, &core_init, &handle_core_connect,
                           &handle_core_disconnect, NULL, GNUNET_NO, NULL,
                           GNUNET_NO, core_handlers);
  if (core_api == NULL)
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

  /* FIXME: Once handle_core_disconnect is implemented, both below assertion should not
   fail. */
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
  
  /* FIXME: fix_fingers will also be a task like this.
     Add it later. */
  if (GNUNET_SCHEDULER_NO_TASK != verify_immediate_successor)
  {
    GNUNET_SCHEDULER_cancel (verify_immediate_successor);
    verify_immediate_successor = GNUNET_SCHEDULER_NO_TASK;
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