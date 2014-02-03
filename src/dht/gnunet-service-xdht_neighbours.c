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


/*TODO 
 * 1. Remove extra comments - FIXME,TODO,SUPU
 * 2. Use GNUNET_Log to debug
 */

/**
 * Maximum possible fingers of a peer.
 */
#define MAX_FINGERS 256

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
 * FIXME: I have defined this struct between GNUNET_NETWORK_STRUCT_BEGIN. Is
 * it correct? Also, I am using the same struct inside finger info and trailsetup
 * trailsetupresult message. Is it correct? Verify while testing. */
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
   struct GNUNET_PeerIdentity *peer;
  
};


/**
 * FIXME : I am using the same struct TrailPeerList in both finger info
 * and peertrailsetupmessage. Verify if its okay.
 * P2P Trail setup message
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
  struct GNUNET_PeerIdentity *source_peer;

  /**
   * Finger id to which we want to set up the trail to. 
   */
  struct GNUNET_PeerIdentity *destination_finger;

  /**
   * This field contains the peer to which this packet is forwarded.
   */
  struct GNUNET_PeerIdentity *current_destination;
 
  /**
   * Head of trail list.
   */
  struct TrailPeerList *head;
  
  /**
   * Tail of trail list.
   */
  struct TrailPeerList *tail;
  
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
  struct GNUNET_PeerIdentity *finger;

  /**
   * Peer which was looking for the trail to finger. 
   */
  struct GNUNET_PeerIdentity *destination_peer;

  /**
   * This field contains the peer to which this packet is forwarded.
   */
  struct GNUNET_PeerIdentity *current_destination;
  
  /**
   * Head of trail list.
   */
  struct TrailPeerList *head;
  
  /**
   * Tail of trail list.
   */
  struct TrailPeerList *tail;
  
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
 *  Entry in friend_peers map.
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
 * Entry in finger_peers map.
 */
struct FingerInfo
{
  /**
   * What is the identity of the finger peer?
   */
  struct GNUNET_PeerIdentity id;
  
  /**
   * Start of the interval of keys for which this finger is responsible.
   */
  unsigned int interval_start;

  /**
   * End of the interval of keys for which this finger is responsible.
   */
  unsigned int interval_end;

  /**
   * Head of trail list.
   */
  struct TrailPeerList *head;

  /**
   * Tail of trail list.
   */
  struct TrailPeerList *tail;
  
};


/**
 * Task that sends FIND FINGER TRAIL requests.
 */
static GNUNET_SCHEDULER_TaskIdentifier find_finger_trail_task;

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
static struct GNUNET_CONTAINER_MultiPeerMap *friend_peers;

/**
 * Hash map of all the fingers of a peer
 */
static struct GNUNET_CONTAINER_MultiPeerMap *finger_peers;

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
static unsigned int current_finger_id;


/**
 * Called when core is ready to send a message we asked for
 * out to the destination. 
 * 
 * @param cls the 'struct FriendInfo' of the target friend peer
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
  if (pending == NULL)
  {
    /* no messages pending */
    return 0;
  }
  if (buf == NULL)
  {
    peer->th =
        GNUNET_CORE_notify_transmit_ready (core_api, GNUNET_NO,
                                           pending->importance,
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
                                           pending->importance,
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
  
  /*FIXME : here I don't know the use of importance, time out
    Will check at run time if its all correct. */
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
 * FIXME: Check the parameters. 
 * Set up the trial message and forwards this message to friend. 
 * 
 * @param Finger id to which we want to setup the trail.
 * @param Friend id through which we will try to setup the trail.
 */
void
GDS_NEIGHBOURS_trail_setup(struct GNUNET_PeerIdentity *finger_id,
                                  struct FriendInfo *target_friend)
{
  /*
   * FIXME: check if pending message actually contains the correct data.
   */
  struct P2PPendingMessage *pending;
  /* FIXME: why I have defined as **? verify by testing. */
  struct PeerTrailSetupMessage *tsm;


  if (target_friend->pending_count >= MAXIMUM_PENDING_PER_FRIEND)
  {
    GNUNET_STATISTICS_update (GDS_stats, gettext_noop ("# P2P messages dropped due to full queue"),
				1, GNUNET_NO);
  }
  
  /* SUPU: Verify if this copy between pending message, tsm is correct? */
  pending = GNUNET_malloc (sizeof (struct P2PPendingMessage));
  /*SUPU: What does this code do? Does this intialize pending with
   values of tsm? */
  tsm = (struct PeerTrailSetupMessage *) &pending[1];
  pending->msg = &tsm->header;
  tsm->header.type = htons (GNUNET_MESSAGE_TYPE_DHT_P2P_TRAIL_SETUP);
  tsm->destination_finger = finger_id;
  tsm->source_peer = &my_identity;
  GNUNET_CONTAINER_DLL_insert_tail (target_friend->head, target_friend->tail, pending);
  target_friend->pending_count++;
  process_friend_queue(target_friend);
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

}


/**FIXME: Old implementation just to remove error.
 * Handle a reply (route to origin).  Only forwards the reply back to
 * other peers waiting for it.  Does not do local caching or
 * forwarding to local clients.
 *
 * @param target neighbour that should receive the block (if still connected)
 * @param type type of the block
 * @param expiration_time when does the content expire
 * @param key key for the content
 * @param put_path_length number of entries in put_path
 * @param put_path peers the original PUT traversed (if tracked)
 * @param get_path_length number of entries in put_path
 * @param get_path peers this reply has traversed so far (if tracked)
 * @param data payload of the reply
 * @param data_size number of bytes in data
 */
void
GDS_NEIGHBOURS_handle_reply (const struct GNUNET_PeerIdentity *target,
                             enum GNUNET_BLOCK_Type type,
                             struct GNUNET_TIME_Absolute expiration_time,
                             const struct GNUNET_HashCode * key,
                             unsigned int put_path_length,
                             const struct GNUNET_PeerIdentity *put_path,
                             unsigned int get_path_length,
                             const struct GNUNET_PeerIdentity *get_path,
                             const void *data, size_t data_size)
{
    
}


/**
 * SUPU: Check again. 
 * I have written a code where 
 * 1. I choose a random index from 0 to current size of my map.
 * 2. Create an iterator.
 * 3. set the iterator value to the current index id.
 * 4. get the element stored at that index id.
 * 5. return the index to calling function.
 * I have not yet tested this function and I am not sure if its correct. 
 * Randomly choose one of your friends from the friends_peer map
 * @return Friend
 */
static struct FriendInfo *
get_random_friend()
{ 
  unsigned int current_size;
  unsigned int *index; 
  unsigned int j = 0;
  struct GNUNET_CONTAINER_MultiPeerMapIterator *iter;
  struct GNUNET_PeerIdentity key_ret;
  struct FriendInfo *friend;
  
  current_size = GNUNET_CONTAINER_multipeermap_size(friend_peers);
  
  /* Element stored at this index in friend_peers map should be chosen friend. */
  index = GNUNET_CRYPTO_random_permute (GNUNET_CRYPTO_QUALITY_WEAK, current_size);
  
  /* Create an iterator for friend_peers map. */
  iter = GNUNET_CONTAINER_multipeermap_iterator_create(friend_peers);
  
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
 * TODO: Check the logic of using current_finger_id again. 
 * This code is not correct. I need to check the pointers and 
 * correct use of memcpy and all the data type. 
 * Use Chord formula finger[i]=(n+2^(i-1))mod m,
 * where i = current finger map index - max. 256 bits
 * n = own peer identity - 256 bits
 * m = number of bits in peer id - 256 bits
 * @return finger_peer_id for which we have to find the trail through network.
 */
static 
struct GNUNET_PeerIdentity *
finger_id_to_search()
{
  
  struct GNUNET_PeerIdentity *finger_peer_id;
  uint32_t peer_id;
  uint32_t finger_id;
  
  finger_peer_id = GNUNET_malloc (sizeof (struct GNUNET_PeerIdentity));
 
  /* Copy unsigned char array into peer_id. */
  if (0 == memcpy(&peer_id,&my_identity.public_key.q_y,sizeof(uint32_t)))
    return NULL;
  
  
  /* We do all the arithmetic operation on peer_id to get finger_id*/
  finger_id = (uint32_t)(peer_id + pow(2,current_finger_id)) % MAX_FINGERS;
  
  
  /* Copy the finger_id to finger_peer_id. */
  if (0 == memcpy(&finger_peer_id->public_key.q_y,&finger_id,sizeof(uint32_t)))
    return NULL;
  
   /* FIXME: Here I increment the index so that next time when we enter this 
     function, then we begin the search from current index. Is it possible
     to set this value when we add the finger id to our finger table. No, because
     even there is a call going on to find the finger, we can start another call 
     to search another peer.  */
   current_finger_id = (current_finger_id+1) % MAX_FINGERS;
  
  /* Check if you already have an entry in finger_peers for this finger_id.
   If yes then again look for a new finger_id. */
   if(NULL == GNUNET_CONTAINER_multipeermap_get(finger_peers,finger_peer_id))
   {
     /* Is the recursion safe here? */
     finger_peer_id = finger_id_to_search();
   }
  
  return finger_peer_id;
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
static
struct GNUNET_PeerIdentity*
find_immediate_predecessor()
{
    /* Using your own peer identity, calculate your predecessor
     in the network. Try to setup path to this predecessor using
     the same logic as used for other fingers. 
     If we already have a trail to our predecessor then send NULL and 
     calling function should be able to handle that case. */
  return NULL;
}


/**
 * Task to send a find finger trail message. We attempt to find trail
 * to our finger in the network.
 *
 * @param cls closure for this task
 * @param tc the context under which the task is running
 */
static void
send_find_finger_trail_message (void *cls,
                        const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_PeerIdentity *finger_peer_id;
  struct FriendInfo *friend_peer_id;
  struct GNUNET_TIME_Relative next_send_time;
  
  /* We already have found trail to each of our possible fingers in the network. */
  if (GNUNET_CONTAINER_multipeermap_size(finger_peers) == MAX_FINGERS)
  {
    /* We can find trail to our immediate predecessor in the network. */  
    finger_peer_id = find_immediate_predecessor();  
    if(NULL == finger_peer_id)
    {
      /* We already have a trail to reach to immediate predecessor. */
      goto new_find_trail_request;
    }
  }
  else
  {
    /* Find the finger_peer_id for which we want to setup the trail */
    finger_peer_id = finger_id_to_search();
  }
  
  /* Choose a friend randomly from your friend_peers map. */
  friend_peer_id = get_random_friend();
  
  /* We found a friend.*/
  if(NULL != friend_peer_id)
    GDS_NEIGHBOURS_trail_setup(finger_peer_id, friend_peer_id);
  
  
  new_find_trail_request:

  next_send_time.rel_value_us =
      DHT_MINIMUM_FIND_FINGER_TRAIL_INTERVAL.rel_value_us +
      GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_WEAK,
                                DHT_MAXIMUM_FIND_FINGER_TRAIL_INTERVAL.rel_value_us /
                                (current_finger_id + 1));
 
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
  
  /* If peer already exists in our friend_peers, then exit. */
  if (GNUNET_YES ==
      GNUNET_CONTAINER_multipeermap_contains (friend_peers,
                                              peer))
  {
    GNUNET_break (0);
    return;
  }

  GNUNET_STATISTICS_update (GDS_stats, gettext_noop ("# peers connected"), 1,
                            GNUNET_NO);

  ret = GNUNET_new (struct FriendInfo);
  ret->id = *peer;

  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multipeermap_put (friend_peers,
                                                    peer, ret,
                                                    GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));

  /* got a first connection, good time to start with FIND FINGER TRAIL requests... */
  if (1 == GNUNET_CONTAINER_multipeermap_size(friend_peers))
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
     1. Search the friend,finger and check your own id to find the closest
     * predecessor the given key. --> find_predecessor()
     2. If self then datache_store
     3. If friend, then add to peer queue 
     4. If finger, then add to the peer queue of the first hop.
     * in put message also maintain a field current_destination and use
     * same logic as trail setup to understand if you are just part of trail
     * to reach to a particular peer or you are endpoint of trail or just a friend.
     * 
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
  return 0;
}


/**
 * Core handler for p2p result messages.
 *
 * @param cls closure
 * @param message message
 * @param peer peer identity this notification is about
 * @return #GNUNET_YES (do not cut p2p connection)
 */
static int
handle_dht_p2p_result (void *cls, const struct GNUNET_PeerIdentity *peer,
                       const struct GNUNET_MessageHeader *message)
{
  return 0;
}


/**
 * FIXME:
 * Are we comparing the predecessor with our own identity also.
 * Its important.
 * Here also we would be comparing the numeric value of
 * peer identity. We read the element from our map. Extract
 * the peer id and compare it with destination id. But again
 * this comparison is on values. Same issue again. 
 * Find the predecessor for given finger_id from the
 * friend and finger table.
 * if friend, then just return the friend 
 * if finger, then return the next hop to forward the packet to and also
 * set the current_destination field to finger_id. 
 * @param destination peer id's predecessor we are looking for. 
 * @return
 */
static struct GNUNET_PeerIdentity *
find_successor(struct GNUNET_PeerIdentity *destination)
{
  unsigned int friend_index;
  unsigned int finger_index;
  struct GNUNET_CONTAINER_MultiPeerMapIterator *friend_iter;
  struct GNUNET_CONTAINER_MultiPeerMapIterator *finger_iter;
  struct GNUNET_PeerIdentity key_ret;
  struct FriendInfo *friend;
  struct FingerInfo *finger;
  
  /* Should I keep a variable to remember if GNUNET_PeerIdentity is 
   friend or finger. */
  friend_iter = GNUNET_CONTAINER_multipeermap_iterator_create (friend_peers); 
  
  /*iterate over friend map till you reach a peer id such that destination <= peer id */ 
  for (friend_index = 0; friend_index < GNUNET_CONTAINER_multipeermap_size (friend_peers); friend_index++)
  {
    if(GNUNET_YES == GNUNET_CONTAINER_multipeermap_iterator_next(friend_iter,&key_ret,(const void **)&friend)) 
    {
          /*
           * 1. Check if friend >= destination.
           * 2. If yes then check if friend <= current_predecessor,
           *    if yes then curret_predecessor = friend.
           * 3 If not then do nothing.
           */
    }
  }
  

  finger_iter = GNUNET_CONTAINER_multipeermap_iterator_create (finger_peers);  
  /*iterate over finger map till you reach a peer id such that destination <= peer id */ 
  for (finger_index = 0; finger_index < GNUNET_CONTAINER_multipeermap_size (friend_peers); finger_index++)
  {
    if(GNUNET_YES == GNUNET_CONTAINER_multipeermap_iterator_next(finger_iter,&key_ret,(const void **)&finger)) 
    {
      /*
       * 1. Check if finger >= destination.
       * 2. If yes then check if finger <= current_predecessor,
       *    if yes then curret_predecessor = finger.
       * 3 If not then do nothing.
       */
    }
  }
 
  /* Check between friend and finger value to decide which is the predecessor. 
     If friend, then send the friend id.
     If finger, then send the next hop.
     Also set the current_destination = friend, if friend
     or else current_destination = finger. */
  return NULL;
}


/* Traverse the trail list to find the prev hop to store in routing table. */
static
struct GNUNET_PeerIdentity *
find_trail_list_prev_hop(struct PeerTrailSetupMessage *trail_result)
{
  /*FIXME: I don't see any function in existing dll implementation, to 
   just read the dll backward or forward. So, I would implement one here. 
   * As no one else uses this functionality so I guess its okay to just
   * implement it here.  */
  return NULL;
}


/**
 * FIXME: 
 * 1. Check if we are maintaining the 64k size of struct PeerTrailSetupMessage.
 * when we add ourself to the trail list. 
 * 2. Ensure every case is handled for current_destination. 
 * 3. When should you call GDS_Routing_Add? 
 * Core handler for P2P trail setup message.
 * @param cls closure
 * @param message message
 * @param peer peer identity this notification is about
 * @return #GNUNET_YES 
 */
static int
handle_dht_p2p_trail_setup(void *cls, const struct GNUNET_PeerIdentity *peer,
                    const struct GNUNET_MessageHeader *message)
{
  struct PeerTrailSetupMessage *trail_setup; 
  struct GNUNET_PeerIdentity *next_hop;
  struct GNUNET_PeerIdentity *prev_hop; 
  struct FriendInfo *friend;
  struct TrailPeerList *peer_entry;
  struct P2PPendingMessage *pending;
  
  uint16_t msize;
   
  msize = ntohs (message->size);
  if (msize < sizeof (struct PeerTrailSetupMessage))
  {
    GNUNET_break_op (0);
    return GNUNET_YES;
  }
  
  trail_setup = (struct PeerTrailSetupMessage *) message;
  
  GNUNET_STATISTICS_update (GDS_stats,
                            gettext_noop ("# TRAIL SETUP requests received"), 1,
                            GNUNET_NO);
  GNUNET_STATISTICS_update (GDS_stats,
                            gettext_noop ("# TRAIL SETUP bytes received"), msize,
                            GNUNET_NO);
  
  
  /* Check the value of current_destination and handle the respective case. */
  if(trail_setup->current_destination == NULL)
  {
    /* Find the next peer to pass the trail setup message. */  
    next_hop = find_successor(trail_setup->destination_finger);
  }
  else if( 0 == (GNUNET_CRYPTO_cmp_peer_identity(trail_setup->current_destination,&my_identity)))
  {
    /* I am current destination, find the next peer to pass the trail setup message. */  
    next_hop = find_successor(trail_setup->destination_finger);  
  }
  else
  {
    /* I am part of the trail to reach to current_destination. */
    next_hop = GDS_Routing_search(trail_setup->source_peer, trail_setup->current_destination, trail_setup->tail->peer);
  }
 
  
  if(0 == (GNUNET_CRYPTO_cmp_peer_identity(next_hop,&my_identity)))
  {
    /* I am the closest successor of the destination finger in the network. */
    /*TODO::
      1. Prepare a trail setup result message.
      2. Add yourself to trail list. 
      3. send packet to last element in the list. 
    */
    return GNUNET_YES;
  }
  
  /* FIXME:
   * Do we really need to pass the whole trail_setup? I guess
   * we can just pass the double linked list. 
  */
   prev_hop = find_trail_list_prev_hop(trail_setup);
     
  /* Add an entry in the routing table. 
   SUPU: Here we are adding an entry to our routing table because we are not final
   destination.So, it means we are part of a routing trail. It may happen
   that we found next_hop from searching the routing table. So, in GDS_ROUTING_Add,
   we should first check if there is already an entry for current_destination. If yes
   then don't add.*/
  GDS_ROUTING_add(trail_setup->source_peer,trail_setup->current_destination,prev_hop,next_hop);
  
  /* FIXME:
   * 1. Insert next hop into trail list.
   * 2. I don't see any function to just read the DLL. Need to see again if there is
   * one. If not then need to write something. */
  peer_entry = GNUNET_malloc (sizeof (struct TrailPeerList));
  peer_entry->peer = &my_identity;
  peer_entry->next = NULL;
  peer_entry->prev = NULL;
  
  /*SUPU what is this stupid code that I have written. */
  GNUNET_CONTAINER_DLL_insert_tail(trail_setup->head->next,trail_setup->tail->prev,peer_entry);
  
  /* Find the struct FriendInfo for next_hop peer id. */
  friend = GNUNET_CONTAINER_multipeermap_get(friend_peers,next_hop);
  
  if (friend->pending_count >= MAXIMUM_PENDING_PER_FRIEND)
  {
    GNUNET_STATISTICS_update (GDS_stats, gettext_noop ("# P2P messages dropped due to full queue"),
				1, GNUNET_NO);
  }
  
  /* Send trail setup message to next hop friend. */
  pending = GNUNET_malloc (sizeof (struct P2PPendingMessage));
  trail_setup = (struct PeerTrailSetupMessage *) &pending[1];
  pending->msg = &trail_setup->header;
  GNUNET_CONTAINER_DLL_insert_tail (friend->head, friend->tail, pending);
  friend->pending_count++;
  process_friend_queue(friend);
  return GNUNET_YES;
}


/* Add an entry to finger table. */
static 
void finger_table_add(struct PeerTrailSetupResultMessage *result)
{
    /* 1. create a struct FingerInfo and copy respective members
     * of result into this struct. 
     * Add the whole trail in your finger table, 
     also add interval. */
}


/* Traverse the trail list to find the next hop to pass the result message. */
static
struct GNUNET_PeerIdentity *
find_trail_list_next_hop(struct PeerTrailSetupResultMessage *trail_result)
{
    /* Setup the current_destination value to new next hop found. */
    return NULL;
}


/**
 * Core handle for p2p trail construction result messages.
 * @param cls closure
 * @param message message
 * @param peer peer identity this notification is about
 * @return #GNUNET_YES (do not cut p2p connection)
 * @return
 */
static int
handle_dht_p2p_trail_setup_result(void *cls, const struct GNUNET_PeerIdentity *peer,
                    const struct GNUNET_MessageHeader *message)
{
  /* FIXME: Should it be const? */
  struct PeerTrailSetupResultMessage *trail_result;
  struct GNUNET_PeerIdentity *next_hop;
  struct FriendInfo *friend;
  struct P2PPendingMessage *pending;
  trail_result = (struct PeerTrailSetupResultMessage *) message;   
 
  uint16_t msize;
   
  msize = ntohs (message->size);
  if (msize < sizeof (struct PeerTrailSetupResultMessage))
  {
    GNUNET_break_op (0);
    return GNUNET_YES;
  }  
  
  /* This should always be the case. */
  if( 0 == (GNUNET_CRYPTO_cmp_peer_identity(trail_result->current_destination,&my_identity)))
  {
    /* Am I the destination ? */
    if( 0 == (GNUNET_CRYPTO_cmp_peer_identity(trail_result->destination_peer,&my_identity)))
    {
      /* I am the destination. Add the trail to my finger table. */
      finger_table_add(trail_result);
      return GNUNET_YES;
    }
    else
    {
      /* Find the next peer in the trail list to pass the message to. */
      next_hop = find_trail_list_next_hop(trail_result);
      
      /* Find the struct FriendInfo for next_hop peer id. */
      friend = GNUNET_CONTAINER_multipeermap_get(friend_peers,next_hop);
      
      if (friend->pending_count >= MAXIMUM_PENDING_PER_FRIEND)
      {
        GNUNET_STATISTICS_update (GDS_stats, gettext_noop ("# P2P messages dropped due to full queue"),
				1, GNUNET_NO);
      }
      /* Send trail setup result message to next hop friend. */
      /*FIXME:
       I have not yet written the code to copy struct trail message to
       pending message. Also, before sending the message I need to check
       the MAXIMUM_PENDNIG_PEER limit is not crossed. Modify the same part
       of code for handle_dht_p2p_trail_setup. */
      pending = GNUNET_malloc (sizeof (struct P2PPendingMessage));
      trail_result = (struct PeerTrailSetupResultMessage *) &pending[1];
      pending->msg = &trail_result->header;
      GNUNET_CONTAINER_DLL_insert_tail (friend->head, friend->tail, pending);
      friend->pending_count++;
      process_friend_queue(friend);
      
      return GNUNET_YES;
     }
  }    
  else
    return GNUNET_SYSERR;
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
    {&handle_dht_p2p_result, GNUNET_MESSAGE_TYPE_DHT_P2P_RESULT, 0},
    {&handle_dht_p2p_trail_setup, GNUNET_MESSAGE_TYPE_DHT_P2P_TRAIL_SETUP, 0},
    {&handle_dht_p2p_trail_setup_result, GNUNET_MESSAGE_TYPE_DHT_P2P_TRAIL_SETUP_RESULT, 0},
    {NULL, 0, 0}
  };

  /*ASK: What is ATS? Why do we need it? */
  atsAPI = GNUNET_ATS_performance_init (GDS_cfg, NULL, NULL);
  core_api =
    GNUNET_CORE_connect (GDS_cfg, NULL, &core_init, &handle_core_connect,
                           &handle_core_disconnect, NULL, GNUNET_NO, NULL,
                           GNUNET_NO, core_handlers);
  if (core_api == NULL)
    return GNUNET_SYSERR;

  friend_peers = GNUNET_CONTAINER_multipeermap_create (256, GNUNET_NO);
  finger_peers = GNUNET_CONTAINER_multipeermap_create (256, GNUNET_NO);
  
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

  GNUNET_assert (0 == GNUNET_CONTAINER_multipeermap_size (friend_peers));
  GNUNET_CONTAINER_multipeermap_destroy (friend_peers);
  friend_peers = NULL;

  GNUNET_assert (0 == GNUNET_CONTAINER_multipeermap_size (finger_peers));
  GNUNET_CONTAINER_multipeermap_destroy (finger_peers);
  finger_peers = NULL;

  if (GNUNET_SCHEDULER_NO_TASK != find_finger_trail_task)
  {
    GNUNET_SCHEDULER_cancel (find_finger_trail_task);
    find_finger_trail_task = GNUNET_SCHEDULER_NO_TASK;
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