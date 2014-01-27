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
 1. Add logic to get connected to your predecessor 
 because when nodes join/fail , you need to maintain correct
 pointers to predecessor and your successor i.e.your first finger,
 to update tables.
 2. Remove extra comments.  */

/**
 * Maximum possible fingers of a peer.
 */
#define MAX_FINGERS 256

/**
 * Maximum allowed number of pending messages per peer.
 */
#define MAXIMUM_PENDING_PER_PEER 64

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
 * FIXME : I am using the same structure trail list in both finger info
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
  struct TrailList *head;
  
  /**
   * Tail of trail list.
   */
  struct TrailList *tail;
  
};


/**
 * P2P Trail setup Result message
 * FIXME: There seem to be no difference between trail_setup and trailsetupresult
 * Can we somehow merge these two. As in result we don't have to do any
 * search in our finger or friend table thats why I kept it separate. But is it
 * actually required to keep these two things different. 
 */
struct PeerTrailSetupResultMessage
{
  /**
   * Type: #GNUNET_MESSAGE_TYPE_DHT_P2P_TRAIL_RESULT_SETUP
   */
  struct GNUNET_MessageHeader header;

  /* It should contain the list of peers which form the trail. 
   and also maintain a pointer to the current_peer to which we have to forward
   the packet. We have to maintain the whole list in this message because
   at the end source peer will store this list in its finger table. */
  
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
  struct TrailList *head;
  
  /**
   * Tail of trail list.
   */
  struct TrailList *tail;
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
 *  Linked List of peers which are part of trail to reach a particular Finger.
 */
struct TrailList
{
   /**
   * Pointer to next item in the list
   */
   struct TrailList *next;

   /**
   * Pointer to previous item in the list
   */
   struct TrailList *prev;
   
   /**
    * An element in this trail list
    */
   struct GNUNET_PeerIdentity *peer;
  
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
   * What is the identity of the peer?
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
  struct TrailList *head;

  /**
   * Tail of trail list.
   */
  struct TrailList *tail;
  
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
 * Handle to ATS.
 */
static struct GNUNET_ATS_PerformanceHandle *atsAPI;

/**
 * Handle to CORE.
 */
static struct GNUNET_CORE_Handle *core_api;

/**
 * The highest finger_id that we have found trail to.
 */
static unsigned int finger_id;


/**
 * TODO: Check this function again. 
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
 * Transmit all messages in the peer's message queue.
 *
 * @param peer message queue to process
 */
static void
process_peer_queue (struct FriendInfo *peer)
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


    if (target_friend->pending_count >= MAXIMUM_PENDING_PER_PEER)
    {
      GNUNET_STATISTICS_update (GDS_stats, gettext_noop ("# P2P messages dropped due to full queue"),
				1, GNUNET_NO);
    }

    pending = GNUNET_malloc (sizeof (struct P2PPendingMessage));
    tsm = (struct PeerTrailSetupMessage *) &pending[1];
    pending->msg = &tsm->header;
    tsm->header.type = htons (GNUNET_MESSAGE_TYPE_DHT_P2P_TRAIL_SETUP);
    tsm->destination_finger = finger_id;
    tsm->source_peer = &my_identity;
    GNUNET_CONTAINER_DLL_insert_tail (target_friend->head, target_friend->tail, pending);
    target_friend->pending_count++;
    process_peer_queue(target_friend);
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
 * Randomly choose one of your friends from the friends_peer map
 * @return Friend
 */
static struct FriendInfo *
get_friend()
{
  /*1. get the size of your friend map first.
    2. Then, choose a number randomly from 0 to size-1
    3. Then create an iterator to extract the peer id from friend map
       This function should be defined in this file as no other file uses it.*/
  
  //unsigned int current_size;
  //unsigned int *index; 
  
  //current_size = GNUNET_CONTAINER_multipeermap_size(friend_peers);
  
  /* Element stored at this index in friend_peers map should be chosen friend. */
  //index = GNUNET_CRYPTO_random_permute (GNUNET_CRYPTO_QUALITY_WEAK, current_size);
  
  
  /*TODO: Add a function which will get the element stored at that index in
   our friend_peers_map.Take care of parameters.  */
 
  return NULL;
}


/**
 * Use Chord formula finger[i]=(n+2^(i-1))mod m,
 * where i = current finger map index.
 * n = own peer identity
 * m = number of bits in peer id.
 * @return finger_peer_id for which we have to find the trail through network.
 */
//static 
struct GNUNET_PeerIdentity *
finger_id_to_search()
{
  
  //struct GNUNET_PeerIdentity *finger_peer_id;

  /*TODO: Add a wrapper in crypto_ecc.c to add an integer do mod operation on integer
    to find peer id. Take care of parameters. You should work on the value of 
   finger_id not on its pointer. */ 

  //return finger_peer_id;
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
  
  /* FIXME: Not sure if this is required. Here I am checking if I have
     already found trail for each of the possible finger. If yes then don't look
     anymore in the network. We can at this point may even look for the
     predecessor in the network. It handles the case where one of the peer
     gets disconnected -- as we remove the element from finger_peers, and the
     size will not be MAX_FINGERS.*/
  if (GNUNET_CONTAINER_multipeermap_size(finger_peers) == MAX_FINGERS)
  {
      /*FIXME: Should we call find_predecessor_peer here. We need to maintain 
       pointer to predecessor in the network to handle node join/failure case. */
      return;
  }

  /* Find the finger_peer_id for which we want to setup the trial */
  finger_peer_id = finger_id_to_search();

  /* Choose a friend randomly from your friend_peers map. */
  friend_peer_id = get_friend();

  /*FIXME: Check if we are passing parameters correctly. */
  GDS_NEIGHBOURS_trail_setup(finger_peer_id, friend_peer_id);

  /* FIXME: Is using finger_id to generate random function ok here. */
  next_send_time.rel_value_us =
      DHT_MINIMUM_FIND_FINGER_TRAIL_INTERVAL.rel_value_us +
      GNUNET_CRYPTO_random_u64 (GNUNET_CRYPTO_QUALITY_WEAK,
                                DHT_MAXIMUM_FIND_FINGER_TRAIL_INTERVAL.rel_value_us /
                                (finger_id + 1));

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
 * Method called whenever a peer disconnects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 */
static void
handle_core_disconnect (void *cls,
			const struct GNUNET_PeerIdentity *peer)
{
  /* Here I guess
   1. if a core disconnect, then mark it disconnected or remove the entry from
   friend/finger table.
   2. If entry is removed from finger table then remove trail also. 
   Here is case where we started put operation but a peer got disconnected and 
   we removed the entry from the table. 
   How to handle such a case. */
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
 * Read the trail setup message backwards to find which is the next hop to which
 * it should be send to.
 * @return
 
static
struct GNUNET_PeerIdentity *
find_next_hop()
{
    return NULL;
}*/


/**
 * Find the predecessor for given finger_id from the
 * friend and finger table.
 * if friend, then just return the friend 
 * if finger, then return the next hop to forward the packet to and also
 * set the current_destination field to finger_id. 
 * @param destination peer id's predecessor we are looking for. 
 * @return
 */
static struct GNUNET_PeerIdentity *
find_predecessor(struct GNUNET_PeerIdentity *destination)
{
    /*iterate over friend map till you reach a peer id such that 
     destination <= peer id */ 
    
    return NULL;
}


/**
 * Core handler for P2P trail setup message.
 * FIXME: 
 * 1. Check if we are maintaining the 64k size of struct PeerTrailSetupMessage.
 * when we add ourself to the trail list. 
 * 2. Ensure that you set the correct value of current_destination.
 * @param cls closure
 * @param message message
 * @param peer peer identity this notification is about
 * @return #GNUNET_YES 
 */
static int
handle_dht_p2p_trail_setup(void *cls, const struct GNUNET_PeerIdentity *peer,
                    const struct GNUNET_MessageHeader *message)
{
  /*SUPU: Why am I defining this message as const? */ 
  const struct PeerTrailSetupMessage *trail_setup;
  struct GNUNET_PeerIdentity *next_hop;
  
  uint16_t msize;
   
  msize = ntohs (message->size);
  if (msize < sizeof (struct PeerTrailSetupMessage))
  {
    GNUNET_break_op (0);
    return GNUNET_YES;
  }
  
  /*SUPU: So here we have the message that we got from one of our peer into
   our own trail_setup message.*/
  trail_setup = (const struct PeerTrailSetupMessage *) message;
  
  GNUNET_STATISTICS_update (GDS_stats,
                            gettext_noop ("# TRAIL SETUP requests received"), 1,
                            GNUNET_NO);
  GNUNET_STATISTICS_update (GDS_stats,
                            gettext_noop ("# TRAIL SETUP bytes received"), msize,
                            GNUNET_NO);
  
  
  /*Check the value of current_destination and handle the respective case. */
  if(trail_setup->current_destination == NULL)
  {
      /*if there is no value set up for current destination then
       just call find_predecessor() */
      next_hop = find_predecessor(trail_setup->destination_finger);
  }
  else if( 0 == (GNUNET_CRYPTO_cmp_peer_identity(trail_setup->current_destination,&my_identity)))
  {
      /* If this packet is send to me.
       1. call find_predecessor() if it returns your own identity, then 
       * prepare a trail setup message and send to last element of our trail
       * list. 
       2. if find_predecessor(), returns a friend id then send the packet along 
       that.
       */
      next_hop = find_predecessor(trail_setup->destination_finger);
      if(0 == (GNUNET_CRYPTO_cmp_peer_identity(next_hop,&my_identity)))
      {
          /*1. Prepare a trail setup message.
            2. Add yourself to trail list. 
            3. send packet to last element in the list. 
        */
      }
      else
      {
         /* send the message to next_hop.*/ 
          goto forward;
      }
  }
  else
  {
     /* here is trail_setup is not NULL, but it is not equal to my_identity
      so, it means I am part of the trail to reach to current_destination.
      so , search in routing table to find which is the next hop to send this
      packet to.*/
      next_hop = GDS_Routing_search(trail_setup->source_peer, trail_setup->current_destination, trail_setup->tail->peer);
  }
  /*If you have reached here, it means that we have still not reached our
   final destination, so we now 
   1. add ourself to trail list
   2. pass the message to next_hop. */
  forward:
  
  return GNUNET_YES;
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
    /**
     * Just read the linked list backwards and send the packet to next hop 
     * till you don't reach the source
     * but if you are source, then add an entry in finger table for given finger id.
     * 
     * 
     */
    //const struct PeerTrailSetupResultMessage *trail_result;
    //trail_result = (const struct PeerTrailSetupResultMessage *) message;
    
    /*FIXME: This code is wrong, I am writing just to understand the flow,
    if(trail_result->destination == message->destination)
    {
       This condition holds true, then we should add an entry in our
         routing table and store this finger and its trail. 
     struct finger_info = with interval . 
     GNUNET_multipeer_map_insert(finger_map)
     * GDS_Routing_add();
    }
    else
    {
        Read the trail list, Check the next_hop and pass the packet to it. 
         FIXME: Should we an entry in our own routing table. 
    }*/
    
    return 0;
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