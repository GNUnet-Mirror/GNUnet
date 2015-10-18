/*
     This file is part of GNUnet.
     Copyright (C) 2013, 2015 Christian Grothoff (and other contributing authors)

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
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/
/**
 * @file cadet/gnunet-service-cadet_peer.c
 * @brief GNUnet CADET service connection handling
 * @author Bartlomiej Polot
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_signatures.h"
#include "gnunet_transport_service.h"
#include "gnunet_ats_service.h"
#include "gnunet_core_service.h"
#include "gnunet_statistics_service.h"
#include "cadet_protocol.h"
#include "gnunet-service-cadet_peer.h"
#include "gnunet-service-cadet_dht.h"
#include "gnunet-service-cadet_connection.h"
#include "gnunet-service-cadet_tunnel.h"
#include "cadet_path.h"

#define LOG(level, ...) GNUNET_log_from (level,"cadet-p2p",__VA_ARGS__)
#define LOG2(level, ...) GNUNET_log_from_nocheck(level,"cadet-p2p",__VA_ARGS__)


/******************************************************************************/
/********************************   STRUCTS  **********************************/
/******************************************************************************/

/**
 * Struct containing info about a queued transmission to this peer
 */
struct CadetPeerQueue
{
  /**
   * DLL next
   */
  struct CadetPeerQueue *next;

  /**
   * DLL previous
   */
  struct CadetPeerQueue *prev;

  /**
   * Peer this transmission is directed to.
   */
  struct CadetPeer *peer;

  /**
   * Connection this message belongs to.
   */
  struct CadetConnection *c;

  /**
   * Is FWD in c?
   */
  int fwd;

  /**
   * Pointer to info stucture used as cls.
   */
  void *cls;

  /**
   * Type of message
   */
  uint16_t type;

  /**
   * Type of message
   */
  uint16_t payload_type;

  /**
   * Type of message
   */
  uint32_t payload_id;

  /**
   * Size of the message
   */
  size_t size;

  /**
   * Set when this message starts waiting for CORE.
   */
  struct GNUNET_TIME_Absolute start_waiting;

  /**
   * Function to call on sending.
   */
  GCP_sent cont;

  /**
   * Closure for callback.
   */
  void *cont_cls;
};


/**
 * Struct containing all information regarding a given peer
 */
struct CadetPeer
{
  /**
   * ID of the peer
   */
  GNUNET_PEER_Id id;

  /**
   * Last time we heard from this peer
   */
  struct GNUNET_TIME_Absolute last_contact;

  /**
   * Paths to reach the peer, ordered by ascending hop count
   */
  struct CadetPeerPath *path_head;

  /**
   * Paths to reach the peer, ordered by ascending hop count
   */
  struct CadetPeerPath *path_tail;

  /**
   * Handle to stop the DHT search for paths to this peer
   */
  struct GCD_search_handle *search_h;

  /**
   * Handle to stop the DHT search for paths to this peer
   */
  struct GNUNET_SCHEDULER_Task *search_delayed;

  /**
   * Tunnel to this peer, if any.
   */
  struct CadetTunnel *tunnel;

  /**
   * Connections that go through this peer; indexed by tid.
   */
  struct GNUNET_CONTAINER_MultiHashMap *connections;

  /**
   * Handle for queued transmissions
   */
  struct GNUNET_CORE_TransmitHandle *core_transmit;

  /**
   * Timestamp
   */
  struct GNUNET_TIME_Absolute tmt_time;

  /**
   * Transmission queue to core DLL head
   */
  struct CadetPeerQueue *queue_head;

  /**
   * Transmission queue to core DLL tail
   */
  struct CadetPeerQueue *queue_tail;

  /**
   * How many messages are in the queue to this peer.
   */
  unsigned int queue_n;

  /**
   * Hello message.
   */
  struct GNUNET_HELLO_Message* hello;

  /**
   * Handle to us offering the HELLO to the transport.
   */
  struct GNUNET_TRANSPORT_OfferHelloHandle *hello_offer;

  /**
   * Handle to our ATS request asking ATS to suggest an address
   * to TRANSPORT for this peer (to establish a direct link).
   */
  struct GNUNET_ATS_ConnectivitySuggestHandle *connectivity_suggestion;

};


/******************************************************************************/
/*******************************   GLOBALS  ***********************************/
/******************************************************************************/

/**
 * Global handle to the statistics service.
 */
extern struct GNUNET_STATISTICS_Handle *stats;

/**
 * Local peer own ID (full value).
 */
extern struct GNUNET_PeerIdentity my_full_id;

/**
 * Local peer own ID (short)
 */
extern GNUNET_PEER_Id myid;

/**
 * Peers known, indexed by PeerIdentity, values of type `struct CadetPeer`.
 */
static struct GNUNET_CONTAINER_MultiPeerMap *peers;

/**
 * How many peers do we want to remember?
 */
static unsigned long long max_peers;

/**
 * Percentage of messages that will be dropped (for test purposes only).
 */
static unsigned long long drop_percent;

/**
 * Handle to communicate with CORE.
 */
static struct GNUNET_CORE_Handle *core_handle;

/**
 * Handle to communicate with ATS.
 */
static struct GNUNET_ATS_ConnectivityHandle *ats_ch;

/**
 * Handle to try to start new connections.
 */
static struct GNUNET_TRANSPORT_Handle *transport_handle;

/**
 * Shutdown falg.
 */
static int in_shutdown;


/******************************************************************************/
/*****************************     DEBUG      *********************************/
/******************************************************************************/

/**
 * Log all kinds of info about the queueing status of a peer.
 *
 * @param p Peer whose queue to show.
 * @param level Error level to use for logging.
 */
static void
queue_debug (const struct CadetPeer *p, enum GNUNET_ErrorType level)
{
  struct GNUNET_TIME_Relative core_wait_time;
  struct CadetPeerQueue *q;
  int do_log;

  do_log = GNUNET_get_log_call_status (level & (~GNUNET_ERROR_TYPE_BULK),
                                       "cadet-p2p",
                                       __FILE__, __FUNCTION__, __LINE__);
  if (0 == do_log)
    return;

  LOG2 (level, "QQQ Message queue towards %s\n", GCP_2s (p));
  LOG2 (level, "QQQ  queue length: %u\n", p->queue_n);
  LOG2 (level, "QQQ  core tmt rdy: %p\n", p->core_transmit);
  if (NULL != p->core_transmit)
  {
    core_wait_time = GNUNET_TIME_absolute_get_duration (p->tmt_time);
    LOG2 (level, "QQQ  core called %s ago\n",
          GNUNET_STRINGS_relative_time_to_string (core_wait_time, GNUNET_NO));
  }
  for (q = p->queue_head; NULL != q; q = q->next)
  {
    LOG2 (level, "QQQ  - %s %s on %s\n",
         GC_m2s (q->type), GC_f2s (q->fwd), GCC_2s (q->c));
    LOG2 (level, "QQQ    payload %s, %u\n",
         GC_m2s (q->payload_type), q->payload_id);
    LOG2 (level, "QQQ    size: %u bytes\n", q->size);
  }

  LOG2 (level, "QQQ End queue towards %s\n", GCP_2s (p));
}


/**
 * Log all kinds of info about a peer.
 *
 * @param peer Peer.
 */
void
GCP_debug (const struct CadetPeer *p, enum GNUNET_ErrorType level)
{
  struct CadetPeerPath *path;
  unsigned int conns;
  int do_log;

  do_log = GNUNET_get_log_call_status (level & (~GNUNET_ERROR_TYPE_BULK),
                                       "cadet-p2p",
                                       __FILE__, __FUNCTION__, __LINE__);
  if (0 == do_log)
    return;

  if (NULL == p)
  {
    LOG2 (level, "PPP DEBUG PEER NULL\n");
    return;
  }

  LOG2 (level, "PPP DEBUG PEER %s\n", GCP_2s (p));
  LOG2 (level, "PPP last contact %s\n",
       GNUNET_STRINGS_absolute_time_to_string (p->last_contact));
  for (path = p->path_head; NULL != path; path = path->next)
  {
    char *s;

    s = path_2s (path);
    LOG2 (level, "PPP path: %s\n", s);
    GNUNET_free (s);
  }

  LOG2 (level, "PPP core transmit handle %p\n", p->core_transmit);
  LOG2 (level, "PPP DHT GET handle %p\n", p->search_h);
  conns = 0;
  if (NULL != p->connections)
    conns += GNUNET_CONTAINER_multihashmap_size (p->connections);
  LOG2 (level, "PPP # connections over link to peer: %u\n", conns);
  queue_debug (p, level);
  LOG2 (level, "PPP DEBUG END\n");
}


/******************************************************************************/
/*****************************  CORE HELPERS  *********************************/
/******************************************************************************/


/**
 * Iterator to notify all connections of a broken link. Mark connections
 * to destroy after all traffic has been sent.
 *
 * @param cls Closure (disconnected peer).
 * @param key Current key code (peer id).
 * @param value Value in the hash map (connection).
 *
 * @return #GNUNET_YES to continue to iterate.
 */
static int
notify_broken (void *cls,
               const struct GNUNET_HashCode *key,
               void *value)
{
  struct CadetPeer *peer = cls;
  struct CadetConnection *c = value;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Notifying %s due to %s disconnect\n",
       GCC_2s (c), GCP_2s (peer));
  GCC_neighbor_disconnected (c, peer);
  return GNUNET_YES;
}


/**
 * Remove the direct path to the peer.
 *
 * @param peer Peer to remove the direct path from.
 *
 */
static struct CadetPeerPath *
pop_direct_path (struct CadetPeer *peer)
{
  struct CadetPeerPath *iter;

  for (iter = peer->path_head; NULL != iter; iter = iter->next)
  {
    if (2 >= iter->length)
    {
      GNUNET_CONTAINER_DLL_remove (peer->path_head, peer->path_tail, iter);
      return iter;
    }
  }
  return NULL;
}


/******************************************************************************/
/***************************** CORE CALLBACKS *********************************/
/******************************************************************************/


/**
 * Method called whenever a given peer connects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 */
static void
core_connect (void *cls,
              const struct GNUNET_PeerIdentity *peer)
{
  struct CadetPeer *neighbor;
  struct CadetPeerPath *path;
  char own_id[16];

  GCC_check_connections ();
  GNUNET_snprintf (own_id,
                   sizeof (own_id),
                   "%s",
                   GNUNET_i2s (&my_full_id));
  neighbor = GCP_get (peer, GNUNET_YES);
  if (myid == neighbor->id)
  {
    LOG (GNUNET_ERROR_TYPE_INFO,
         "CONNECTED %s (self)\n",
         own_id);
    path = path_new (1);
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_INFO,
         "CONNECTED %s <= %s\n",
         own_id,
         GNUNET_i2s (peer));
    path = path_new (2);
    path->peers[1] = neighbor->id;
    GNUNET_PEER_change_rc (neighbor->id, 1);
  }
  path->peers[0] = myid;
  GNUNET_PEER_change_rc (myid, 1);
  GCP_add_path (neighbor, path, GNUNET_YES);

  GNUNET_assert (NULL == neighbor->connections);
  neighbor->connections = GNUNET_CONTAINER_multihashmap_create (16, GNUNET_NO);
  GNUNET_assert (NULL != neighbor->connections);

  GNUNET_STATISTICS_update (stats,
                            "# peers",
                            1,
                            GNUNET_NO);

  if ( (NULL != GCP_get_tunnel (neighbor)) &&
       (0 > GNUNET_CRYPTO_cmp_peer_identity (&my_full_id, peer)) )
    GCP_connect (neighbor);
  GCC_check_connections ();
}


/**
 * Method called whenever a peer disconnects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 */
static void
core_disconnect (void *cls,
                 const struct GNUNET_PeerIdentity *peer)
{
  struct CadetPeer *p;
  struct CadetPeerPath *direct_path;
  char own_id[16];

  GCC_check_connections ();
  strncpy (own_id, GNUNET_i2s (&my_full_id), 16);
  own_id[15] = '\0';
  p = GNUNET_CONTAINER_multipeermap_get (peers, peer);
  if (NULL == p)
  {
    GNUNET_break (GNUNET_YES == in_shutdown);
    return;
  }
  if (myid == p->id)
    LOG (GNUNET_ERROR_TYPE_INFO,
         "DISCONNECTED %s (self)\n",
         own_id);
  else
    LOG (GNUNET_ERROR_TYPE_INFO,
         "DISCONNECTED %s <= %s\n",
         own_id, GNUNET_i2s (peer));
  direct_path = pop_direct_path (p);
  GNUNET_CONTAINER_multihashmap_iterate (p->connections,
                                         &notify_broken,
                                         p);
  GNUNET_CONTAINER_multihashmap_destroy (p->connections);
  p->connections = NULL;
  if (NULL != p->core_transmit)
  {
    GNUNET_CORE_notify_transmit_ready_cancel (p->core_transmit);
    p->core_transmit = NULL;
    p->tmt_time.abs_value_us = 0;
  }
  GNUNET_STATISTICS_update (stats,
                            "# peers",
                            -1,
                            GNUNET_NO);
  path_destroy (direct_path);
  GCC_check_connections ();
}


/**
 * Functions to handle messages from core
 */
static struct GNUNET_CORE_MessageHandler core_handlers[] = {
  {&GCC_handle_create, GNUNET_MESSAGE_TYPE_CADET_CONNECTION_CREATE, 0},
  {&GCC_handle_confirm, GNUNET_MESSAGE_TYPE_CADET_CONNECTION_ACK,
    sizeof (struct GNUNET_CADET_ConnectionACK)},
  {&GCC_handle_broken, GNUNET_MESSAGE_TYPE_CADET_CONNECTION_BROKEN,
    sizeof (struct GNUNET_CADET_ConnectionBroken)},
  {&GCC_handle_destroy, GNUNET_MESSAGE_TYPE_CADET_CONNECTION_DESTROY,
    sizeof (struct GNUNET_CADET_ConnectionDestroy)},
  {&GCC_handle_ack, GNUNET_MESSAGE_TYPE_CADET_ACK,
    sizeof (struct GNUNET_CADET_ACK)},
  {&GCC_handle_poll, GNUNET_MESSAGE_TYPE_CADET_POLL,
    sizeof (struct GNUNET_CADET_Poll)},
  {&GCC_handle_kx, GNUNET_MESSAGE_TYPE_CADET_KX, 0},
  {&GCC_handle_encrypted, GNUNET_MESSAGE_TYPE_CADET_ENCRYPTED, 0},
  {&GCC_handle_encrypted, GNUNET_MESSAGE_TYPE_CADET_AX, 0},
  {NULL, 0, 0}
};


/**
 * To be called on core init/fail.
 *
 * @param cls Closure (config)
 * @param identity the public identity of this peer
 */
static void
core_init (void *cls,
           const struct GNUNET_PeerIdentity *identity)
{
  const struct GNUNET_CONFIGURATION_Handle *c = cls;
  static int i = 0;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Core init\n");
  if (0 != memcmp (identity, &my_full_id, sizeof (my_full_id)))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR, _("Wrong CORE service\n"));
    LOG (GNUNET_ERROR_TYPE_ERROR, " core id %s\n", GNUNET_i2s (identity));
    LOG (GNUNET_ERROR_TYPE_ERROR, " my id %s\n", GNUNET_i2s (&my_full_id));
    GNUNET_CORE_disconnect (core_handle);
    core_handle = GNUNET_CORE_connect (c, /* Main configuration */
                                       NULL,      /* Closure passed to CADET functions */
                                       &core_init,        /* Call core_init once connected */
                                       &core_connect,     /* Handle connects */
                                       &core_disconnect,  /* remove peers on disconnects */
                                       NULL,      /* Don't notify about all incoming messages */
                                       GNUNET_NO, /* For header only in notification */
                                       NULL,      /* Don't notify about all outbound messages */
                                       GNUNET_NO, /* For header-only out notification */
                                       core_handlers);    /* Register these handlers */
    if (10 < i++)
      GNUNET_assert (0);
  }
  GML_start ();
}


/**
  * Core callback to write a pre-constructed data packet to core buffer
  *
  * @param cls Closure (CadetTransmissionDescriptor with data in "data" member).
  * @param size Number of bytes available in buf.
  * @param buf Where the to write the message.
  *
  * @return number of bytes written to buf
  */
static size_t
send_core_data_raw (void *cls, size_t size, void *buf)
{
  struct GNUNET_MessageHeader *msg = cls;
  size_t total_size;

  GNUNET_assert (NULL != msg);
  total_size = ntohs (msg->size);

  if (total_size > size)
  {
    GNUNET_break (0);
    return 0;
  }
  memcpy (buf, msg, total_size);
  GNUNET_free (cls);
  return total_size;
}


/**
 * Function to send a create connection message to a peer.
 *
 * @param c Connection to create.
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t
send_core_connection_create (struct CadetConnection *c, size_t size, void *buf)
{
  struct GNUNET_CADET_ConnectionCreate *msg;
  struct GNUNET_PeerIdentity *peer_ptr;
  const struct CadetPeerPath *p = GCC_get_path (c);
  size_t size_needed;
  int i;

  if (NULL == p)
    return 0;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Sending CONNECTION CREATE...\n");
  size_needed =
      sizeof (struct GNUNET_CADET_ConnectionCreate) +
      p->length * sizeof (struct GNUNET_PeerIdentity);

  if (size < size_needed || NULL == buf)
  {
    GNUNET_break (0);
    return 0;
  }
  msg = (struct GNUNET_CADET_ConnectionCreate *) buf;
  msg->header.size = htons (size_needed);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_CADET_CONNECTION_CREATE);
  msg->cid = *GCC_get_id (c);

  peer_ptr = (struct GNUNET_PeerIdentity *) &msg[1];
  for (i = 0; i < p->length; i++)
  {
    GNUNET_PEER_resolve (p->peers[i], peer_ptr++);
  }

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "CONNECTION CREATE (%u bytes long) sent!\n",
       size_needed);
  return size_needed;
}


/**
 * Creates a path ack message in buf and frees all unused resources.
 *
 * @param c Connection to send an ACK on.
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 *
 * @return number of bytes written to buf
 */
static size_t
send_core_connection_ack (struct CadetConnection *c, size_t size, void *buf)
{
  struct GNUNET_CADET_ConnectionACK *msg = buf;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Sending CONNECTION ACK...\n");
  if (sizeof (struct GNUNET_CADET_ConnectionACK) > size)
  {
    GNUNET_break (0);
    return 0;
  }
  msg->header.size = htons (sizeof (struct GNUNET_CADET_ConnectionACK));
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_CADET_CONNECTION_ACK);
  msg->cid = *GCC_get_id (c);

  LOG (GNUNET_ERROR_TYPE_DEBUG, "CONNECTION ACK sent!\n");
  return sizeof (struct GNUNET_CADET_ConnectionACK);
}


/******************************************************************************/
/********************************   STATIC  ***********************************/
/******************************************************************************/


/**
 * Get priority for a queued message.
 *
 * @param q Queued message
 *
 * @return CORE priority to use.
 */
static enum GNUNET_CORE_Priority
get_priority (struct CadetPeerQueue *q)
{
  enum GNUNET_CORE_Priority low;
  enum GNUNET_CORE_Priority high;

  if (NULL == q)
  {
    GNUNET_break (0);
    return GNUNET_CORE_PRIO_BACKGROUND;
  }

  /* Relayed traffic has lower priority, our own traffic has higher */
  if (NULL == q->c || GNUNET_NO == GCC_is_origin (q->c, q->fwd))
  {
    low = GNUNET_CORE_PRIO_BEST_EFFORT;
    high = GNUNET_CORE_PRIO_URGENT;
  }
  else
  {
    low = GNUNET_CORE_PRIO_URGENT;
    high = GNUNET_CORE_PRIO_CRITICAL_CONTROL;
  }

  /* Bulky payload has lower priority, control traffic has higher. */
  if (GNUNET_MESSAGE_TYPE_CADET_ENCRYPTED == q->type
      || GNUNET_MESSAGE_TYPE_CADET_AX == q->type)
    return low;
  else
    return high;
}


/**
 * Destroy the peer_info and free any allocated resources linked to it
 *
 * @param peer The peer_info to destroy.
 * @return #GNUNET_OK on success
 */
static int
peer_destroy (struct CadetPeer *peer)
{
  struct GNUNET_PeerIdentity id;
  struct CadetPeerPath *p;
  struct CadetPeerPath *nextp;

  GNUNET_PEER_resolve (peer->id, &id);
  GNUNET_PEER_change_rc (peer->id, -1);

  LOG (GNUNET_ERROR_TYPE_INFO,
       "destroying peer %s\n",
       GNUNET_i2s (&id));

  if (GNUNET_YES != GNUNET_CONTAINER_multipeermap_remove (peers, &id, peer))
  {
    GNUNET_break (0);
    LOG (GNUNET_ERROR_TYPE_WARNING, " peer not in peermap!!\n");
  }
  GCP_stop_search (peer);
  p = peer->path_head;
  while (NULL != p)
  {
    nextp = p->next;
    GNUNET_CONTAINER_DLL_remove (peer->path_head,
                                 peer->path_tail,
                                 p);
    path_destroy (p);
    p = nextp;
  }
  if (NULL != peer->tunnel)
    GCT_destroy_empty (peer->tunnel);
  if (NULL != peer->connections)
  {
    GNUNET_assert (0 == GNUNET_CONTAINER_multihashmap_size (peer->connections));
    GNUNET_CONTAINER_multihashmap_destroy (peer->connections);
  }
  if (NULL != peer->core_transmit)
    GNUNET_CORE_notify_transmit_ready_cancel (peer->core_transmit);
  if (NULL != peer->hello_offer)
  {
    GNUNET_TRANSPORT_offer_hello_cancel (peer->hello_offer);
    peer->hello_offer = NULL;
  }
  if (NULL != peer->connectivity_suggestion)
  {
    GNUNET_ATS_connectivity_suggest_cancel (peer->connectivity_suggestion);
    peer->connectivity_suggestion = NULL;
  }
  GNUNET_free_non_null (peer->hello);
  GNUNET_free (peer);
  return GNUNET_OK;
}


/**
 * Iterator over peer hash map entries to destroy the peer during in_shutdown.
 *
 * @param cls closure
 * @param key current key code
 * @param value value in the hash map
 * @return #GNUNET_YES if we should continue to iterate,
 *         #GNUNET_NO if not.
 */
static int
shutdown_peer (void *cls,
               const struct GNUNET_PeerIdentity *key,
               void *value)
{
  struct CadetPeer *p = value;
  struct CadetTunnel *t = p->tunnel;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  shutting down %s\n", GCP_2s (p));
  if (NULL != t)
    GCT_destroy (t);
  p->tunnel = NULL;
  peer_destroy (p);
  return GNUNET_YES;
}



/**
 * Check if peer is searching for a path (either active or delayed search).
 *
 * @param peer Peer to check
 * @return #GNUNET_YES if there is a search active.
 *         #GNUNET_NO otherwise.
 */
static int
is_searching (const struct CadetPeer *peer)
{
  return ( (NULL == peer->search_h) &&
           (NULL == peer->search_delayed) ) ?
    GNUNET_NO : GNUNET_YES;
}


/**
 * @brief Start a search for a peer.
 *
 * @param cls Closure (Peer to search for).
 * @param tc Task context.
 */
static void
delayed_search (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct CadetPeer *peer = cls;

  peer->search_delayed = NULL;
  if (0 != (GNUNET_SCHEDULER_REASON_SHUTDOWN & tc->reason))
    return;
  GCC_check_connections ();
  GCP_start_search (peer);
  GCC_check_connections ();
}


/**
 * Returns if peer is used (has a tunnel or is neighbor).
 *
 * @param peer Peer to check.
 * @return #GNUNET_YES if peer is in use.
 */
static int
peer_is_used (struct CadetPeer *peer)
{
  struct CadetPeerPath *p;

  if (NULL != peer->tunnel)
    return GNUNET_YES;

  for (p = peer->path_head; NULL != p; p = p->next)
  {
    if (p->length < 3)
      return GNUNET_YES;
  }
    return GNUNET_NO;
}


/**
 * Iterator over all the peers to get the oldest timestamp.
 *
 * @param cls Closure (unsued).
 * @param key ID of the peer.
 * @param value Peer_Info of the peer.
 */
static int
peer_get_oldest (void *cls,
                 const struct GNUNET_PeerIdentity *key,
                 void *value)
{
  struct CadetPeer *p = value;
  struct GNUNET_TIME_Absolute *abs = cls;

  /* Don't count active peers */
  if (GNUNET_YES == peer_is_used (p))
    return GNUNET_YES;

  if (abs->abs_value_us < p->last_contact.abs_value_us)
    abs->abs_value_us = p->last_contact.abs_value_us;

  return GNUNET_YES;
}


/**
 * Iterator over all the peers to remove the oldest entry.
 *
 * @param cls Closure (unsued).
 * @param key ID of the peer.
 * @param value Peer_Info of the peer.
 */
static int
peer_timeout (void *cls,
              const struct GNUNET_PeerIdentity *key,
              void *value)
{
  struct CadetPeer *p = value;
  struct GNUNET_TIME_Absolute *abs = cls;

  LOG (GNUNET_ERROR_TYPE_WARNING,
       "peer %s timeout\n", GNUNET_i2s (key));

  if (p->last_contact.abs_value_us == abs->abs_value_us &&
      GNUNET_NO == peer_is_used (p))
  {
    peer_destroy (p);
    return GNUNET_NO;
  }
    return GNUNET_YES;
}


/**
 * Delete oldest unused peer.
 */
static void
peer_delete_oldest (void)
{
  struct GNUNET_TIME_Absolute abs;

  abs = GNUNET_TIME_UNIT_FOREVER_ABS;

  GNUNET_CONTAINER_multipeermap_iterate (peers,
                                         &peer_get_oldest,
                                         &abs);
  GNUNET_CONTAINER_multipeermap_iterate (peers,
                                         &peer_timeout,
                                         &abs);
}


/**
 * Choose the best (yet unused) path towards a peer,
 * considering the tunnel properties.
 *
 * @param peer The destination peer.
 * @return Best current known path towards the peer, if any.
 */
static struct CadetPeerPath *
peer_get_best_path (const struct CadetPeer *peer)
{
  struct CadetPeerPath *best_p;
  struct CadetPeerPath *p;
  unsigned int best_cost;
  unsigned int cost;

  best_cost = UINT_MAX;
  best_p = NULL;
  for (p = peer->path_head; NULL != p; p = p->next)
  {
    if (GNUNET_NO == path_is_valid (p))
      continue; /* Don't use invalid paths. */
    if (GNUNET_YES == GCT_is_path_used (peer->tunnel, p))
      continue; /* If path is already in use, skip it. */

    if ((cost = GCT_get_path_cost (peer->tunnel, p)) < best_cost)
    {
      best_cost = cost;
      best_p = p;
    }
  }
  return best_p;
}


/**
 * Is this queue element sendable?
 *
 * - All management traffic is always sendable.
 * - For payload traffic, check the connection flow control.
 *
 * @param q Queue element to inspect.
 * @return #GNUNET_YES if it is sendable, #GNUNET_NO otherwise.
 */
static int
queue_is_sendable (struct CadetPeerQueue *q)
{
  /* Is PID-independent? */
  switch (q->type)
  {
    case GNUNET_MESSAGE_TYPE_CADET_ACK:
    case GNUNET_MESSAGE_TYPE_CADET_POLL:
    case GNUNET_MESSAGE_TYPE_CADET_KX:
    case GNUNET_MESSAGE_TYPE_CADET_CONNECTION_CREATE:
    case GNUNET_MESSAGE_TYPE_CADET_CONNECTION_ACK:
    case GNUNET_MESSAGE_TYPE_CADET_CONNECTION_DESTROY:
    case GNUNET_MESSAGE_TYPE_CADET_CONNECTION_BROKEN:
      return GNUNET_YES;

    case GNUNET_MESSAGE_TYPE_CADET_ENCRYPTED:
    case GNUNET_MESSAGE_TYPE_CADET_AX:
      break;

    default:
      GNUNET_break (0);
  }

  return GCC_is_sendable (q->c, q->fwd);
}


/**
 * Get first sendable message.
 *
 * @param peer The destination peer.
 *
 * @return First transmittable message, if any. Otherwise, NULL.
 */
static struct CadetPeerQueue *
peer_get_first_message (const struct CadetPeer *peer)
{
  struct CadetPeerQueue *q;

  for (q = peer->queue_head; NULL != q; q = q->next)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Checking q:%p on c:%s\n", q, GCC_2s (q->c));
    if (queue_is_sendable (q))
      return q;
  }

  return NULL;
}


/**
 * Function to process paths received for a new peer addition. The recorded
 * paths form the initial tunnel, which can be optimized later.
 * Called on each result obtained for the DHT search.
 *
 * @param cls Closure (peer towards a path has been found).
 * @param path Path created from the DHT query. Will be freed afterwards.
 */
static void
search_handler (void *cls, const struct CadetPeerPath *path)
{
  struct CadetPeer *peer = cls;
  unsigned int connection_count;

  GCC_check_connections ();
  GCP_add_path_to_all (path, GNUNET_NO);

  /* Count connections */
  connection_count = GCT_count_connections (peer->tunnel);

  /* If we already have our minimum (or more) connections, it's enough */
  if (CONNECTIONS_PER_TUNNEL <= connection_count)
  {
    GCC_check_connections ();
    return;
  }

  if (CADET_TUNNEL_SEARCHING == GCT_get_cstate (peer->tunnel))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, " ... connect!\n");
    GCP_connect (peer);
  }
  GCC_check_connections ();
}


/**
 * Adjust core requested size to accomodate an ACK.
 *
 * @param message_size Requested size.
 *
 * @return Size enough to fit @c message_size and an ACK.
 */
static size_t
get_core_size (size_t message_size)
{
  return message_size + sizeof (struct GNUNET_CADET_ACK);
}


/**
 * Fill a core buffer with the appropriate data for the queued message.
 *
 * @param queue Queue element for the message.
 * @param buf Core buffer to fill.
 * @param size Size remaining in @c buf.
 * @param[out] pid In case its an encrypted payload, set payload.
 *
 * @return Bytes written to @c buf.
 */
static size_t
fill_buf (struct CadetPeerQueue *queue, void *buf, size_t size, uint32_t *pid)
{
  struct CadetConnection *c = queue->c;
  size_t msg_size;

  switch (queue->type)
  {
    case GNUNET_MESSAGE_TYPE_CADET_ENCRYPTED:
      *pid = GCC_get_pid (queue->c, queue->fwd);
      LOG (GNUNET_ERROR_TYPE_DEBUG, "  otr payload ID %u\n", *pid);
      msg_size = send_core_data_raw (queue->cls, size, buf);
      ((struct GNUNET_CADET_Encrypted *) buf)->pid = htonl (*pid);
      break;
    case GNUNET_MESSAGE_TYPE_CADET_AX:
      *pid = GCC_get_pid (queue->c, queue->fwd);
      LOG (GNUNET_ERROR_TYPE_DEBUG, "  ax payload ID %u\n", *pid);
      msg_size = send_core_data_raw (queue->cls, size, buf);
      ((struct GNUNET_CADET_AX *) buf)->pid = htonl (*pid);
      break;
    case GNUNET_MESSAGE_TYPE_CADET_CONNECTION_DESTROY:
    case GNUNET_MESSAGE_TYPE_CADET_CONNECTION_BROKEN:
    case GNUNET_MESSAGE_TYPE_CADET_KX:
    case GNUNET_MESSAGE_TYPE_CADET_ACK:
    case GNUNET_MESSAGE_TYPE_CADET_POLL:
      LOG (GNUNET_ERROR_TYPE_DEBUG, "  raw %s\n", GC_m2s (queue->type));
      msg_size = send_core_data_raw (queue->cls, size, buf);
      break;
    case GNUNET_MESSAGE_TYPE_CADET_CONNECTION_CREATE:
      LOG (GNUNET_ERROR_TYPE_DEBUG, "  path create\n");
      if (GCC_is_origin (c, GNUNET_YES))
        msg_size = send_core_connection_create (c, size, buf);
      else
        msg_size = send_core_data_raw (queue->cls, size, buf);
      break;
    case GNUNET_MESSAGE_TYPE_CADET_CONNECTION_ACK:
      LOG (GNUNET_ERROR_TYPE_DEBUG, "  path ack\n");
      if (GCC_is_origin (c, GNUNET_NO) ||
          GCC_is_origin (c, GNUNET_YES))
      {
        msg_size = send_core_connection_ack (c, size, buf);
      }
      else
      {
        msg_size = send_core_data_raw (queue->cls, size, buf);
      }
      break;
    case GNUNET_MESSAGE_TYPE_CADET_DATA:
    case GNUNET_MESSAGE_TYPE_CADET_CHANNEL_CREATE:
    case GNUNET_MESSAGE_TYPE_CADET_CHANNEL_DESTROY:
      /* This should be encapsulted */
      msg_size = 0;
      GNUNET_assert (0);
      break;
    default:
      GNUNET_break (0);
      LOG (GNUNET_ERROR_TYPE_WARNING, "  type unknown: %u\n", queue->type);
      msg_size = 0;
  }

  GNUNET_assert (size >= msg_size);

  return msg_size;
}


/**
 * Debug function should NEVER return true in production code, useful to
 * simulate losses for testcases.
 *
 * @param q Queue handle with info about the message.
 *
 * @return #GNUNET_YES or #GNUNET_NO with the decision to drop.
 */
static int
should_I_drop (struct CadetPeerQueue *q)
{
  if (0 == drop_percent)
    return GNUNET_NO;

  if (GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, 101) < drop_percent)
    return GNUNET_YES;

  return GNUNET_NO;
}


/**
 * Core callback to write a queued packet to core buffer
 *
 * @param cls Closure (peer info).
 * @param size Number of bytes available in buf.
 * @param buf Where the to write the message.
 *
 * @return number of bytes written to buf
 */
static size_t
queue_send (void *cls, size_t size, void *buf)
{
  struct CadetPeer *peer = cls;
  struct CadetConnection *c;
  struct CadetPeerQueue *queue;
  struct GNUNET_TIME_Relative core_wait_time;
  const char *wait_s;
  const struct GNUNET_PeerIdentity *dst_id;
  size_t msg_size;
  size_t total_size;
  size_t rest;
  char *dst;
  uint32_t pid;

  GCC_check_connections ();
  LOG (GNUNET_ERROR_TYPE_DEBUG, "\n");
  LOG (GNUNET_ERROR_TYPE_DEBUG, "\n");
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Queue send towards %s (max %u)\n",
       GCP_2s (peer), size);

  /* Sanity checking */
  if (NULL == buf || 0 == size)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  not allowed/\n");
    if (GNUNET_NO == in_shutdown)
    {
      queue = peer_get_first_message (peer);
      if (NULL == queue)
      {
        peer->core_transmit = NULL;
        peer->tmt_time.abs_value_us = 0;
        GCC_check_connections ();
        return 0;
      }
      dst_id = GNUNET_PEER_resolve2 (peer->id);
      peer->core_transmit =
          GNUNET_CORE_notify_transmit_ready (core_handle,
                                             GNUNET_NO, get_priority (queue),
                                             GNUNET_TIME_UNIT_FOREVER_REL,
                                             dst_id,
                                             get_core_size (queue->size),
                                             &queue_send,
                                             peer);
      peer->tmt_time = GNUNET_TIME_absolute_get ();
    }
    else
    {
      peer->core_transmit = NULL;
      peer->tmt_time.abs_value_us = 0;
    }
    GCC_check_connections ();
    return 0;
  }

  /* Init */
  rest = size;
  total_size = 0;
  dst = (char *) buf;
  pid = 0;
  peer->core_transmit = NULL;
  queue = peer_get_first_message (peer);
  if (NULL == queue)
  {
    GNUNET_break (0); /* Core tmt_rdy should've been canceled */
    peer->tmt_time.abs_value_us = 0;
    return 0;
  }
  core_wait_time = GNUNET_TIME_absolute_get_duration (peer->tmt_time);
  wait_s = GNUNET_STRINGS_relative_time_to_string (core_wait_time, GNUNET_YES);
  if (core_wait_time.rel_value_us >= 1000000)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         " %s: core wait time %s (> 1 second) for %u bytes\n",
         GCP_2s (peer), wait_s, queue->size);
  }
  peer->tmt_time.abs_value_us = 0;

  /* Copy all possible messages to the core buffer */
  while (NULL != queue && rest >= queue->size)
  {
    c = queue->c;

    LOG (GNUNET_ERROR_TYPE_DEBUG, "  on conn %s %s\n",
         GCC_2s (c), GC_f2s(queue->fwd));
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  size %u ok (%u/%u)\n",
         queue->size, total_size, size);

    msg_size = fill_buf (queue, (void *) dst, size, &pid);

    if (should_I_drop (queue))
    {
      LOG (GNUNET_ERROR_TYPE_WARNING, "DD %s (%s %u) on conn %s %s\n",
           GC_m2s (queue->type), GC_m2s (queue->payload_type),
           queue->payload_id, GCC_2s (c), GC_f2s (queue->fwd));
      msg_size = 0;
    }
    else
    {
      LOG (GNUNET_ERROR_TYPE_INFO,
           ">>> %s (%s %4u) on conn %s (%p) %s [%5u], after %s\n",
           GC_m2s (queue->type), GC_m2s (queue->payload_type),
           queue->payload_id, GCC_2s (c), c,
           GC_f2s (queue->fwd), msg_size, wait_s);
    }
    total_size += msg_size;
    rest -= msg_size;
    dst = &dst[msg_size];
    msg_size = 0;

    /* Free queue, but cls was freed by send_core_* in fill_buf. */
    (void) GCP_queue_destroy (queue, GNUNET_NO, GNUNET_YES, pid);

    /* Next! */
    queue = peer_get_first_message (peer);
  }

  /* If more data in queue, send next */
  if (NULL != queue)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  more data! (%u)\n", queue->size);
    if (NULL == peer->core_transmit)
    {
      dst_id = GNUNET_PEER_resolve2 (peer->id);
      peer->core_transmit =
          GNUNET_CORE_notify_transmit_ready (core_handle,
                                             GNUNET_NO, get_priority (queue),
                                             GNUNET_TIME_UNIT_FOREVER_REL,
                                             dst_id,
                                             get_core_size (queue->size),
                                             &queue_send,
                                             peer);
      peer->tmt_time = GNUNET_TIME_absolute_get ();
      queue->start_waiting = GNUNET_TIME_absolute_get ();
    }
    else
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, "*   tmt rdy called somewhere else\n");
    }
//     GCC_start_poll (); FIXME needed?
  }
  else
  {
//     GCC_stop_poll(); FIXME needed?
  }

  LOG (GNUNET_ERROR_TYPE_DEBUG, "  return %d\n", total_size);
  queue_debug (peer, GNUNET_ERROR_TYPE_DEBUG);
  GCC_check_connections ();
  return total_size;
}


/******************************************************************************/
/********************************    API    ***********************************/
/******************************************************************************/


/**
 * Free a transmission that was already queued with all resources
 * associated to the request.
 *
 * If connection was marked to be destroyed, and this was the last queued
 * message on it, the connection will be free'd as a result.
 *
 * @param queue Queue handler to cancel.
 * @param clear_cls Is it necessary to free associated cls?
 * @param sent Was it really sent? (Could have been canceled)
 * @param pid PID, if relevant (was sent and was a payload message).
 *
 * @return #GNUNET_YES if connection was destroyed as a result,
 *         #GNUNET_NO otherwise.
 */
int
GCP_queue_destroy (struct CadetPeerQueue *queue,
                   int clear_cls,
                   int sent,
                   uint32_t pid)
{
  struct CadetPeer *peer;
  int connection_destroyed;

  GCC_check_connections ();
  peer = queue->peer;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "queue destroy %s\n", GC_m2s (queue->type));
  if (GNUNET_YES == clear_cls)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, " free cls\n");
    switch (queue->type)
    {
      case GNUNET_MESSAGE_TYPE_CADET_CONNECTION_DESTROY:
        LOG (GNUNET_ERROR_TYPE_INFO, "destroying a DESTROY message\n");
        /* fall through */
      case GNUNET_MESSAGE_TYPE_CADET_CONNECTION_ACK:
      case GNUNET_MESSAGE_TYPE_CADET_CONNECTION_CREATE:
      case GNUNET_MESSAGE_TYPE_CADET_CONNECTION_BROKEN:
      case GNUNET_MESSAGE_TYPE_CADET_KX:
      case GNUNET_MESSAGE_TYPE_CADET_ENCRYPTED:
      case GNUNET_MESSAGE_TYPE_CADET_AX:
      case GNUNET_MESSAGE_TYPE_CADET_ACK:
      case GNUNET_MESSAGE_TYPE_CADET_POLL:
        GNUNET_free_non_null (queue->cls);
        break;

      default:
        GNUNET_break (0);
        LOG (GNUNET_ERROR_TYPE_ERROR, " type %s unknown!\n",
             GC_m2s (queue->type));
    }
  }
  GNUNET_CONTAINER_DLL_remove (peer->queue_head, peer->queue_tail, queue);

  if (queue->type != GNUNET_MESSAGE_TYPE_CADET_ACK &&
      queue->type != GNUNET_MESSAGE_TYPE_CADET_POLL)
  {
    peer->queue_n--;
  }

  if (NULL != queue->cont)
  {
    struct GNUNET_TIME_Relative wait_time;

    wait_time = GNUNET_TIME_absolute_get_duration (queue->start_waiting);
    LOG (GNUNET_ERROR_TYPE_DEBUG, " calling callback, time elapsed %s\n",
         GNUNET_STRINGS_relative_time_to_string (wait_time, GNUNET_NO));
    connection_destroyed = queue->cont (queue->cont_cls,
                                        queue->c, sent, queue->type, pid,
                                        queue->fwd, queue->size, wait_time);
  }
  else
  {
    connection_destroyed = GNUNET_NO;
  }

  if (NULL == peer_get_first_message (peer) && NULL != peer->core_transmit)
  {
    GNUNET_CORE_notify_transmit_ready_cancel (peer->core_transmit);
    peer->core_transmit = NULL;
    peer->tmt_time.abs_value_us = 0;
  }

  GNUNET_free (queue);
  GCC_check_connections ();
  return connection_destroyed;
}


/**
 * @brief Queue and pass message to core when possible.
 *
 * @param peer Peer towards which to queue the message.
 * @param cls Closure (@c type dependant). It will be used by queue_send to
 *            build the message to be sent if not already prebuilt.
 * @param type Type of the message.
 * @param payload_type Type of the message's payload
 *                     0 if the message is a retransmission (unknown payload).
 *                     UINT16_MAX if the message does not have payload.
 * @param payload_id ID of the payload (MID, ACK #, etc)
 * @param size Size of the message.
 * @param c Connection this message belongs to (can be NULL).
 * @param fwd Is this a message going root->dest? (FWD ACK are NOT FWD!)
 * @param cont Continuation to be called once CORE has taken the message.
 * @param cont_cls Closure for @c cont.
 *
 * @return Handle to cancel the message before it is sent. Once cont is called
 *         message has been sent and therefore the handle is no longer valid.
 */
struct CadetPeerQueue *
GCP_queue_add (struct CadetPeer *peer,
               void *cls,
               uint16_t type,
               uint16_t payload_type,
               uint32_t payload_id,
               size_t size,
               struct CadetConnection *c,
               int fwd,
               GCP_sent cont,
               void *cont_cls)
{
  struct CadetPeerQueue *q;
  int priority;
  int call_core;

  GCC_check_connections ();
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "que %s (%s %4u) on conn %s (%p) %s towards %s (size %u)\n",
       GC_m2s (type), GC_m2s (payload_type), payload_id,
       GCC_2s (c), c, GC_f2s (fwd), GCP_2s (peer), size);

  if (NULL == peer->connections)
  {
    /* We are not connected to this peer, ignore request. */
    LOG (GNUNET_ERROR_TYPE_INFO, "%s not a neighbor\n", GCP_2s (peer));
    GNUNET_STATISTICS_update (stats, "# messages dropped due to wrong hop", 1,
                              GNUNET_NO);
    return NULL;
  }

  priority = 0;

  if (GNUNET_MESSAGE_TYPE_CADET_POLL == type ||
      GNUNET_MESSAGE_TYPE_CADET_ACK == type)
  {
    priority = 100;
  }

  LOG (GNUNET_ERROR_TYPE_DEBUG, "priority %d\n", priority);

  call_core = (NULL == c || type == GNUNET_MESSAGE_TYPE_CADET_KX) ?
               GNUNET_YES : GCC_is_sendable (c, fwd);
  q = GNUNET_new (struct CadetPeerQueue);
  q->cls = cls;
  q->type = type;
  q->payload_type = payload_type;
  q->payload_id = payload_id;
  q->size = size;
  q->peer = peer;
  q->c = c;
  q->fwd = fwd;
  q->cont = cont;
  q->cont_cls = cont_cls;
  if (100 > priority)
  {
    GNUNET_CONTAINER_DLL_insert_tail (peer->queue_head, peer->queue_tail, q);
    peer->queue_n++;
  }
  else
  {
    GNUNET_CONTAINER_DLL_insert (peer->queue_head, peer->queue_tail, q);
    call_core = GNUNET_YES;
  }

  q->start_waiting = GNUNET_TIME_absolute_get ();
  if (NULL == peer->core_transmit && GNUNET_YES == call_core)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "calling core tmt rdy towards %s for %u bytes\n",
         GCP_2s (peer), size);
    peer->core_transmit =
        GNUNET_CORE_notify_transmit_ready (core_handle,
                                           GNUNET_NO, get_priority (q),
                                           GNUNET_TIME_UNIT_FOREVER_REL,
                                           GNUNET_PEER_resolve2 (peer->id),
                                           get_core_size (size),
                                           &queue_send, peer);
    peer->tmt_time = GNUNET_TIME_absolute_get ();
  }
  else if (GNUNET_NO == call_core)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "core tmt rdy towards %s not needed\n",
         GCP_2s (peer));

  }
  else
  {
    struct GNUNET_TIME_Relative elapsed;
    elapsed = GNUNET_TIME_absolute_get_duration (peer->tmt_time);
    LOG (GNUNET_ERROR_TYPE_DEBUG, "core tmt rdy towards %s already called %s\n",
         GCP_2s (peer),
         GNUNET_STRINGS_relative_time_to_string (elapsed, GNUNET_NO));

  }
  queue_debug (peer, GNUNET_ERROR_TYPE_DEBUG);
  GCC_check_connections ();
  return q;
}


/**
 * Cancel all queued messages to a peer that belong to a certain connection.
 *
 * @param peer Peer towards whom to cancel.
 * @param c Connection whose queued messages to cancel. Might be destroyed by
 *          the sent continuation call.
 */
void
GCP_queue_cancel (struct CadetPeer *peer,
                  struct CadetConnection *c)
{
  struct CadetPeerQueue *q;
  struct CadetPeerQueue *next;
  struct CadetPeerQueue *prev;
  int connection_destroyed;

  GCC_check_connections ();
  connection_destroyed = GNUNET_NO;
  for (q = peer->queue_head; NULL != q; q = next)
  {
    prev = q->prev;
    if (q->c == c)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "GMP queue cancel %s\n",
           GC_m2s (q->type));
      GNUNET_assert (GNUNET_NO == connection_destroyed);
      if (GNUNET_MESSAGE_TYPE_CADET_CONNECTION_DESTROY == q->type)
      {
        q->c = NULL;
      }
      else
      {
        connection_destroyed = GCP_queue_destroy (q, GNUNET_YES, GNUNET_NO, 0);
      }

      /* Get next from prev, q->next might be already freed:
       * queue destroy -> callback -> GCC_destroy -> cancel_queues -> here
       */
      if (NULL == prev)
        next = peer->queue_head;
      else
        next = prev->next;
    }
    else
    {
      next = q->next;
    }
  }

  if ( (NULL == peer->queue_head) &&
       (NULL != peer->core_transmit) )
  {
    GNUNET_CORE_notify_transmit_ready_cancel (peer->core_transmit);
    peer->core_transmit = NULL;
    peer->tmt_time.abs_value_us = 0;
  }
  GCC_check_connections ();
}


/**
 * Get the first transmittable message for a connection.
 *
 * @param peer Neighboring peer.
 * @param c Connection.
 *
 * @return First transmittable message.
 */
static struct CadetPeerQueue *
connection_get_first_message (struct CadetPeer *peer, struct CadetConnection *c)
{
  struct CadetPeerQueue *q;

  for (q = peer->queue_head; NULL != q; q = q->next)
  {
    if (q->c != c)
      continue;
    if (queue_is_sendable (q))
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, "  sendable!!\n");
      return q;
    }
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  not sendable\n");
  }

  return NULL;
}


/**
 * Get the first message for a connection and unqueue it.
 *
 * Only tunnel (or higher) level messages are unqueued. Connection specific
 * messages are silently destroyed upon encounter.
 *
 * @param peer Neighboring peer.
 * @param c Connection.
 * @param destroyed[in/out] Was the connection destroyed (prev/as a result)?.
 *                          Can NOT be NULL.
 *
 * @return First message for this connection.
 */
struct GNUNET_MessageHeader *
GCP_connection_pop (struct CadetPeer *peer,
                    struct CadetConnection *c,
                    int *destroyed)
{
  struct CadetPeerQueue *q;
  struct CadetPeerQueue *next;
  struct GNUNET_MessageHeader *msg;
  int dest;

  GCC_check_connections ();
  GNUNET_assert (NULL != destroyed);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "connection_pop on conn %p\n", c);
  for (q = peer->queue_head; NULL != q; q = next)
  {
    next = q->next;
    if (q->c != c)
      continue;
    LOG (GNUNET_ERROR_TYPE_DEBUG, " - queued: %s (%s %u), cont: %p\n",
         GC_m2s (q->type), GC_m2s (q->payload_type), q->payload_id,
         q->cont);
    switch (q->type)
    {
      case GNUNET_MESSAGE_TYPE_CADET_CONNECTION_CREATE:
      case GNUNET_MESSAGE_TYPE_CADET_CONNECTION_ACK:
      case GNUNET_MESSAGE_TYPE_CADET_CONNECTION_DESTROY:
      case GNUNET_MESSAGE_TYPE_CADET_CONNECTION_BROKEN:
      case GNUNET_MESSAGE_TYPE_CADET_ACK:
      case GNUNET_MESSAGE_TYPE_CADET_POLL:
        dest = GCP_queue_destroy (q, GNUNET_YES, GNUNET_NO, 0);
        if (GNUNET_YES == dest)
        {
          GNUNET_break (GNUNET_NO == *destroyed);
          *destroyed = GNUNET_YES;
        }
        continue;

      case GNUNET_MESSAGE_TYPE_CADET_KX:
      case GNUNET_MESSAGE_TYPE_CADET_ENCRYPTED:
      case GNUNET_MESSAGE_TYPE_CADET_AX:
      case GNUNET_MESSAGE_TYPE_CADET_AX_KX:
        msg = (struct GNUNET_MessageHeader *) q->cls;
        dest = GCP_queue_destroy (q, GNUNET_NO, GNUNET_NO, 0);
        if (GNUNET_YES == dest)
        {
          GNUNET_break (GNUNET_NO == *destroyed);
          *destroyed = GNUNET_YES;
        }
        return msg;

      default:
        GNUNET_break (0);
        LOG (GNUNET_ERROR_TYPE_DEBUG, "Unknown message %s\n", GC_m2s (q->type));
    }
  }
  GCC_check_connections ();
  return NULL;
}


/**
 * Unlock a possibly locked queue for a connection.
 *
 * If there is a message that can be sent on this connection, call core for it.
 * Otherwise (if core transmit is already called or there is no sendable
 * message) do nothing.
 *
 * @param peer Peer who keeps the queue.
 * @param c Connection whose messages to unlock.
 */
void
GCP_queue_unlock (struct CadetPeer *peer, struct CadetConnection *c)
{
  struct CadetPeerQueue *q;
  size_t size;

  GCC_check_connections ();
  if (NULL != peer->core_transmit)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  already unlocked!\n");
    return; /* Already unlocked */
  }

  q = connection_get_first_message (peer, c);
  if (NULL == q)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  queue empty!\n");
    return; /* Nothing to transmit */
  }

  size = q->size;
  peer->core_transmit =
      GNUNET_CORE_notify_transmit_ready (core_handle,
                                         GNUNET_NO, get_priority (q),
                                         GNUNET_TIME_UNIT_FOREVER_REL,
                                         GNUNET_PEER_resolve2 (peer->id),
                                         get_core_size (size),
                                         &queue_send,
                                         peer);
  peer->tmt_time = GNUNET_TIME_absolute_get ();
  GCC_check_connections ();
}


/**
 * Initialize the peer subsystem.
 *
 * @param c Configuration.
 */
void
GCP_init (const struct GNUNET_CONFIGURATION_Handle *c)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "GCP_init\n");
  in_shutdown = GNUNET_NO;
  peers = GNUNET_CONTAINER_multipeermap_create (128, GNUNET_NO);
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (c, "CADET", "MAX_PEERS",
                                             &max_peers))
  {
    GNUNET_log_config_invalid (GNUNET_ERROR_TYPE_WARNING,
                               "CADET", "MAX_PEERS", "USING DEFAULT");
    max_peers = 1000;
  }

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (c, "CADET", "DROP_PERCENT",
                                             &drop_percent))
  {
    drop_percent = 0;
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_WARNING, "**************************************\n");
    LOG (GNUNET_ERROR_TYPE_WARNING, "Cadet is running with DROP enabled.\n");
    LOG (GNUNET_ERROR_TYPE_WARNING, "This is NOT a good idea!\n");
    LOG (GNUNET_ERROR_TYPE_WARNING, "Remove DROP_PERCENT from config file.\n");
    LOG (GNUNET_ERROR_TYPE_WARNING, "**************************************\n");
  }
  ats_ch = GNUNET_ATS_connectivity_init (c);
  core_handle = GNUNET_CORE_connect (c, /* Main configuration */
                                     NULL,      /* Closure passed to CADET functions */
                                     &core_init,        /* Call core_init once connected */
                                     &core_connect,     /* Handle connects */
                                     &core_disconnect,  /* remove peers on disconnects */
                                     NULL,      /* Don't notify about all incoming messages */
                                     GNUNET_NO, /* For header only in notification */
                                     NULL,      /* Don't notify about all outbound messages */
                                     GNUNET_NO, /* For header-only out notification */
                                     core_handlers);    /* Register these handlers */
  if (GNUNET_YES !=
      GNUNET_CONFIGURATION_get_value_yesno (c, "CADET", "DISABLE_TRY_CONNECT"))
  {
    transport_handle = GNUNET_TRANSPORT_connect (c, &my_full_id, NULL, /* cls */
                                                 /* Notify callbacks */
                                                 NULL, NULL, NULL);
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_WARNING, "**************************************\n");
    LOG (GNUNET_ERROR_TYPE_WARNING, "*  DISABLE TRYING CONNECT in config  *\n");
    LOG (GNUNET_ERROR_TYPE_WARNING, "*  Use this only for test purposes.  *\n");
    LOG (GNUNET_ERROR_TYPE_WARNING, "**************************************\n");
    transport_handle = NULL;
  }



  if (NULL == core_handle)
  {
    GNUNET_break (0);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

}


/**
 * Shut down the peer subsystem.
 */
void
GCP_shutdown (void)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Shutting down peer subsystem\n");
  in_shutdown = GNUNET_YES;
  GNUNET_CONTAINER_multipeermap_iterate (peers,
                                         &shutdown_peer,
                                         NULL);
  if (NULL != core_handle)
  {
    GNUNET_CORE_disconnect (core_handle);
    core_handle = NULL;
  }
  if (NULL != transport_handle)
  {
    GNUNET_TRANSPORT_disconnect (transport_handle);
    transport_handle = NULL;
  }
  if (NULL != ats_ch)
  {
    GNUNET_ATS_connectivity_done (ats_ch);
    ats_ch = NULL;
  }
  GNUNET_PEER_change_rc (myid, -1);
  GNUNET_CONTAINER_multipeermap_destroy (peers);
  peers = NULL;
}


/**
 * Retrieve the CadetPeer stucture associated with the peer. Optionally create
 * one and insert it in the appropriate structures if the peer is not known yet.
 *
 * @param peer_id Full identity of the peer.
 * @param create #GNUNET_YES if a new peer should be created if unknown.
 *               #GNUNET_NO otherwise.
 *
 * @return Existing or newly created peer structure.
 *         NULL if unknown and not requested @a create
 */
struct CadetPeer *
GCP_get (const struct GNUNET_PeerIdentity *peer_id, int create)
{
  struct CadetPeer *peer;

  peer = GNUNET_CONTAINER_multipeermap_get (peers, peer_id);
  if (NULL == peer)
  {
    peer = GNUNET_new (struct CadetPeer);
    if (GNUNET_CONTAINER_multipeermap_size (peers) > max_peers)
    {
      peer_delete_oldest ();
    }
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CONTAINER_multipeermap_put (peers,
                                                      peer_id,
                                                      peer,
                                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
    peer->id = GNUNET_PEER_intern (peer_id);
  }
  peer->last_contact = GNUNET_TIME_absolute_get ();

  return peer;
}


/**
 * Retrieve the CadetPeer stucture associated with the peer. Optionally create
 * one and insert it in the appropriate structures if the peer is not known yet.
 *
 * @param peer Short identity of the peer.
 * @param create #GNUNET_YES if a new peer should be created if unknown.
 *               #GNUNET_NO otherwise.
 *
 * @return Existing or newly created peer structure.
 *         NULL if unknown and not requested @a create
 */
struct CadetPeer *
GCP_get_short (const GNUNET_PEER_Id peer, int create)
{
  return GCP_get (GNUNET_PEER_resolve2 (peer), create);
}


/**
 * Function called once #GNUNET_TRANSPORT_offer_hello() is done.
 * Marks the operation as finished.
 *
 * @param cls Closure (our `struct CadetPeer`).
 * @param tc TaskContext.
 */
static void
hello_offer_done (void *cls,
                  const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct CadetPeer *peer = cls;

  peer->hello_offer = NULL;
}


/**
 * Try to establish a new connection to this peer (in its tunnel).
 * If the peer doesn't have any path to it yet, try to get one.
 * If the peer already has some path, send a CREATE CONNECTION towards it.
 *
 * @param peer Peer to connect to.
 */
void
GCP_connect (struct CadetPeer *peer)
{
  struct CadetTunnel *t;
  struct CadetPeerPath *path;
  struct CadetConnection *c;
  int rerun_search;

  GCC_check_connections ();
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "peer_connect towards %s\n",
       GCP_2s (peer));
  /* If we have a current hello, try to connect using it. */
  GCP_try_connect (peer);

  t = peer->tunnel;
  c = NULL;
  rerun_search = GNUNET_NO;

  if (NULL != peer->path_head)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  some path exists\n");
    path = peer_get_best_path (peer);
    if (NULL != path)
    {
      char *s;

      s = path_2s (path);
      LOG (GNUNET_ERROR_TYPE_DEBUG, "  path to use: %s\n", s);
      GNUNET_free (s);

      c = GCT_use_path (t, path);
      if (NULL == c)
      {
        /* This case can happen when the path includes a first hop that is
         * not yet known to be connected.
         *
         * This happens quite often during testing when running cadet
         * under valgrind: core connect notifications come very late
         * and the DHT result has already come and created a valid
         * path.  In this case, the peer->connections
         * hashmaps will be NULL and tunnel_use_path will not be able
         * to create a connection from that path.
         *
         * Re-running the DHT GET should give core time to callback.
         *
         * GCT_use_path -> GCC_new -> register_neighbors takes care of
         * updating statistics about this issue.
         */
        rerun_search = GNUNET_YES;
      }
      else
      {
        GCC_send_create (c);
        return;
      }
    }
    else
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, "  but is NULL, all paths are in use\n");
    }
  }

  if (GNUNET_YES == rerun_search)
  {
    struct GNUNET_TIME_Relative delay;

    GCP_stop_search (peer);
    delay = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS, 100);
    peer->search_delayed = GNUNET_SCHEDULER_add_delayed (delay,
                                                         &delayed_search,
                                                         peer);
    GCC_check_connections ();
    return;
  }

  if (GNUNET_NO == is_searching (peer))
    GCP_start_search (peer);
  GCC_check_connections ();
}


/**
 * Chech whether there is a direct (core level)  connection to peer.
 *
 * @param peer Peer to check.
 *
 * @return #GNUNET_YES if there is a direct connection.
 */
int
GCP_is_neighbor (const struct CadetPeer *peer)
{
  struct CadetPeerPath *path;

  if (NULL == peer->connections)
    return GNUNET_NO;

  for (path = peer->path_head; NULL != path; path = path->next)
  {
    if (3 > path->length)
      return GNUNET_YES;
  }

  /* Is not a neighbor but connections is not NULL, probably disconnecting */
  GNUNET_break (0);
  return GNUNET_NO;
}


/**
 * Create and initialize a new tunnel towards a peer, in case it has none.
 * In case the peer already has a tunnel, nothing is done.
 *
 * Does not generate any traffic, just creates the local data structures.
 *
 * @param peer Peer towards which to create the tunnel.
 */
void
GCP_add_tunnel (struct CadetPeer *peer)
{
  GCC_check_connections ();
  if (NULL != peer->tunnel)
    return;
  peer->tunnel = GCT_new (peer);
  GCC_check_connections ();
}


/**
 * Add a connection to a neighboring peer.
 *
 * Store that the peer is the first hop of the connection in one
 * direction and that on peer disconnect the connection must be
 * notified and destroyed, for it will no longer be valid.
 *
 * @param peer Peer to add connection to.
 * @param c Connection to add.
 * @param pred #GNUNET_YES if we are predecessor, #GNUNET_NO if we are successor
 */
void
GCP_add_connection (struct CadetPeer *peer,
                    struct CadetConnection *c,
                    int pred)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "adding connection %s\n",
       GCC_2s (c));
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "to peer %s\n",
       GCP_2s (peer));
  GNUNET_assert (NULL != peer->connections);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multihashmap_put (peer->connections,
                                                    GCC_get_h (c),
                                                    c,
                                                    GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Peer %s has now %u connections.\n",
       GCP_2s (peer),
       GNUNET_CONTAINER_multihashmap_size (peer->connections));
}


/**
 * Add the path to the peer and update the path used to reach it in case this
 * is the shortest.
 *
 * @param peer Destination peer to add the path to.
 * @param path New path to add. Last peer must be @c peer.
 *             Path will be either used of freed if already known.
 * @param trusted Do we trust that this path is real?
 *
 * @return path if path was taken, pointer to existing duplicate if exists
 *         NULL on error.
 */
struct CadetPeerPath *
GCP_add_path (struct CadetPeer *peer,
              struct CadetPeerPath *path,
              int trusted)
{
  struct CadetPeerPath *aux;
  unsigned int l;
  unsigned int l2;

  GCC_check_connections ();
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "adding path [%u] to peer %s\n",
       path->length, GCP_2s (peer));

  if (NULL == peer || NULL == path
      || path->peers[path->length - 1] != peer->id)
  {
    GNUNET_break (0);
    path_destroy (path);
    return NULL;
  }

  for (l = 1; l < path->length; l++)
  {
    if (path->peers[l] == myid)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, " shortening path by %u\n", l);
      for (l2 = 0; l2 < path->length - l; l2++)
      {
        path->peers[l2] = path->peers[l + l2];
      }
      path->length -= l;
      l = 1;
      path->peers = GNUNET_realloc (path->peers,
                                    path->length * sizeof (GNUNET_PEER_Id));
    }
  }

  LOG (GNUNET_ERROR_TYPE_DEBUG, " final length: %u\n", path->length);

  if (2 >= path->length && GNUNET_NO == trusted)
  {
    /* Only allow CORE to tell us about direct paths */
    path_destroy (path);
    return NULL;
  }

  l = path_get_length (path);
  if (0 == l)
  {
    path_destroy (path);
    return NULL;
  }

  GNUNET_assert (peer->id == path->peers[path->length - 1]);
  for (aux = peer->path_head; aux != NULL; aux = aux->next)
  {
    l2 = path_get_length (aux);
    if (l2 > l)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, "  added\n");
      GNUNET_CONTAINER_DLL_insert_before (peer->path_head,
                                          peer->path_tail, aux, path);
      goto finish;
    }
    else
    {
      if (l2 == l && memcmp (path->peers, aux->peers, l) == 0)
      {
        LOG (GNUNET_ERROR_TYPE_DEBUG, "  already known\n");
        path_destroy (path);
        return aux;
      }
    }
  }
  GNUNET_CONTAINER_DLL_insert_tail (peer->path_head, peer->path_tail,
                                    path);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  added last\n");

finish:
  if (NULL != peer->tunnel
      && CONNECTIONS_PER_TUNNEL > GCT_count_connections (peer->tunnel)
      && 2 < path->length) /* Direct paths are handled by core_connect */
  {
    GCP_connect (peer);
  }
  GCC_check_connections ();
  return path;
}


/**
 * Add the path to the origin peer and update the path used to reach it in case
 * this is the shortest.
 * The path is given in peer_info -> destination, therefore we turn the path
 * upside down first.
 *
 * @param peer Peer to add the path to, being the origin of the path.
 * @param path New path to add after being inversed.
 *             Path will be either used or freed.
 * @param trusted Do we trust that this path is real?
 *
 * @return path if path was taken, pointer to existing duplicate if exists
 *         NULL on error.
 */
struct CadetPeerPath *
GCP_add_path_to_origin (struct CadetPeer *peer,
                        struct CadetPeerPath *path,
                        int trusted)
{
  if (NULL == path)
    return NULL;
  path_invert (path);
  return GCP_add_path (peer, path, trusted);
}


/**
 * Adds a path to the info of all the peers in the path
 *
 * @param p Path to process.
 * @param confirmed Whether we know if the path works or not.
 */
void
GCP_add_path_to_all (const struct CadetPeerPath *p, int confirmed)
{
  unsigned int i;

  /* TODO: invert and add */
  GCC_check_connections ();
  for (i = 0; i < p->length && p->peers[i] != myid; i++) /* skip'em */ ;
  for (i++; i < p->length; i++)
  {
    struct CadetPeer *peer;
    struct CadetPeerPath *copy;

    peer = GCP_get_short (p->peers[i], GNUNET_YES);
    copy = path_duplicate (p);
    copy->length = i + 1;
    GCP_add_path (peer, copy, 3 > p->length ? GNUNET_NO : confirmed);
  }
  GCC_check_connections ();
}


/**
 * Remove any path to the peer that has the exact same peers as the one given.
 *
 * @param peer Peer to remove the path from.
 * @param path Path to remove. Is always destroyed .
 */
void
GCP_remove_path (struct CadetPeer *peer, struct CadetPeerPath *path)
{
  struct CadetPeerPath *iter;
  struct CadetPeerPath *next;

  GCC_check_connections ();
  GNUNET_assert (myid == path->peers[0]);
  GNUNET_assert (peer->id == path->peers[path->length - 1]);

  LOG (GNUNET_ERROR_TYPE_INFO, "Removing path %p (%u) from %s\n",
       path, path->length, GCP_2s (peer));

  for (iter = peer->path_head; NULL != iter; iter = next)
  {
    next = iter->next;
    if (0 == path_cmp (path, iter))
    {
      GNUNET_CONTAINER_DLL_remove (peer->path_head, peer->path_tail, iter);
      if (iter != path)
        path_destroy (iter);
    }
  }
  path_destroy (path);
  GCC_check_connections ();
}


/**
 * Check that we are aware of a connection from a neighboring peer.
 *
 * @param peer Peer to the connection is with
 * @param c Connection that should be in the map with this peer.
 */
void
GCP_check_connection (const struct CadetPeer *peer,
                      const struct CadetConnection *c)
{
  GNUNET_assert (NULL != peer);
  GNUNET_assert (NULL != peer->connections);
    return;
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap_contains_value (peer->connections,
                                                               GCC_get_h (c),
                                                               c));
}


/**
 * Remove a connection from a neighboring peer.
 *
 * @param peer Peer to remove connection from.
 * @param c Connection to remove.
 */
void
GCP_remove_connection (struct CadetPeer *peer,
                       const struct CadetConnection *c)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Removing connection %s\n",
       GCC_2s (c));
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "from peer %s\n",
       GCP_2s (peer));
  if ( (NULL == peer) ||
       (NULL == peer->connections) )
    return;
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap_remove (peer->connections,
                                                       GCC_get_h (c),
                                                       c));
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Peer %s remains with %u connections.\n",
       GCP_2s (peer),
       GNUNET_CONTAINER_multihashmap_size (peer->connections));
}


/**
 * Start the DHT search for new paths towards the peer: we don't have
 * enough good connections.
 *
 * @param peer Destination peer.
 */
void
GCP_start_search (struct CadetPeer *peer)
{
  const struct GNUNET_PeerIdentity *id;
  struct CadetTunnel *t = peer->tunnel;

  GCC_check_connections ();
 if (NULL != peer->search_h)
  {
    GNUNET_break (0);
    return;
  }

  if (NULL != peer->search_delayed)
    GCP_stop_search (peer);

  id = GNUNET_PEER_resolve2 (peer->id);
  peer->search_h = GCD_search (id, &search_handler, peer);

  if (NULL == t)
  {
    /* Why would we search for a peer with no tunnel towards it? */
    GNUNET_break (0);
    return;
  }

  if (CADET_TUNNEL_NEW == GCT_get_cstate (t)
      || 0 == GCT_count_any_connections (t))
  {
    GCT_change_cstate (t, CADET_TUNNEL_SEARCHING);
  }
  GCC_check_connections ();
}


/**
 * Stop the DHT search for new paths towards the peer: we already have
 * enough good connections.
 *
 * @param peer Destination peer.
 */
void
GCP_stop_search (struct CadetPeer *peer)
{
  GCC_check_connections ();
  if (NULL != peer->search_h)
  {
    GCD_search_stop (peer->search_h);
    peer->search_h = NULL;
  }
  if (NULL != peer->search_delayed)
  {
    GNUNET_SCHEDULER_cancel (peer->search_delayed);
    peer->search_delayed = NULL;
  }
  GCC_check_connections ();
}


/**
 * Get the Full ID of a peer.
 *
 * @param peer Peer to get from.
 *
 * @return Full ID of peer.
 */
const struct GNUNET_PeerIdentity *
GCP_get_id (const struct CadetPeer *peer)
{
  return GNUNET_PEER_resolve2 (peer->id);
}


/**
 * Get the Short ID of a peer.
 *
 * @param peer Peer to get from.
 *
 * @return Short ID of peer.
 */
GNUNET_PEER_Id
GCP_get_short_id (const struct CadetPeer *peer)
{
  return peer->id;
}


/**
 * Set tunnel.
 *
 * If tunnel is NULL and there was a search active, stop it, as it's useless.
 *
 * @param peer Peer.
 * @param t Tunnel.
 */
void
GCP_set_tunnel (struct CadetPeer *peer, struct CadetTunnel *t)
{
  peer->tunnel = t;
  if (NULL == t && GNUNET_YES == is_searching (peer))
  {
    GCP_stop_search (peer);
  }
}


/**
 * Get the tunnel towards a peer.
 *
 * @param peer Peer to get from.
 *
 * @return Tunnel towards peer.
 */
struct CadetTunnel *
GCP_get_tunnel (const struct CadetPeer *peer)
{
  if (NULL == peer)
    return NULL;
  return peer->tunnel;
}


/**
 * Set the hello message.
 *
 * @param peer Peer whose message to set.
 * @param hello Hello message.
 */
void
GCP_set_hello (struct CadetPeer *peer, const struct GNUNET_HELLO_Message *hello)
{
  struct GNUNET_HELLO_Message *old;
  size_t size;

  GCC_check_connections ();
 LOG (GNUNET_ERROR_TYPE_DEBUG, "set hello for %s\n", GCP_2s (peer));
  if (NULL == hello)
    return;

  old = GCP_get_hello (peer);
  if (NULL == old)
  {
    size = GNUNET_HELLO_size (hello);
    peer->hello = GNUNET_malloc (size);
    memcpy (peer->hello, hello, size);
  }
  else
  {
    peer->hello = GNUNET_HELLO_merge (old, hello);
    GNUNET_free (old);
  }
  GCC_check_connections ();
}


/**
 * Get the hello message.
 *
 * @param peer Peer whose message to get.
 *
 * @return Hello message.
 */
struct GNUNET_HELLO_Message *
GCP_get_hello (struct CadetPeer *peer)
{
  struct GNUNET_TIME_Absolute expiration;
  struct GNUNET_TIME_Relative remaining;

  if (NULL == peer->hello)
    return NULL;

  expiration = GNUNET_HELLO_get_last_expiration (peer->hello);
  remaining = GNUNET_TIME_absolute_get_remaining (expiration);
  if (0 == remaining.rel_value_us)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, " get - hello expired on %s\n",
         GNUNET_STRINGS_absolute_time_to_string (expiration));
    GNUNET_free (peer->hello);
    peer->hello = NULL;
  }
  return peer->hello;
}


/**
 * Try to connect to a peer on TRANSPORT level.
 *
 * @param peer Peer to whom to connect.
 */
void
GCP_try_connect (struct CadetPeer *peer)
{
  struct GNUNET_HELLO_Message *hello;
  struct GNUNET_MessageHeader *mh;

  if (NULL == transport_handle)
    return;
  GCC_check_connections ();
  if (GNUNET_YES == GCP_is_neighbor (peer))
    return;
  hello = GCP_get_hello (peer);
  if (NULL == hello)
    return;

  mh = GNUNET_HELLO_get_header (hello);
  peer->hello_offer = GNUNET_TRANSPORT_offer_hello (transport_handle,
                                                    mh,
                                                    &hello_offer_done,
                                                    peer);
  peer->connectivity_suggestion
    = GNUNET_ATS_connectivity_suggest (ats_ch,
                                       GNUNET_PEER_resolve2 (peer->id),
                                       1 /* strength */);
  GCC_check_connections ();
}


/**
 * Notify a peer that a link between two other peers is broken. If any path
 * used that link, eliminate it.
 *
 * @param peer Peer affected by the change.
 * @param peer1 Peer whose link is broken.
 * @param peer2 Peer whose link is broken.
 */
void
GCP_notify_broken_link (struct CadetPeer *peer,
                        const struct GNUNET_PeerIdentity *peer1,
                        const struct GNUNET_PeerIdentity *peer2)
{
  struct CadetPeerPath *iter;
  struct CadetPeerPath *next;
  unsigned int i;
  GNUNET_PEER_Id p1;
  GNUNET_PEER_Id p2;

  GCC_check_connections ();
  p1 = GNUNET_PEER_search (peer1);
  p2 = GNUNET_PEER_search (peer2);

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Link %u-%u broken\n", p1, p2);
  if (0 == p1 || 0 == p2)
  {
    /* We don't even know them */
    return;
  }

  for (iter = peer->path_head; NULL != iter; iter = next)
  {
    next = iter->next;
    for (i = 0; i < iter->length - 1; i++)
    {
      if ((iter->peers[i] == p1 && iter->peers[i + 1] == p2)
          || (iter->peers[i] == p2 && iter->peers[i + 1] == p1))
      {
        char *s;

        s = path_2s (iter);
        LOG (GNUNET_ERROR_TYPE_DEBUG, " - invalidating %s\n", s);
        GNUNET_free (s);

        path_invalidate (iter);
      }
    }
  }
  GCC_check_connections ();
}


/**
 * Count the number of known paths toward the peer.
 *
 * @param peer Peer to get path info.
 *
 * @return Number of known paths.
 */
unsigned int
GCP_count_paths (const struct CadetPeer *peer)
{
  struct CadetPeerPath *iter;
  unsigned int i;

  for (iter = peer->path_head, i = 0; NULL != iter; iter = iter->next)
    i++;

  return i;
}


/**
 * Iterate over the paths to a peer.
 *
 * @param peer Peer to get path info.
 * @param callback Function to call for every path.
 * @param cls Closure for @a callback.
 *
 * @return Number of iterated paths.
 */
unsigned int
GCP_iterate_paths (struct CadetPeer *peer,
                   GCP_path_iterator callback,
                   void *cls)
{
  struct CadetPeerPath *iter;
  unsigned int i;

  for (iter = peer->path_head, i = 0; NULL != iter; iter = iter->next)
  {
    i++;
    if (GNUNET_YES != callback (cls, peer, iter))
      break;
  }

  return i;
}


/**
 * Iterate all known peers.
 *
 * @param iter Iterator.
 * @param cls Closure for @c iter.
 */
void
GCP_iterate_all (GNUNET_CONTAINER_PeerMapIterator iter,
                 void *cls)
{
  GCC_check_connections ();
  GNUNET_CONTAINER_multipeermap_iterate (peers,
                                         iter,
                                         cls);
  GCC_check_connections ();
}


/**
 * Get the static string for a peer ID.
 *
 * @param peer Peer.
 *
 * @return Static string for it's ID.
 */
const char *
GCP_2s (const struct CadetPeer *peer)
{
  if (NULL == peer)
    return "(NULL)";
  return GNUNET_i2s (GNUNET_PEER_resolve2 (peer->id));
}


/* end of gnunet-service-cadet_peer.c */
