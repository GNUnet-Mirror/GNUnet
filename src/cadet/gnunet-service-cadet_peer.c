/*
     This file is part of GNUnet.
     (C) 2013 Christian Grothoff (and other contributing authors)

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


#include "platform.h"
#include "gnunet_util_lib.h"

#include "gnunet_transport_service.h"
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
  GCP_sent callback;

    /**
     * Closure for callback.
     */
  void *callback_cls;
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
     * Tunnel to this peer, if any.
     */
  struct CadetTunnel *tunnel;

    /**
     * Connections that go through this peer, indexed by tid;
     */
  struct GNUNET_CONTAINER_MultiHashMap *connections;

    /**
     * Handle for queued transmissions
     */
  struct GNUNET_CORE_TransmitHandle *core_transmit;

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
 * Peers known, indexed by PeerIdentity (CadetPeer).
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
 * Handle to communicate with core.
 */
static struct GNUNET_CORE_Handle *core_handle;

/**
 * Handle to try to start new connections.
 */
static struct GNUNET_TRANSPORT_Handle *transport_handle;


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
  if (NULL != p->connections)
    conns = GNUNET_CONTAINER_multihashmap_size (p->connections);
  else
    conns = 0;
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
 * @param cls Closure (peer disconnected).
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

  LOG (GNUNET_ERROR_TYPE_DEBUG, "  notifying %s due to %s\n",
       GCC_2s (c), GCP_2s (peer));
  GCC_notify_broken (c, peer);

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
    if (2 <= iter->length)
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
core_connect (void *cls, const struct GNUNET_PeerIdentity *peer)
{
  struct CadetPeer *mp;
  struct CadetPeerPath *path;
  char own_id[16];

  strncpy (own_id, GNUNET_i2s (&my_full_id), 15);
  mp = GCP_get (peer);
  if (myid == mp->id)
  {
    LOG (GNUNET_ERROR_TYPE_INFO, "CONNECTED %s (self)\n", own_id);
    path = path_new (1);
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_INFO, "CONNECTED %s <= %s\n",
         own_id, GNUNET_i2s (peer));
    path = path_new (2);
    path->peers[1] = mp->id;
    GNUNET_PEER_change_rc (mp->id, 1);
    GNUNET_STATISTICS_update (stats, "# peers", 1, GNUNET_NO);
  }
  path->peers[0] = myid;
  GNUNET_PEER_change_rc (myid, 1);
  GCP_add_path (mp, path, GNUNET_YES);

  mp->connections = GNUNET_CONTAINER_multihashmap_create (32, GNUNET_YES);

  if (NULL != GCP_get_tunnel (mp) &&
      0 > GNUNET_CRYPTO_cmp_peer_identity (&my_full_id, peer))
  {
    GCP_connect (mp);
  }

  return;
}


/**
 * Method called whenever a peer disconnects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 */
static void
core_disconnect (void *cls, const struct GNUNET_PeerIdentity *peer)
{
  struct CadetPeer *p;
  struct CadetPeerPath *direct_path;
  char own_id[16];

  strncpy (own_id, GNUNET_i2s (&my_full_id), 15);
  p = GNUNET_CONTAINER_multipeermap_get (peers, peer);
  if (NULL == p)
  {
    GNUNET_break (0);
    return;
  }
  if (myid == p->id)
    LOG (GNUNET_ERROR_TYPE_INFO, "DISCONNECTED %s (self)\n", own_id);
  else
    LOG (GNUNET_ERROR_TYPE_INFO, "DISCONNECTED %s <= %s\n",
         own_id, GNUNET_i2s (peer));
  direct_path = pop_direct_path (p);
  GNUNET_CONTAINER_multihashmap_iterate (p->connections, &notify_broken, p);
  GNUNET_CONTAINER_multihashmap_destroy (p->connections);
  p->connections = NULL;
  if (NULL != p->core_transmit)
    {
      GNUNET_CORE_notify_transmit_ready_cancel (p->core_transmit);
      p->core_transmit = NULL;
    }
  GNUNET_STATISTICS_update (stats, "# peers", -1, GNUNET_NO);

  path_destroy (direct_path);
  return;
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
  {&GCC_handle_encrypted, GNUNET_MESSAGE_TYPE_CADET_ENCRYPTED, 0},
  {&GCC_handle_kx, GNUNET_MESSAGE_TYPE_CADET_KX, 0},
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
      GNUNET_abort();
  }
  GML_start ();
  return;
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
  if (GNUNET_MESSAGE_TYPE_CADET_ENCRYPTED == q->type)
    return low;
  else
    return high;
}


/**
 * Iterator over tunnel hash map entries to destroy the tunnel during shutdown.
 *
 * @param cls closure
 * @param key current key code
 * @param value value in the hash map
 * @return #GNUNET_YES if we should continue to iterate,
 *         #GNUNET_NO if not.
 */
static int
shutdown_tunnel (void *cls,
                 const struct GNUNET_PeerIdentity *key,
                 void *value)
{
  struct CadetPeer *p = value;
  struct CadetTunnel *t = p->tunnel;

  if (NULL != t)
    GCT_destroy (t);
  return GNUNET_YES;
}


/**
 * Destroy the peer_info and free any allocated resources linked to it
 *
 * @param peer The peer_info to destroy.
 *
 * @return GNUNET_OK on success
 */
static int
peer_destroy (struct CadetPeer *peer)
{
  struct GNUNET_PeerIdentity id;
  struct CadetPeerPath *p;
  struct CadetPeerPath *nextp;

  GNUNET_PEER_resolve (peer->id, &id);
  GNUNET_PEER_change_rc (peer->id, -1);

  LOG (GNUNET_ERROR_TYPE_WARNING, "destroying peer %s\n", GNUNET_i2s (&id));

  if (GNUNET_YES !=
    GNUNET_CONTAINER_multipeermap_remove (peers, &id, peer))
  {
    GNUNET_break (0);
    LOG (GNUNET_ERROR_TYPE_WARNING, " not in peermap!!\n");
  }
  if (NULL != peer->search_h)
  {
    GCD_search_stop (peer->search_h);
  }
  p = peer->path_head;
  while (NULL != p)
  {
    nextp = p->next;
    GNUNET_CONTAINER_DLL_remove (peer->path_head, peer->path_tail, p);
    path_destroy (p);
    p = nextp;
  }
  GCT_destroy_empty (peer->tunnel);
  GNUNET_free (peer);
  return GNUNET_OK;
}


/**
 * Returns if peer is used (has a tunnel or is neighbor).
 *
 * @param peer Peer to check.
 *
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
 *
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
 *
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
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Checking %p towards %s\n", q, GCC_2s (q->c));
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
 * @param cls closure
 * @param path
 */
static void
search_handler (void *cls, const struct CadetPeerPath *path)
{
  struct CadetPeer *peer = cls;
  unsigned int connection_count;

  GCP_add_path_to_all (path, GNUNET_NO);

  /* Count connections */
  connection_count = GCT_count_connections (peer->tunnel);

  /* If we already have 3 (or more (?!)) connections, it's enough */
  if (3 <= connection_count)
    return;

  if (CADET_TUNNEL_SEARCHING == GCT_get_cstate (peer->tunnel))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, " ... connect!\n");
    GCP_connect (peer);
  }
  return;
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
  const struct GNUNET_PeerIdentity *dst_id;
  size_t data_size;
  uint32_t pid;

  pid = 0;
  peer->core_transmit = NULL;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Queue send towards %s (max %u)\n",
       GCP_2s (peer), size);

  if (NULL == buf || 0 == size)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Buffer size 0.\n");
    return 0;
  }

  /* Initialize */
  queue = peer_get_first_message (peer);
  if (NULL == queue)
  {
    GNUNET_assert (0); /* Core tmt_rdy should've been canceled */
    return 0;
  }
  c = queue->c;

  dst_id = GNUNET_PEER_resolve2 (peer->id);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  on connection %s %s\n",
       GCC_2s (c), GC_f2s(queue->fwd));
  /* Check if buffer size is enough for the message */
  if (queue->size > size)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING, "not enough room (%u vs %u), reissue\n",
         queue->size, size);
    peer->core_transmit =
      GNUNET_CORE_notify_transmit_ready (core_handle,
                                         GNUNET_NO, get_priority (queue),
                                         GNUNET_TIME_UNIT_FOREVER_REL,
                                         dst_id,
                                         queue->size,
                                         &queue_send,
                                         peer);
    return 0;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  size %u ok\n", queue->size);

  /* Fill buf */
  switch (queue->type)
  {
    case GNUNET_MESSAGE_TYPE_CADET_ENCRYPTED:
      pid = GCC_get_pid (queue->c, queue->fwd);
      LOG (GNUNET_ERROR_TYPE_DEBUG, "  payload ID %u\n", pid);
      data_size = send_core_data_raw (queue->cls, size, buf);
      ((struct GNUNET_CADET_Encrypted *) buf)->pid = htonl (pid);
      break;
    case GNUNET_MESSAGE_TYPE_CADET_CONNECTION_DESTROY:
    case GNUNET_MESSAGE_TYPE_CADET_CONNECTION_BROKEN:
    case GNUNET_MESSAGE_TYPE_CADET_KX:
    case GNUNET_MESSAGE_TYPE_CADET_ACK:
    case GNUNET_MESSAGE_TYPE_CADET_POLL:
      LOG (GNUNET_ERROR_TYPE_DEBUG, "  raw %s\n", GC_m2s (queue->type));
      data_size = send_core_data_raw (queue->cls, size, buf);
      break;
    case GNUNET_MESSAGE_TYPE_CADET_CONNECTION_CREATE:
      LOG (GNUNET_ERROR_TYPE_DEBUG, "  path create\n");
      if (GCC_is_origin (c, GNUNET_YES))
        data_size = send_core_connection_create (c, size, buf);
      else
        data_size = send_core_data_raw (queue->cls, size, buf);
      break;
    case GNUNET_MESSAGE_TYPE_CADET_CONNECTION_ACK:
      LOG (GNUNET_ERROR_TYPE_DEBUG, "  path ack\n");
      if (GCC_is_origin (c, GNUNET_NO) ||
          GCC_is_origin (c, GNUNET_YES))
        data_size = send_core_connection_ack (c, size, buf);
      else
        data_size = send_core_data_raw (queue->cls, size, buf);
      break;
    case GNUNET_MESSAGE_TYPE_CADET_DATA:
    case GNUNET_MESSAGE_TYPE_CADET_CHANNEL_CREATE:
    case GNUNET_MESSAGE_TYPE_CADET_CHANNEL_DESTROY:
      /* This should be encapsulted */
      GNUNET_break (0);
      data_size = 0;
      break;
    default:
      GNUNET_break (0);
      LOG (GNUNET_ERROR_TYPE_WARNING, "  type unknown: %u\n", queue->type);
      data_size = 0;
  }

  if (0 < drop_percent &&
      GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, 101) < drop_percent)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING, "DD %s (%s %u) on connection %s %s\n",
         GC_m2s (queue->type), GC_m2s (queue->payload_type), queue->payload_id,
         GCC_2s (c), GC_f2s (queue->fwd));
    data_size = 0;
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_INFO,
         "snd %s (%s %u) on connection %s (%p) %s (size %u)\n",
         GC_m2s (queue->type), GC_m2s (queue->payload_type),
         queue->payload_id, GCC_2s (c), c, GC_f2s (queue->fwd), data_size);
  }

  /* Free queue, but cls was freed by send_core_*. */
  (void) GCP_queue_destroy (queue, GNUNET_NO, GNUNET_YES, pid);

  /* If more data in queue, send next */
  queue = peer_get_first_message (peer);
  if (NULL != queue)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  more data!\n");
    if (NULL == peer->core_transmit)
    {
      peer->core_transmit =
          GNUNET_CORE_notify_transmit_ready (core_handle,
                                             GNUNET_NO, get_priority (queue),
                                             GNUNET_TIME_UNIT_FOREVER_REL,
                                             dst_id,
                                             queue->size,
                                             &queue_send,
                                             peer);
      queue->start_waiting = GNUNET_TIME_absolute_get ();
    }
    else
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
                  "*   tmt rdy called somewhere else\n");
    }
//     GCC_start_poll (); FIXME needed?
  }
  else
  {
//     GCC_stop_poll(); FIXME needed?
  }

  LOG (GNUNET_ERROR_TYPE_DEBUG, "  return %d\n", data_size);
  queue_debug (peer, GNUNET_ERROR_TYPE_DEBUG);
  return data_size;
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
GCP_queue_destroy (struct CadetPeerQueue *queue, int clear_cls,
                   int sent, uint32_t pid)
{
  struct CadetPeer *peer;
  int connection_destroyed;

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

  if (NULL != queue->callback)
  {
    struct GNUNET_TIME_Relative core_wait_time;

    LOG (GNUNET_ERROR_TYPE_DEBUG, " calling callback\n");
    core_wait_time = GNUNET_TIME_absolute_get_duration (queue->start_waiting);
    connection_destroyed = queue->callback (queue->callback_cls,
                                            queue->c, sent, queue->type, pid,
                                            queue->fwd, queue->size,
                                            core_wait_time);
  }
  else
  {
    connection_destroyed = GNUNET_NO;
  }

  if (NULL == peer_get_first_message (peer) && NULL != peer->core_transmit)
  {
    GNUNET_CORE_notify_transmit_ready_cancel (peer->core_transmit);
    peer->core_transmit = NULL;
  }

  GNUNET_free (queue);
  return connection_destroyed;
}


/**
 * @brief Queue and pass message to core when possible.
 *
 * @param peer Peer towards which to queue the message.
 * @param cls Closure (@c type dependant). It will be used by queue_send to
 *            build the message to be sent if not already prebuilt.
 * @param type Type of the message, 0 for a raw message.
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
GCP_queue_add (struct CadetPeer *peer, void *cls, uint16_t type,
               uint16_t payload_type, uint32_t payload_id, size_t size,
               struct CadetConnection *c, int fwd,
               GCP_sent cont, void *cont_cls)
{
  struct CadetPeerQueue *q;
  int error_level;
  int priority;
  int call_core;

  if (NULL == c && GNUNET_MESSAGE_TYPE_CADET_CONNECTION_BROKEN != type)
    error_level = GNUNET_ERROR_TYPE_ERROR;
  else
    error_level = GNUNET_ERROR_TYPE_INFO;
  LOG (error_level,
       "que %s (%s %u) on connection %s (%p) %s towards %s (size %u)\n",
       GC_m2s (type), GC_m2s (payload_type), payload_id,
       GCC_2s (c), c, GC_f2s (fwd), GCP_2s (peer), size);

  if (error_level == GNUNET_ERROR_TYPE_ERROR)
    GNUNET_abort ();
  if (NULL == peer->connections)
  {
    /* We are not connected to this peer, ignore request. */
    LOG (GNUNET_ERROR_TYPE_WARNING, "%s not a neighbor\n", GCP_2s (peer));
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
  q->callback = cont;
  q->callback_cls = cont_cls;
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
                                           size, &queue_send, peer);
    q->start_waiting = GNUNET_TIME_absolute_get ();
  }
  else if (GNUNET_NO == call_core)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "core tmt rdy towards %s not needed\n",
         GCP_2s (peer));

  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "core tmt rdy towards %s already called\n",
         GCP_2s (peer));

  }
  queue_debug (peer, GNUNET_ERROR_TYPE_DEBUG);
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
GCP_queue_cancel (struct CadetPeer *peer, struct CadetConnection *c)
{
  struct CadetPeerQueue *q;
  struct CadetPeerQueue *next;
  struct CadetPeerQueue *prev;
  int connection_destroyed;

  connection_destroyed = GNUNET_NO;
  for (q = peer->queue_head; NULL != q; q = next)
  {
    prev = q->prev;
    if (q->c == c)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, "GMP queue cancel %s\n", GC_m2s (q->type));
      GNUNET_break (GNUNET_NO == connection_destroyed);
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

  if (NULL == peer->queue_head && NULL != peer->core_transmit)
  {
    GNUNET_CORE_notify_transmit_ready_cancel (peer->core_transmit);
    peer->core_transmit = NULL;
  }
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

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Connection pop on connection %p\n", c);
  for (q = peer->queue_head; NULL != q; q = next)
  {
    GNUNET_break (NULL == destroyed || GNUNET_NO == *destroyed);
    next = q->next;
    if (q->c != c)
      continue;
    LOG (GNUNET_ERROR_TYPE_DEBUG, " - queued: %s (%s %u), callback: %p\n",
         GC_m2s (q->type), GC_m2s (q->payload_type), q->payload_id,
         q->callback);
    switch (q->type)
    {
      case GNUNET_MESSAGE_TYPE_CADET_CONNECTION_CREATE:
      case GNUNET_MESSAGE_TYPE_CADET_CONNECTION_ACK:
      case GNUNET_MESSAGE_TYPE_CADET_CONNECTION_DESTROY:
      case GNUNET_MESSAGE_TYPE_CADET_CONNECTION_BROKEN:
      case GNUNET_MESSAGE_TYPE_CADET_ACK:
      case GNUNET_MESSAGE_TYPE_CADET_POLL:
        dest = GCP_queue_destroy (q, GNUNET_YES, GNUNET_NO, 0);
        if (NULL != destroyed && GNUNET_YES == dest)
          *destroyed = GNUNET_YES;
        continue;

      case GNUNET_MESSAGE_TYPE_CADET_KX:
      case GNUNET_MESSAGE_TYPE_CADET_ENCRYPTED:
        msg = (struct GNUNET_MessageHeader *) q->cls;
        dest = GCP_queue_destroy (q, GNUNET_NO, GNUNET_NO, 0);
        if (NULL != destroyed && GNUNET_YES == dest)
          *destroyed = GNUNET_YES;
        return msg;

      default:
        GNUNET_break (0);
        LOG (GNUNET_ERROR_TYPE_DEBUG, "Unknown message %s\n", GC_m2s (q->type));
    }
  }

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
                                         size,
                                         &queue_send,
                                         peer);
}


/**
 * Initialize the peer subsystem.
 *
 * @param c Configuration.
 */
void
GCP_init (const struct GNUNET_CONFIGURATION_Handle *c)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG, "init\n");
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
  GNUNET_CONTAINER_multipeermap_iterate (peers, &shutdown_tunnel, NULL);

  if (core_handle != NULL)
  {
    GNUNET_CORE_disconnect (core_handle);
    core_handle = NULL;
  }
  if (transport_handle != NULL)
  {
    GNUNET_TRANSPORT_disconnect (transport_handle);
    transport_handle = NULL;
  }
  GNUNET_PEER_change_rc (myid, -1);
}


/**
 * Retrieve the CadetPeer stucture associated with the peer, create one
 * and insert it in the appropriate structures if the peer is not known yet.
 *
 * @param peer_id Full identity of the peer.
 *
 * @return Existing or newly created peer structure.
 */
struct CadetPeer *
GCP_get (const struct GNUNET_PeerIdentity *peer_id)
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
        GNUNET_CONTAINER_multipeermap_put (peers, peer_id, peer,
                                           GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
        peer->id = GNUNET_PEER_intern (peer_id);
  }
  peer->last_contact = GNUNET_TIME_absolute_get ();

  return peer;
}


/**
 * Retrieve the CadetPeer stucture associated with the peer, create one
 * and insert it in the appropriate structures if the peer is not known yet.
 *
 * @param peer Short identity of the peer.
 *
 * @return Existing or newly created peer structure.
 */
struct CadetPeer *
GCP_get_short (const GNUNET_PEER_Id peer)
{
  return GCP_get (GNUNET_PEER_resolve2 (peer));
}


/**
 * Try to connect to a peer on transport level.
 *
 * @param cls Closure (peer).
 * @param tc TaskContext.
 */
static void
try_connect (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct CadetPeer *peer = cls;

  if (0 != (GNUNET_SCHEDULER_REASON_SHUTDOWN & tc->reason))
    return;

  GNUNET_TRANSPORT_try_connect (transport_handle,
                                GNUNET_PEER_resolve2 (peer->id), NULL, NULL);
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
  struct CadetPeerPath *p;
  struct CadetConnection *c;
  int rerun_search;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "peer_connect towards %s\n", GCP_2s (peer));

  /* If we have a current hello, try to connect using it. */
  GCP_try_connect (peer);

  t = peer->tunnel;
  c = NULL;
  rerun_search = GNUNET_NO;

  if (NULL != peer->path_head)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  some path exists\n");
    p = peer_get_best_path (peer);
    if (NULL != p)
    {
      char *s;

      s = path_2s (p);
      LOG (GNUNET_ERROR_TYPE_DEBUG, "  path to use: %s\n", s);
      GNUNET_free (s);

      c = GCT_use_path (t, p);
      if (NULL == c)
      {
        /* This case can happen when the path includes a first hop that is
         * not yet known to be connected.
         *
         * This happens quite often during testing when running cadet
         * under valgrind: core connect notifications come very late and the
         * DHT result has already come and created a valid path.
         * In this case, the peer->connections hashmap will be NULL and
         * tunnel_use_path will not be able to create a connection from that
         * path.
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

  if (NULL != peer->search_h && GNUNET_YES == rerun_search)
  {
    GCD_search_stop (peer->search_h);
    peer->search_h = NULL;
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  Stopping DHT GET for peer %s\n",
         GCP_2s (peer));
  }

  if (NULL == peer->search_h)
  {
    const struct GNUNET_PeerIdentity *id;

    id = GNUNET_PEER_resolve2 (peer->id);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
                "  Starting DHT GET for peer %s\n", GCP_2s (peer));
    peer->search_h = GCD_search (id, &search_handler, peer);
    if (CADET_TUNNEL_NEW == GCT_get_cstate (t)
        || 0 == GCT_count_any_connections (t))
      GCT_change_cstate (t, CADET_TUNNEL_SEARCHING);
  }
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
  if (NULL != peer->tunnel)
    return;
  peer->tunnel = GCT_new (peer);
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
 *
 * @return GNUNET_OK on success.
 */
int
GCP_add_connection (struct CadetPeer *peer,
                    struct CadetConnection *c)
{
  int result;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "adding connection %s\n", GCC_2s (c));
  LOG (GNUNET_ERROR_TYPE_DEBUG, "to peer %s\n", GCP_2s (peer));

  if (NULL == peer->connections)
  {
    GNUNET_break (0);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Peer %s is not a neighbor!\n",
         GCP_2s (peer));
    return GNUNET_SYSERR;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "peer %s ok, has %u connections.\n",
       GCP_2s (peer), GNUNET_CONTAINER_multihashmap_size (peer->connections));
  result = GNUNET_CONTAINER_multihashmap_put (peer->connections,
                                              GCC_get_h (c),
                                              c,
                                              GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       " now has %u connections.\n",
       GNUNET_CONTAINER_multihashmap_size (peer->connections));
  LOG (GNUNET_ERROR_TYPE_DEBUG, "result %u\n", result);

  return result;
}


/**
 * Add the path to the peer and update the path used to reach it in case this
 * is the shortest.
 *
 * @param peer Destination peer to add the path to.
 * @param path New path to add. Last peer must be the peer in arg 1.
 *             Path will be either used of freed if already known.
 * @param trusted Do we trust that this path is real?
 *
 * @return path if path was taken, pointer to existing duplicate if exists
 *         NULL on error.
 */
struct CadetPeerPath *
GCP_add_path (struct CadetPeer *peer, struct CadetPeerPath *path,
              int trusted)
{
  struct CadetPeerPath *aux;
  unsigned int l;
  unsigned int l2;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "adding path [%u] to peer %s\n",
       path->length, GCP_2s (peer));

  if ((NULL == peer) || (NULL == path))
  {
    GNUNET_break (0);
    path_destroy (path);
    return NULL;
  }
  if (path->peers[path->length - 1] != peer->id)
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
      if (NULL != peer->tunnel && 3 < GCT_count_connections (peer->tunnel))
      {
        GCP_connect (peer);
      }
      return path;
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
  if (NULL != peer->tunnel && 3 < GCT_count_connections (peer->tunnel))
  {
    GCP_connect (peer);
  }
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
  for (i = 0; i < p->length && p->peers[i] != myid; i++) /* skip'em */ ;
  for (i++; i < p->length; i++)
  {
    struct CadetPeer *aux;
    struct CadetPeerPath *copy;

    aux = GCP_get_short (p->peers[i]);
    copy = path_duplicate (p);
    copy->length = i + 1;
    GCP_add_path (aux, copy, p->length < 3 ? GNUNET_NO : confirmed);
  }
}


/**
 * Remove any path to the peer that has the extact same peers as the one given.
 *
 * @param peer Peer to remove the path from.
 * @param path Path to remove. Is always destroyed .
 */
void
GCP_remove_path (struct CadetPeer *peer, struct CadetPeerPath *path)
{
  struct CadetPeerPath *iter;
  struct CadetPeerPath *next;

  GNUNET_assert (myid == path->peers[0]);
  GNUNET_assert (peer->id == path->peers[path->length - 1]);

  for (iter = peer->path_head; NULL != iter; iter = next)
  {
    next = iter->next;
    if (0 == memcmp (path->peers, iter->peers,
                     sizeof (GNUNET_PEER_Id) * path->length))
    {
      GNUNET_CONTAINER_DLL_remove (peer->path_head, peer->path_tail, iter);
      if (iter != path)
        path_destroy (iter);
    }
  }
  path_destroy (path);
}


/**
 * Remove a connection from a neighboring peer.
 *
 * @param peer Peer to remove connection from.
 * @param c Connection to remove.
 *
 * @return GNUNET_OK on success.
 */
int
GCP_remove_connection (struct CadetPeer *peer,
                       const struct CadetConnection *c)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG, "removing connection %s\n", GCC_2s (c));
  LOG (GNUNET_ERROR_TYPE_DEBUG, "from peer %s\n", GCP_2s (peer));

  if (NULL == peer || NULL == peer->connections)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Peer %s is not a neighbor!\n",
         GCP_2s (peer));
    return GNUNET_SYSERR;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "peer %s ok, has %u connections.\n",
       GCP_2s (peer), GNUNET_CONTAINER_multihashmap_size (peer->connections));

  return GNUNET_CONTAINER_multihashmap_remove (peer->connections,
                                               GCC_get_h (c),
                                               c);
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
  if (NULL != peer->search_h)
  {
    GNUNET_break (0);
    return;
  }

  peer->search_h = GCD_search (GCP_get_id (peer), &search_handler, peer);
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
  if (NULL == peer->search_h)
  {
    return;
  }

  GCD_search_stop (peer->search_h);
  peer->search_h = NULL;
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
 * @param peer Peer.
 * @param t Tunnel.
 */
void
GCP_set_tunnel (struct CadetPeer *peer, struct CadetTunnel *t)
{
  peer->tunnel = t;
  if (NULL == t && NULL != peer->search_h)
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

  LOG (GNUNET_ERROR_TYPE_DEBUG, "set hello for %s\n", GCP_2s (peer));
  if (NULL == hello)
    return;

  old = GCP_get_hello (peer);
  if (NULL == old)
  {
    size = GNUNET_HELLO_size (hello);
    LOG (GNUNET_ERROR_TYPE_DEBUG, " new (%u bytes)\n", size);
    peer->hello = GNUNET_malloc (size);
    memcpy (peer->hello, hello, size);
  }
  else
  {
    peer->hello = GNUNET_HELLO_merge (old, hello);
    LOG (GNUNET_ERROR_TYPE_DEBUG, " merge into %p (%u bytes)\n",
         peer->hello, GNUNET_HELLO_size (hello));
    GNUNET_free (old);
  }
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

  hello = GCP_get_hello (peer);
  if (NULL == hello)
    return;

  mh = GNUNET_HELLO_get_header (hello);
  GNUNET_TRANSPORT_offer_hello (transport_handle, mh, try_connect, peer);
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
                        struct GNUNET_PeerIdentity *peer1,
                        struct GNUNET_PeerIdentity *peer2)
{
  struct CadetPeerPath *iter;
  struct CadetPeerPath *next;
  unsigned int i;
  GNUNET_PEER_Id p1;
  GNUNET_PEER_Id p2;

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
 * Iterate all known peers.
 *
 * @param iter Iterator.
 * @param cls Closure for @c iter.
 */
void
GCP_iterate_all (GNUNET_CONTAINER_PeerMapIterator iter, void *cls)
{
  GNUNET_CONTAINER_multipeermap_iterate (peers, iter, cls);
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
