/*
     This file is part of GNUnet.
     Copyright (C) 2017 GNUnet e.V.

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
 * @file cadet/gnunet-service-cadet_core.c
 * @brief cadet service; interaction with CORE service
 * @author Bartlomiej Polot
 * @author Christian Grothoff
 *
 * All functions in this file should use the prefix GCO (Gnunet Cadet cOre (bottom))
 *
 * TODO:
 * - Optimization: given BROKEN messages, destroy paths (?)
 */
#include "platform.h"
#include "gnunet-service-cadet-new_core.h"
#include "gnunet-service-cadet-new_paths.h"
#include "gnunet-service-cadet-new_peer.h"
#include "gnunet-service-cadet-new_connection.h"
#include "gnunet-service-cadet-new_tunnels.h"
#include "gnunet_core_service.h"
#include "cadet_protocol.h"

/**
 * Number of messages we are willing to buffer per route.
 */
#define ROUTE_BUFFER_SIZE 8


/**
 * Information we keep per direction for a route.
 */
struct RouteDirection
{
  /**
   * Target peer.
   */
  struct CadetPeer *hop;

  /**
   * Route this direction is part of.
   */
  struct CadetRoute *my_route;

  /**
   * Message queue manager for @e hop.
   */
  struct GCP_MessageQueueManager *mqm;

  /**
   * Cyclic message buffer to @e hop.
   */
  struct GNUNET_MQ_Envelope *out_buffer[ROUTE_BUFFER_SIZE];

  /**
   * Next write offset to use to append messages to @e out_buffer.
   */
  unsigned int out_wpos;

  /**
   * Next read offset to use to retrieve messages from @e out_buffer.
   */
  unsigned int out_rpos;

  /**
   * Is @e mqm currently ready for transmission?
   */
  int is_ready;

};


/**
 * Description of a segment of a `struct CadetConnection` at the
 * intermediate peers.  Routes are basically entries in a peer's
 * routing table for forwarding traffic.  At both endpoints, the
 * routes are terminated by a `struct CadetConnection`, which knows
 * the complete `struct CadetPath` that is formed by the individual
 * routes.
 */
struct CadetRoute
{

  /**
   * Information about the next hop on this route.
   */
  struct RouteDirection next;

  /**
   * Information about the previous hop on this route.
   */
  struct RouteDirection prev;

  /**
   * Unique identifier for the connection that uses this route.
   */
  struct GNUNET_CADET_ConnectionTunnelIdentifier cid;

  /**
   * When was this route last in use?
   */
  struct GNUNET_TIME_Absolute last_use;

};


/**
 * Handle to the CORE service.
 */
static struct GNUNET_CORE_Handle *core;

/**
 * Routes on which this peer is an intermediate.
 */
static struct GNUNET_CONTAINER_MultiShortmap *routes;


/**
 * Get the route corresponding to a hash.
 *
 * @param cid hash generated from the connection identifier
 */
static struct CadetRoute *
get_route (const struct GNUNET_CADET_ConnectionTunnelIdentifier *cid)
{
  return GNUNET_CONTAINER_multishortmap_get (routes,
                                             &cid->connection_of_tunnel);
}


/**
 * We message @a msg from @a prev.  Find its route by @a cid and
 * forward to the next hop.  Drop and signal broken route if we do not
 * have a route.
 *
 * @param prev previous hop (sender)
 * @param cid connection identifier, tells us which route to use
 * @param msg the message to forward
 */
static void
route_message (struct CadetPeer *prev,
               const struct GNUNET_CADET_ConnectionTunnelIdentifier *cid,
               const struct GNUNET_MessageHeader *msg)
{
  struct CadetRoute *route;
  struct RouteDirection *dir;
  struct GNUNET_MQ_Envelope *env;

  route = get_route (cid);
  if (NULL == route)
  {
    struct GNUNET_MQ_Envelope *env;
    struct GNUNET_CADET_ConnectionBrokenMessage *bm;

    env = GNUNET_MQ_msg (bm,
                         GNUNET_MESSAGE_TYPE_CADET_CONNECTION_BROKEN);
    bm->cid = *cid;
    bm->peer1 = my_full_id;
    GCP_send_ooo (prev,
                  env);
    return;
  }
  dir = (prev == route->prev.hop) ? &route->next : &route->prev;
  if (GNUNET_YES == dir->is_ready)
  {
    dir->is_ready = GNUNET_NO;
    GCP_send (dir->mqm,
              GNUNET_MQ_msg_copy (msg));
    return;
  }
  env = dir->out_buffer[dir->out_wpos];
  if (NULL != env)
  {
    /* Queue full, drop earliest message in queue */
    GNUNET_assert (dir->out_rpos == dir->out_wpos);
    GNUNET_MQ_discard (env);
    dir->out_rpos++;
    if (ROUTE_BUFFER_SIZE == dir->out_rpos)
      dir->out_rpos = 0;
  }
  env = GNUNET_MQ_msg_copy (msg);
  dir->out_buffer[dir->out_wpos] = env;
  dir->out_wpos++;
  if (ROUTE_BUFFER_SIZE == dir->out_wpos)
    dir->out_wpos = 0;
}


/**
 * Check if the create_connection message has the appropriate size.
 *
 * @param cls Closure (unused).
 * @param msg Message to check.
 *
 * @return #GNUNET_YES if size is correct, #GNUNET_NO otherwise.
 */
static int
check_connection_create (void *cls,
                         const struct GNUNET_CADET_ConnectionCreateMessage *msg)
{
  uint16_t size = ntohs (msg->header.size) - sizeof (*msg);

  if (0 != (size % sizeof (struct GNUNET_PeerIdentity)))
  {
    GNUNET_break_op (0);
    return GNUNET_NO;
  }
  return GNUNET_YES;
}


/**
 * Free internal data of a route direction.
 *
 * @param dir direction to destroy (do NOT free memory of 'dir' itself)
 */
static void
destroy_direction (struct RouteDirection *dir)
{
  for (unsigned int i=0;i<ROUTE_BUFFER_SIZE;i++)
    if (NULL != dir->out_buffer[i])
    {
      GNUNET_MQ_discard (dir->out_buffer[i]);
      dir->out_buffer[i] = NULL;
    }
  if (NULL != dir->mqm)
  {
    GCP_request_mq_cancel (dir->mqm,
                           NULL);
    dir->mqm = NULL;
  }
}


/**
 * Destroy our state for @a route.
 *
 * @param route route to destroy
 */
static void
destroy_route (struct CadetRoute *route)
{
  destroy_direction (&route->prev);
  destroy_direction (&route->next);
  GNUNET_free (route);
}


/**
 * Send message that a route is broken between @a peer1 and @a peer2.
 *
 * @param target where to send the message
 * @param cid connection identifier to use
 * @param peer1 one of the peers where a link is broken
 * @param peer2 another one of the peers where a link is broken
 */
static void
send_broken (struct RouteDirection *target,
             const struct GNUNET_CADET_ConnectionTunnelIdentifier *cid,
             const struct GNUNET_PeerIdentity *peer1,
             const struct GNUNET_PeerIdentity *peer2)
{
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_CADET_ConnectionBrokenMessage *bm;

  env = GNUNET_MQ_msg (bm,
                       GNUNET_MESSAGE_TYPE_CADET_CONNECTION_BROKEN);
  bm->cid = *cid;
  if (NULL != peer1)
    bm->peer1 = *peer1;
  if (NULL != peer2)
    bm->peer2 = *peer2;
  GCP_request_mq_cancel (target->mqm,
                         env);
  target->mqm = NULL;
}


/**
 * Function called when the message queue to the previous hop
 * becomes available/unavailable.  We expect this function to
 * be called immediately when we register, and then again
 * later if the connection ever goes down.
 *
 * @param cls the `struct RouteDirection`
 * @param available #GNUNET_YES if sending is now possible,
 *                  #GNUNET_NO if sending is no longer possible
 *                  #GNUNET_SYSERR if sending is no longer possible
 *                                 and the last envelope was discarded
 */
static void
dir_ready_cb (void *cls,
              int ready)
{
  struct RouteDirection *dir = cls;
  struct CadetRoute *route = dir->my_route;
  struct RouteDirection *odir;

  if (GNUNET_YES == ready)
  {
    struct GNUNET_MQ_Envelope *env;

    dir->is_ready = GNUNET_YES;
    if (NULL != (env = dir->out_buffer[dir->out_rpos]))
    {
      dir->out_buffer[dir->out_rpos] = NULL;
      dir->out_rpos++;
      if (ROUTE_BUFFER_SIZE == dir->out_rpos)
        dir->out_rpos = 0;
      dir->is_ready = GNUNET_NO;
      GCP_send (dir->mqm,
                env);
    }
    return;
  }
  odir = (dir == &route->next) ? &route->prev : &route->next;
  send_broken (&route->next,
               &route->cid,
               GCP_get_id (odir->hop),
               &my_full_id);
  destroy_route (route);
}


/**
 * Initialize one of the directions of a route.
 *
 * @param route route the direction belongs to
 * @param dir direction to initialize
 * @param hop next hop on in the @a dir
 */
static void
dir_init (struct RouteDirection *dir,
          struct CadetRoute *route,
          struct CadetPeer *hop)
{
  dir->hop = hop;
  dir->my_route = route;
  dir->mqm = GCP_request_mq (hop,
                             &dir_ready_cb,
                             dir);
  GNUNET_assert (GNUNET_YES == dir->is_ready);
}


/**
 * Handle for #GNUNET_MESSAGE_TYPE_CADET_CONNECTION_CREATE
 *
 * @param cls Closure (CadetPeer for neighbor that sent the message).
 * @param msg Message itself.
 */
static void
handle_connection_create (void *cls,
                          const struct GNUNET_CADET_ConnectionCreateMessage *msg)
{
  struct CadetPeer *sender = cls;
  struct CadetPeer *next;
  const struct GNUNET_PeerIdentity *pids = (const struct GNUNET_PeerIdentity *) &msg[1];
  struct CadetRoute *route;
  uint16_t size = ntohs (msg->header.size) - sizeof (*msg);
  unsigned int path_length;
  unsigned int off;

  path_length = size / sizeof (struct GNUNET_PeerIdentity);
  /* Initiator is at offset 0. */
  for (off=1;off<path_length;off++)
    if (0 == memcmp (&my_full_id,
                     &pids[off],
                     sizeof (struct GNUNET_PeerIdentity)))
      break;
  if (off == path_length)
  {
    /* We are not on the path, bogus request */
    GNUNET_break_op (0);
    return;
  }
  /* Check previous hop */
  if (sender != GCP_get (&pids[off - 1],
                         GNUNET_NO))
  {
    /* sender is not on the path, not allowed */
    GNUNET_break_op (0);
    return;
  }
  if (NULL !=
      get_route (&msg->cid))
  {
    /* Duplicate CREATE, pass it on, previous one might have been lost! */
    route_message (sender,
                   &msg->cid,
                   &msg->header);
    return;
  }
  if (off == path_length - 1)
  {
    /* We are the destination, create connection */
    struct CadetConnection *cc;
    struct CadetPeerPath *path;
    struct CadetPeer *origin;

    cc = GNUNET_CONTAINER_multishortmap_get (connections,
                                             &msg->cid.connection_of_tunnel);
    if (NULL != cc)
    {
      GCC_handle_duplicate_create (cc);
      return;
    }

    path = GCPP_get_path_from_route (path_length,
                                     pids);
    origin = GCP_get (&pids[0],
                      GNUNET_YES);
    GCT_add_inbound_connection (GCT_create_tunnel (origin),
                                &msg->cid,
                                path);
    return;
  }
  /* We are merely a hop on the way, check if we can support the route */
  next = GCP_get (&pids[off + 1],
                  GNUNET_NO);
  if ( (NULL == next) ||
       (GNUNET_NO == GCP_has_core_connection (next)) )
  {
    /* unworkable, send back BROKEN notification */
    struct GNUNET_MQ_Envelope *env;
    struct GNUNET_CADET_ConnectionBrokenMessage *bm;

    env = GNUNET_MQ_msg (bm,
                         GNUNET_MESSAGE_TYPE_CADET_CONNECTION_BROKEN);
    bm->cid = msg->cid;
    bm->peer1 = pids[off + 1];
    bm->peer2 = my_full_id;
    GCP_send_ooo (sender,
                  env);
    return;
  }

  /* Workable route, create routing entry */
  route = GNUNET_new (struct CadetRoute);
  route->cid = msg->cid;
  dir_init (&route->prev,
            route,
            sender);
  dir_init (&route->next,
            route,
            next);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multishortmap_put (routes,
                                                     &route->cid.connection_of_tunnel,
                                                     route,
                                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
}


/**
 * Handle for #GNUNET_MESSAGE_TYPE_CADET_CONNECTION_CREATE_ACK
 *
 * @param cls Closure (CadetPeer for neighbor that sent the message).
 * @param msg Message itself.
 */
static void
handle_connection_create_ack (void *cls,
                              const struct GNUNET_CADET_ConnectionCreateAckMessage *msg)
{
  struct CadetPeer *peer = cls;
  struct CadetConnection *cc;

  /* First, check if ACK belongs to a connection that ends here. */
  cc = GNUNET_CONTAINER_multishortmap_get (connections,
                                           &msg->cid.connection_of_tunnel);
  if (NULL != cc)
  {
    /* verify ACK came from the right direction */
    struct CadetPeerPath *path = GCC_get_path (cc);

    if (peer !=
        GCPP_get_peer_at_offset (path,
                                 0))
    {
      /* received ACK from unexpected direction, ignore! */
      GNUNET_break_op (0);
      return;
    }
    GCC_handle_connection_create_ack (cc);
    return;
  }

  /* We're just an intermediary peer, route the message along its path */
  route_message (peer,
                 &msg->cid,
                 &msg->header);
}


/**
 * Handle for #GNUNET_MESSAGE_TYPE_CADET_CONNECTION_BROKEN
 *
 * @param cls Closure (CadetPeer for neighbor that sent the message).
 * @param msg Message itself.
 * @deprecated duplicate logic with #handle_destroy(); dedup!
 */
static void
handle_connection_broken (void *cls,
                          const struct GNUNET_CADET_ConnectionBrokenMessage *msg)
{
  struct CadetPeer *peer = cls;
  struct CadetConnection *cc;
  struct CadetRoute *route;

  /* First, check if message belongs to a connection that ends here. */
  cc = GNUNET_CONTAINER_multishortmap_get (connections,
                                           &msg->cid.connection_of_tunnel);
  if (NULL != cc)
  {
    /* verify message came from the right direction */
    struct CadetPeerPath *path = GCC_get_path (cc);

    if (peer !=
        GCPP_get_peer_at_offset (path,
                                 0))
    {
      /* received message from unexpected direction, ignore! */
      GNUNET_break_op (0);
      return;
    }
    GCC_destroy (cc);

    /* FIXME: also destroy the path up to the specified link! */
    return;
  }

  /* We're just an intermediary peer, route the message along its path */
  route = get_route (&msg->cid);
  route_message (peer,
                 &msg->cid,
                 &msg->header);
  destroy_route (route);
  /* FIXME: also destroy paths we MAY have up to the specified link! */
}


/**
 * Handle for #GNUNET_MESSAGE_TYPE_CADET_CONNECTION_DESTROY
 *
 * @param cls Closure (CadetPeer for neighbor that sent the message).
 * @param msg Message itself.
 */
static void
handle_connection_destroy (void *cls,
                           const struct GNUNET_CADET_ConnectionDestroyMessage *msg)
{
  struct CadetPeer *peer = cls;
  struct CadetConnection *cc;
  struct CadetRoute *route;

  /* First, check if message belongs to a connection that ends here. */
  cc = GNUNET_CONTAINER_multishortmap_get (connections,
                                           &msg->cid.connection_of_tunnel);
  if (NULL != cc)
  {
    /* verify message came from the right direction */
    struct CadetPeerPath *path = GCC_get_path (cc);

    if (peer !=
        GCPP_get_peer_at_offset (path,
                                 0))
    {
      /* received message from unexpected direction, ignore! */
      GNUNET_break_op (0);
      return;
    }
    GCC_destroy (cc);
    return;
  }

  /* We're just an intermediary peer, route the message along its path */
  route = get_route (&msg->cid);
  route_message (peer,
                 &msg->cid,
                 &msg->header);
  destroy_route (route);
}


/**
 * Handle for #GNUNET_MESSAGE_TYPE_CADET_TUNNEL_KX
 *
 * @param cls Closure (CadetPeer for neighbor that sent the message).
 * @param msg Message itself.
 */
static void
handle_tunnel_kx (void *cls,
                  const struct GNUNET_CADET_TunnelKeyExchangeMessage *msg)
{
  struct CadetPeer *peer = cls;
  struct CadetConnection *cc;

  /* First, check if message belongs to a connection that ends here. */
  cc = GNUNET_CONTAINER_multishortmap_get (connections,
                                           &msg->cid.connection_of_tunnel);
  if (NULL != cc)
  {
    /* verify message came from the right direction */
    struct CadetPeerPath *path = GCC_get_path (cc);

    if (peer !=
        GCPP_get_peer_at_offset (path,
                                 0))
    {
      /* received message from unexpected direction, ignore! */
      GNUNET_break_op (0);
      return;
    }
    GCC_handle_kx (cc,
                   msg);
    return;
  }

  /* We're just an intermediary peer, route the message along its path */
  route_message (peer,
                 &msg->cid,
                 &msg->header);
}


/**
 * Check if the encrypted message has the appropriate size.
 *
 * @param cls Closure (unused).
 * @param msg Message to check.
 *
 * @return #GNUNET_YES if size is correct, #GNUNET_NO otherwise.
 */
static int
check_tunnel_encrypted (void *cls,
                        const struct GNUNET_CADET_TunnelEncryptedMessage *msg)
{
  return GNUNET_YES;
}


/**
 * Handle for #GNUNET_MESSAGE_TYPE_CADET_TUNNEL_ENCRYPTED.
 *
 * @param cls Closure (CadetPeer for neighbor that sent the message).
 * @param msg Message itself.
 */
static void
handle_tunnel_encrypted (void *cls,
                         const struct GNUNET_CADET_TunnelEncryptedMessage *msg)
{
  struct CadetPeer *peer = cls;
  struct CadetConnection *cc;

  /* First, check if message belongs to a connection that ends here. */
  cc = GNUNET_CONTAINER_multishortmap_get (connections,
                                           &msg->cid.connection_of_tunnel);
  if (NULL != cc)
  {
    /* verify message came from the right direction */
    struct CadetPeerPath *path = GCC_get_path (cc);

    if (peer !=
        GCPP_get_peer_at_offset (path,
                                 0))
    {
      /* received message from unexpected direction, ignore! */
      GNUNET_break_op (0);
      return;
    }
    GCC_handle_encrypted (cc,
                          msg);
    return;
  }
  /* We're just an intermediary peer, route the message along its path */
  route_message (peer,
                 &msg->cid,
                 &msg->header);
}


/**
 * Function called after #GNUNET_CORE_connect has succeeded (or failed
 * for good).  Note that the private key of the peer is intentionally
 * not exposed here; if you need it, your process should try to read
 * the private key file directly (which should work if you are
 * authorized...).  Implementations of this function must not call
 * #GNUNET_CORE_disconnect (other than by scheduling a new task to
 * do this later).
 *
 * @param cls closure
 * @param my_identity ID of this peer, NULL if we failed
 */
static void
core_init_cb (void *cls,
              const struct GNUNET_PeerIdentity *my_identity)
{
  if (NULL == my_identity)
  {
    GNUNET_break (0);
    return;
  }
  GNUNET_break (0 ==
                memcmp (my_identity,
                        &my_full_id,
                        sizeof (struct GNUNET_PeerIdentity)));
}


/**
 * Method called whenever a given peer connects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 */
static void *
core_connect_cb (void *cls,
                 const struct GNUNET_PeerIdentity *peer,
                 struct GNUNET_MQ_Handle *mq)
{
  struct CadetPeer *cp;

  cp = GCP_get (peer,
                GNUNET_YES);
  GCP_set_mq (cp,
              mq);
  return cp;
}


/**
 * Method called whenever a peer disconnects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 */
static void
core_disconnect_cb (void *cls,
                    const struct GNUNET_PeerIdentity *peer,
                    void *peer_cls)
{
  struct CadetPeer *cp = peer_cls;

  GCP_set_mq (cp,
              NULL);
}


/**
 * Initialize the CORE subsystem.
 *
 * @param c Configuration.
 */
void
GCO_init (const struct GNUNET_CONFIGURATION_Handle *c)
{
  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_var_size (connection_create,
                           GNUNET_MESSAGE_TYPE_CADET_CONNECTION_CREATE,
                           struct GNUNET_CADET_ConnectionCreateMessage,
                           NULL),
    GNUNET_MQ_hd_fixed_size (connection_create_ack,
                             GNUNET_MESSAGE_TYPE_CADET_CONNECTION_CREATE_ACK,
                             struct GNUNET_CADET_ConnectionCreateAckMessage,
                             NULL),
    GNUNET_MQ_hd_fixed_size (connection_broken,
                             GNUNET_MESSAGE_TYPE_CADET_CONNECTION_BROKEN,
                             struct GNUNET_CADET_ConnectionBrokenMessage,
                             NULL),
    GNUNET_MQ_hd_fixed_size (connection_destroy,
                             GNUNET_MESSAGE_TYPE_CADET_CONNECTION_DESTROY,
                             struct GNUNET_CADET_ConnectionDestroyMessage,
                             NULL),
    GNUNET_MQ_hd_fixed_size (tunnel_kx,
                             GNUNET_MESSAGE_TYPE_CADET_TUNNEL_KX,
                             struct GNUNET_CADET_TunnelKeyExchangeMessage,
                             NULL),
    GNUNET_MQ_hd_var_size (tunnel_encrypted,
                           GNUNET_MESSAGE_TYPE_CADET_TUNNEL_ENCRYPTED,
                           struct GNUNET_CADET_TunnelEncryptedMessage,
                           NULL),
    GNUNET_MQ_handler_end ()
  };

  routes = GNUNET_CONTAINER_multishortmap_create (1024,
                                                  GNUNET_NO);
  core = GNUNET_CORE_connect (c,
                              NULL,
                              &core_init_cb,
                              &core_connect_cb,
                              &core_disconnect_cb,
                              handlers);
}


/**
 * Shut down the CORE subsystem.
 */
void
GCO_shutdown ()
{
  if (NULL != core)
  {
    GNUNET_CORE_disconnect (core);
    core = NULL;
  }
  GNUNET_assert (0 == GNUNET_CONTAINER_multishortmap_size (routes));
  GNUNET_CONTAINER_multishortmap_destroy (routes);
}

/* end of gnunet-cadet-service_core.c */
