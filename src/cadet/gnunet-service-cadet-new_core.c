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
 */
#include "platform.h"
#include "gnunet-service-cadet-new_core.h"
#include "gnunet-service-cadet-new_paths.h"
#include "gnunet-service-cadet-new_peer.h"
#include "gnunet-service-cadet-new_connection.h"
#include "gnunet_core_service.h"
#include "cadet_protocol.h"


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
   * Previous hop on this route.
   */
  struct CadetPeer *prev_hop;

  /**
   * Next hop on this route.
   */
  struct CadetPeer *next_hop;

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

  route = get_route (cid);
  if (NULL == route)
  {
    struct GNUNET_MQ_Envelope *env;
    struct GNUNET_CADET_ConnectionBrokenMessage *bm;

    env = GNUNET_MQ_msg (bm,
                         GNUNET_MESSAGE_TYPE_CADET_CONNECTION_BROKEN);
    bm->cid = *cid;
    bm->peer1 = my_full_id;
    GCP_send (prev,
              env);
    return;
  }
  GNUNET_assert (0); /* FIXME: determine next hop from route and prev! */

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
 * Destroy our state for @a route.
 *
 * @param route route to destroy
 */
static void
destroy_route (struct CadetRoute *route)
{
  GNUNET_break (0); // fIXME: implement!
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
  struct CadetPeer *peer = cls;
  uint16_t size = ntohs (msg->header.size) - sizeof (*msg);
  unsigned int path_length;

  path_length = size / sizeof (struct GNUNET_PeerIdentity);
#if FIXME
  GCC_handle_create (peer,
                     &msg->cid,
                     path_length,
                     (const struct GNUNET_PeerIdentity *) &msg[1]);
#endif
}


/**
 * Handle for #GNUNET_MESSAGE_TYPE_CADET_CONNECTION_CREATE_ACK
 *
 * @param cls Closure (CadetPeer for neighbor that sent the message).
 * @param msg Message itself.
 */
static void
handle_connection_ack (void *cls,
                       const struct GNUNET_CADET_ConnectionCreateMessageAckMessage *msg)
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
    GCC_handle_connection_ack (cc);
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
 * Handle for #GNUNET_MESSAGE_TYPE_CADET_TUNNEL_HOP_BY_HOP_ENCRYPTED_ACK.
 *
 * @param cls Closure (CadetPeer for neighbor that sent the message).
 * @param msg Message itself.
 */
static void
handle_hop_by_hop_encrypted_ack (void *cls,
                                 const struct GNUNET_CADET_ConnectionEncryptedAckMessage *msg)
{
  struct CadetPeer *peer = cls;

#if FIXME
  GCC_handle_poll (peer,
                   msg);
#endif
}


/**
 * Handle for #GNUNET_MESSAGE_TYPE_CADET_TUNNEL_ENCRYPTED_POLL
 *
 * @param cls Closure (CadetPeer for neighbor that sent the message).
 * @param msg Message itself.
 */
static void
handle_poll (void *cls,
             const struct GNUNET_CADET_ConnectionHopByHopPollMessage *msg)
{
  struct CadetPeer *peer = cls;

#if FIXME
  GCC_handle_poll (peer,
                   msg);
#endif
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

  /* FIXME: also check all routes going via peer and
     send broken messages to the other direction! */
  GNUNET_break (0);
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
    GNUNET_MQ_hd_fixed_size (connection_ack,
                             GNUNET_MESSAGE_TYPE_CADET_CONNECTION_CREATE_ACK,
                             struct GNUNET_CADET_ConnectionCreateMessageAckMessage,
                             NULL),
    GNUNET_MQ_hd_fixed_size (connection_broken,
                             GNUNET_MESSAGE_TYPE_CADET_CONNECTION_BROKEN,
                             struct GNUNET_CADET_ConnectionBrokenMessage,
                             NULL),
    GNUNET_MQ_hd_fixed_size (connection_destroy,
                             GNUNET_MESSAGE_TYPE_CADET_CONNECTION_DESTROY,
                             struct GNUNET_CADET_ConnectionDestroyMessage,
                             NULL),
    GNUNET_MQ_hd_fixed_size (hop_by_hop_encrypted_ack,
                             GNUNET_MESSAGE_TYPE_CADET_CONNECTION_HOP_BY_HOP_ENCRYPTED_ACK,
                             struct GNUNET_CADET_ConnectionEncryptedAckMessage,
                             NULL),
    GNUNET_MQ_hd_fixed_size (poll,
                             GNUNET_MESSAGE_TYPE_CADET_TUNNEL_ENCRYPTED_POLL,
                             struct GNUNET_CADET_ConnectionHopByHopPollMessage,
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
