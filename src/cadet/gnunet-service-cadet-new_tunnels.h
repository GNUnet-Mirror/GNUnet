
/*
     This file is part of GNUnet.
     Copyright (C) 2001-2017 GNUnet e.V.

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
 * @file cadet/gnunet-service-cadet-new_tunnels.h
 * @brief Information we track per tunnel.
 * @author Bartlomiej Polot
 * @author Christian Grothoff
 */
#ifndef GNUNET_SERVICE_CADET_TUNNELS_H
#define GNUNET_SERVICE_CADET_TUNNELS_H

#include "gnunet-service-cadet-new.h"
#include "cadet_protocol.h"


/**
 * How many connections would we like to have per tunnel?
 */
#define DESIRED_CONNECTIONS_PER_TUNNEL 3


/**
 * All the connectivity states a tunnel can be in.
 */
enum CadetTunnelCState
{
  /**
   * Uninitialized status, should never appear in operation.
   */
  CADET_TUNNEL_NEW,

  /**
   * No path to the peer known yet.
   */
  CADET_TUNNEL_SEARCHING,

  /**
   * Request sent, not yet answered.
   */
  CADET_TUNNEL_WAITING,

  /**
   * Peer connected and ready to accept data.
   */
  CADET_TUNNEL_READY,

  /**
   * Tunnel being shut down, don't try to keep it alive.
   */
  CADET_TUNNEL_SHUTDOWN
};



/**
 * All the encryption states a tunnel can be in.
 */
enum CadetTunnelEState
{
  /**
   * Uninitialized status, should never appear in operation.
   */
  CADET_TUNNEL_KEY_UNINITIALIZED,

  /**
   * Ephemeral key sent, waiting for peer's key.
   */
  CADET_TUNNEL_KEY_SENT,

  /**
   * In OTR: New ephemeral key and ping sent, waiting for pong.
   *
   * This means that we DO have the peer's ephemeral key, otherwise the
   * state would be KEY_SENT. We DO NOT have a valid session key (either no
   * previous key or previous key expired).
   *
   *
   * In Axolotl: Key sent and received but no deciphered traffic yet.
   *
   * This means that we can send traffic (otherwise we would never complete
   * the handshake), but we don't have complete confirmation. Since the first
   * traffic MUST be a complete channel creation 3-way handshake, no payload
   * will be sent before confirmation.
   */
  CADET_TUNNEL_KEY_PING,

  /**
   * Handshake completed: session key available.
   */
  CADET_TUNNEL_KEY_OK,

  /**
   * New ephemeral key and ping sent, waiting for pong. Unlike KEY_PING,
   * we still have a valid session key and therefore we *can* still send
   * traffic on the tunnel.
   */
  CADET_TUNNEL_KEY_REKEY
};


/**
 * Get the static string for the peer this tunnel is directed.
 *
 * @param t Tunnel.
 *
 * @return Static string the destination peer's ID.
 */
const char *
GCT_2s (const struct CadetTunnel *t);


/**
 * Create a tunnel to @a destionation.  Must only be called
 * from within #GCP_get_tunnel().
 *
 * @param destination where to create the tunnel to
 * @return new tunnel to @a destination
 */
struct CadetTunnel *
GCT_create_tunnel (struct CadetPeer *destination);


/**
 * Add a @a connection to the @a tunnel.
 *
 * @param t a tunnel
 * @param cid connection identifer to use for the connection
 * @param path path to use for the connection
 */
void
GCT_add_inbound_connection (struct CadetTunnel *t,
                            const struct GNUNET_CADET_ConnectionTunnelIdentifier *cid,
                            struct CadetPeerPath *path);


/**
 * Return the peer to which this tunnel goes.
 *
 * @param t a tunnel
 * @return the destination of the tunnel
 */
struct CadetPeer *
GCT_get_destination (struct CadetTunnel *t);


/**
 * Consider using the path @a p for the tunnel @a t.
 * The tunnel destination is at offset @a off in path @a p.
 *
 * @param cls our tunnel
 * @param path a path to our destination
 * @param off offset of the destination on path @a path
 */
void
GCT_consider_path (struct CadetTunnel *t,
                   struct CadetPeerPath *p,
                   unsigned int off);


/**
 * Add a channel to a tunnel.
 *
 * @param t Tunnel.
 * @param ch Channel
 * @return unique number identifying @a ch within @a t
 */
struct GNUNET_CADET_ChannelTunnelNumber
GCT_add_channel (struct CadetTunnel *t,
                 struct CadetChannel *ch);


/**
 * Remove a channel from a tunnel.
 *
 * @param t Tunnel.
 * @param ch Channel
 * @param gid unique number identifying @a ch within @a t
 */
void
GCT_remove_channel (struct CadetTunnel *t,
                    struct CadetChannel *ch,
                    struct GNUNET_CADET_ChannelTunnelNumber gid);


/**
 * Send a DESTROY message via the tunnel.
 *
 * @param t the tunnel to transmit over
 * @param chid ID of the channel to destroy
 */
void
GCT_send_channel_destroy (struct CadetTunnel *t,
                          struct GNUNET_CADET_ChannelTunnelNumber chid);


/**
 * Sends an already built message on a tunnel, encrypting it and
 * choosing the best connection if not provided.
 *
 * @param message Message to send. Function modifies it.
 * @param t Tunnel on which this message is transmitted.
 * @param cont Continuation to call once message is really sent.
 * @param cont_cls Closure for @c cont.
 * @return Handle to cancel message. NULL if @c cont is NULL.
 */
struct CadetTunnelQueueEntry *
GCT_send (struct CadetTunnel *t,
          const struct GNUNET_MessageHeader *message,
          GNUNET_SCHEDULER_TaskCallback cont,
          void *cont_cls);


/**
 * Cancel a previously sent message while it's in the queue.
 *
 * ONLY can be called before the continuation given to the send
 * function is called. Once the continuation is called, the message is
 * no longer in the queue!
 *
 * @param q Handle to the queue entry to cancel.
 */
void
GCT_send_cancel (struct CadetTunnelQueueEntry *q);


/**
 * Return the number of channels using a tunnel.
 *
 * @param t tunnel to count obtain the number of channels for
 * @return number of channels using the tunnel
 */
unsigned int
GCT_count_channels (struct CadetTunnel *t);


/**
 * Return the number of connections available for a tunnel.
 *
 * @param t tunnel to count obtain the number of connections for
 * @return number of connections available for the tunnel
 */
unsigned int
GCT_count_any_connections (struct CadetTunnel *t);


/**
 * Iterator over connections.
 *
 * @param cls closure
 * @param c one of the connections
 */
typedef void
(*GCT_ConnectionIterator) (void *cls,
                           struct CadetConnection *c);


/**
 * Iterate over all connections of a tunnel.
 *
 * @param t Tunnel whose connections to iterate.
 * @param iter Iterator.
 * @param iter_cls Closure for @c iter.
 */
void
GCT_iterate_connections (struct CadetTunnel *t,
                         GCT_ConnectionIterator iter,
                         void *iter_cls);


/**
 * Iterator over channels.
 *
 * @param cls closure
 * @param ch one of the channels
 */
typedef void
(*GCT_ChannelIterator) (void *cls,
                        struct CadetChannel *ch);


/**
 * Iterate over all channels of a tunnel.
 *
 * @param t Tunnel whose channels to iterate.
 * @param iter Iterator.
 * @param iter_cls Closure for @c iter.
 */
void
GCT_iterate_channels (struct CadetTunnel *t,
                      GCT_ChannelIterator iter,
                      void *iter_cls);


/**
 * Get the connectivity state of a tunnel.
 *
 * @param t Tunnel.
 *
 * @return Tunnel's connectivity state.
 */
enum CadetTunnelCState
GCT_get_cstate (struct CadetTunnel *t);


/**
 * Get the encryption state of a tunnel.
 *
 * @param t Tunnel.
 *
 * @return Tunnel's encryption state.
 */
enum CadetTunnelEState
GCT_get_estate (struct CadetTunnel *t);


/**
 * Handle KX message.
 *
 * @param ct connection/tunnel combo that received encrypted message
 * @param msg the key exchange message
 */
void
GCT_handle_kx (struct CadetTConnection *ct,
               const struct GNUNET_CADET_TunnelKeyExchangeMessage *msg);


/**
 * Handle encrypted message.
 *
 * @param ct connection/tunnel combo that received encrypted message
 * @param msg the encrypted message to decrypt
 */
void
GCT_handle_encrypted (struct CadetTConnection *ct,
                      const struct GNUNET_CADET_TunnelEncryptedMessage *msg);


/**
 * Log all possible info about the tunnel state.
 *
 * @param t Tunnel to debug.
 * @param level Debug level to use.
 */
void
GCT_debug (const struct CadetTunnel *t,
           enum GNUNET_ErrorType level);


#endif
