/*
     This file is part of GNUnet.
     Copyright (C) 2001-2017 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
 */

/**
 * @file cadet/gnunet-service-cadet_tunnels.h
 * @brief Information we track per tunnel.
 * @author Bartlomiej Polot
 * @author Christian Grothoff
 */
#ifndef GNUNET_SERVICE_CADET_TUNNELS_H
#define GNUNET_SERVICE_CADET_TUNNELS_H

#include "gnunet-service-cadet.h"
#include "cadet_protocol.h"


/**
 * How many connections would we like to have per tunnel?
 */
#define DESIRED_CONNECTIONS_PER_TUNNEL 3


/**
 * All the encryption states a tunnel can be in.
 */
enum CadetTunnelEState
{
  /**
   * Uninitialized status, we need to send KX.  We will stay
   * in this state until the first connection is up.
   */
  CADET_TUNNEL_KEY_UNINITIALIZED,

  /**
   * KX message sent, waiting for other peer's KX_AUTH.
   */
  CADET_TUNNEL_KEY_AX_SENT,

  /**
   * KX message received, trying to send back KX_AUTH.
   */
  CADET_TUNNEL_KEY_AX_RECV,

  /**
   * KX message sent and received, trying to send back KX_AUTH.
   */
  CADET_TUNNEL_KEY_AX_SENT_AND_RECV,

  /**
   * KX received and we sent KX_AUTH back, but we got no traffic yet,
   * so we're waiting for either KX_AUTH or ENCRYPED traffic from
   * the other peer.
   *
   * We will not yet send traffic, as this might have been a replay.
   * The other (initiating) peer should send a CHANNEL_OPEN next
   * anyway, and then we are in business!
   */
  CADET_TUNNEL_KEY_AX_AUTH_SENT,

  /**
   * Handshake completed: session key available.
   */
  CADET_TUNNEL_KEY_OK
};

/**
 * Am I Alice or Betty (some call her Bob), or talking to myself?
 *
 * @param other the other peer
 * @return #GNUNET_YES for Alice, #GNUNET_NO for Betty, #GNUNET_SYSERR if talking to myself
 */
int
GCT_alice_or_betty (const struct GNUNET_PeerIdentity *other);

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
 * Destroys the tunnel @a t now, without delay. Used during shutdown.
 *
 * @param t tunnel to destroy
 */
void
GCT_destroy_tunnel_now (struct CadetTunnel *t);


/**
 * Add a @a connection to the @a tunnel.
 *
 * @param t a tunnel
 * @param cid connection identifer to use for the connection
 * @param path path to use for the connection
 * @return #GNUNET_OK on success,
 *         #GNUNET_SYSERR on failure (duplicate connection)
 */
int
GCT_add_inbound_connection (struct CadetTunnel *t,
                            const struct
                            GNUNET_CADET_ConnectionTunnelIdentifier *cid,
                            struct CadetPeerPath *path);


/**
 * We lost a connection, remove it from our list and clean up
 * the connection object itself.
 *
 * @param ct binding of connection to tunnel of the connection that was lost.
 */
void
GCT_connection_lost (struct CadetTConnection *ct);


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
 * @param ctn unique number identifying @a ch within @a t
 */
void
GCT_remove_channel (struct CadetTunnel *t,
                    struct CadetChannel *ch,
                    struct GNUNET_CADET_ChannelTunnelNumber ctn);


/**
 * Send a DESTROY message via the tunnel.
 *
 * @param t the tunnel to transmit over
 * @param ctn ID of the channel to destroy
 */
void
GCT_send_channel_destroy (struct CadetTunnel *t,
                          struct GNUNET_CADET_ChannelTunnelNumber ctn);


/**
 * Function called when a transmission requested using #GCT_send is done.
 *
 * @param cls closure
 * @param ctn identifier of the connection used for transmission, NULL if
 *            the transmission failed (to be used to match ACKs to the
 *            respective connection for connection performance evaluation)
 */
typedef void
(*GCT_SendContinuation)(void *cls,
                        const struct
                        GNUNET_CADET_ConnectionTunnelIdentifier *cid);


/**
 * Sends an already built message on a tunnel, encrypting it and
 * choosing the best connection if not provided.
 *
 * @param message Message to send. Function modifies it.
 * @param t Tunnel on which this message is transmitted.
 * @param cont Continuation to call once message is really sent.
 * @param cont_cls Closure for @c cont.
 * @return Handle to cancel message.
 */
struct CadetTunnelQueueEntry *
GCT_send (struct CadetTunnel *t,
          const struct GNUNET_MessageHeader *message,
          GCT_SendContinuation cont,
          void *cont_cls,
	  struct GNUNET_CADET_ChannelTunnelNumber *ctn);


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
GCT_count_any_connections (const struct CadetTunnel *t);


/**
 * Iterator over connections.
 *
 * @param cls closure
 * @param ct one of the connections
 */
typedef void
(*GCT_ConnectionIterator) (void *cls,
                           struct CadetTConnection *ct);


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
 * Get the encryption state of a tunnel.
 *
 * @param t Tunnel.
 *
 * @return Tunnel's encryption state.
 */
enum CadetTunnelEState
GCT_get_estate (struct CadetTunnel *t);

/**
 * Change the tunnel encryption state.
 * If the encryption state changes to OK, stop the rekey task.
 *
 * @param t Tunnel whose encryption state to change, or NULL.
 * @param state New encryption state.
 */
void
GCT_change_estate (struct CadetTunnel *t,
                   enum CadetTunnelEState state);

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
 * Handle KX_AUTH message.
 *
 * @param ct connection/tunnel combo that received encrypted message
 * @param msg the key exchange message
 */
void
GCT_handle_kx_auth (struct CadetTConnection *ct,
                    const struct
                    GNUNET_CADET_TunnelKeyExchangeAuthMessage *msg);


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
