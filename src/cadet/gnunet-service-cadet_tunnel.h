/*
     This file is part of GNUnet.
     Copyright (C) 2013 Christian Grothoff (and other contributing authors)

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
 * @file cadet/gnunet-service-cadet_tunnel.h
 * @brief cadet service; dealing with tunnels and crypto
 * @author Bartlomiej Polot
 *
 * All functions in this file should use the prefix GMT (Gnunet Cadet Tunnel)
 */

#ifndef GNUNET_SERVICE_CADET_TUNNEL_H
#define GNUNET_SERVICE_CADET_TUNNEL_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "platform.h"
#include "gnunet_util_lib.h"

#define CONNECTIONS_PER_TUNNEL 3

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
   * New ephemeral key and ping sent, waiting for pong.
   * This means that we DO have the peer's ephemeral key, otherwise the
   * state would be KEY_SENT. We DO NOT have a valid session key (either no
   * previous key or previous key expired).
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
  CADET_TUNNEL_KEY_REKEY,
};

/**
 * Struct containing all information regarding a given peer
 */
struct CadetTunnel;


#include "gnunet-service-cadet_channel.h"
#include "gnunet-service-cadet_connection.h"
#include "gnunet-service-cadet_peer.h"

/**
 * Handle for messages queued but not yet sent.
 */
struct CadetTunnelQueue;

/**
 * Callback called when a queued message is sent.
 *
 * @param cls Closure.
 * @param t Tunnel this message was on.
 * @param type Type of message sent.
 * @param size Size of the message.
 */
typedef void (*GCT_sent) (void *cls,
                          struct CadetTunnel *t,
                          struct CadetTunnelQueue *q,
                          uint16_t type, size_t size);

typedef void (*GCT_conn_iter) (void *cls, struct CadetConnection *c);
typedef void (*GCT_chan_iter) (void *cls, struct CadetChannel *ch);


/******************************************************************************/
/********************************    API    ***********************************/
/******************************************************************************/

/**
 * Initialize tunnel subsystem.
 *
 * @param c Configuration handle.
 * @param key ECC private key, to derive all other keys and do crypto.
 */
void
GCT_init (const struct GNUNET_CONFIGURATION_Handle *c,
          const struct GNUNET_CRYPTO_EddsaPrivateKey *key);

/**
 * Shut down the tunnel subsystem.
 */
void
GCT_shutdown (void);

/**
 * Create a tunnel.
 *
 * @param destination Peer this tunnel is towards.
 */
struct CadetTunnel *
GCT_new (struct CadetPeer *destination);

/**
 * Tunnel is empty: destroy it.
 *
 * Notifies all connections about the destruction.
 *
 * @param t Tunnel to destroy.
 */
void
GCT_destroy_empty (struct CadetTunnel *t);

/**
 * Destroy tunnel if empty (no more channels).
 *
 * @param t Tunnel to destroy if empty.
 */
void
GCT_destroy_if_empty (struct CadetTunnel *t);

/**
 * Destroy the tunnel.
 *
 * This function does not generate any warning traffic to clients or peers.
 *
 * Tasks:
 * Cancel messages belonging to this tunnel queued to neighbors.
 * Free any allocated resources linked to the tunnel.
 *
 * @param t The tunnel to destroy.
 */
void
GCT_destroy (struct CadetTunnel *t);


/**
 * Change the tunnel's connection state.
 *
 * @param t Tunnel whose connection state to change.
 * @param cstate New connection state.
 */
void
GCT_change_cstate (struct CadetTunnel* t, enum CadetTunnelCState cstate);


/**
 * Change the tunnel encryption state.
 *
 * @param t Tunnel whose encryption state to change.
 * @param state New encryption state.
 */
void
GCT_change_estate (struct CadetTunnel* t, enum CadetTunnelEState state);

/**
 * Add a connection to a tunnel.
 *
 * @param t Tunnel.
 * @param c Connection.
 */
void
GCT_add_connection (struct CadetTunnel *t, struct CadetConnection *c);

/**
 * Remove a connection from a tunnel.
 *
 * @param t Tunnel.
 * @param c Connection.
 */
void
GCT_remove_connection (struct CadetTunnel *t, struct CadetConnection *c);

/**
 * Add a channel to a tunnel.
 *
 * @param t Tunnel.
 * @param ch Channel.
 */
void
GCT_add_channel (struct CadetTunnel *t, struct CadetChannel *ch);

/**
 * Remove a channel from a tunnel.
 *
 * @param t Tunnel.
 * @param ch Channel.
 */
void
GCT_remove_channel (struct CadetTunnel *t, struct CadetChannel *ch);

/**
 * Search for a channel by global ID.
 *
 * @param t Tunnel containing the channel.
 * @param chid Public channel number.
 *
 * @return channel handler, NULL if doesn't exist
 */
struct CadetChannel *
GCT_get_channel (struct CadetTunnel *t, CADET_ChannelNumber chid);

/**
 * Decrypt and demultiplex by message type. Call appropriate handler
 * for a message towards a channel of a local tunnel.
 *
 * @param t Tunnel this message came on.
 * @param msg Message header.
 */
void
GCT_handle_encrypted (struct CadetTunnel *t,
                      const struct GNUNET_MessageHeader *msg);


/**
 * Demultiplex an encapsulated KX message by message type.
 *
 * @param t Tunnel on which the message came.
 * @param message KX message itself.
 */
void
GCT_handle_kx (struct CadetTunnel *t,
               const struct GNUNET_MessageHeader *message);

/**
 * @brief Use the given path for the tunnel.
 * Update the next and prev hops (and RCs).
 * (Re)start the path refresh in case the tunnel is locally owned.
 *
 * @param t Tunnel to update.
 * @param p Path to use.
 *
 * @return Connection created.
 */
struct CadetConnection *
GCT_use_path (struct CadetTunnel *t, struct CadetPeerPath *p);

/**
 * Count all created connections of a tunnel. Not necessarily ready connections!
 *
 * @param t Tunnel on which to count.
 *
 * @return Number of connections created, either being established or ready.
 */
unsigned int
GCT_count_any_connections (struct CadetTunnel *t);

/**
 * Count established (ready) connections of a tunnel.
 *
 * @param t Tunnel on which to count.
 *
 * @return Number of connections.
 */
unsigned int
GCT_count_connections (struct CadetTunnel *t);

/**
 * Count channels of a tunnel.
 *
 * @param t Tunnel on which to count.
 *
 * @return Number of channels.
 */
unsigned int
GCT_count_channels (struct CadetTunnel *t);

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
 * Get the maximum buffer space for a tunnel towards a local client.
 *
 * @param t Tunnel.
 *
 * @return Biggest buffer space offered by any channel in the tunnel.
 */
unsigned int
GCT_get_channels_buffer (struct CadetTunnel *t);

/**
 * Get the total buffer space for a tunnel for P2P traffic.
 *
 * @param t Tunnel.
 *
 * @return Buffer space offered by all connections in the tunnel.
 */
unsigned int
GCT_get_connections_buffer (struct CadetTunnel *t);

/**
 * Get the tunnel's destination.
 *
 * @param t Tunnel.
 *
 * @return ID of the destination peer.
 */
const struct GNUNET_PeerIdentity *
GCT_get_destination (struct CadetTunnel *t);

/**
 * Get the tunnel's next free Channel ID.
 *
 * @param t Tunnel.
 *
 * @return ID of a channel free to use.
 */
CADET_ChannelNumber
GCT_get_next_chid (struct CadetTunnel *t);

/**
 * Send ACK on one or more channels due to buffer in connections.
 *
 * @param t Channel which has some free buffer space.
 */
void
GCT_unchoke_channels (struct CadetTunnel *t);

/**
 * Send ACK on one or more connections due to buffer space to the client.
 *
 * Iterates all connections of the tunnel and sends ACKs appropriately.
 *
 * @param t Tunnel which has some free buffer space.
 */
void
GCT_send_connection_acks (struct CadetTunnel *t);

/**
 * Cancel a previously sent message while it's in the queue.
 *
 * ONLY can be called before the continuation given to the send function
 * is called. Once the continuation is called, the message is no longer in the
 * queue.
 *
 * @param q Handle to the queue.
 */
void
GCT_cancel (struct CadetTunnelQueue *q);

/**
 * Sends an already built message on a tunnel, encrypting it and
 * choosing the best connection.
 *
 * @param message Message to send. Function modifies it.
 * @param t Tunnel on which this message is transmitted.
 * @param c Connection to use (autoselect if NULL).
 * @param force Force the tunnel to take the message (buffer overfill).
 * @param cont Continuation to call once message is really sent.
 * @param cont_cls Closure for @c cont.
 *
 * @return Handle to cancel message. NULL if @c cont is NULL.
 */
struct CadetTunnelQueue *
GCT_send_prebuilt_message (const struct GNUNET_MessageHeader *message,
                           struct CadetTunnel *t, struct CadetConnection *c,
                           int force, GCT_sent cont, void *cont_cls);

/**
 * Send an Axolotl KX message.
 *
 * @param t Tunnel on which to send it.
 */
void
GCT_send_ax_kx (struct CadetTunnel *t);

/**
 * Sends an already built and encrypted message on a tunnel, choosing the best
 * connection. Useful for re-queueing messages queued on a destroyed connection.
 *
 * @param message Message to send. Function modifies it.
 * @param t Tunnel on which this message is transmitted.
 */
void
GCT_resend_message (const struct GNUNET_MessageHeader *message,
                    struct CadetTunnel *t);

/**
 * Is the tunnel directed towards the local peer?
 *
 * @param t Tunnel.
 *
 * @return #GNUNET_YES if it is loopback.
 */
int
GCT_is_loopback (const struct CadetTunnel *t);

/**
 * Is the tunnel using this path already?
 *
 * @param t Tunnel.
 * @param p Path.
 *
 * @return #GNUNET_YES a connection uses this path.
 */
int
GCT_is_path_used (const struct CadetTunnel *t, const struct CadetPeerPath *p);

/**
 * Get a cost of a path for a tunnel considering existing connections.
 *
 * @param t Tunnel.
 * @param path Candidate path.
 *
 * @return Cost of the path (path length + number of overlapping nodes)
 */
unsigned int
GCT_get_path_cost (const struct CadetTunnel *t,
                   const struct CadetPeerPath *path);

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
 * Log all possible info about the tunnel state.
 *
 * @param t Tunnel to debug.
 * @param level Debug level to use.
 */
void
GCT_debug (const struct CadetTunnel *t, enum GNUNET_ErrorType level);

/**
 * Iterate all tunnels.
 *
 * @param iter Iterator.
 * @param cls Closure for @c iter.
 */
void
GCT_iterate_all (GNUNET_CONTAINER_PeerMapIterator iter, void *cls);

/**
 * Count all tunnels.
 *
 * @return Number of tunnels to remote peers kept by this peer.
 */
unsigned int
GCT_count_all (void);

/**
 * Iterate all connections of a tunnel.
 *
 * @param t Tunnel whose connections to iterate.
 * @param iter Iterator.
 * @param cls Closure for @c iter.
 */
void
GCT_iterate_connections (struct CadetTunnel *t, GCT_conn_iter iter, void *cls);

/**
 * Iterate all channels of a tunnel.
 *
 * @param t Tunnel whose channels to iterate.
 * @param iter Iterator.
 * @param cls Closure for @c iter.
 */
void
GCT_iterate_channels (struct CadetTunnel *t, GCT_chan_iter iter, void *cls);

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_CADET_SERVICE_TUNNEL_H */
#endif
/* end of gnunet-cadet-service_tunnel.h */
