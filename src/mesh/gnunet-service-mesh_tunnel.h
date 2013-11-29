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

/**
 * @file mesh/gnunet-service-mesh_tunnel.h
 * @brief mesh service; dealing with tunnels and crypto
 * @author Bartlomiej Polot
 *
 * All functions in this file should use the prefix GMT (Gnunet Mesh Tunnel)
 */

#ifndef GNUNET_SERVICE_MESH_TUNNEL_H
#define GNUNET_SERVICE_MESH_TUNNEL_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "platform.h"
#include "gnunet_util_lib.h"

/**
 * All the connectivity states a tunnel can be in.
 */
enum MeshTunnel3CState
{
    /**
     * Uninitialized status, should never appear in operation.
     */
  MESH_TUNNEL3_NEW,

    /**
     * Path to the peer not known yet.
     */
  MESH_TUNNEL3_SEARCHING,

    /**
     * Request sent, not yet answered.
     */
  MESH_TUNNEL3_WAITING,

    /**
     * Peer connected and ready to accept data.
     */
  MESH_TUNNEL3_READY,
};


/**
 * All the encryption states a tunnel can be in.
 */
enum MeshTunnel3EState
{
  /**
   * Uninitialized status, should never appear in operation.
   */
  MESH_TUNNEL3_KEY_UNINITIALIZED,

  /**
   * Ephemeral key sent, waiting for peer's key.
   */
  MESH_TUNNEL3_KEY_SENT,

  /**
   * New ephemeral key and ping sent, waiting for pong.
   * This means that we DO have the peer's ephemeral key, otherwise the
   * state would be KEY_SENT.
   */
  MESH_TUNNEL3_KEY_PING,

  /**
   * Handshake completed: session key available.
   */
  MESH_TUNNEL3_KEY_OK,
};

/**
 * Struct containing all information regarding a given peer
 */
struct MeshTunnel3;


#include "gnunet-service-mesh_channel.h"
#include "gnunet-service-mesh_connection.h"
#include "gnunet-service-mesh_peer.h"

/**
 * Handle for messages queued but not yet sent.
 */
struct MeshTunnel3Queue;

/**
 * Callback called when a queued message is sent.
 *
 * @param cls Closure.
 * @param t Tunnel this message was on.
 * @param type Type of message sent.
 * @param size Size of the message.
 */
typedef void (*GMT_sent) (void *cls,
                          struct MeshTunnel3 *t,
                          struct MeshTunnel3Queue *q,
                          uint16_t type, size_t size);


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
GMT_init (const struct GNUNET_CONFIGURATION_Handle *c,
          const struct GNUNET_CRYPTO_EddsaPrivateKey *key);

/**
 * Shut down the tunnel subsystem.
 */
void
GMT_shutdown (void);

/**
 * Create a tunnel.
 *
 * @param destination Peer this tunnel is towards.
 */
struct MeshTunnel3 *
GMT_new (struct MeshPeer *destination);

/**
 * Tunnel is empty: destroy it.
 *
 * Notifies all connections about the destruction.
 *
 * @param t Tunnel to destroy.
 */
void
GMT_destroy_empty (struct MeshTunnel3 *t);

/**
 * Destroy tunnel if empty (no more channels).
 *
 * @param t Tunnel to destroy if empty.
 */
void
GMT_destroy_if_empty (struct MeshTunnel3 *t);

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
GMT_destroy (struct MeshTunnel3 *t);


/**
 * Change the tunnel's connection state.
 *
 * @param t Tunnel whose connection state to change.
 * @param cstate New connection state.
 */
void
GMT_change_cstate (struct MeshTunnel3* t, enum MeshTunnel3CState state);


/**
 * Change the tunnel encryption state.
 *
 * @param t Tunnel whose encryption state to change.
 * @param state New encryption state.
 */
void
GMT_change_estate (struct MeshTunnel3* t, enum MeshTunnel3EState state);

/**
 * Add a connection to a tunnel.
 *
 * @param t Tunnel.
 * @param c Connection.
 */
void
GMT_add_connection (struct MeshTunnel3 *t, struct MeshConnection *c);

/**
 * Remove a connection from a tunnel.
 *
 * @param t Tunnel.
 * @param c Connection.
 */
void
GMT_remove_connection (struct MeshTunnel3 *t, struct MeshConnection *c);

/**
 * Add a channel to a tunnel.
 *
 * @param t Tunnel.
 * @param ch Channel.
 */
void
GMT_add_channel (struct MeshTunnel3 *t, struct MeshChannel *ch);

/**
 * Remove a channel from a tunnel.
 *
 * @param t Tunnel.
 * @param ch Channel.
 */
void
GMT_remove_channel (struct MeshTunnel3 *t, struct MeshChannel *ch);

/**
 * Search for a channel by global ID.
 *
 * @param t Tunnel containing the channel.
 * @param chid Public channel number.
 *
 * @return channel handler, NULL if doesn't exist
 */
struct MeshChannel *
GMT_get_channel (struct MeshTunnel3 *t, MESH_ChannelNumber chid);

/**
 * Decrypt and demultiplex by message type. Call appropriate handler
 * for a message
 * towards a channel of a local tunnel.
 *
 * @param t Tunnel this message came on.
 * @param msg Message header.
 */
void
GMT_handle_encrypted (struct MeshTunnel3 *t,
                      const struct GNUNET_MESH_Encrypted *msg);

/**
 * Demultiplex an encapsulated KX message by message type.
 *
 * @param t Tunnel on which the message came.
 * @param message KX message itself.
 */
void
GMT_handle_kx (struct MeshTunnel3 *t,
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
struct MeshConnection *
GMT_use_path (struct MeshTunnel3 *t, struct MeshPeerPath *p);

/**
 * Count established (ready) connections of a tunnel.
 *
 * @param t Tunnel on which to count.
 *
 * @return Number of connections.
 */
unsigned int
GMT_count_connections (struct MeshTunnel3 *t);

/**
 * Count channels of a tunnel.
 *
 * @param t Tunnel on which to count.
 *
 * @return Number of channels.
 */
unsigned int
GMT_count_channels (struct MeshTunnel3 *t);

/**
 * Get the connectivity state of a tunnel.
 *
 * @param t Tunnel.
 *
 * @return Tunnel's connectivity state.
 */
enum MeshTunnel3CState
GMT_get_cstate (struct MeshTunnel3 *t);

/**
 * Get the maximum buffer space for a tunnel towards a local client.
 *
 * @param t Tunnel.
 *
 * @return Biggest buffer space offered by any channel in the tunnel.
 */
unsigned int
GMT_get_channels_buffer (struct MeshTunnel3 *t);

/**
 * Get the total buffer space for a tunnel for P2P traffic.
 *
 * @param t Tunnel.
 *
 * @return Buffer space offered by all connections in the tunnel.
 */
unsigned int
GMT_get_connections_buffer (struct MeshTunnel3 *t);

/**
 * Get the tunnel's destination.
 *
 * @param t Tunnel.
 *
 * @return ID of the destination peer.
 */
const struct GNUNET_PeerIdentity *
GMT_get_destination (struct MeshTunnel3 *t);

/**
 * Get the tunnel's next free Channel ID.
 *
 * @param t Tunnel.
 *
 * @return ID of a channel free to use.
 */
MESH_ChannelNumber
GMT_get_next_chid (struct MeshTunnel3 *t);

/**
 * Send ACK on one or more channels due to buffer in connections.
 *
 * @param t Channel which has some free buffer space.
 */
void
GMT_unchoke_channels (struct MeshTunnel3 *t);

/**
 * Send ACK on one or more connections due to buffer space to the client.
 *
 * Iterates all connections of the tunnel and sends ACKs appropriately.
 *
 * @param t Tunnel which has some free buffer space.
 */
void
GMT_send_connection_acks (struct MeshTunnel3 *t);

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
GMT_cancel (struct MeshTunnel3Queue *q);

/**
 * Sends an already built message on a tunnel, encrypting it and
 * choosing the best connection.
 *
 * @param message Message to send. Function modifies it.
 * @param t Tunnel on which this message is transmitted.
 * @param ch Channel on which this message is transmitted.
 * @param fwd Is this a fwd message on @c ch?
 * @param force Force the tunnel to take the message (buffer overfill).
 * @param cont Continuation to call once message is really sent.
 * @param cont_cls Closure for @c cont.
 *
 * @return Handle to cancel message. NULL if @c cont is NULL.
 */
struct MeshTunnel3Queue *
GMT_send_prebuilt_message (const struct GNUNET_MessageHeader *message,
                           struct MeshTunnel3 *t,
                           struct MeshChannel *ch, int fwd, int force,
                           GMT_sent cont, void *cont_cls);

/**
 * Is the tunnel directed towards the local peer?
 *
 * @param t Tunnel.
 *
 * @return #GNUNET_YES if it is loopback.
 */
int
GMT_is_loopback (const struct MeshTunnel3 *t);

/**
 * Is the tunnel using this path already?
 *
 * @param t Tunnel.
 * @param p Path.
 *
 * @return #GNUNET_YES a connection uses this path.
 */
int
GMT_is_path_used (const struct MeshTunnel3 *t, const struct MeshPeerPath *p);

/**
 * Get a cost of a path for a tunnel considering existing connections.
 *
 * @param t Tunnel.
 * @param path Candidate path.
 *
 * @return Cost of the path (path length + number of overlapping nodes)
 */
unsigned int
GMT_get_path_cost (const struct MeshTunnel3 *t,
                   const struct MeshPeerPath *path);

/**
 * Get the static string for the peer this tunnel is directed.
 *
 * @param t Tunnel.
 *
 * @return Static string the destination peer's ID.
 */
const char *
GMT_2s (const struct MeshTunnel3 *t);

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_MESH_SERVICE_TUNNEL_H */
#endif
/* end of gnunet-mesh-service_tunnel.h */
