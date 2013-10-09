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
 * All the states a tunnel can be in.
 */
enum MeshTunnelState
{
    /**
     * Uninitialized status, should never appear in operation.
     */
  MESH_TUNNEL_NEW,

    /**
     * Path to the peer not known yet
     */
  MESH_TUNNEL_SEARCHING,

    /**
     * Request sent, not yet answered.
     */
  MESH_TUNNEL_WAITING,

    /**
     * Peer connected and ready to accept data
     */
  MESH_TUNNEL_READY,

    /**
     * Peer connected previosly but not responding
     */
  MESH_TUNNEL_RECONNECTING
};

/**
 * Struct containing all information regarding a given peer
 */
struct MeshTunnel3;


#include "gnunet-service-mesh_channel.h"
#include "gnunet-service-mesh_connection.h"


/******************************************************************************/
/********************************    API    ***********************************/
/******************************************************************************/

/**
 * Initialize tunnel subsystem.
 *
 * @param c Configuration handle.
 * @param id Peer identity.
 * @param key ECC private key, to derive all other keys and do crypto.
 */
void
GMT_init (const struct GNUNET_CONFIGURATION_Handle *c,
          const struct GNUNET_PeerIdentity *id,
          const struct GNUNET_CRYPTO_EccPrivateKey *key);

/**
 * Shut down the tunnel subsystem.
 */
void
GMT_shutdown (void);

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
 * Change the tunnel state.
 *
 * @param t Tunnel whose state to change.
 * @param state New state.
 */
void
GMT_change_state (struct MeshTunnel3* t, enum MeshTunnelState state);

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
 * Cache a message to be sent once tunnel is online.
 *
 * @param t Tunnel to hold the message.
 * @param ch Channel the message is about.
 * @param msg Message itself (copy will be made).
 * @param fwd Is this fwd?
 */
void
GMT_queue_data (struct MeshTunnel3 *t,
                struct MeshChannel *ch,
                struct GNUNET_MessageHeader *msg,
                int fwd);

/**
 * Send all cached messages that we can, tunnel is online.
 *
 * @param t Tunnel that holds the messages.
 * @param fwd Is this fwd?
 */
void
GMT_send_queued_data (struct MeshTunnel3 *t, int fwd);

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
 * Get the state of a tunnel.
 *
 * @param t Tunnel.
 *
 * @return Tunnel's state.
 */
enum MeshTunnelState
GMT_get_state (struct MeshTunnel3 *t);

/**
 * Get the total buffer space for a tunnel.
 *
 * @param t Tunnel.
 * @param fwd Is this for FWD traffic?
 *
 * @return Buffer space offered by all connections in the tunnel.
 */
unsigned int
GMT_get_buffer (struct MeshTunnel3 *t, int fwd);

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
 * Sends an already built message on a tunnel, encrypting it and
 * choosing the best connection.
 *
 * @param message Message to send. Function modifies it.
 * @param t Tunnel on which this message is transmitted.
 * @param ch Channel on which this message is transmitted.
 * @param fwd Is this a fwd message?
 */
void
GMT_send_prebuilt_message (const struct GNUNET_MessageHeader *message,
                           struct MeshTunnel3 *t,
                           struct MeshChannel *ch,
                           int fwd);

/**
 * Is the tunnel directed towards the local peer?
 *
 * @param t Tunnel.
 *
 * @return GNUNET_YES if it is loopback.
 */
int
GMT_is_loopback (const struct MeshTunnel3 *t);

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
