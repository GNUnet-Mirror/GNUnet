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
 * @file mesh/gnunet-service-mesh_connection.h
 * @brief mesh service; dealing with connections
 * @author Bartlomiej Polot
 *
 * All functions in this file should use the prefix GMC (Gnunet Mesh Connection)
 */

#ifndef GNUNET_SERVICE_MESH_CONNECTION_H
#define GNUNET_SERVICE_MESH_CONNECTION_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet_util_lib.h"


/**
 * All the states a connection can be in.
 */
enum MeshConnectionState
{
  /**
   * Uninitialized status, should never appear in operation.
   */
  MESH_CONNECTION_NEW,

  /**
   * Connection create message sent, waiting for ACK.
   */
  MESH_CONNECTION_SENT,

  /**
   * Connection ACK sent, waiting for ACK.
   */
  MESH_CONNECTION_ACK,

  /**
   * Connection confirmed, ready to carry traffic.
   */
  MESH_CONNECTION_READY,
};


/**
 * Struct containing all information regarding a connection to a peer.
 */
struct MeshConnection;

#include "mesh_path.h"
#include "gnunet-service-mesh_channel.h"
#include "gnunet-service-mesh_peer.h"




/**
 * Core handler for connection creation.
 *
 * @param cls Closure (unused).
 * @param peer Sender (neighbor).
 * @param message Message.
 *
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
int
GMC_handle_create (void *cls, const struct GNUNET_PeerIdentity *peer,
                   const struct GNUNET_MessageHeader *message);

/**
 * Core handler for path confirmations.
 *
 * @param cls closure
 * @param message message
 * @param peer peer identity this notification is about
 *
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
int
GMC_handle_confirm (void *cls, const struct GNUNET_PeerIdentity *peer,
                    const struct GNUNET_MessageHeader *message);

/**
 * Core handler for notifications of broken paths
 *
 * @param cls Closure (unused).
 * @param peer Peer identity of sending neighbor.
 * @param message Message.
 *
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
int
GMC_handle_broken (void *cls, const struct GNUNET_PeerIdentity *peer,
                   const struct GNUNET_MessageHeader *message);

/**
 * Core handler for tunnel destruction
 *
 * @param cls Closure (unused).
 * @param peer Peer identity of sending neighbor.
 * @param message Message.
 *
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
int
GMC_handle_destroy (void *cls, const struct GNUNET_PeerIdentity *peer,
                    const struct GNUNET_MessageHeader *message);

/**
 * Core handler for mesh network traffic going orig->dest.
 *
 * @param cls Closure (unused).
 * @param message Message received.
 * @param peer Peer who sent the message.
 *
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
int
GMC_handle_fwd (void *cls, const struct GNUNET_PeerIdentity *peer,
                const struct GNUNET_MessageHeader *message);


/**
 * Core handler for mesh network traffic going dest->orig.
 *
 * @param cls Closure (unused).
 * @param message Message received.
 * @param peer Peer who sent the message.
 *
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
int
GMC_handle_bck (void *cls, const struct GNUNET_PeerIdentity *peer,
                const struct GNUNET_MessageHeader *message);

/**
 * Core handler for mesh network traffic point-to-point acks.
 *
 * @param cls closure
 * @param message message
 * @param peer peer identity this notification is about
 *
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
int
GMC_handle_ack (void *cls, const struct GNUNET_PeerIdentity *peer,
                const struct GNUNET_MessageHeader *message);

/**
 * Core handler for mesh network traffic point-to-point ack polls.
 *
 * @param cls closure
 * @param message message
 * @param peer peer identity this notification is about
 *
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
int
GMC_handle_poll (void *cls, const struct GNUNET_PeerIdentity *peer,
                 const struct GNUNET_MessageHeader *message);

/**
 * Core handler for mesh keepalives.
 *
 * @param cls closure
 * @param message message
 * @param peer peer identity this notification is about
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 *
 * TODO: Check who we got this from, to validate route.
 */
int
GMC_handle_keepalive (void *cls, const struct GNUNET_PeerIdentity *peer,
                      const struct GNUNET_MessageHeader *message);

/**
 * Send an ACK on the appropriate connection/channel, depending on
 * the direction and the position of the peer.
 *
 * @param c Which connection to send the hop-by-hop ACK.
 * @param ch Channel, if any.
 * @param fwd Is this a fwd ACK? (will go dest->root)
 */
void
GMC_send_ack (struct MeshConnection *c, struct MeshChannel *ch, int fwd);

/**
 * Initialize the connections subsystem
 *
 * @param c Configuration handle.
 */
void
GMC_init (const struct GNUNET_CONFIGURATION_Handle *c);

/**
 * Shut down the connections subsystem.
 */
void
GMC_shutdown (void);

/**
 * Create a connection.
 *
 * @param cid Connection ID (either created locally or imposed remotely).
 * @param t Tunnel this connection belongs to (or NULL);
 * @param p Path this connection has to use.
 * @param own_pos Own position in the @c p path.
 */
struct MeshConnection *
GMC_new (const struct GNUNET_HashCode *cid,
         struct MeshTunnel3 *t,
         struct MeshPeerPath *p,
         unsigned int own_pos);

/**
 * Connection is no longer needed: destroy it and remove from tunnel.
 *
 * @param c Connection to destroy.
 */
void
GMC_destroy (struct MeshConnection *c);

/**
 * Get the connection ID.
 *
 * @param c Connection to get the ID from.
 *
 * @return ID of the connection.
 */
const struct GNUNET_HashCode *
GMC_get_id (const struct MeshConnection *c);

/**
 * Get the connection state.
 *
 * @param c Connection to get the state from.
 *
 * @return state of the connection.
 */
enum MeshConnectionState
GMC_get_state (const struct MeshConnection *c);

/**
 * Get the connection tunnel.
 *
 * @param c Connection to get the tunnel from.
 *
 * @return tunnel of the connection.
 */
struct MeshTunnel3 *
GMC_get_tunnel (const struct MeshConnection *c);

/**
 * Get free buffer space in a connection.
 *
 * @param c Connection.
 * @param fwd Is query about FWD traffic?
 *
 * @return Free buffer space [0 - max_msgs_queue/max_connections]
 */
unsigned int
GMC_get_buffer (struct MeshConnection *c, int fwd);

/**
 * Get messages queued in a connection.
 *
 * @param c Connection.
 * @param fwd Is query about FWD traffic?
 *
 * @return Number of messages queued.
 */
unsigned int
GMC_get_qn (struct MeshConnection *c, int fwd);

/**
 * Send FWD keepalive packets for a connection.
 *
 * @param cls Closure (connection for which to send the keepalive).
 * @param tc Notification context.
 */
void
GMC_fwd_keepalive (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);

/**
 * Send BCK keepalive packets for a connection.
 *
 * @param cls Closure (connection for which to send the keepalive).
 * @param tc Notification context.
 */
void
GMC_bck_keepalive (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Change the tunnel state.
 *
 * @param c Connection whose state to change.
 * @param state New state.
 */
void
GMC_change_state (struct MeshConnection* c, enum MeshConnectionState state);

/**
 * Notify other peers on a connection of a broken link. Mark connections
 * to destroy after all traffic has been sent.
 *
 * @param c Connection on which there has been a disconnection.
 * @param peer Peer that disconnected.
 * @param my_full_id My ID (to send to other peers).
 */
void
GMC_notify_broken (struct MeshConnection *c,
                   struct MeshPeer *peer,
                   struct GNUNET_PeerIdentity *my_full_id);

/**
 * Is this peer the first one on the connection?
 *
 * @param c Connection.
 * @param fwd Is this about fwd traffic?
 *
 * @return GNUNET_YES if origin, GNUNET_NO if relay/terminal.
 */
int
GMC_is_origin (struct MeshConnection *c, int fwd);

/**
 * Is this peer the last one on the connection?
 *
 * @param c Connection.
 * @param fwd Is this about fwd traffic?
 *            Note that the ROOT is the terminal for BCK traffic!
 *
 * @return GNUNET_YES if terminal, GNUNET_NO if relay/origin.
 */
int
GMC_is_terminal (struct MeshConnection *c, int fwd);

/**
 * Sends an already built message on a connection, properly registering
 * all used resources.
 *
 * @param message Message to send. Function makes a copy of it.
 *                If message is not hop-by-hop, decrements TTL of copy.
 * @param c Connection on which this message is transmitted.
 * @param ch Channel on which this message is transmitted, or NULL.
 * @param fwd Is this a fwd message?
 */
void
GMC_send_prebuilt_message (const struct GNUNET_MessageHeader *message,
                           struct MeshConnection *c,
                           struct MeshChannel *ch,
                           int fwd);

/**
 * Send a message to all peers in this connection that the connection
 * is no longer valid.
 *
 * If some peer should not receive the message, it should be zero'ed out
 * before calling this function.
 *
 * @param c The connection whose peers to notify.
 */
void
GMC_send_destroy (struct MeshConnection *c);

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_SERVICE_MESH_CONNECTION_H */
#endif
/* end of gnunet-service-mesh_connection.h */
