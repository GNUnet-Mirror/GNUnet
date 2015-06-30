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
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/

/**
 * @file cadet/gnunet-service-cadet_connection.h
 * @brief cadet service; dealing with connections
 * @author Bartlomiej Polot
 *
 * All functions in this file should use the prefix GMC (Gnunet Cadet Connection)
 */

#ifndef GNUNET_SERVICE_CADET_CONNECTION_H
#define GNUNET_SERVICE_CADET_CONNECTION_H

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
enum CadetConnectionState
{
  /**
   * Uninitialized status, should never appear in operation.
   */
  CADET_CONNECTION_NEW,

  /**
   * Connection create message sent, waiting for ACK.
   */
  CADET_CONNECTION_SENT,

  /**
   * Connection ACK sent, waiting for ACK.
   */
  CADET_CONNECTION_ACK,

  /**
   * Connection confirmed, ready to carry traffic.
   */
  CADET_CONNECTION_READY,

  /**
   * Connection to be destroyed, just waiting to empty queues.
   */
  CADET_CONNECTION_DESTROYED,

  /**
   * Connection to be destroyed because of a distant peer, same as DESTROYED.
   */
  CADET_CONNECTION_BROKEN,
};


/**
 * Struct containing all information regarding a connection to a peer.
 */
struct CadetConnection;

/**
 * Handle for messages queued but not yet sent.
 */
struct CadetConnectionQueue;

#include "cadet_path.h"
#include "gnunet-service-cadet_channel.h"
#include "gnunet-service-cadet_peer.h"



/**
 * Callback called when a queued message is sent.
 *
 * @param cls Closure.
 * @param c Connection this message was on.
 * @param type Type of message sent.
 * @param fwd Was this a FWD going message?
 * @param size Size of the message.
 */
typedef void (*GCC_sent) (void *cls,
                          struct CadetConnection *c,
                          struct CadetConnectionQueue *q,
                          uint16_t type, int fwd, size_t size);

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
GCC_handle_create (void *cls, const struct GNUNET_PeerIdentity *peer,
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
GCC_handle_confirm (void *cls, const struct GNUNET_PeerIdentity *peer,
                    const struct GNUNET_MessageHeader *message);

/**
 * Core handler for notifications of broken paths
 *
 * @param cls Closure (unused).
 * @param id Peer identity of sending neighbor.
 * @param message Message.
 *
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
int
GCC_handle_broken (void* cls,
                   const struct GNUNET_PeerIdentity* id,
                   const struct GNUNET_MessageHeader* message);

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
GCC_handle_destroy (void *cls, const struct GNUNET_PeerIdentity *peer,
                    const struct GNUNET_MessageHeader *message);

/**
 * Core handler for key exchange traffic (ephemeral key, ping, pong).
 *
 * @param cls Closure (unused).
 * @param message Message received.
 * @param peer Peer who sent the message.
 *
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
int
GCC_handle_kx (void *cls, const struct GNUNET_PeerIdentity *peer,
               const struct GNUNET_MessageHeader *message);

/**
 * Core handler for encrypted cadet network traffic (channel mgmt, data).
 *
 * @param cls Closure (unused).
 * @param message Message received.
 * @param peer Peer who sent the message.
 *
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
int
GCC_handle_encrypted (void *cls, const struct GNUNET_PeerIdentity *peer,
                      const struct GNUNET_MessageHeader *message);

/**
 * Core handler for axolotl key exchange traffic.
 *
 * @param cls Closure (unused).
 * @param message Message received.
 * @param peer Neighbor who sent the message.
 *
 * @return GNUNET_OK, to keep the connection open.
 */
int
GCC_handle_ax_kx (void *cls, const struct GNUNET_PeerIdentity *peer,
                  const struct GNUNET_MessageHeader *message);

/**
 * Core handler for axolotl encrypted cadet network traffic.
 *
 * @param cls Closure (unused).
 * @param message Message received.
 * @param peer Neighbor who sent the message.
 *
 * @return GNUNET_OK, to keep the connection open.
 */
int
GCC_handle_ax (void *cls, const struct GNUNET_PeerIdentity *peer,
               struct GNUNET_MessageHeader *message);

/**
 * Core handler for cadet network traffic point-to-point acks.
 *
 * @param cls closure
 * @param message message
 * @param peer peer identity this notification is about
 *
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
int
GCC_handle_ack (void *cls, const struct GNUNET_PeerIdentity *peer,
                const struct GNUNET_MessageHeader *message);

/**
 * Core handler for cadet network traffic point-to-point ack polls.
 *
 * @param cls closure
 * @param message message
 * @param peer peer identity this notification is about
 *
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
int
GCC_handle_poll (void *cls, const struct GNUNET_PeerIdentity *peer,
                 const struct GNUNET_MessageHeader *message);

/**
 * Core handler for cadet keepalives.
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
GCC_handle_keepalive (void *cls, const struct GNUNET_PeerIdentity *peer,
                      const struct GNUNET_MessageHeader *message);

/**
 * Send an ACK on the appropriate connection/channel, depending on
 * the direction and the position of the peer.
 *
 * @param c Which connection to send the hop-by-hop ACK.
 * @param fwd Is this a fwd ACK? (will go dest->root).
 * @param force Send the ACK even if suboptimal (e.g. requested by POLL).
 */
void
GCC_send_ack (struct CadetConnection *c, int fwd, int force);

/**
 * Initialize the connections subsystem
 *
 * @param c Configuration handle.
 */
void
GCC_init (const struct GNUNET_CONFIGURATION_Handle *c);

/**
 * Shut down the connections subsystem.
 */
void
GCC_shutdown (void);

/**
 * Create a connection.
 *
 * @param cid Connection ID (either created locally or imposed remotely).
 * @param t Tunnel this connection belongs to (or NULL);
 * @param path Path this connection has to use (copy is made).
 * @param own_pos Own position in the @c path path.
 *
 * @return Newly created connection, NULL in case of error (own id not in path).
 */
struct CadetConnection *
GCC_new (const struct GNUNET_CADET_Hash *cid,
         struct CadetTunnel *t,
         struct CadetPeerPath *path,
         unsigned int own_pos);

/**
 * Connection is no longer needed: destroy it.
 *
 * Cancels all pending traffic (including possible DESTROY messages), all
 * maintenance tasks and removes the connection from neighbor peers and tunnel.
 *
 * @param c Connection to destroy.
 */
void
GCC_destroy (struct CadetConnection *c);

/**
 * Get the connection ID.
 *
 * @param c Connection to get the ID from.
 *
 * @return ID of the connection.
 */
const struct GNUNET_CADET_Hash *
GCC_get_id (const struct CadetConnection *c);


/**
 * Get a hash for the connection ID.
 *
 * @param c Connection to get the hash.
 *
 * @return Hash expanded from the ID of the connection.
 */
const struct GNUNET_HashCode *
GCC_get_h (const struct CadetConnection *c);


/**
 * Get the connection path.
 *
 * @param c Connection to get the path from.
 *
 * @return path used by the connection.
 */
const struct CadetPeerPath *
GCC_get_path (const struct CadetConnection *c);

/**
 * Get the connection state.
 *
 * @param c Connection to get the state from.
 *
 * @return state of the connection.
 */
enum CadetConnectionState
GCC_get_state (const struct CadetConnection *c);

/**
 * Get the connection tunnel.
 *
 * @param c Connection to get the tunnel from.
 *
 * @return tunnel of the connection.
 */
struct CadetTunnel *
GCC_get_tunnel (const struct CadetConnection *c);

/**
 * Get free buffer space in a connection.
 *
 * @param c Connection.
 * @param fwd Is query about FWD traffic?
 *
 * @return Free buffer space [0 - max_msgs_queue/max_connections]
 */
unsigned int
GCC_get_buffer (struct CadetConnection *c, int fwd);

/**
 * Get how many messages have we allowed to send to us from a direction.
 *
 * @param c Connection.
 * @param fwd Are we asking about traffic from FWD (BCK messages)?
 *
 * @return last_ack_sent - last_pid_recv
 */
unsigned int
GCC_get_allowed (struct CadetConnection *c, int fwd);

/**
 * Get messages queued in a connection.
 *
 * @param c Connection.
 * @param fwd Is query about FWD traffic?
 *
 * @return Number of messages queued.
 */
unsigned int
GCC_get_qn (struct CadetConnection *c, int fwd);

/**
 * Get next PID to use.
 *
 * @param c Connection.
 * @param fwd Is query about FWD traffic?
 *
 * @return Last PID used + 1.
 */
unsigned int
GCC_get_pid (struct CadetConnection *c, int fwd);

/**
 * Allow the connection to advertise a buffer of the given size.
 *
 * The connection will send an @c fwd ACK message (so: in direction !fwd)
 * allowing up to last_pid_recv + buffer.
 *
 * @param c Connection.
 * @param buffer How many more messages the connection can accept.
 * @param fwd Is this about FWD traffic? (The ack will go dest->root).
 */
void
GCC_allow (struct CadetConnection *c, unsigned int buffer, int fwd);

/**
 * Send FWD keepalive packets for a connection.
 *
 * @param cls Closure (connection for which to send the keepalive).
 * @param tc Notification context.
 */
void
GCC_fwd_keepalive (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);

/**
 * Send BCK keepalive packets for a connection.
 *
 * @param cls Closure (connection for which to send the keepalive).
 * @param tc Notification context.
 */
void
GCC_bck_keepalive (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Notify other peers on a connection of a broken link. Mark connections
 * to destroy after all traffic has been sent.
 *
 * @param c Connection on which there has been a disconnection.
 * @param peer Peer that disconnected.
 */
void
GCC_notify_broken (struct CadetConnection *c,
                   struct CadetPeer *peer);

/**
 * Is this peer the first one on the connection?
 *
 * @param c Connection.
 * @param fwd Is this about fwd traffic?
 *
 * @return #GNUNET_YES if origin, #GNUNET_NO if relay/terminal.
 */
int
GCC_is_origin (struct CadetConnection *c, int fwd);

/**
 * Is this peer the last one on the connection?
 *
 * @param c Connection.
 * @param fwd Is this about fwd traffic?
 *            Note that the ROOT is the terminal for BCK traffic!
 *
 * @return #GNUNET_YES if terminal, #GNUNET_NO if relay/origin.
 */
int
GCC_is_terminal (struct CadetConnection *c, int fwd);

/**
 * See if we are allowed to send by the next hop in the given direction.
 *
 * @param c Connection.
 * @param fwd Is this about fwd traffic?
 *
 * @return #GNUNET_YES in case it's OK to send.
 */
int
GCC_is_sendable (struct CadetConnection *c, int fwd);

/**
 * Check if this connection is a direct one (never trim a direct connection).
 *
 * @param c Connection.
 *
 * @return #GNUNET_YES in case it's a direct connection, #GNUNET_NO otherwise.
 */
int
GCC_is_direct (struct CadetConnection *c);

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
GCC_cancel (struct CadetConnectionQueue *q);

/**
 * Sends an already built message on a connection, properly registering
 * all used resources.
 *
 * @param message Message to send. Function makes a copy of it.
 *                If message is not hop-by-hop, decrements TTL of copy.
 * @param payload_type Type of payload, in case the message is encrypted.
 * @param c Connection on which this message is transmitted.
 * @param fwd Is this a fwd message?
 * @param force Force the connection to accept the message (buffer overfill).
 * @param cont Continuation called once message is sent. Can be NULL.
 * @param cont_cls Closure for @c cont.
 *
 * @return Handle to cancel the message before it's sent.
 *         NULL on error or if @c cont is NULL.
 *         Invalid on @c cont call.
 */
struct CadetConnectionQueue *
GCC_send_prebuilt_message (const struct GNUNET_MessageHeader *message,
                           uint16_t payload_type, uint32_t payload_id,
                           struct CadetConnection *c, int fwd, int force,
                           GCC_sent cont, void *cont_cls);

/**
 * Sends a CREATE CONNECTION message for a path to a peer.
 * Changes the connection and tunnel states if necessary.
 *
 * @param connection Connection to create.
 */
void
GCC_send_create (struct CadetConnection *connection);

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
GCC_send_destroy (struct CadetConnection *c);

/**
 * @brief Start a polling timer for the connection.
 *
 * When a neighbor does not accept more traffic on the connection it could be
 * caused by a simple congestion or by a lost ACK. Polling enables to check
 * for the lastest ACK status for a connection.
 *
 * @param c Connection.
 * @param fwd Should we poll in the FWD direction?
 */
void
GCC_start_poll (struct CadetConnection *c, int fwd);


/**
 * @brief Stop polling a connection for ACKs.
 *
 * Once we have enough ACKs for future traffic, polls are no longer necessary.
 *
 * @param c Connection.
 * @param fwd Should we stop the poll in the FWD direction?
 */
void
GCC_stop_poll (struct CadetConnection *c, int fwd);

/**
 * Get a (static) string for a connection.
 *
 * @param c Connection.
 */
const char *
GCC_2s (const struct CadetConnection *c);

/**
 * Log all possible info about the connection state.
 *
 * @param c Connection to debug.
 * @param level Debug level to use.
 */
void
GCC_debug (const struct CadetConnection *c, enum GNUNET_ErrorType level);

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_SERVICE_CADET_CONNECTION_H */
#endif
/* end of gnunet-service-cadet_connection.h */
