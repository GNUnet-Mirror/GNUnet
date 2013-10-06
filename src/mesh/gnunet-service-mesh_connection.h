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
 * Struct containing all information regarding a connection to a peer.
 */
struct MeshConnection;

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
 * @param cid Connection ID.
 */
struct MeshConnection *
GMC_new (const struct GNUNET_HashCode *cid);

/**
 * Connection is no longer needed: destroy it and remove from tunnel.
 *
 * @param c Connection to destroy.
 */
void
GMC_destroy (struct MeshConnection *c);

/**
 * Count connections in a DLL.
 */
unsigned int
GMC_count (const struct MeshConnection *head);

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
 * Iterator to notify all connections of a broken link. Mark connections
 * to destroy after all traffic has been sent.
 *
 * @param cls Closure (peer disconnected).
 * @param key Current key code (tid).
 * @param value Value in the hash map (connection).
 *
 * @return GNUNET_YES if we should continue to iterate,
 *         GNUNET_NO if not.
 */
int
GMC_notify_broken (void *cls,
                   const struct GNUNET_HashCode *key,
                   void *value);

/**
 * @brief Queue and pass message to core when possible.
 *
 * @param cls Closure (@c type dependant). It will be used by queue_send to
 *            build the message to be sent if not already prebuilt.
 * @param type Type of the message, 0 for a raw message.
 * @param size Size of the message.
 * @param c Connection this message belongs to (cannot be NULL).
 * @param ch Channel this message belongs to, if applicable (otherwise NULL).
 * @param fwd Is this a message going root->dest? (FWD ACK are NOT FWD!)
 */
void
GMC_queue_add (void* cls,
               uint16_t type,
               size_t size,
               struct MeshConnection* c,
               struct MeshChannel* ch,
               int fwd);


/**
 * Free a transmission that was already queued with all resources
 * associated to the request.
 *
 * @param queue Queue handler to cancel.
 * @param clear_cls Is it necessary to free associated cls?
 */
void
GMC_queue_destroy (struct MeshPeerQueue *queue, int clear_cls);


/**
 * Core callback to write a queued packet to core buffer
 *
 * @param cls Closure (peer info).
 * @param size Number of bytes available in buf.
 * @param buf Where the to write the message.
 *
 * @return number of bytes written to buf
 */
size_t
GMC_queue_send (void *cls, size_t size, void *buf);



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



#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_SERVICE_MESH_CONNECTION_H */
#endif
/* end of gnunet-service-mesh_connection.h */