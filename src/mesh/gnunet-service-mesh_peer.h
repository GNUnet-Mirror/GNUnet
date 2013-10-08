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
 * @file mesh/gnunet-service-mesh_peer.h
 * @brief mesh service; dealing with remote peers
 * @author Bartlomiej Polot
 *
 * All functions in this file should use the prefix GMP (Gnunet Mesh Peer)
 */

#ifndef GNUNET_SERVICE_MESH_PEER_H
#define GNUNET_SERVICE_MESH_PEER_H

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
 * Struct containing all information regarding a given peer
 */
struct MeshPeer;


/******************************************************************************/
/********************************    API    ***********************************/
/******************************************************************************/

/**
 * Initialize peer subsystem.
 *
 * @param c Configuration.
 */
void
GMP_init (const struct GNUNET_CONFIGURATION_Handle *c);

/**
 * Shut down the peer subsystem.
 */
void
GMP_shutdown (void);

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
GMP_queue_add (void *cls, uint16_t type, size_t size, 
               struct MeshConnection *c,
               struct MeshChannel *ch,
               int fwd);

/**
 * Free a transmission that was already queued with all resources
 * associated to the request.
 *
 * @param queue Queue handler to cancel.
 * @param clear_cls Is it necessary to free associated cls?
 */
void
GMP_queue_destroy (struct MeshPeerQueue *queue, int clear_cls);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_MESH_SERVICE_PEER_H */
#endif
/* end of gnunet-mesh-service_peer.h */