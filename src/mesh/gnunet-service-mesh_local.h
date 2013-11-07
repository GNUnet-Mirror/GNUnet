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
 * @file mesh/gnunet-service-mesh_local.h
 * @brief mesh service; dealing with local clients
 * @author Bartlomiej Polot
 *
 * All functions in this file should use the prefix GML (Gnunet Mesh Local)
 */

#ifndef GNUNET_SERVICE_MESH_LOCAL_H
#define GNUNET_SERVICE_MESH_LOCAL_H

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
 * Struct containing information about a client of the service
 */
struct MeshClient;

#include "gnunet-service-mesh_channel.h"

/******************************************************************************/
/********************************    API    ***********************************/
/******************************************************************************/

/**
 * Initialize server subsystem.
 *
 * @param handle Server handle.
 */
void
GML_init (struct GNUNET_SERVER_Handle *handle);

/**
 * Install server (service) handlers and start listening to clients.
 */
void
GML_start (void);

/**
 * Shutdown server.
 */
void
GML_shutdown (void);

/**
 * Get a channel from a client.
 *
 * @param c Client to check.
 * @param chid Channel ID, must be local (> 0x800...).
 *
 * @return non-NULL if channel exists in the clients lists
 */
struct MeshChannel *
GML_channel_get (struct MeshClient *c, uint32_t chid);

/**
 * Add a channel to a client
 *
 * @param client Client.
 * @param chid Channel ID.
 * @param ch Channel.
 */
void
GML_channel_add (struct MeshClient *client,
                 uint32_t chid,
                 struct MeshChannel *ch);

/**
 * Remove a channel from a client
 *
 * @param client Client.
 * @param chid Channel ID.
 * @param ch Channel.
 */
void
GML_channel_remove (struct MeshClient *client,
                    uint32_t chid,
                    struct MeshChannel *ch);

/**
 * Get the tunnel's next free local channel ID.
 *
 * @param c Client.
 *
 * @return LID of a channel free to use.
 */
MESH_ChannelNumber
GML_get_next_chid (struct MeshClient *c);

/**
 * Check if client has registered with the service and has not disconnected
 *
 * @param client the client to check
 *
 * @return non-NULL if client exists in the global DLL
 */
struct MeshClient *
GML_client_get (struct GNUNET_SERVER_Client *client);

/**
 * Find a client that has opened a port
 *
 * @param port Port to check.
 *
 * @return non-NULL if a client has the port.
 */
struct MeshClient *
GML_client_get_by_port (uint32_t port);

/**
 * Deletes a tunnel from a client (either owner or destination).
 *
 * @param c Client whose tunnel to delete.
 * @param ch Channel which should be deleted.
 * @param id Channel ID.
 */
void
GML_client_delete_channel (struct MeshClient *c,
                           struct MeshChannel *ch,
                           MESH_ChannelNumber id);

/**
 * Build a local ACK message and send it to a local client, if needed.
 *
 * If the client was already allowed to send data, do nothing.
 *
 * @param c Client to whom send the ACK.
 * @param id Channel ID to use
 */
void
GML_send_ack (struct MeshClient *c, MESH_ChannelNumber id);

/**
 * Build a local channel NACK message and send it to a local client.
 *
 * @param c Client to whom send the NACK.
 * @param id Channel ID to use
 */
void
GML_send_nack (struct MeshClient *c, MESH_ChannelNumber id);

/**
 * Notify the appropriate client that a new incoming channel was created.
 *
 * @param c Client to notify.
 * @param id Channel ID.
 * @param port Channel's destination port.
 * @param opt Options (bit array).
 * @param peer Origin peer.
 */
void
GML_send_channel_create (struct MeshClient *c,
                         uint32_t id, uint32_t port, uint32_t opt,
                         const struct GNUNET_PeerIdentity *peer);

/**
 * Notify a client that a channel is no longer valid.
 *
 * @param c Client.
 * @param id ID of the channel that is destroyed.
 */
void
GML_send_channel_destroy (struct MeshClient *c, uint32_t id);

/**
 * Modify the mesh message ID from global to local and send to client.
 *
 * @param c Client to send to.
 * @param msg Message to modify and send.
 * @param id Channel ID to use (c can be both owner and client).
 */
void
GML_send_data (struct MeshClient *c,
               const struct GNUNET_MESH_Data *msg,
               MESH_ChannelNumber id);

/**
 * Get the static string to represent a client.
 *
 * @param c Client.
 *
 * @return Static string for the client.
 */
const char *
GML_2s (const struct MeshClient *c);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_MESH_SERVICE_LOCAL_H */
#endif
/* end of gnunet-mesh-service_LOCAL.h */