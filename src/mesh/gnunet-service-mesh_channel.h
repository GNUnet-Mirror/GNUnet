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
 * @file mesh/gnunet-service-mesh_channel.h
 * @brief mesh service; dealing with end-to-end channels
 * @author Bartlomiej Polot
 *
 * All functions in this file should use the prefix GMCH (Gnunet Mesh CHannel)
 */

#ifndef GNUNET_SERVICE_MESH_CHANNEL_H
#define GNUNET_SERVICE_MESH_CHANNEL_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "platform.h"
#include "gnunet_util_lib.h"

#include "mesh_protocol.h"
#include "mesh.h"

/**
 * Struct containing all information regarding a channel to a remote client.
 */
struct MeshChannel;


#include "gnunet-service-mesh_tunnel.h"
#include "gnunet-service-mesh_local.h"


/**
 * Destroy a channel and free all resources.
 *
 * @param ch Channel to destroy.
 */
void
GMCH_destroy (struct MeshChannel *ch);

/**
 * Get channel ID.
 *
 * @param ch Channel.
 *
 * @return ID
 */
MESH_ChannelNumber
GMCH_get_id (const struct MeshChannel *ch);

/**
 * Get the channel tunnel.
 *
 * @param ch Channel to get the tunnel from.
 *
 * @return tunnel of the channel.
 */
struct MeshTunnel3 *
GMCH_get_tunnel (const struct MeshChannel *ch);

/**
 * Get free buffer space towards the client on a specific channel.
 *
 * @param ch Channel.
 * @param fwd Is query about FWD traffic?
 *
 * @return Free buffer space [0 - 64]
 */
unsigned int
GMCH_get_buffer (struct MeshChannel *ch, int fwd);


/**
 * Get flow control status of end point: is client allow to send?
 *
 * @param ch Channel.
 * @param fwd Is query about FWD traffic? (Request root status).
 *
 * @return #GNUNET_YES if client is allowed to send us data.
 */
int
GMCH_get_allowed (struct MeshChannel *ch, int fwd);


/**
 * Is the root client for this channel on this peer?
 *
 * @param ch Channel.
 * @param fwd Is this for fwd traffic?
 *
 * @return #GNUNET_YES in case it is.
 */
int
GMCH_is_origin (struct MeshChannel *ch, int fwd);

/**
 * Is the destination client for this channel on this peer?
 *
 * @param ch Channel.
 * @param fwd Is this for fwd traffic?
 *
 * @return #GNUNET_YES in case it is.
 */
int
GMCH_is_terminal (struct MeshChannel *ch, int fwd);

/**
 * Send an end-to-end ACK message for the most recent in-sequence payload.
 *
 * If channel is not reliable, do nothing.
 *
 * @param ch Channel this is about.
 * @param fwd Is for FWD traffic? (ACK dest->owner)
 */
void
GMCH_send_data_ack (struct MeshChannel *ch, int fwd);

/**
 * Notify the destination client that a new incoming channel was created.
 *
 * @param ch Channel that was created.
 */
void
GMCH_send_create (struct MeshChannel *ch);

/**
 * Allow a client to send us more data, in case it was choked.
 *
 * @param ch Channel.
 * @param fwd Is this about FWD traffic? (Root client).
 */
void
GMCH_allow_client (struct MeshChannel *ch, int fwd);

/**
 * Log channel info.
 *
 * @param ch Channel.
 */
void
GMCH_debug (struct MeshChannel *ch);

/**
 * Handle an ACK given by a client.
 *
 * Mark client as ready and send him any buffered data we could have for him.
 *
 * @param ch Channel.
 * @param fwd Is this a "FWD ACK"? (FWD ACKs are sent by root and go BCK)
 */
void
GMCH_handle_local_ack (struct MeshChannel *ch, int fwd);

/**
 * Handle data given by a client.
 *
 * Check whether the client is allowed to send in this tunnel, save if channel
 * is reliable and send an ACK to the client if there is still buffer space
 * in the tunnel.
 *
 * @param ch Channel.
 * @param c Client which sent the data.
 * @param message Message.
 * @param fwd Is this a FWD data?
 *
 * @return GNUNET_OK if everything goes well, GNUNET_SYSERR in case of en error.
 */
int
GMCH_handle_local_data (struct MeshChannel *ch,
                        struct MeshClient *c,
                        struct GNUNET_MessageHeader *message,
                        int fwd);

/**
 * Handle a channel destroy requested by a client.
 *
 * Destroy the channel and the tunnel in case this was the last channel.
 *
 * @param ch Channel.
 * @param c Client that requested the destruction (to avoid notifying him).
 * @param is_root Is the request coming from root?
 */
void
GMCH_handle_local_destroy (struct MeshChannel *ch,
                           struct MeshClient *c,
                           int is_root);

/**
 * Handle a channel create requested by a client.
 *
 * Create the channel and the tunnel in case this was the first0 channel.
 *
 * @param c Client that requested the creation (will be the root).
 * @param msg Create Channel message.
 *
 * @return GNUNET_OK if everything went fine, GNUNET_SYSERR otherwise.
 */
int
GMCH_handle_local_create (struct MeshClient *c,
                          struct GNUNET_MESH_ChannelMessage *msg);

/**
 * Handler for mesh network payload traffic.
 *
 * @param ch Channel for the message.
 * @param msg Unencryted data message.
 * @param fwd Is this message fwd? This only is meaningful in loopback channels.
 *            #GNUNET_YES if message is FWD on the respective channel (loopback)
 *            #GNUNET_NO if message is BCK on the respective channel (loopback)
 *            #GNUNET_SYSERR if message on a one-ended channel (remote)
 */
void
GMCH_handle_data (struct MeshChannel *ch,
                  const struct GNUNET_MESH_Data *msg,
                  int fwd);

/**
 * Handler for mesh network traffic end-to-end ACKs.
 *
 * @param ch Channel on which we got this message.
 * @param msg Data message.
 * @param fwd Is this message fwd? This only is meaningful in loopback channels.
 *            #GNUNET_YES if message is FWD on the respective channel (loopback)
 *            #GNUNET_NO if message is BCK on the respective channel (loopback)
 *            #GNUNET_SYSERR if message on a one-ended channel (remote)
 */
void
GMCH_handle_data_ack (struct MeshChannel *ch,
                      const struct GNUNET_MESH_DataACK *msg,
                      int fwd);

/**
 * Handler for channel create messages.
 *
 * Does not have fwd parameter because it's always 'FWD': channel is incoming.
 *
 * @param t Tunnel this channel will be in.
 * @param msg Channel crate message.
 */
struct MeshChannel *
GMCH_handle_create (struct MeshTunnel3 *t,
                    const struct GNUNET_MESH_ChannelCreate *msg);

/**
 * Handler for channel NACK messages.
 *
 * NACK messages always go dest -> root, no need for 'fwd' or 'msg' parameter.
 *
 * @param ch Channel.
 */
void
GMCH_handle_nack (struct MeshChannel *ch);

/**
 * Handler for channel ack messages.
 *
 * @param ch Channel this channel is to be created in.
 * @param msg Message.
 * @param fwd Is this message fwd? This only is meaningful in loopback channels.
 *            #GNUNET_YES if message is FWD on the respective channel (loopback)
 *            #GNUNET_NO if message is BCK on the respective channel (loopback)
 *            #GNUNET_SYSERR if message on a one-ended channel (remote)
 */
void
GMCH_handle_ack (struct MeshChannel *ch,
                 const struct GNUNET_MESH_ChannelManage *msg,
                 int fwd);

/**
 * Handler for channel destroy messages.
 *
 * @param ch Channel this channel is to be destroyed of.
 * @param msg Message.
 * @param fwd Is this message fwd? This only is meaningful in loopback channels.
 *            #GNUNET_YES if message is FWD on the respective channel (loopback)
 *            #GNUNET_NO if message is BCK on the respective channel (loopback)
 *            #GNUNET_SYSERR if message on a one-ended channel (remote)
 */
void
GMCH_handle_destroy (struct MeshChannel *ch,
                     const struct GNUNET_MESH_ChannelManage *msg,
                     int fwd);

/**
 * Sends an already built message on a channel.
 *
 * If the channel is on a loopback tunnel, notifies the appropriate destination
 * client locally.
 *
 * On a normal channel passes the message to the tunnel for encryption and
 * sending on a connection.
 *
 * This function DOES NOT save the message for retransmission.
 *
 * @param message Message to send. Function makes a copy of it.
 * @param ch Channel on which this message is transmitted.
 * @param fwd Is this a fwd message?
 * @param existing_copy This is a retransmission, don't save a copy.
 */
void
GMCH_send_prebuilt_message (const struct GNUNET_MessageHeader *message,
                            struct MeshChannel *ch, int fwd,
                            void *existing_copy);

/**
 * Get the static string for identification of the channel.
 *
 * @param ch Channel.i
 *
 * @return Static string with the channel IDs.
 */
const char *
GMCH_2s (const struct MeshChannel *ch);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_SERVICE_MESH_CHANNEL_H */
#endif
/* end of gnunet-service-mesh_channel.h */
