
/*
     This file is part of GNUnet.
     Copyright (C) 2001-2017 GNUnet e.V.

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
 * @file cadet/gnunet-service-cadet-new_channel.h
 * @brief GNUnet CADET service with encryption
 * @author Bartlomiej Polot
 * @author Christian Grothoff
 */
#ifndef GNUNET_SERVICE_CADET_CHANNEL_H
#define GNUNET_SERVICE_CADET_CHANNEL_H

#include "gnunet-service-cadet-new.h"
#include "gnunet-service-cadet-new_peer.h"
#include "cadet_protocol.h"


/**
 * A channel is a bidirectional connection between two CADET
 * clients.  Communiation can be reliable, unreliable, in-order
 * or out-of-order.  One client is the "local" client, this
 * one initiated the connection.   The other client is the
 * "incoming" client, this one listened on a port to accept
 * the connection from the "local" client.
 */
struct CadetChannel;


/**
 * Get the static string for identification of the channel.
 *
 * @param ch Channel.
 *
 * @return Static string with the channel IDs.
 */
const char *
GCCH_2s (const struct CadetChannel *ch);


/**
 * Log channel info.
 *
 * @param ch Channel.
 * @param level Debug level to use.
 */
void
GCCH_debug (struct CadetChannel *ch,
            enum GNUNET_ErrorType level);


/**
 * Get the channel's public ID.
 *
 * @param ch Channel.
 *
 * @return ID used to identify the channel with the remote peer.
 */
struct GNUNET_CADET_ChannelTunnelNumber
GCCH_get_id (const struct CadetChannel *ch);


/**
 * Create a new channel.
 *
 * @param owner local client owning the channel
 * @param owner_id local chid of this channel at the @a owner
 * @param destination peer to which we should build the channel
 * @param port desired port at @a destination
 * @param options options for the channel
 * @return handle to the new channel
 */
struct CadetChannel *
GCCH_channel_local_new (struct CadetClient *owner,
                        struct GNUNET_CADET_ClientChannelNumber owner_id,
                        struct CadetPeer *destination,
                        const struct GNUNET_HashCode *port,
                        uint32_t options);


/**
 * A client is bound to the port that we have a channel
 * open to.  Send the acknowledgement for the connection
 * request and establish the link with the client.
 *
 * @param ch open incoming channel
 * @param c client listening on the respective port
 */
void
GCCH_bind (struct CadetChannel *ch,
           struct CadetClient *c);


/**
 * Destroy locally created channel.  Called by the
 * local client, so no need to tell the client.
 *
 * @param ch channel to destroy
 */
void
GCCH_channel_local_destroy (struct CadetChannel *ch);


/**
 * Function called once and only once after a channel was bound
 * to its tunnel via #GCT_add_channel() is ready for transmission.
 * Note that this is only the case for channels that this peer
 * initiates, as for incoming channels we assume that they are
 * ready for transmission immediately upon receiving the open
 * message.  Used to bootstrap the #GCT_send() process.
 *
 * @param ch the channel for which the tunnel is now ready
 */
void
GCCH_tunnel_up (struct CadetChannel *ch);


/**
 * Create a new channel based on a request coming in over the network.
 *
 * @param t tunnel to the remote peer
 * @param chid identifier of this channel in the tunnel
 * @param origin peer to who initiated the channel
 * @param port desired local port
 * @param options options for the channel
 * @return handle to the new channel
 */
struct CadetChannel *
GCCH_channel_incoming_new (struct CadetTunnel *t,
                           struct GNUNET_CADET_ChannelTunnelNumber chid,
                           const struct GNUNET_HashCode *port,
                           uint32_t options);


/**
 * Destroy channel that was incoming.  Called by the
 * local client, so no need to tell the client.
 *
 * @param ch channel to destroy
 */
void
GCCH_channel_incoming_destroy (struct CadetChannel *ch);


/**
 * We got payload data for a channel.  Pass it on to the client.
 *
 * @param ch channel that got data
 */
void
GCCH_handle_channel_plaintext_data (struct CadetChannel *ch,
                                    const struct GNUNET_CADET_ChannelAppDataMessage *msg);


/**
 * We got an acknowledgement for payload data for a channel.
 * Possibly resume transmissions.
 *
 * @param ch channel that got the ack
 * @param ack details about what was received
 */
void
GCCH_handle_channel_plaintext_data_ack (struct CadetChannel *ch,
                                        const struct GNUNET_CADET_ChannelDataAckMessage *ack);


/**
 * We got an acknowledgement for the creation of the channel
 * (the port is open on the other side). Begin transmissions.
 *
 * @param ch channel to destroy
 */
void
GCCH_handle_channel_open_ack (struct CadetChannel *ch);


/**
 * Destroy channel, based on the other peer closing the
 * connection.  Also needs to remove this channel from
 * the tunnel.
 *
 * FIXME: need to make it possible to defer destruction until we have
 * received all messages up to the destroy, and right now the destroy
 * message (and this API) fails to give is the information we need!
 *
 * FIXME: also need to know if the other peer got a destroy from
 * us before!
 *
 * @param ch channel to destroy
 */
void
GCCH_handle_remote_destroy (struct CadetChannel *ch);


/**
 * Handle data given by a client.
 *
 * Check whether the client is allowed to send in this tunnel, save if
 * channel is reliable and send an ACK to the client if there is still
 * buffer space in the tunnel.
 *
 * @param ch Channel.
 * @param message payload to transmit.
 * @return #GNUNET_OK if everything goes well,
 *         #GNUNET_SYSERR in case of an error.
 */
int
GCCH_handle_local_data (struct CadetChannel *ch,
                        const struct GNUNET_MessageHeader *message);


/**
 * Handle ACK from client on local channel.
 *
 * @param ch channel to destroy
 */
void
GCCH_handle_local_ack (struct CadetChannel *ch);

#endif
