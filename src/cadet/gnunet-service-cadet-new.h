
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
 * @file cadet/gnunet-service-cadet-new.h
 * @brief Information we track per peer.
 * @author Bartlomiej Polot
 * @author Christian Grothoff
 */
#ifndef GNUNET_SERVICE_CADET_H
#define GNUNET_SERVICE_CADET_H

/**
 * A client to the CADET service.
 */
struct CadetClient;

/**
 * A peer in the GNUnet network.
 */
struct CadetPeer;

/**
 * Tunnel from us to another peer.
 */
struct CadetTunnel;

/**
 * Entry in the message queue of a `struct CadetTunnel`
 */
struct CadetTunnelQueueEntry;

/**
 * A path of peer in the GNUnet network.
 */
struct CadetPeerPath;

/**
 * Active path through the network (used by a tunnel).
 */
struct CadetConnection;

/**
 * Logical end-to-end conenction between clients.
 */
struct CadetChannel;

/**
 * Handle to the statistics service.
 */
extern struct GNUNET_STATISTICS_Handle *stats;

/**
 * Handle to communicate with ATS.
 */
extern struct GNUNET_ATS_ConnectivityHandle *ats_ch;

/**
 * Local peer own ID.
 */
extern struct GNUNET_PeerIdentity my_full_id;

/**
 * Own private key.
 */
extern struct GNUNET_CRYPTO_EddsaPrivateKey *my_private_key;

/**
 * All ports clients of this peer have opened.
 */
extern struct GNUNET_CONTAINER_MultiHashMap *open_ports;

/**
 * Map from ports to channels where the ports were closed at the
 * time we got the inbound connection.
 * Indexed by port, contains `struct CadetChannel`.
 */
extern struct GNUNET_CONTAINER_MultiHashMap *loose_channels;

/**
 * Map from PIDs to `struct CadetPeer` entries.
 */
extern struct GNUNET_CONTAINER_MultiPeerMap *peers;


/**
 * Send a message to a client.
 *
 * @param c client to get the message
 * @param env envelope with the message
 */
void
GSC_send_to_client (struct CadetClient *c,
                    struct GNUNET_MQ_Envelope *env);


/**
 * Bind incoming channel to this client, and notify client
 * about incoming connection.
 *
 * @param c client to bind to
 * @param ch channel to be bound
 * @param dest peer that establishes the connection
 * @param port port number
 * @param options options
 * @return local channel number assigned to the new client
 */
struct GNUNET_CADET_ClientChannelNumber
GSC_bind (struct CadetClient *c,
          struct CadetChannel *ch,
          struct CadetPeer *dest,
          const struct GNUNET_HashCode *port,
          uint32_t options);


/**
 * Return identifier for a client as a string.
 *
 * @param c client to identify
 * @return string for debugging
 */
const char *
GSC_2s (struct CadetClient *c);


#endif
