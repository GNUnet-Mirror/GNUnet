
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

#include "gnunet_util_lib.h"

/**
 * A client to the CADET service.  Each client gets a unique handle.
 */
struct CadetClient;

/**
 * A peer in the GNUnet network.  Each peer we care about must have one globally
 * unique such handle within this process.
 */
struct CadetPeer;

/**
 * Tunnel from us to another peer.  There can only be at most one
 * tunnel per peer.
 */
struct CadetTunnel;

/**
 * Entry in the message queue of a `struct CadetTunnel`.
 */
struct CadetTunnelQueueEntry;

/**
 * A path of peer in the GNUnet network.  There must only be at most
 * once such path.  Paths may share disjoint prefixes, but must all
 * end at a unique suffix.  Paths must also not be proper subsets of
 * other existing paths.
 */
struct CadetPeerPath;

/**
 * Entry in a peer path.
 */
struct CadetPeerPathEntry
{
  /**
   * DLL of paths where the same @e peer is at the same offset.
   */
  struct CadetPeerPathEntry *next;

  /**
   * DLL of paths where the same @e peer is at the same offset.
   */
  struct CadetPeerPathEntry *prev;

  /**
   * The peer at this offset of the path.
   */
  struct CadetPeer *peer;

  /**
   * Path this entry belongs to.
   */
  struct CadetPeerPath *path;

  /**
   * Connection using this path, or NULL for none.
   */
  struct CadetConnection *cc;

  /**
   * Path's historic score up to this point.  Basically, how often did
   * we succeed or fail to use the path up to this entry in a
   * connection.  Positive values indicate good experiences, negative
   * values bad experiences.  Code updating the score must guard
   * against overflows.
   */
  int score;

};

/**
 * Entry in list of connections used by tunnel, with metadata.
 */
struct CadetTConnection;

/**
 * Active path through the network (used by a tunnel).  There may
 * be at most one connection per path.
 */
struct CadetConnection;

/**
 * Logical end-to-end conenction between clients.  There can be
 * any number of channels between clients.
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
 * Map from expanded connection hash codes to `struct CadetConnection` objects.
 */
extern struct GNUNET_CONTAINER_MultiHashMap *connections;

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
 * How many messages are needed to trigger an AXOLOTL ratchet advance.
 */
extern unsigned long long ratchet_messages;

/**
 * How long until we trigger a ratched advance due to time.
 */
extern struct GNUNET_TIME_Relative ratchet_time;



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
