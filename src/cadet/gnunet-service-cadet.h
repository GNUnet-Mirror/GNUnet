/*
     This file is part of GNUnet.
     Copyright (C) 2001-2017 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
 */

/**
 * @file cadet/gnunet-service-cadet.h
 * @brief Information we track per peer.
 * @author Bartlomiej Polot
 * @author Christian Grothoff
 */
#ifndef GNUNET_SERVICE_CADET_H
#define GNUNET_SERVICE_CADET_H

#include "gnunet_util_lib.h"
#include "cadet_protocol.h"

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
struct CadetTConnection
{
  /**
   * Next in DLL.
   */
  struct CadetTConnection *next;

  /**
   * Prev in DLL.
   */
  struct CadetTConnection *prev;

  /**
   * Connection handle.
   */
  struct CadetConnection *cc;

  /**
   * Tunnel this connection belongs to.
   */
  struct CadetTunnel *t;

  /**
   * Creation time, to keep oldest connection alive.
   */
  struct GNUNET_TIME_Absolute created;

  /**
   * Connection throughput, to keep fastest connection alive.
   */
  uint32_t throughput;

  /**
   * Is the connection currently ready for transmission?
   */
  int is_ready;
};


/**
 * Port opened by a client.
 */
struct OpenPort
{
  /**
   * Client that opened the port.
   */
  struct CadetClient *c;

  /**
   * Port number.
   */
  struct GNUNET_HashCode port;

  /**
   * Port hashed with our PID (matches incoming OPEN messages).
   */
  struct GNUNET_HashCode h_port;
};


/**
 * Active path through the network (used by a tunnel).  There may
 * be at most one connection per path.
 */
struct CadetConnection;

/**
 * Description of a segment of a `struct CadetConnection` at the
 * intermediate peers.  Routes are basically entries in a peer's
 * routing table for forwarding traffic.  At both endpoints, the
 * routes are terminated by a `struct CadetConnection`, which knows
 * the complete `struct CadetPath` that is formed by the individual
 * routes.
 */
struct CadetRoute;

/**
 * Logical end-to-end conenction between clients.  There can be
 * any number of channels between clients.
 */
struct CadetChannel;

/**
 * Handle to our configuration.
 */
extern const struct GNUNET_CONFIGURATION_Handle *cfg;

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
 * All ports clients of this peer have opened.  Maps from
 * a hashed port to a `struct OpenPort`.
 */
extern struct GNUNET_CONTAINER_MultiHashMap *open_ports;

/**
 * Map from `struct GNUNET_CADET_ConnectionTunnelIdentifier`
 * hash codes to `struct CadetConnection` objects.
 */
extern struct GNUNET_CONTAINER_MultiShortmap *connections;

/**
 * Map from ports to channels where the ports were closed at the
 * time we got the inbound connection.
 * Indexed by h_port, contains `struct CadetChannel`.
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
 * How frequently do we send KEEPALIVE messages on idle connections?
 */
extern struct GNUNET_TIME_Relative keepalive_period;

/**
 * Signal that shutdown is happening: prevent recovery measures.
 */
extern int shutting_down;

/**
 * Set to non-zero values to create random drops to test retransmissions.
 */
extern unsigned long long drop_percent;


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
 * A channel was destroyed by the other peer. Tell our client.
 *
 * @param c client that lost a channel
 * @param ccn channel identification number for the client
 * @param ch the channel object
 */
void
GSC_handle_remote_channel_destroy (struct CadetClient *c,
                                   struct GNUNET_CADET_ClientChannelNumber ccn,
                                   struct CadetChannel *ch);

/**
 * A client that created a loose channel that was not bound to a port
 * disconnected, drop it from the #loose_channels list.
 *
 * @param h_port the hashed port the channel was trying to bind to
 * @param ch the channel that was lost
 */
void
GSC_drop_loose_channel (const struct GNUNET_HashCode *h_port,
                        struct CadetChannel *ch);


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
