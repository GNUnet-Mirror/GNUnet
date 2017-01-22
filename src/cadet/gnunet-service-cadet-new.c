/*
     This file is part of GNUnet.
     Copyright (C) 2001-2013, 2017 GNUnet e.V.

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
 * @file cadet/gnunet-service-cadet-new.c
 * @brief GNUnet CADET service with encryption
 * @author Bartlomiej Polot
 * @author Christian Grothoff
 *
 * Dictionary:
 * - peer: other cadet instance. If there is direct connection it's a neighbor.
 * - path: series of directly connected peer from one peer to another.
 * - connection: path which is being used in a tunnel.
 * - tunnel: encrypted connection to a peer, neighbor or not.
 * - channel: logical link between two clients, on the same or different peers.
 *            have properties like reliability.
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "cadet.h"
#include "gnunet_statistics_service.h"
#include "gnunet-service-cadet-new.h"
#include "gnunet-service-cadet-new_channel.h"
#include "gnunet-service-cadet-new_connection.h"
#include "gnunet-service-cadet-new_core.h"
#include "gnunet-service-cadet-new_dht.h"
#include "gnunet-service-cadet-new_hello.h"
#include "gnunet-service-cadet-new_tunnels.h"
#include "gnunet-service-cadet-new_peer.h"
#include "gnunet-service-cadet-new_paths.h"

#define LOG(level, ...) GNUNET_log (level,__VA_ARGS__)


/**
 * Struct containing information about a client of the service
 */
struct CadetClient
{
  /**
   * Linked list next
   */
  struct CadetClient *next;

  /**
   * Linked list prev
   */
  struct CadetClient *prev;

  /**
   * Tunnels that belong to this client, indexed by local id,
   * value is a `struct CadetChannel`.
   */
  struct GNUNET_CONTAINER_MultiHashMap32 *channels;

  /**
   * Handle to communicate with the client
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Client handle.
   */
  struct GNUNET_SERVICE_Client *client;

  /**
   * Ports that this client has declared interest in.
   * Indexed by port, contains *Client.
   */
  struct GNUNET_CONTAINER_MultiHashMap *ports;

  /**
   * Channel ID to use for the next incoming channel for this client.
   * Wraps around (in theory).
   */
  struct GNUNET_CADET_ClientChannelNumber next_ccn;

  /**
   * ID of the client, mainly for debug messages. Purely internal to this file.
   */
  unsigned int id;
};

/******************************************************************************/
/***********************      GLOBAL VARIABLES     ****************************/
/******************************************************************************/

/****************************** Global variables ******************************/

/**
 * Handle to our configuration.
 */
const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Handle to the statistics service.
 */
struct GNUNET_STATISTICS_Handle *stats;

/**
 * Handle to communicate with ATS.
 */
struct GNUNET_ATS_ConnectivityHandle *ats_ch;

/**
 * Local peer own ID.
 */
struct GNUNET_PeerIdentity my_full_id;

/**
 * Own private key.
 */
struct GNUNET_CRYPTO_EddsaPrivateKey *my_private_key;

/**
 * Signal that shutdown is happening: prevent recover measures.
 */
int shutting_down;

/**
 * DLL with all the clients, head.
 */
static struct CadetClient *clients_head;

/**
 * DLL with all the clients, tail.
 */
static struct CadetClient *clients_tail;

/**
 * Next ID to assign to a client.
 */
static unsigned int next_client_id;

/**
 * All ports clients of this peer have opened.
 */
struct GNUNET_CONTAINER_MultiHashMap *open_ports;

/**
 * Map from ports to channels where the ports were closed at the
 * time we got the inbound connection.
 * Indexed by port, contains `struct CadetChannel`.
 */
struct GNUNET_CONTAINER_MultiHashMap *loose_channels;

/**
 * Map from PIDs to `struct CadetPeer` entries.
 */
struct GNUNET_CONTAINER_MultiPeerMap *peers;

/**
 * Map from `struct GNUNET_CADET_ConnectionTunnelIdentifier`
 * hash codes to `struct CadetConnection` objects.
 */
struct GNUNET_CONTAINER_MultiShortmap *connections;

/**
 * How many messages are needed to trigger an AXOLOTL ratchet advance.
 */
unsigned long long ratchet_messages;

/**
 * How long until we trigger a ratched advance due to time.
 */
struct GNUNET_TIME_Relative ratchet_time;


/**
 * Send a message to a client.
 *
 * @param c client to get the message
 * @param env envelope with the message
 */
void
GSC_send_to_client (struct CadetClient *c,
                    struct GNUNET_MQ_Envelope *env)
{
  GNUNET_MQ_send (c->mq,
                  env);
}


/**
 * Return identifier for a client as a string.
 *
 * @param c client to identify
 * @return string for debugging
 */
const char *
GSC_2s (struct CadetClient *c)
{
  static char buf[32];

  GNUNET_snprintf (buf,
                   sizeof (buf),
                   "Client(%u)",
                   c->id);
  return buf;
}


/**
 * Lookup channel of client @a c by @a ccn.
 *
 * @param c client to look in
 * @param ccn channel ID to look up
 * @return NULL if no such channel exists
 */
static struct CadetChannel *
lookup_channel (struct CadetClient *c,
                struct GNUNET_CADET_ClientChannelNumber ccn)
{
  return GNUNET_CONTAINER_multihashmap32_get (c->channels,
                                              ntohl (ccn.channel_of_client));
}


/**
 * Obtain the next LID to use for incoming connections to
 * the given client.
 *
 * @param c client handle
 */
static struct GNUNET_CADET_ClientChannelNumber
client_get_next_ccn (struct CadetClient *c)
{
  struct GNUNET_CADET_ClientChannelNumber ccn = c->next_ccn;

  /* increment until we have a free one... */
  while (NULL !=
         lookup_channel (c,
                         ccn))
  {
    ccn.channel_of_client
      = htonl (1 + (ntohl (ccn.channel_of_client)));
    if (ntohl (ccn.channel_of_client) >=
        GNUNET_CADET_LOCAL_CHANNEL_ID_CLI)
      ccn.channel_of_client = htonl (0);
  }
  c->next_ccn.channel_of_client
    = htonl (1 + (ntohl (ccn.channel_of_client)));
  return ccn;
}


/**
 * Bind incoming channel to this client, and notify client about
 * incoming connection.  Caller is responsible for notifying the other
 * peer about our acceptance of the channel.
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
          uint32_t options)
{
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_CADET_LocalChannelCreateMessage *msg;
  struct GNUNET_CADET_ClientChannelNumber ccn;

  ccn = client_get_next_ccn (c);
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap32_put (c->channels,
                                                      ntohl (ccn.channel_of_client),
                                                      ch,
                                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Accepting incoming %s from %s on open port %s (%u)\n",
       GCCH_2s (ch),
       GCP_2s (dest),
       GNUNET_h2s (port),
       ntohl (options));
  /* notify local client about incoming connection! */
  env = GNUNET_MQ_msg (msg,
                       GNUNET_MESSAGE_TYPE_CADET_LOCAL_CHANNEL_CREATE);
  msg->ccn = ccn;
  msg->port = *port;
  msg->opt = htonl (options);
  msg->peer = *GCP_get_id (dest);
  GSC_send_to_client (c,
                      env);
  return ccn;
}


/**
 * Callback invoked on all peers to destroy all tunnels
 * that may still exist.
 *
 * @param cls NULL
 * @param pid identify of a peer
 * @param value a `struct CadetPeer` that may still have a tunnel
 * @return #GNUNET_OK (iterate over all entries)
 */
static int
destroy_tunnels_now (void *cls,
                     const struct GNUNET_PeerIdentity *pid,
                     void *value)
{
  struct CadetPeer *cp = value;
  struct CadetTunnel *t = GCP_get_tunnel (cp,
                                          GNUNET_NO);

  if (NULL != t)
    GCT_destroy_tunnel_now (t);
  return GNUNET_OK;
}


/**
 * Callback invoked on all peers to destroy all tunnels
 * that may still exist.
 *
 * @param cls NULL
 * @param pid identify of a peer
 * @param value a `struct CadetPeer` that may still have a tunnel
 * @return #GNUNET_OK (iterate over all entries)
 */
static int
destroy_paths_now (void *cls,
                   const struct GNUNET_PeerIdentity *pid,
                   void *value)
{
  struct CadetPeer *cp = value;

  GCP_drop_owned_paths (cp);
  return GNUNET_OK;
}


/**
 * Task run during shutdown.
 *
 * @param cls unused
 */
static void
shutdown_task (void *cls)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Shutting down\n");
  shutting_down = GNUNET_YES;
  GCO_shutdown ();
  if (NULL != stats)
  {
    GNUNET_STATISTICS_destroy (stats,
                               GNUNET_NO);
    stats = NULL;
  }
  if (NULL != open_ports)
  {
    GNUNET_CONTAINER_multihashmap_destroy (open_ports);
    open_ports = NULL;
  }
  if (NULL != loose_channels)
  {
    GNUNET_CONTAINER_multihashmap_destroy (loose_channels);
    loose_channels = NULL;
  }
  /* Destroy tunnels.  Note that all channels must be destroyed first! */
  GCP_iterate_all (&destroy_tunnels_now,
                   NULL);
  /* All tunnels, channels, connections and CORE must be down before this point. */
  GCP_iterate_all (&destroy_paths_now,
                   NULL);
  /* All paths, tunnels, channels, connections and CORE must be down before this point. */
  GCP_destroy_all_peers ();
  if (NULL != peers)
  {
    GNUNET_CONTAINER_multipeermap_destroy (peers);
    peers = NULL;
  }
  if (NULL != connections)
  {
    GNUNET_CONTAINER_multishortmap_destroy (connections);
    connections = NULL;
  }
  if (NULL != ats_ch)
  {
    GNUNET_ATS_connectivity_done (ats_ch);
    ats_ch = NULL;
  }
  GCD_shutdown ();
  GCH_shutdown ();
  GNUNET_free_non_null (my_private_key);
  my_private_key = NULL;
}


/**
 * We had a remote connection @a value to port @a port before
 * client @a cls opened port @a port.  Bind them now.
 *
 * @param cls the `struct CadetClient`
 * @param port the port
 * @param value the `struct CadetChannel`
 * @return #GNUNET_YES (iterate over all such channels)
 */
static int
bind_loose_channel (void *cls,
                    const struct GNUNET_HashCode *port,
                    void *value)
{
  struct CadetClient *c = cls;
  struct CadetChannel *ch = value;

  GCCH_bind (ch,
             c);
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap_remove (loose_channels,
                                                       port,
                                                       value));
  return GNUNET_YES;
}


/**
 * Handle port open request.  Creates a mapping from the
 * port to the respective client and checks whether we have
 * loose channels trying to bind to the port.  If so, those
 * are bound.
 *
 * @param cls Identification of the client.
 * @param pmsg The actual message.
 */
static void
handle_port_open (void *cls,
                  const struct GNUNET_CADET_PortMessage *pmsg)
{
  struct CadetClient *c = cls;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Open port %s requested by %s\n",
       GNUNET_h2s (&pmsg->port),
       GSC_2s (c));
  if (NULL == c->ports)
    c->ports = GNUNET_CONTAINER_multihashmap_create (4,
                                                      GNUNET_NO);
  if (GNUNET_OK !=
      GNUNET_CONTAINER_multihashmap_put (c->ports,
                                         &pmsg->port,
                                         c,
                                         GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY))
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (c->client);
    return;
  }
  (void) GNUNET_CONTAINER_multihashmap_put (open_ports,
                                            &pmsg->port,
                                            c,
                                            GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
  GNUNET_CONTAINER_multihashmap_get_multiple (loose_channels,
                                              &pmsg->port,
                                              &bind_loose_channel,
                                              c);
  GNUNET_SERVICE_client_continue (c->client);
}


/**
 * Handler for port close requests.  Marks this port as closed
 * (unless of course we have another client with the same port
 * open).  Note that existing channels accepted on the port are
 * not affected.
 *
 * @param cls Identification of the client.
 * @param pmsg The actual message.
 */
static void
handle_port_close (void *cls,
                   const struct GNUNET_CADET_PortMessage *pmsg)
{
  struct CadetClient *c = cls;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Closing port %s as requested by %s\n",
       GNUNET_h2s (&pmsg->port),
       GSC_2s (c));
  if (GNUNET_YES !=
      GNUNET_CONTAINER_multihashmap_remove (c->ports,
                                            &pmsg->port,
                                            c))
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (c->client);
    return;
  }
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap_remove (open_ports,
                                                       &pmsg->port,
                                                       c));
  GNUNET_SERVICE_client_continue (c->client);
}


/**
 * Handler for requests for us creating a new channel to another peer and port.
 *
 * @param cls Identification of the client.
 * @param tcm The actual message.
 */
static void
handle_channel_create (void *cls,
                       const struct GNUNET_CADET_LocalChannelCreateMessage *tcm)
{
  struct CadetClient *c = cls;
  struct CadetChannel *ch;

  if (ntohl (tcm->ccn.channel_of_client) < GNUNET_CADET_LOCAL_CHANNEL_ID_CLI)
  {
    /* Channel ID not in allowed range. */
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (c->client);
    return;
  }
  ch = lookup_channel (c,
                       tcm->ccn);
  if (NULL != ch)
  {
    /* Channel ID already in use. Not allowed. */
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (c->client);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "New channel to %s at port %s requested by %s\n",
       GNUNET_i2s (&tcm->peer),
       GNUNET_h2s (&tcm->port),
       GSC_2s (c));

  /* Create channel */
  ch = GCCH_channel_local_new (c,
                               tcm->ccn,
                               GCP_get (&tcm->peer,
                                        GNUNET_YES),
                               &tcm->port,
                               ntohl (tcm->opt));
  if (NULL == ch)
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (c->client);
    return;
  }
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap32_put (c->channels,
                                                      ntohl (tcm->ccn.channel_of_client),
                                                      ch,
                                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));

  GNUNET_SERVICE_client_continue (c->client);
}


/**
 * Handler for requests of destroying an existing channel.
 *
 * @param cls client identification of the client
 * @param msg the actual message
 */
static void
handle_channel_destroy (void *cls,
                        const struct GNUNET_CADET_LocalChannelDestroyMessage *msg)
{
  struct CadetClient *c = cls;
  struct CadetChannel *ch;

  ch = lookup_channel (c,
                       msg->ccn);
  if (NULL == ch)
  {
    /* Client attempted to destroy unknown channel */
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (c->client);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_INFO,
       "%s is destroying %s\n",
       GSC_2s(c),
       GCCH_2s (ch));
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap32_remove (c->channels,
                                                         ntohl (msg->ccn.channel_of_client),
                                                         ch));
  GCCH_channel_local_destroy (ch);
  GNUNET_SERVICE_client_continue (c->client);
}


/**
 * Check for client traffic data message is well-formed.
 *
 * @param cls identification of the client
 * @param msg the actual message
 * @return #GNUNET_OK if @a msg is OK, #GNUNET_SYSERR if not
 */
static int
check_data (void *cls,
            const struct GNUNET_CADET_LocalData *msg)
{
  size_t payload_size;
  size_t payload_claimed_size;
  const char *buf;
  struct GNUNET_MessageHeader pa;

  /* Sanity check for message size */
  payload_size = ntohs (msg->header.size) - sizeof (*msg);
  if ( (payload_size < sizeof (struct GNUNET_MessageHeader)) ||
       (GNUNET_CONSTANTS_MAX_CADET_MESSAGE_SIZE < payload_size) )
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  buf = (const char *) &msg[1];
  do {
    /* need to memcpy() for alignment */
    GNUNET_memcpy (&pa,
                   buf,
                   sizeof (pa));
    payload_claimed_size = ntohs (pa.size);
    if (payload_size < payload_claimed_size)
    {
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
    payload_size -= payload_claimed_size;
    buf += payload_claimed_size;
  } while (payload_size >= sizeof (struct GNUNET_MessageHeader));
  if (0 != payload_size)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handler for client payload traffic to be send on a channel to
 * another peer.
 *
 * @param cls identification of the client
 * @param msg the actual message
 */
static void
handle_data (void *cls,
             const struct GNUNET_CADET_LocalData *msg)
{
  struct CadetClient *c = cls;
  struct CadetChannel *ch;
  size_t payload_size;
  const char *buf;

  ch = lookup_channel (c,
                       msg->ccn);
  if (NULL == ch)
  {
    /* Channel does not exist! */
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (c->client);
    return;
  }
  payload_size = ntohs (msg->header.size) - sizeof (*msg);
  buf = (const char *) &msg[1];
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received %u bytes payload from %s for %s\n",
       (unsigned int) payload_size,
       GSC_2s (c),
       GCCH_2s (ch));
  if (GNUNET_OK !=
      GCCH_handle_local_data (ch,
                              buf,
                              payload_size))
  {
    GNUNET_SERVICE_client_drop (c->client);
    return;
  }
  GNUNET_SERVICE_client_continue (c->client);
}


/**
 * Handler for client's ACKs for payload traffic.
 *
 * @param cls identification of the client.
 * @param msg The actual message.
 */
static void
handle_ack (void *cls,
            const struct GNUNET_CADET_LocalAck *msg)
{
  struct CadetClient *c = cls;
  struct CadetChannel *ch;

  ch = lookup_channel (c,
                       msg->ccn);
  if (NULL == ch)
  {
    /* Channel does not exist! */
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (c->client);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Got a local ACK from %s for %s\n",
       GSC_2s(c),
       GCCH_2s (ch));
  GCCH_handle_local_ack (ch);
  GNUNET_SERVICE_client_continue (c->client);
}


/**
 * Iterator over all peers to send a monitoring client info about each peer.
 *
 * @param cls Closure ().
 * @param peer Peer ID (tunnel remote peer).
 * @param value Peer info.
 * @return #GNUNET_YES, to keep iterating.
 */
static int
get_all_peers_iterator (void *cls,
                        const struct GNUNET_PeerIdentity *peer,
                        void *value)
{
  struct CadetClient *c = cls;
  struct CadetPeer *p = value;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_CADET_LocalInfoPeer *msg;

  env = GNUNET_MQ_msg (msg,
                       GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_PEERS);
  msg->destination = *peer;
  msg->paths = htons (GCP_count_paths (p));
  msg->tunnel = htons (NULL != GCP_get_tunnel (p,
                                               GNUNET_NO));
  GNUNET_MQ_send (c->mq,
                  env);
  return GNUNET_YES;
}


/**
 * Handler for client's INFO PEERS request.
 *
 * @param cls Identification of the client.
 * @param message The actual message.
 */
static void
handle_get_peers (void *cls,
                  const struct GNUNET_MessageHeader *message)
{
  struct CadetClient *c = cls;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_MessageHeader *reply;

  GCP_iterate_all (&get_all_peers_iterator,
                   c);
  env = GNUNET_MQ_msg (reply,
                       GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_PEERS);
  GNUNET_MQ_send (c->mq,
                  env);
  GNUNET_SERVICE_client_continue (c->client);
}


/**
 * Iterator over all paths of a peer to build an InfoPeer message.
 * Message contains blocks of peers, first not included.
 *
 * @param cls message queue for transmission
 * @param path Path itself
 * @param off offset of the peer on @a path
 * @return #GNUNET_YES if should keep iterating.
 *         #GNUNET_NO otherwise.
 */
static int
path_info_iterator (void *cls,
                    struct CadetPeerPath *path,
                    unsigned int off)
{
  struct GNUNET_MQ_Handle *mq = cls;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_MessageHeader *resp;
  struct GNUNET_PeerIdentity *id;
  uint16_t path_size;
  unsigned int i;
  unsigned int path_length;

  path_length = GCPP_get_length (path);
  path_size = sizeof (struct GNUNET_PeerIdentity) * (path_length - 1);
  if (sizeof (*resp) + path_size > UINT16_MAX)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Path of %u entries is too long for info message\n",
         path_length);
    return GNUNET_YES;
  }
  env = GNUNET_MQ_msg_extra (resp,
                             path_size,
                             GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_PEER);
  id = (struct GNUNET_PeerIdentity *) &resp[1];

  /* Don't copy first peer.  First peer is always the local one.  Last
   * peer is always the destination (leave as 0, EOL).
   */
  for (i = 0; i < off; i++)
    id[i] = *GCP_get_id (GCPP_get_peer_at_offset (path,
                                                  i + 1));
  GNUNET_MQ_send (mq,
                  env);
  return GNUNET_YES;
}


/**
 * Handler for client's SHOW_PEER request.
 *
 * @param cls Identification of the client.
 * @param msg The actual message.
 */
static void
handle_show_peer (void *cls,
                  const struct GNUNET_CADET_LocalInfo *msg)
{
  struct CadetClient *c = cls;
  struct CadetPeer *p;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_MessageHeader *resp;

  p = GCP_get (&msg->peer,
               GNUNET_NO);
  if (NULL != p)
    GCP_iterate_paths (p,
                       &path_info_iterator,
                       c->mq);
  /* Send message with 0/0 to indicate the end */
  env = GNUNET_MQ_msg (resp,
                       GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_PEER_END);
  GNUNET_MQ_send (c->mq,
                  env);
  GNUNET_SERVICE_client_continue (c->client);
}


/**
 * Iterator over all tunnels to send a monitoring client info about each tunnel.
 *
 * @param cls Closure ().
 * @param peer Peer ID (tunnel remote peer).
 * @param value a `struct CadetPeer`
 * @return #GNUNET_YES, to keep iterating.
 */
static int
get_all_tunnels_iterator (void *cls,
                          const struct GNUNET_PeerIdentity *peer,
                          void *value)
{
  struct CadetClient *c = cls;
  struct CadetPeer *p = value;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_CADET_LocalInfoTunnel *msg;
  struct CadetTunnel *t;

  t = GCP_get_tunnel (p,
                      GNUNET_NO);
  if (NULL == t)
    return GNUNET_YES;
  env = GNUNET_MQ_msg (msg,
                       GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_TUNNELS);
  msg->destination = *peer;
  msg->channels = htonl (GCT_count_channels (t));
  msg->connections = htonl (GCT_count_any_connections (t));
  msg->cstate = htons (0);
  msg->estate = htons ((uint16_t) GCT_get_estate (t));
  GNUNET_MQ_send (c->mq,
                  env);
  return GNUNET_YES;
}


/**
 * Handler for client's #GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_TUNNELS request.
 *
 * @param cls client Identification of the client.
 * @param message The actual message.
 */
static void
handle_info_tunnels (void *cls,
                     const struct GNUNET_MessageHeader *message)
{
  struct CadetClient *c = cls;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_MessageHeader *reply;

  GCP_iterate_all (&get_all_tunnels_iterator,
                   c);
  env = GNUNET_MQ_msg (reply,
                       GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_TUNNELS);
  GNUNET_MQ_send (c->mq,
                  env);
  GNUNET_SERVICE_client_continue (c->client);
}


/**
 * Update the message with information about the connection.
 *
 * @param cls a `struct GNUNET_CADET_LocalInfoTunnel` message to update
 * @param c a connection about which we should store information in @a cls
 */
static void
iter_connection (void *cls,
                 struct CadetConnection *c)
{
  struct GNUNET_CADET_LocalInfoTunnel *msg = cls;
  struct GNUNET_CADET_ConnectionTunnelIdentifier *h;

  h = (struct GNUNET_CADET_ConnectionTunnelIdentifier *) &msg[1];
  h[msg->connections++] = *(GCC_get_id (c));
}


/**
 * Update the message with information about the channel.
 *
 * @param cls a `struct GNUNET_CADET_LocalInfoTunnel` message to update
 * @param ch a channel about which we should store information in @a cls
 */
static void
iter_channel (void *cls,
              struct CadetChannel *ch)
{
  struct GNUNET_CADET_LocalInfoTunnel *msg = cls;
  struct GNUNET_CADET_ConnectionTunnelIdentifier *h = (struct GNUNET_CADET_ConnectionTunnelIdentifier *) &msg[1];
  struct GNUNET_CADET_ChannelTunnelNumber *chn
    = (struct GNUNET_CADET_ChannelTunnelNumber *) &h[msg->connections];

  chn[msg->channels++] = GCCH_get_id (ch);
}


/**
 * Handler for client's #GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_TUNNEL request.
 *
 * @param cls Identification of the client.
 * @param msg The actual message.
 */
static void
handle_info_tunnel (void *cls,
                    const struct GNUNET_CADET_LocalInfo *msg)
{
  struct CadetClient *c = cls;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_CADET_LocalInfoTunnel *resp;
  struct CadetTunnel *t;
  struct CadetPeer *p;
  unsigned int ch_n;
  unsigned int c_n;

  p = GCP_get (&msg->peer,
               GNUNET_NO);
  t = GCP_get_tunnel (p,
                      GNUNET_NO);
  if (NULL == t)
  {
    /* We don't know the tunnel */
    struct GNUNET_MQ_Envelope *env;
    struct GNUNET_CADET_LocalInfoTunnel *warn;

    LOG (GNUNET_ERROR_TYPE_INFO,
         "Tunnel to %s unknown\n",
         GNUNET_i2s_full (&msg->peer));
    env = GNUNET_MQ_msg (warn,
                         GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_TUNNEL);
    warn->destination = msg->peer;
    GNUNET_MQ_send (c->mq,
                    env);
    GNUNET_SERVICE_client_continue (c->client);
    return;
  }

  /* Initialize context */
  ch_n = GCT_count_channels (t);
  c_n = GCT_count_any_connections (t);
  env = GNUNET_MQ_msg_extra (resp,
                             c_n * sizeof (struct GNUNET_CADET_ConnectionTunnelIdentifier) +
                             ch_n * sizeof (struct GNUNET_CADET_ChannelTunnelNumber),
                             GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_TUNNEL);
  resp->destination = msg->peer;
  /* Do not reorder! #iter_channel needs counters in HBO! */
  GCT_iterate_connections (t,
                           &iter_connection,
                           resp);
  GCT_iterate_channels (t,
                        &iter_channel,
                        resp);
  resp->connections = htonl (resp->connections);
  resp->channels = htonl (resp->channels);
  resp->cstate = htons (0);
  resp->estate = htons (GCT_get_estate (t));
  GNUNET_MQ_send (c->mq,
                  env);
  GNUNET_SERVICE_client_continue (c->client);
}


/**
 * Iterator over all peers to dump info for each peer.
 *
 * @param cls Closure (unused).
 * @param peer Peer ID (tunnel remote peer).
 * @param value Peer info.
 *
 * @return #GNUNET_YES, to keep iterating.
 */
static int
show_peer_iterator (void *cls,
                    const struct GNUNET_PeerIdentity *peer,
                    void *value)
{
  struct CadetPeer *p = value;
  struct CadetTunnel *t;

  t = GCP_get_tunnel (p,
                      GNUNET_NO);
  if (NULL != t)
    GCT_debug (t,
               GNUNET_ERROR_TYPE_ERROR);
  LOG (GNUNET_ERROR_TYPE_ERROR, "\n");
  return GNUNET_YES;
}


/**
 * Handler for client's INFO_DUMP request.
 *
 * @param cls Identification of the client.
 * @param message The actual message.
 */
static void
handle_info_dump (void *cls,
                  const struct GNUNET_MessageHeader *message)
{
  struct CadetClient *c = cls;

  LOG (GNUNET_ERROR_TYPE_INFO,
       "Received dump info request from client %u\n",
       c->id);

  LOG (GNUNET_ERROR_TYPE_ERROR,
       "*************************** DUMP START ***************************\n");
  for (struct CadetClient *ci = clients_head;
       NULL != ci;
       ci = ci->next)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Client %u (%p), handle: %p, ports: %u, channels: %u\n",
         ci->id,
         ci,
         ci->client,
         (NULL != c->ports)
         ? GNUNET_CONTAINER_multihashmap_size (ci->ports)
         : 0,
         GNUNET_CONTAINER_multihashmap32_size (ci->channels));
  }
  LOG (GNUNET_ERROR_TYPE_ERROR, "***************************\n");
  GCP_iterate_all (&show_peer_iterator,
                   NULL);

  LOG (GNUNET_ERROR_TYPE_ERROR,
       "**************************** DUMP END ****************************\n");

  GNUNET_SERVICE_client_continue (c->client);
}



/**
 * Callback called when a client connects to the service.
 *
 * @param cls closure for the service
 * @param client the new client that connected to the service
 * @param mq the message queue used to send messages to the client
 * @return @a c
 */
static void *
client_connect_cb (void *cls,
		   struct GNUNET_SERVICE_Client *client,
		   struct GNUNET_MQ_Handle *mq)
{
  struct CadetClient *c;

  c = GNUNET_new (struct CadetClient);
  c->client = client;
  c->mq = mq;
  c->id = next_client_id++; /* overflow not important: just for debug */
  c->channels
    = GNUNET_CONTAINER_multihashmap32_create (32);
  GNUNET_CONTAINER_DLL_insert (clients_head,
                               clients_tail,
                               c);
  GNUNET_STATISTICS_update (stats,
                            "# clients",
                            +1,
                            GNUNET_NO);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "%s connected\n",
       GSC_2s (c));
  return c;
}


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
                                   struct CadetChannel *ch)
{
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_CADET_LocalChannelDestroyMessage *tdm;

  env = GNUNET_MQ_msg (tdm,
                       GNUNET_MESSAGE_TYPE_CADET_LOCAL_CHANNEL_DESTROY);
  tdm->ccn = ccn;
  GSC_send_to_client (c,
                      env);
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap32_remove (c->channels,
                                                         ntohl (ccn.channel_of_client),
                                                         ch));
}


/**
 * Iterator for deleting each channel whose client endpoint disconnected.
 *
 * @param cls Closure (client that has disconnected).
 * @param key The local channel id in host byte order
 * @param value The value stored at the key (channel to destroy).
 * @return #GNUNET_OK, keep iterating.
 */
static int
channel_destroy_iterator (void *cls,
                          uint32_t key,
                          void *value)
{
  struct CadetClient *c = cls;
  struct CadetChannel *ch = value;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Destroying %s, due to %s disconnecting.\n",
       GCCH_2s (ch),
       GSC_2s (c));
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap32_remove (c->channels,
                                                         key,
                                                         ch));
  if (key < GNUNET_CADET_LOCAL_CHANNEL_ID_CLI)
    GCCH_channel_local_destroy (ch);
  else
    GCCH_channel_incoming_destroy (ch);
  return GNUNET_OK;
}


/**
 * Remove client's ports from the global hashmap on disconnect.
 *
 * @param cls Closure (unused).
 * @param key the port.
 * @param value the `struct CadetClient` to remove
 * @return #GNUNET_OK, keep iterating.
 */
static int
client_release_ports (void *cls,
                      const struct GNUNET_HashCode *key,
                      void *value)
{
  struct CadetClient *c = value;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Closing port %s due to %s disconnect.\n",
       GNUNET_h2s (key),
       GSC_2s (c));
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap_remove (open_ports,
                                                       key,
                                                       value));
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap_remove (c->ports,
                                                       key,
                                                       value));
  return GNUNET_OK;
}


/**
 * Callback called when a client disconnected from the service
 *
 * @param cls closure for the service
 * @param client the client that disconnected
 * @param internal_cls should be equal to @a c
 */
static void
client_disconnect_cb (void *cls,
		      struct GNUNET_SERVICE_Client *client,
		      void *internal_cls)
{
  struct CadetClient *c = internal_cls;

  GNUNET_assert (c->client == client);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "%s is disconnecting.\n",
       GSC_2s (c));
  if (NULL != c->channels)
  {
    GNUNET_CONTAINER_multihashmap32_iterate (c->channels,
                                             &channel_destroy_iterator,
                                             c);
    GNUNET_CONTAINER_multihashmap32_destroy (c->channels);
  }
  if (NULL != c->ports)
  {
    GNUNET_CONTAINER_multihashmap_iterate (c->ports,
                                           &client_release_ports,
                                           c);
    GNUNET_CONTAINER_multihashmap_destroy (c->ports);
  }
  GNUNET_CONTAINER_DLL_remove (clients_head,
                               clients_tail,
                               c);
  GNUNET_STATISTICS_update (stats,
                            "# clients",
                            -1,
                            GNUNET_NO);
  GNUNET_free (c);
}


/**
 * Setup CADET internals.
 *
 * @param cls closure
 * @param server the initialized server
 * @param c configuration to use
 */
static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *c,
     struct GNUNET_SERVICE_Handle *service)
{
  cfg = c;
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (c,
                                             "CADET",
                                             "RATCHET_MESSAGES",
                                             &ratchet_messages))
  {
    GNUNET_log_config_invalid (GNUNET_ERROR_TYPE_WARNING,
                               "CADET",
                               "RATCHET_MESSAGES",
                               "needs to be a number");
    ratchet_messages = 64;
  }
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_time (c,
                                           "CADET",
                                           "RATCHET_TIME",
                                           &ratchet_time))
  {
    GNUNET_log_config_invalid (GNUNET_ERROR_TYPE_WARNING,
                               "CADET",
                               "RATCHET_TIME",
                               "need delay value");
    ratchet_time = GNUNET_TIME_UNIT_HOURS;
  }

  my_private_key = GNUNET_CRYPTO_eddsa_key_create_from_configuration (c);
  if (NULL == my_private_key)
  {
    GNUNET_break (0);
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  GNUNET_CRYPTO_eddsa_key_get_public (my_private_key,
                                      &my_full_id.public_key);
  stats = GNUNET_STATISTICS_create ("cadet",
                                    c);
  GNUNET_SCHEDULER_add_shutdown (&shutdown_task,
				 NULL);
  ats_ch = GNUNET_ATS_connectivity_init (c);
  /* FIXME: optimize code to allow GNUNET_YES here! */
  open_ports = GNUNET_CONTAINER_multihashmap_create (16,
                                                     GNUNET_NO);
  loose_channels = GNUNET_CONTAINER_multihashmap_create (16,
                                                         GNUNET_NO);
  peers = GNUNET_CONTAINER_multipeermap_create (16,
                                                GNUNET_YES);
  connections = GNUNET_CONTAINER_multishortmap_create (256,
                                                       GNUNET_YES);
  GCH_init (c);
  GCD_init (c);
  GCO_init (c);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "CADET started for peer %s\n",
              GNUNET_i2s (&my_full_id));

}


/**
 * Define "main" method using service macro.
 */
GNUNET_SERVICE_MAIN
("cadet",
 GNUNET_SERVICE_OPTION_NONE,
 &run,
 &client_connect_cb,
 &client_disconnect_cb,
 NULL,
 GNUNET_MQ_hd_fixed_size (port_open,
                          GNUNET_MESSAGE_TYPE_CADET_LOCAL_PORT_OPEN,
                          struct GNUNET_CADET_PortMessage,
                          NULL),
 GNUNET_MQ_hd_fixed_size (port_close,
                          GNUNET_MESSAGE_TYPE_CADET_LOCAL_PORT_CLOSE,
                          struct GNUNET_CADET_PortMessage,
                          NULL),
 GNUNET_MQ_hd_fixed_size (channel_create,
                          GNUNET_MESSAGE_TYPE_CADET_LOCAL_CHANNEL_CREATE,
                          struct GNUNET_CADET_LocalChannelCreateMessage,
                          NULL),
 GNUNET_MQ_hd_fixed_size (channel_destroy,
                          GNUNET_MESSAGE_TYPE_CADET_LOCAL_CHANNEL_DESTROY,
                          struct GNUNET_CADET_LocalChannelDestroyMessage,
                          NULL),
 GNUNET_MQ_hd_var_size (data,
                        GNUNET_MESSAGE_TYPE_CADET_LOCAL_DATA,
                        struct GNUNET_CADET_LocalData,
                        NULL),
 GNUNET_MQ_hd_fixed_size (ack,
                          GNUNET_MESSAGE_TYPE_CADET_LOCAL_ACK,
                          struct GNUNET_CADET_LocalAck,
                          NULL),
 GNUNET_MQ_hd_fixed_size (get_peers,
                          GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_PEERS,
                          struct GNUNET_MessageHeader,
                          NULL),
 GNUNET_MQ_hd_fixed_size (show_peer,
                          GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_PEER,
                          struct GNUNET_CADET_LocalInfo,
                          NULL),
 GNUNET_MQ_hd_fixed_size (info_tunnels,
                          GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_TUNNELS,
                          struct GNUNET_MessageHeader,
                          NULL),
 GNUNET_MQ_hd_fixed_size (info_tunnel,
                          GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_TUNNEL,
                          struct GNUNET_CADET_LocalInfo,
                          NULL),
 GNUNET_MQ_hd_fixed_size (info_dump,
                          GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_DUMP,
                          struct GNUNET_MessageHeader,
                          NULL),
 GNUNET_MQ_handler_end ());

/* end of gnunet-service-cadet-new.c */
