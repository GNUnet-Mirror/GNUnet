/*
     This file is part of GNUnet.
     Copyright (C) 2013 GNUnet e.V.

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


#include "platform.h"
#include "gnunet_util_lib.h"

#include "gnunet_statistics_service.h"

#include "cadet.h"
#include "cadet_protocol.h" /* GNUNET_CADET_Data is shared */

#include "gnunet-service-cadet_local.h"
#include "gnunet-service-cadet_channel.h"

/* INFO DEBUG */
#include "gnunet-service-cadet_tunnel.h"
#include "gnunet-service-cadet_peer.h"

#define LOG(level, ...) GNUNET_log_from(level,"cadet-loc",__VA_ARGS__)

/******************************************************************************/
/********************************   STRUCTS  **********************************/
/******************************************************************************/

/**
 * Struct containing information about a client of the service
 *
 * TODO: add a list of 'waiting' ports
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
   * Tunnels that belong to this client, indexed by local id
   */
  struct GNUNET_CONTAINER_MultiHashMap32 *own_channels;

  /**
   * Tunnels this client has accepted, indexed by incoming local id
   */
  struct GNUNET_CONTAINER_MultiHashMap32 *incoming_channels;

  /**
   * Channel ID for the next incoming channel.
   */
  struct GNUNET_CADET_ClientChannelNumber next_chid;

  /**
   * Handle to communicate with the client
   */
  struct GNUNET_SERVER_Client *handle;

  /**
   * Ports that this client has declared interest in.
   * Indexed by port, contains *Client.
   */
  struct GNUNET_CONTAINER_MultiHashMap *ports;

  /**
   * Whether the client is active or shutting down (don't send confirmations
   * to a client that is shutting down.
   */
  int shutting_down;

  /**
   * ID of the client, mainly for debug messages
   */
  unsigned int id;
};

/******************************************************************************/
/*******************************   GLOBALS  ***********************************/
/******************************************************************************/

/**
 * Global handle to the statistics service.
 */
extern struct GNUNET_STATISTICS_Handle *stats;

/**
 * Handle to server lib.
 */
static struct GNUNET_SERVER_Handle *server_handle;

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
unsigned int next_client_id;

/**
 * All ports clients of this peer have opened.
 */
static struct GNUNET_CONTAINER_MultiHashMap *ports;

/**
 * Notification context, to send messages to local clients.
 */
static struct GNUNET_SERVER_NotificationContext *nc;


/******************************************************************************/
/********************************   STATIC  ***********************************/
/******************************************************************************/

/**
 * Remove client's ports from the global hashmap on disconnect.
 *
 * @param cls Closure (unused).
 * @param key Port.
 * @param value Client structure.
 *
 * @return #GNUNET_OK, keep iterating.
 */
static int
client_release_ports (void *cls,
                      const struct GNUNET_HashCode *key,
                      void *value)
{
  int res;

  res = GNUNET_CONTAINER_multihashmap_remove (ports, key, value);
  if (GNUNET_YES != res)
  {
    GNUNET_break (0);
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Port %s by client %p was not registered.\n",
         GNUNET_h2s (key), value);
  }
  return GNUNET_OK;
}


/**
 * Iterator for deleting each channel whose client endpoint disconnected.
 *
 * @param cls Closure (client that has disconnected).
 * @param key The local channel id (used to access the hashmap).
 * @param value The value stored at the key (channel to destroy).
 *
 * @return #GNUNET_OK, keep iterating.
 */
static int
channel_destroy_iterator (void *cls,
                          uint32_t key,
                          void *value)
{
  struct CadetChannel *ch = value;
  struct CadetClient *c = cls;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       " Channel %s destroy, due to client %s shutdown.\n",
       GCCH_2s (ch), GML_2s (c));

  GCCH_handle_local_destroy (ch,
                             c,
                             key < GNUNET_CADET_LOCAL_CHANNEL_ID_CLI);
  return GNUNET_OK;
}


/**
 * Unregister data and free memory for a client.
 *
 * @param c Client to destroy. No longer valid after call.
 */
static void
client_destroy (struct CadetClient *c)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  client destroy: %p/%u\n", c, c->id);
  GNUNET_SERVER_client_drop (c->handle);
  c->shutting_down = GNUNET_YES;

  if (NULL != c->own_channels)
  {
    GNUNET_CONTAINER_multihashmap32_iterate (c->own_channels,
                                             &channel_destroy_iterator, c);
    GNUNET_CONTAINER_multihashmap32_destroy (c->own_channels);
  }
  if (NULL != c->incoming_channels)
  {
    GNUNET_CONTAINER_multihashmap32_iterate (c->incoming_channels,
                                             &channel_destroy_iterator, c);
    GNUNET_CONTAINER_multihashmap32_destroy (c->incoming_channels);
  }
  if (NULL != c->ports)
  {
    GNUNET_CONTAINER_multihashmap_iterate (c->ports,
                                           &client_release_ports, c);
    GNUNET_CONTAINER_multihashmap_destroy (c->ports);
  }

  GNUNET_CONTAINER_DLL_remove (clients_head, clients_tail, c);
  GNUNET_STATISTICS_update (stats, "# clients", -1, GNUNET_NO);
  GNUNET_SERVER_client_set_user_context (c->handle, NULL);
  GNUNET_free (c);
}


/**
 * Create a client record, register data and initialize memory.
 *
 * @param client Client's handle.
 */
static struct CadetClient *
client_new (struct GNUNET_SERVER_Client *client)
{
  struct CadetClient *c;

  GNUNET_SERVER_client_keep (client);
  GNUNET_SERVER_notification_context_add (nc, client);

  c = GNUNET_new (struct CadetClient);
  c->handle = client;
  c->id = next_client_id++; /* overflow not important: just for debug */

  c->own_channels = GNUNET_CONTAINER_multihashmap32_create (32);
  c->incoming_channels = GNUNET_CONTAINER_multihashmap32_create (32);

  GNUNET_SERVER_client_set_user_context (client, c);
  GNUNET_CONTAINER_DLL_insert (clients_head, clients_tail, c);
  GNUNET_STATISTICS_update (stats, "# clients", +1, GNUNET_NO);

  LOG (GNUNET_ERROR_TYPE_DEBUG, "  client created: %p/%u\n", c, c->id);

  return c;
}


/******************************************************************************/
/********************************  HANDLES  ***********************************/
/******************************************************************************/

/**
 * Handler for client connection.
 *
 * @param cls Closure (unused).
 * @param client Client handler.
 */
static void
handle_client_connect (void *cls, struct GNUNET_SERVER_Client *client)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Client connected: %p\n", client);
  if (NULL == client)
    return;

  (void) client_new (client);
}


/**
 * Handler for client disconnection
 *
 * @param cls closure
 * @param client identification of the client; NULL
 *        for the last call when the server is destroyed
 */
static void
handle_client_disconnect (void *cls, struct GNUNET_SERVER_Client *client)
{
  struct CadetClient *c;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Client disconnected: %p\n", client);

  c = GML_client_get (client);
  if (NULL != c)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "matching client found (%u, %p)\n",
                c->id, c);
    client_destroy (c);
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, " disconnecting client's context NULL\n");
  }
  return;
}


/**
 * Handler for port open requests.
 *
 * @param cls Closure.
 * @param client Identification of the client.
 * @param message The actual message.
 */
static void
handle_port_open (void *cls, struct GNUNET_SERVER_Client *client,
                  const struct GNUNET_MessageHeader *message)
{
  struct CadetClient *c;
  struct GNUNET_CADET_PortMessage *pmsg;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "open port requested\n");

  /* Sanity check for client registration */
  if (NULL == (c = GML_client_get (client)))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  by client %u\n", c->id);

  /* Message size sanity check */
  if (sizeof (struct GNUNET_CADET_PortMessage) != ntohs (message->size))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  pmsg = (struct GNUNET_CADET_PortMessage *) message;
  if (NULL == c->ports)
  {
    c->ports = GNUNET_CONTAINER_multihashmap_create (4, GNUNET_NO);
  }
  /* store in client's hashmap */
  if (GNUNET_OK !=
      GNUNET_CONTAINER_multihashmap_put (c->ports, &pmsg->port, c,
                                         GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  /* store in global hashmap */
  /* FIXME only allow one client to have the port open,
   *       have a backup hashmap with waiting clients */
  GNUNET_CONTAINER_multihashmap_put (ports, &pmsg->port, c,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);

  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Handler for port close requests.
 *
 * @param cls Closure.
 * @param client Identification of the client.
 * @param message The actual message.
 */
static void
handle_port_close (void *cls, struct GNUNET_SERVER_Client *client,
                   const struct GNUNET_MessageHeader *message)
{
  struct CadetClient *c;
  struct GNUNET_CADET_PortMessage *pmsg;
  int removed;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "close port requested\n");

  /* Sanity check for client registration */
  if (NULL == (c = GML_client_get (client)))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  by client %u\n", c->id);

    /* Message size sanity check */
  if (sizeof (struct GNUNET_CADET_PortMessage) != ntohs (message->size))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  pmsg = (struct GNUNET_CADET_PortMessage *) message;
  removed = GNUNET_CONTAINER_multihashmap_remove (c->ports, &pmsg->port, c);
  GNUNET_break_op (GNUNET_YES == removed);
  removed = GNUNET_CONTAINER_multihashmap_remove (ports, &pmsg->port, c);
  GNUNET_break_op (GNUNET_YES == removed);

  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Handler for requests of new channels.
 *
 * @param cls Closure.
 * @param client Identification of the client.
 * @param message The actual message.
 */
static void
handle_channel_create (void *cls, struct GNUNET_SERVER_Client *client,
                       const struct GNUNET_MessageHeader *message)
{
  struct CadetClient *c;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "\n");
  LOG (GNUNET_ERROR_TYPE_DEBUG, "new channel requested\n");

  /* Sanity check for client registration */
  if (NULL == (c = GML_client_get (client)))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  by client %u\n", c->id);

  /* Message size sanity check */
  if (sizeof (struct GNUNET_CADET_ChannelCreateMessage)
      != ntohs (message->size))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  if (GNUNET_OK !=
      GCCH_handle_local_create (c,
                                (struct GNUNET_CADET_ChannelCreateMessage *)
                                message))
  {
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Handler for requests of deleting tunnels
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_channel_destroy (void *cls, struct GNUNET_SERVER_Client *client,
                        const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_CADET_ChannelDestroyMessage *msg;
  struct CadetClient *c;
  struct CadetChannel *ch;
  struct GNUNET_CADET_ClientChannelNumber chid;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Got a DESTROY CHANNEL from client!\n");

  /* Sanity check for client registration */
  if (NULL == (c = GML_client_get (client)))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  by client %u\n", c->id);

  /* Message sanity check */
  if (sizeof (struct GNUNET_CADET_ChannelDestroyMessage)
      != ntohs (message->size))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  msg = (struct GNUNET_CADET_ChannelDestroyMessage *) message;

  /* Retrieve tunnel */
  chid = msg->channel_id;
  ch = GML_channel_get (c, chid);

  LOG (GNUNET_ERROR_TYPE_INFO, "Client %u is destroying channel %X\n",
       c->id, chid);

  if (NULL == ch)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING, "  channel %X not found\n", chid);
    GNUNET_STATISTICS_update (stats,
                              "# client destroy messages on unknown channel",
                              1, GNUNET_NO);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }

  GCCH_handle_local_destroy (ch,
                             c,
                             ntohl (chid.channel_of_client) < GNUNET_CADET_LOCAL_CHANNEL_ID_CLI);

  GNUNET_SERVER_receive_done (client, GNUNET_OK);
  return;
}


/**
 * Handler for client traffic
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_data (void *cls, struct GNUNET_SERVER_Client *client,
             const struct GNUNET_MessageHeader *message)
{
  const struct GNUNET_MessageHeader *payload;
  struct GNUNET_CADET_LocalData *msg;
  struct CadetClient *c;
  struct CadetChannel *ch;
  struct GNUNET_CADET_ClientChannelNumber chid;
  size_t message_size;
  size_t payload_size;
  size_t payload_claimed_size;
  int fwd;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "\n");
  LOG (GNUNET_ERROR_TYPE_DEBUG, "\n");
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Got data from a client\n");

  /* Sanity check for client registration */
  if (NULL == (c = GML_client_get (client)))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  /* Sanity check for message size */
  message_size = ntohs (message->size);
  if (sizeof (struct GNUNET_CADET_LocalData)
      + sizeof (struct GNUNET_MessageHeader) > message_size
      || GNUNET_CONSTANTS_MAX_CADET_MESSAGE_SIZE < message_size)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  /* Sanity check for payload size */
  payload_size = message_size - sizeof (struct GNUNET_CADET_LocalData);
  msg = (struct GNUNET_CADET_LocalData *) message;
  payload = (struct GNUNET_MessageHeader *) &msg[1];
  payload_claimed_size = ntohs (payload->size);
  if (sizeof (struct GNUNET_MessageHeader) > payload_claimed_size
      || GNUNET_CONSTANTS_MAX_CADET_MESSAGE_SIZE < payload_claimed_size
      || payload_claimed_size > payload_size)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "client claims to send %u bytes in %u payload\n",
         payload_claimed_size, payload_size);
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  chid = msg->id;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  %u bytes (%u payload) by client %u\n",
       payload_size, payload_claimed_size, c->id);

  /* Channel exists? */
  fwd = ntohl (chid.channel_of_client) >= GNUNET_CADET_LOCAL_CHANNEL_ID_CLI;
  ch = GML_channel_get (c, chid);
  if (NULL == ch)
  {
    GNUNET_STATISTICS_update (stats,
                              "# client data messages on unknown channel",
                              1, GNUNET_NO);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }

  if (GNUNET_OK != GCCH_handle_local_data (ch, c, fwd, payload, payload_size))
  {
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  LOG (GNUNET_ERROR_TYPE_DEBUG, "receive done OK\n");
  GNUNET_SERVER_receive_done (client, GNUNET_OK);

  return;
}


/**
 * Handler for client's ACKs for payload traffic.
 *
 * @param cls Closure (unused).
 * @param client Identification of the client.
 * @param message The actual message.
 */
static void
handle_ack (void *cls, struct GNUNET_SERVER_Client *client,
            const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_CADET_LocalAck *msg;
  struct CadetChannel *ch;
  struct CadetClient *c;
  struct GNUNET_CADET_ClientChannelNumber chid;
  int fwd;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "\n");
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Got a local ACK\n");

  /* Sanity check for client registration */
  if (NULL == (c = GML_client_get (client)))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  by client %u\n", c->id);

  msg = (struct GNUNET_CADET_LocalAck *) message;

  /* Channel exists? */
  chid = msg->channel_id;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  on channel %X\n",
       ntohl (chid.channel_of_client));
  ch = GML_channel_get (c, chid);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "   -- ch %p\n", ch);
  if (NULL == ch)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Channel %X unknown.\n",
         ntohl (chid.channel_of_client));
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  for client %u.\n", c->id);
    GNUNET_STATISTICS_update (stats,
                              "# client ack messages on unknown channel",
                              1, GNUNET_NO);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }

  /* If client is root, the ACK is going FWD, therefore this is "BCK ACK". */
  /* If client is dest, the ACK is going BCK, therefore this is "FWD ACK" */
  fwd = ntohl (chid.channel_of_client) < GNUNET_CADET_LOCAL_CHANNEL_ID_CLI;

  GCCH_handle_local_ack (ch, fwd);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Iterator over all peers to send a monitoring client info about each peer.
 *
 * @param cls Closure ().
 * @param peer Peer ID (tunnel remote peer).
 * @param value Peer info.
 *
 * @return #GNUNET_YES, to keep iterating.
 */
static int
get_all_peers_iterator (void *cls,
                        const struct GNUNET_PeerIdentity * peer,
                        void *value)
{
  struct GNUNET_SERVER_Client *client = cls;
  struct CadetPeer *p = value;
  struct GNUNET_CADET_LocalInfoPeer msg;

  msg.header.size = htons (sizeof (msg));
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_PEERS);
  msg.destination = *peer;
  msg.paths = htons (GCP_count_paths (p));
  msg.tunnel = htons (NULL != GCP_get_tunnel (p));

  LOG (GNUNET_ERROR_TYPE_DEBUG, "sending info about peer %s\n",
       GNUNET_i2s (peer));

  GNUNET_SERVER_notification_context_unicast (nc, client,
                                              &msg.header, GNUNET_NO);
  return GNUNET_YES;
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
                        const struct GNUNET_PeerIdentity * peer,
                        void *value)
{
  struct CadetPeer *p = value;
  struct CadetTunnel *t;

  t = GCP_get_tunnel (p);
  if (NULL != t)
    GCT_debug (t, GNUNET_ERROR_TYPE_ERROR);

  LOG (GNUNET_ERROR_TYPE_ERROR, "\n");

  return GNUNET_YES;
}


/**
 * Iterator over all paths of a peer to build an InfoPeer message.
 *
 * Message contains blocks of peers, first not included.
 *
 * @param cls Closure (message to build).
 * @param peer Peer this path is towards.
 * @param path Path itself
 * @return #GNUNET_YES if should keep iterating.
 *         #GNUNET_NO otherwise.
 */
static int
path_info_iterator (void *cls,
                    struct CadetPeer *peer,
                    struct CadetPeerPath *path)
{
  struct GNUNET_CADET_LocalInfoPeer *resp = cls;
  struct GNUNET_PeerIdentity *id;
  uint16_t msg_size;
  uint16_t path_size;
  unsigned int i;

  msg_size = ntohs (resp->header.size);
  path_size = sizeof (struct GNUNET_PeerIdentity) * (path->length - 1);

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Info Path %u\n", path->length);
  if (msg_size + path_size > UINT16_MAX)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING, "path too long for info message\n");
    return GNUNET_NO;
  }

  i = msg_size - sizeof (struct GNUNET_CADET_LocalInfoPeer);
  i = i / sizeof (struct GNUNET_PeerIdentity);

  /* Set id to the address of the first free peer slot. */
  id = (struct GNUNET_PeerIdentity *) &resp[1];
  id = &id[i];

  /* Don't copy first peers.
   * First peer is always the local one.
   * Last peer is always the destination (leave as 0, EOL).
   */
  for (i = 0; i < path->length - 1; i++)
  {
    GNUNET_PEER_resolve (path->peers[i + 1], &id[i]);
    LOG (GNUNET_ERROR_TYPE_DEBUG, " %s\n", GNUNET_i2s (&id[i]));
  }

  resp->header.size = htons (msg_size + path_size);

  return GNUNET_YES;
}


/**
 * Handler for client's INFO PEERS request.
 *
 * @param cls Closure (unused).
 * @param client Identification of the client.
 * @param message The actual message.
 */
static void
handle_get_peers (void *cls, struct GNUNET_SERVER_Client *client,
                    const struct GNUNET_MessageHeader *message)
{
  struct CadetClient *c;
  struct GNUNET_MessageHeader reply;

  /* Sanity check for client registration */
  if (NULL == (c = GML_client_get (client)))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received get peers request from client %u (%p)\n",
       c->id, client);

  GCP_iterate_all (get_all_peers_iterator, client);
  reply.size = htons (sizeof (reply));
  reply.type = htons (GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_PEERS);
  GNUNET_SERVER_notification_context_unicast (nc, client, &reply, GNUNET_NO);

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Get peers request from client %u completed\n", c->id);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Handler for client's SHOW_PEER request.
 *
 * @param cls Closure (unused).
 * @param client Identification of the client.
 * @param message The actual message.
 */
void
handle_show_peer (void *cls, struct GNUNET_SERVER_Client *client,
                  const struct GNUNET_MessageHeader *message)
{
  const struct GNUNET_CADET_LocalInfo *msg;
  struct GNUNET_CADET_LocalInfoPeer *resp;
  struct CadetPeer *p;
  struct CadetClient *c;
  unsigned char cbuf[64 * 1024];

  /* Sanity check for client registration */
  if (NULL == (c = GML_client_get (client)))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  msg = (struct GNUNET_CADET_LocalInfo *) message;
  resp = (struct GNUNET_CADET_LocalInfoPeer *) cbuf;
  LOG (GNUNET_ERROR_TYPE_INFO,
       "Received peer info request from client %u for peer %s\n",
       c->id, GNUNET_i2s_full (&msg->peer));

  resp->header.type = htons (GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_PEER);
  resp->header.size = htons (sizeof (struct GNUNET_CADET_LocalInfoPeer));
  resp->destination = msg->peer;
  p = GCP_get (&msg->peer, GNUNET_NO);
  if (NULL == p)
  {
    /* We don't know the peer */

    LOG (GNUNET_ERROR_TYPE_INFO, "Peer %s unknown\n",
         GNUNET_i2s_full (&msg->peer));
    resp->paths = htons (0);
    resp->tunnel = htons (NULL != GCP_get_tunnel (p));

    GNUNET_SERVER_notification_context_unicast (nc, client,
                                                &resp->header,
                                                GNUNET_NO);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }

  resp->paths = htons (GCP_count_paths (p));
  resp->tunnel = htons (NULL != GCP_get_tunnel (p));
  GCP_iterate_paths (p, &path_info_iterator, resp);

  GNUNET_SERVER_notification_context_unicast (nc, c->handle,
                                              &resp->header, GNUNET_NO);

  LOG (GNUNET_ERROR_TYPE_INFO, "Show peer from client %u completed.\n", c->id);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Iterator over all tunnels to send a monitoring client info about each tunnel.
 *
 * @param cls Closure ().
 * @param peer Peer ID (tunnel remote peer).
 * @param value Tunnel info.
 *
 * @return #GNUNET_YES, to keep iterating.
 */
static int
get_all_tunnels_iterator (void *cls,
                          const struct GNUNET_PeerIdentity * peer,
                          void *value)
{
  struct GNUNET_SERVER_Client *client = cls;
  struct CadetTunnel *t = value;
  struct GNUNET_CADET_LocalInfoTunnel msg;

  msg.header.size = htons (sizeof (msg));
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_TUNNELS);
  msg.destination = *peer;
  msg.channels = htonl (GCT_count_channels (t));
  msg.connections = htonl (GCT_count_any_connections (t));
  msg.cstate = htons ((uint16_t) GCT_get_cstate (t));
  msg.estate = htons ((uint16_t) GCT_get_estate (t));

  LOG (GNUNET_ERROR_TYPE_DEBUG, "sending info about tunnel ->%s\n",
       GNUNET_i2s (peer));

  GNUNET_SERVER_notification_context_unicast (nc, client,
                                              &msg.header, GNUNET_NO);
  return GNUNET_YES;
}


/**
 * Handler for client's INFO TUNNELS request.
 *
 * @param cls Closure (unused).
 * @param client Identification of the client.
 * @param message The actual message.
 */
static void
handle_get_tunnels (void *cls, struct GNUNET_SERVER_Client *client,
                    const struct GNUNET_MessageHeader *message)
{
  struct CadetClient *c;
  struct GNUNET_MessageHeader reply;

  /* Sanity check for client registration */
  if (NULL == (c = GML_client_get (client)))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received get tunnels request from client %u (%p)\n",
       c->id, client);

  GCT_iterate_all (get_all_tunnels_iterator, client);
  reply.size = htons (sizeof (reply));
  reply.type = htons (GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_TUNNELS);
  GNUNET_SERVER_notification_context_unicast (nc, client, &reply, GNUNET_NO);

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Get tunnels request from client %u completed\n", c->id);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


static void
iter_connection (void *cls, struct CadetConnection *c)
{
  struct GNUNET_CADET_LocalInfoTunnel *msg = cls;
  struct GNUNET_CADET_Hash *h = (struct GNUNET_CADET_Hash *) &msg[1];

  h[msg->connections] = *(GCC_get_id (c));
  msg->connections++;
}

static void
iter_channel (void *cls, struct CadetChannel *ch)
{
  struct GNUNET_CADET_LocalInfoTunnel *msg = cls;
  struct GNUNET_CADET_Hash *h = (struct GNUNET_CADET_Hash *) &msg[1];
  struct GNUNET_CADET_ChannelNumber *chn = (struct GNUNET_CADET_ChannelNumber *) &h[msg->connections];

  chn[msg->channels] = GCCH_get_id (ch);
  msg->channels++;
}


/**
 * Handler for client's SHOW_TUNNEL request.
 *
 * @param cls Closure (unused).
 * @param client Identification of the client.
 * @param message The actual message.
 */
void
handle_show_tunnel (void *cls, struct GNUNET_SERVER_Client *client,
                    const struct GNUNET_MessageHeader *message)
{
  const struct GNUNET_CADET_LocalInfo *msg;
  struct GNUNET_CADET_LocalInfoTunnel *resp;
  struct CadetClient *c;
  struct CadetTunnel *t;
  unsigned int ch_n;
  unsigned int c_n;
  size_t size;

  /* Sanity check for client registration */
  if (NULL == (c = GML_client_get (client)))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  msg = (struct GNUNET_CADET_LocalInfo *) message;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received tunnel info request from client %u for tunnel %s\n",
       c->id, GNUNET_i2s_full(&msg->peer));

  t = GCP_get_tunnel (GCP_get (&msg->peer, GNUNET_NO));
  if (NULL == t)
  {
    /* We don't know the tunnel */
    struct GNUNET_CADET_LocalInfoTunnel warn;

    LOG (GNUNET_ERROR_TYPE_INFO, "Tunnel %s unknown %u\n",
         GNUNET_i2s_full(&msg->peer), sizeof (warn));
    warn.header.type = htons (GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_TUNNEL);
    warn.header.size = htons (sizeof (warn));
    warn.destination = msg->peer;
    warn.channels = htonl (0);
    warn.connections = htonl (0);
    warn.cstate = htons (0);
    warn.estate = htons (0);

    GNUNET_SERVER_notification_context_unicast (nc, client,
                                                &warn.header,
                                                GNUNET_NO);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }

  /* Initialize context */
  ch_n = GCT_count_channels (t);
  c_n = GCT_count_any_connections (t);

  size = sizeof (struct GNUNET_CADET_LocalInfoTunnel);
  size += c_n * sizeof (struct GNUNET_CADET_Hash);
  size += ch_n * sizeof (struct GNUNET_CADET_ChannelNumber);

  resp = GNUNET_malloc (size);
  resp->header.type = htons (GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_TUNNEL);
  resp->header.size = htons (size);
  resp->destination = msg->peer;
  /* Do not interleave with iterators, iter_channel needs conn in HBO */
  GCT_iterate_connections (t, &iter_connection, resp);
  GCT_iterate_channels (t, &iter_channel, resp);
  resp->connections = htonl (resp->connections);
  resp->channels = htonl (resp->channels);
  /* Do not interleave end */
  resp->cstate = htons (GCT_get_cstate (t));
  resp->estate = htons (GCT_get_estate (t));
  GNUNET_SERVER_notification_context_unicast (nc, c->handle,
                                              &resp->header, GNUNET_NO);
  GNUNET_free (resp);

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Show tunnel request from client %u completed. %u conn, %u ch\n",
       c->id, c_n, ch_n);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Handler for client's INFO_DUMP request.
 *
 * @param cls Closure (unused).
 * @param client Identification of the client.
 * @param message The actual message.
 */
void
handle_info_dump (void *cls, struct GNUNET_SERVER_Client *client,
                  const struct GNUNET_MessageHeader *message)
{
  struct CadetClient *c;

  /* Sanity check for client registration */
  if (NULL == (c = GML_client_get (client)))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  LOG (GNUNET_ERROR_TYPE_INFO, "Received dump info request from client %u\n",
       c->id);
  LOG (GNUNET_ERROR_TYPE_ERROR,
       "*************************** DUMP START ***************************\n");

  for (c = clients_head; NULL != c; c = c->next)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR, "Client %u (%p), handle: %p\n",
         c->id, c, c->handle);
    if (NULL != c->ports)
      LOG (GNUNET_ERROR_TYPE_ERROR, "\t%3u ports registered\n",
           GNUNET_CONTAINER_multihashmap_size (c->ports));
    else
      LOG (GNUNET_ERROR_TYPE_ERROR, "\t no ports registered\n");
    LOG (GNUNET_ERROR_TYPE_ERROR, "\t%3u own channles\n",
         GNUNET_CONTAINER_multihashmap32_size (c->own_channels));
    LOG (GNUNET_ERROR_TYPE_ERROR, "\t%3u incoming channles\n",
         GNUNET_CONTAINER_multihashmap32_size (c->incoming_channels));
  }
  LOG (GNUNET_ERROR_TYPE_ERROR, "***************************\n");
  GCP_iterate_all (&show_peer_iterator, NULL);

  LOG (GNUNET_ERROR_TYPE_ERROR,
       "**************************** DUMP END ****************************\n");

  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Functions to handle messages from clients
 */
static struct GNUNET_SERVER_MessageHandler client_handlers[] = {
  {&handle_port_open, NULL, GNUNET_MESSAGE_TYPE_CADET_LOCAL_PORT_OPEN,
    sizeof (struct GNUNET_CADET_PortMessage)},
  {&handle_port_close, NULL, GNUNET_MESSAGE_TYPE_CADET_LOCAL_PORT_CLOSE,
    sizeof (struct GNUNET_CADET_PortMessage)},
  {&handle_channel_create, NULL, GNUNET_MESSAGE_TYPE_CADET_CHANNEL_CREATE,
   sizeof (struct GNUNET_CADET_ChannelCreateMessage)},
  {&handle_channel_destroy, NULL, GNUNET_MESSAGE_TYPE_CADET_CHANNEL_DESTROY,
   sizeof (struct GNUNET_CADET_ChannelDestroyMessage)},
  {&handle_data, NULL, GNUNET_MESSAGE_TYPE_CADET_LOCAL_DATA, 0},
  {&handle_ack, NULL, GNUNET_MESSAGE_TYPE_CADET_LOCAL_ACK,
   sizeof (struct GNUNET_CADET_LocalAck)},
  {&handle_get_peers, NULL, GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_PEERS,
   sizeof (struct GNUNET_MessageHeader)},
  {&handle_show_peer, NULL, GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_PEER,
   sizeof (struct GNUNET_CADET_LocalInfo)},
  {&handle_get_tunnels, NULL, GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_TUNNELS,
   sizeof (struct GNUNET_MessageHeader)},
  {&handle_show_tunnel, NULL, GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_TUNNEL,
   sizeof (struct GNUNET_CADET_LocalInfo)},
  {&handle_info_dump, NULL, GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_DUMP,
   sizeof (struct GNUNET_MessageHeader)},
  {NULL, NULL, 0, 0}
};



/******************************************************************************/
/********************************    API    ***********************************/
/******************************************************************************/

/**
 * Initialize server subsystem.
 *
 * @param handle Server handle.
 */
void
GML_init (struct GNUNET_SERVER_Handle *handle)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG, "init\n");
  server_handle = handle;
  GNUNET_SERVER_suspend (server_handle);
  ports = GNUNET_CONTAINER_multihashmap_create (16, GNUNET_NO);
}


/**
 * Install server (service) handlers and start listening to clients.
 */
void
GML_start (void)
{
  GNUNET_SERVER_add_handlers (server_handle, client_handlers);
  GNUNET_SERVER_connect_notify (server_handle,  &handle_client_connect, NULL);
  GNUNET_SERVER_disconnect_notify (server_handle, &handle_client_disconnect,
                                   NULL);
  nc = GNUNET_SERVER_notification_context_create (server_handle, 1);

  clients_head = NULL;
  clients_tail = NULL;
  next_client_id = 0;
  GNUNET_SERVER_resume (server_handle);
}


/**
 * Shutdown server.
 */
void
GML_shutdown (void)
{
  struct CadetClient *c;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Shutting down local\n");

  for (c = clients_head; NULL != clients_head; c = clients_head)
    client_destroy (c);

  if (nc != NULL)
  {
    GNUNET_SERVER_notification_context_destroy (nc);
    nc = NULL;
  }

}


/**
 * Get a channel from a client.
 *
 * @param c Client to check.
 * @param chid Channel ID, must be local (> 0x800...).
 *
 * @return non-NULL if channel exists in the clients lists
 */
struct CadetChannel *
GML_channel_get (struct CadetClient *c,
                 struct GNUNET_CADET_ClientChannelNumber chid)
{
  struct GNUNET_CONTAINER_MultiHashMap32 *map;

  if (ntohl (chid.channel_of_client) >= GNUNET_CADET_LOCAL_CHANNEL_ID_CLI)
    map = c->own_channels;
  else
    map = c->incoming_channels;

  if (NULL == map)
  {
    GNUNET_break (0);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Client %s does no t have a valid map for CHID %X\n",
         GML_2s (c), chid);
    return NULL;
  }
  return GNUNET_CONTAINER_multihashmap32_get (map,
                                              chid.channel_of_client);
}


/**
 * Add a channel to a client
 *
 * @param client Client.
 * @param chid Channel ID.
 * @param ch Channel.
 */
void
GML_channel_add (struct CadetClient *client,
                 struct GNUNET_CADET_ClientChannelNumber chid,
                 struct CadetChannel *ch)
{
  if (ntohl (chid.channel_of_client) >= GNUNET_CADET_LOCAL_CHANNEL_ID_CLI)
    GNUNET_CONTAINER_multihashmap32_put (client->own_channels,
                                         chid.channel_of_client,
                                         ch,
                                         GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
  else
    GNUNET_CONTAINER_multihashmap32_put (client->incoming_channels,
                                         chid.channel_of_client,
                                         ch,
                                         GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
}


/**
 * Remove a channel from a client.
 *
 * @param client Client.
 * @param chid Channel ID.
 * @param ch Channel.
 */
void
GML_channel_remove (struct CadetClient *client,
                    struct GNUNET_CADET_ClientChannelNumber chid,
                    struct CadetChannel *ch)
{
  if (ntohl (chid.channel_of_client) >= GNUNET_CADET_LOCAL_CHANNEL_ID_CLI)
    GNUNET_CONTAINER_multihashmap32_remove (client->own_channels,
                                            chid.channel_of_client,
                                            ch);
  else
    GNUNET_CONTAINER_multihashmap32_remove (client->incoming_channels,
                                            chid.channel_of_client,
                                            ch);
}


/**
 * Get the tunnel's next free local channel ID.
 *
 * @param c Client.
 *
 * @return LID of a channel free to use.
 */
struct GNUNET_CADET_ClientChannelNumber
GML_get_next_chid (struct CadetClient *c)
{
  struct GNUNET_CADET_ClientChannelNumber chid;

  while (NULL != GML_channel_get (c,
                                  c->next_chid))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Channel %u exists...\n",
         c->next_chid);
    c->next_chid.channel_of_client
      = htonl (1 + (ntohl (c->next_chid.channel_of_client)));
    if (ntohl (c->next_chid.channel_of_client) >=
        GNUNET_CADET_LOCAL_CHANNEL_ID_CLI)
      c->next_chid.channel_of_client = htonl (0);
  }
  chid = c->next_chid;
  c->next_chid.channel_of_client
    = htonl (1 + (ntohl (c->next_chid.channel_of_client)));

  return chid;
}


/**
 * Check if client has registered with the service and has not disconnected
 *
 * @param client the client to check
 *
 * @return non-NULL if client exists in the global DLL
 */
struct CadetClient *
GML_client_get (struct GNUNET_SERVER_Client *client)
{
  if (NULL == client)
    return NULL;
  return GNUNET_SERVER_client_get_user_context (client,
                                                struct CadetClient);
}


/**
 * Find a client that has opened a port
 *
 * @param port Port to check.
 *
 * @return non-NULL if a client has the port.
 */
struct CadetClient *
GML_client_get_by_port (const struct GNUNET_HashCode *port)
{
  return GNUNET_CONTAINER_multihashmap_get (ports, port);
}


/**
 * Deletes a channel from a client (either owner or destination).
 *
 * @param c Client whose tunnel to delete.
 * @param ch Channel which should be deleted.
 * @param id Channel ID.
 */
void
GML_client_delete_channel (struct CadetClient *c,
                           struct CadetChannel *ch,
                           struct GNUNET_CADET_ClientChannelNumber id)
{
  int res;

  if (ntohl (id.channel_of_client) >= GNUNET_CADET_LOCAL_CHANNEL_ID_CLI)
  {
    res = GNUNET_CONTAINER_multihashmap32_remove (c->own_channels,
                                                  id.channel_of_client,
                                                  ch);
    if (GNUNET_YES != res)
      LOG (GNUNET_ERROR_TYPE_DEBUG, "client_delete_tunnel root KO\n");
  }
  else
  {
    res = GNUNET_CONTAINER_multihashmap32_remove (c->incoming_channels,
                                                  id.channel_of_client,
                                                  ch);
    if (GNUNET_YES != res)
      LOG (GNUNET_ERROR_TYPE_DEBUG, "client_delete_channel dest KO\n");
  }
}

/**
 * Build a local ACK message and send it to a local client, if needed.
 *
 * If the client was already allowed to send data, do nothing.
 *
 * @param c Client to whom send the ACK.
 * @param id Channel ID to use
 */
void
GML_send_ack (struct CadetClient *c,
              struct GNUNET_CADET_ClientChannelNumber id)
{
  struct GNUNET_CADET_LocalAck msg;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "send local %s ack on %X towards %p\n",
       ntohl (id.channel_of_client) < GNUNET_CADET_LOCAL_CHANNEL_ID_CLI
       ? "FWD" : "BCK",
       ntohl (id.channel_of_client),
       c);

  msg.header.size = htons (sizeof (msg));
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_CADET_LOCAL_ACK);
  msg.channel_id = id;
  GNUNET_SERVER_notification_context_unicast (nc,
                                              c->handle,
                                              &msg.header,
                                              GNUNET_NO);

}



/**
 * Notify the client that a new incoming channel was created.
 *
 * @param c Client to notify.
 * @param id Channel ID.
 * @param port Channel's destination port.
 * @param opt Options (bit array).
 * @param peer Origin peer.
 */
void
GML_send_channel_create (struct CadetClient *c,
                         struct GNUNET_CADET_ClientChannelNumber id,
                         const struct GNUNET_HashCode *port,
                         uint32_t opt,
                         const struct GNUNET_PeerIdentity *peer)
{
  struct GNUNET_CADET_ChannelCreateMessage msg;

  msg.header.size = htons (sizeof (msg));
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_CADET_CHANNEL_CREATE);
  msg.channel_id = id;
  msg.port = *port;
  msg.opt = htonl (opt);
  msg.peer = *peer;
  GNUNET_SERVER_notification_context_unicast (nc, c->handle,
                                              &msg.header, GNUNET_NO);
}


/**
 * Build a local channel NACK message and send it to a local client.
 *
 * @param c Client to whom send the NACK.
 * @param id Channel ID to use
 */
void
GML_send_channel_nack (struct CadetClient *c,
                       struct GNUNET_CADET_ClientChannelNumber id)
{
  struct GNUNET_CADET_LocalAck msg;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "send local nack on %X towards %p\n",
       ntohl (id.channel_of_client),
       c);

  msg.header.size = htons (sizeof (msg));
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_CADET_CHANNEL_NACK);
  msg.channel_id = id;
  GNUNET_SERVER_notification_context_unicast (nc,
                                              c->handle,
                                              &msg.header,
                                              GNUNET_NO);

}

/**
 * Notify a client that a channel is no longer valid.
 *
 * @param c Client.
 * @param id ID of the channel that is destroyed.
 */
void
GML_send_channel_destroy (struct CadetClient *c,
                          struct GNUNET_CADET_ClientChannelNumber id)
{
  struct GNUNET_CADET_ChannelDestroyMessage msg;

  if (NULL == c)
  {
    GNUNET_break (0);
    return;
  }
  if (GNUNET_YES == c->shutting_down)
    return;
  msg.header.size = htons (sizeof (msg));
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_CADET_CHANNEL_DESTROY);
  msg.channel_id = id;
  GNUNET_SERVER_notification_context_unicast (nc, c->handle,
                                              &msg.header, GNUNET_NO);
}


/**
 * Modify the cadet message ID from global to local and send to client.
 *
 * @param c Client to send to.
 * @param msg Message to modify and send.
 * @param id Channel ID to use (c can be both owner and client).
 */
void
GML_send_data (struct CadetClient *c,
               const struct GNUNET_CADET_Data *msg,
               struct GNUNET_CADET_ClientChannelNumber id)
{
  struct GNUNET_CADET_LocalData *copy;
  uint16_t size = ntohs (msg->header.size) - sizeof (struct GNUNET_CADET_Data);
  char cbuf[size + sizeof (struct GNUNET_CADET_LocalData)];

  if (size < sizeof (struct GNUNET_MessageHeader))
  {
    GNUNET_break_op (0);
    return;
  }
  if (NULL == c)
  {
    GNUNET_break (0);
    return;
  }
  copy = (struct GNUNET_CADET_LocalData *) cbuf;
  GNUNET_memcpy (&copy[1], &msg[1], size);
  copy->header.size = htons (sizeof (struct GNUNET_CADET_LocalData) + size);
  copy->header.type = htons (GNUNET_MESSAGE_TYPE_CADET_LOCAL_DATA);
  copy->id = id;
  GNUNET_SERVER_notification_context_unicast (nc, c->handle,
                                              &copy->header, GNUNET_NO);
}


/**
 * Get the static string to represent a client.
 *
 * @param c Client.
 *
 * @return Static string for the client.
 */
const char *
GML_2s (const struct CadetClient *c)
{
  static char buf[32];

  SPRINTF (buf, "%u", c->id);
  return buf;
}
