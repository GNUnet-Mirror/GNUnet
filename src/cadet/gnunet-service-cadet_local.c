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
  CADET_ChannelNumber next_chid;

    /**
     * Handle to communicate with the client
     */
  struct GNUNET_SERVER_Client *handle;

    /**
     * Ports that this client has declared interest in.
     * Indexed by port, contains *Client.
     */
  struct GNUNET_CONTAINER_MultiHashMap32 *ports;

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
static struct GNUNET_CONTAINER_MultiHashMap32 *ports;

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
 * @return GNUNET_OK, keep iterating.
 */
static int
client_release_ports (void *cls,
                      uint32_t key,
                      void *value)
{
  int res;

  res = GNUNET_CONTAINER_multihashmap32_remove (ports, key, value);
  if (GNUNET_YES != res)
  {
    GNUNET_break (0);
    LOG (GNUNET_ERROR_TYPE_WARNING,
                "Port %u by client %p was not registered.\n",
                key, value);
  }
  return GNUNET_OK;
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
  struct CadetClient *c;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "client connected: %p\n", client);
  if (NULL == client)
    return;
  c = GNUNET_new (struct CadetClient);
  c->handle = client;
  c->id = next_client_id++; /* overflow not important: just for debug */
  c->next_chid = GNUNET_CADET_LOCAL_CHANNEL_ID_SERV;
  GNUNET_SERVER_client_keep (client);
  GNUNET_SERVER_client_set_user_context (client, c);
  GNUNET_CONTAINER_DLL_insert (clients_head, clients_tail, c);
}


/**
 * Iterator for deleting each channel whose client endpoint disconnected.
 *
 * @param cls Closure (client that has disconnected).
 * @param key The local channel id (used to access the hashmap).
 * @param value The value stored at the key (channel to destroy).
 *
 * @return GNUNET_OK, keep iterating.
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

  GCCH_handle_local_destroy (ch, c, key < GNUNET_CADET_LOCAL_CHANNEL_ID_SERV);
  return GNUNET_OK;
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

  LOG (GNUNET_ERROR_TYPE_DEBUG, "client disconnected: %p\n", client);
  if (client == NULL)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "   (SERVER DOWN)\n");
    return;
  }

  c = GML_client_get (client);
  if (NULL != c)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "matching client found (%u, %p)\n",
                c->id, c);
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
      GNUNET_CONTAINER_multihashmap32_iterate (c->ports,
                                               &client_release_ports, c);
      GNUNET_CONTAINER_multihashmap32_destroy (c->ports);
    }
    GNUNET_CONTAINER_DLL_remove (clients_head, clients_tail, c);
    GNUNET_STATISTICS_update (stats, "# clients", -1, GNUNET_NO);
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  client free (%p)\n", c);
    GNUNET_free (c);
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_WARNING, " context NULL!\n");
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "done!\n");
  return;
}


/**
 * Handler for new clients
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message, which includes messages the client wants
 */
static void
handle_new_client (void *cls, struct GNUNET_SERVER_Client *client,
                   const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_CADET_ClientConnect *cc_msg;
  struct CadetClient *c;
  unsigned int size;
  uint32_t *p;
  unsigned int i;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "\n");
  LOG (GNUNET_ERROR_TYPE_DEBUG, "new client connected %p\n", client);

  /* Check data sanity */
  size = ntohs (message->size) - sizeof (struct GNUNET_CADET_ClientConnect);
  cc_msg = (struct GNUNET_CADET_ClientConnect *) message;
  if (0 != (size % sizeof (uint32_t)))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  size /= sizeof (uint32_t);

  /* Initialize new client structure */
  c = GNUNET_SERVER_client_get_user_context (client, struct CadetClient);
  if (NULL == c)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  LOG (GNUNET_ERROR_TYPE_DEBUG, "  client id %u\n", c->id);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  client has %u ports\n", size);
  if (size > 0)
  {
    uint32_t u32;

    p = (uint32_t *) &cc_msg[1];
    c->ports = GNUNET_CONTAINER_multihashmap32_create (size);
    for (i = 0; i < size; i++)
    {
      u32 = ntohl (p[i]);
      LOG (GNUNET_ERROR_TYPE_DEBUG, "    port: %u\n", u32);

      /* store in client's hashmap */
      GNUNET_CONTAINER_multihashmap32_put (c->ports, u32, c,
                                           GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
      /* store in global hashmap */
      /* FIXME only allow one client to have the port open,
       *       have a backup hashmap with waiting clients */
      GNUNET_CONTAINER_multihashmap32_put (ports, u32, c,
                                           GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
    }
  }

  c->own_channels = GNUNET_CONTAINER_multihashmap32_create (32);
  c->incoming_channels = GNUNET_CONTAINER_multihashmap32_create (32);
  GNUNET_SERVER_notification_context_add (nc, client);
  GNUNET_STATISTICS_update (stats, "# clients", 1, GNUNET_NO);

  GNUNET_SERVER_receive_done (client, GNUNET_OK);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "new client processed\n");
}


/**
 * Handler for requests of new tunnels
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
  if (sizeof (struct GNUNET_CADET_ChannelMessage) != ntohs (message->size))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  if (GNUNET_OK !=
      GCCH_handle_local_create (c,
                                (struct GNUNET_CADET_ChannelMessage *) message))
  {
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  GNUNET_SERVER_receive_done (client, GNUNET_OK);
  return;
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
  struct GNUNET_CADET_ChannelMessage *msg;
  struct CadetClient *c;
  struct CadetChannel *ch;
  CADET_ChannelNumber chid;

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
  if (sizeof (struct GNUNET_CADET_ChannelMessage) != ntohs (message->size))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  msg = (struct GNUNET_CADET_ChannelMessage *) message;

  /* Retrieve tunnel */
  chid = ntohl (msg->channel_id);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  for channel %X\n", chid);
  ch = GML_channel_get (c, chid);
  if (NULL == ch)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  channel %X not found\n", chid);
    GNUNET_STATISTICS_update (stats,
                              "# client destroy messages on unknown channel",
                              1, GNUNET_NO);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }

  GCCH_handle_local_destroy (ch, c, chid < GNUNET_CADET_LOCAL_CHANNEL_ID_SERV);

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
  CADET_ChannelNumber chid;
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

  chid = ntohl (msg->id);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  by client %u\n", c->id);

  /* Channel exists? */
  fwd = chid < GNUNET_CADET_LOCAL_CHANNEL_ID_SERV;
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
  CADET_ChannelNumber chid;
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
  chid = ntohl (msg->channel_id);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  on channel %X\n", chid);
  ch = GML_channel_get (c, chid);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "   -- ch %p\n", ch);
  if (NULL == ch)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Channel %X unknown.\n", chid);
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  for client %u.\n", c->id);
    GNUNET_STATISTICS_update (stats,
                              "# client ack messages on unknown channel",
                              1, GNUNET_NO);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }

  /* If client is root, the ACK is going FWD, therefore this is "BCK ACK". */
  /* If client is dest, the ACK is going BCK, therefore this is "FWD ACK" */
  fwd = chid >= GNUNET_CADET_LOCAL_CHANNEL_ID_SERV;

  GCCH_handle_local_ack (ch, fwd);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);

  return;
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

  GCP_debug (p, GNUNET_ERROR_TYPE_ERROR);

  t = GCP_get_tunnel (p);
  if (NULL != t)
    GCT_debug (t, GNUNET_ERROR_TYPE_ERROR);

  LOG (GNUNET_ERROR_TYPE_ERROR, "\n");

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
  size_t size;

  /* Sanity check for client registration */
  if (NULL == (c = GML_client_get (client)))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  msg = (struct GNUNET_CADET_LocalInfo *) message;
  LOG (GNUNET_ERROR_TYPE_INFO,
       "Received peer info request from client %u for peer %s\n",
       c->id, GNUNET_i2s_full (&msg->peer));

  p = GCP_get (&msg->peer);
  if (NULL == p)
  {
    /* We don't know the peer */
    struct GNUNET_CADET_LocalInfoPeer warn;

    LOG (GNUNET_ERROR_TYPE_INFO, "Peer %s unknown %u\n",
         GNUNET_i2s_full (&msg->peer), sizeof (warn));
    warn.header.type = htons (GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_PEER);
    warn.header.size = htons (sizeof (warn));
    warn.destination = msg->peer;
    warn.paths = htons (0);
    warn.tunnel = htons (NULL != GCP_get_tunnel (p));

    GNUNET_SERVER_notification_context_unicast (nc, client,
                                                &warn.header,
                                                GNUNET_NO);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }

  size = sizeof (struct GNUNET_CADET_LocalInfoPeer);
//   size += c_n * sizeof (struct GNUNET_CADET_Hash);

  resp = GNUNET_malloc (size);
  resp->header.type = htons (GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_PEER);
  resp->header.size = htons (size);
  resp->destination = msg->peer;
  resp->paths = htons (0);
  resp->tunnel = htons (0);

  GNUNET_SERVER_notification_context_unicast (nc, c->handle,
                                              &resp->header, GNUNET_NO);
  GNUNET_free (resp);

  LOG (GNUNET_ERROR_TYPE_INFO, "Show peer request from client %u completed.\n");
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
  struct GNUNET_HashCode *h = (struct GNUNET_HashCode *) &msg[1];
  CADET_ChannelNumber *chn = (CADET_ChannelNumber *) &h[msg->connections];

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
  LOG (GNUNET_ERROR_TYPE_INFO,
       "Received tunnel info request from client %u for tunnel %s\n",
       c->id, GNUNET_i2s_full(&msg->peer));

  t = GCP_get_tunnel (GCP_get (&msg->peer));
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
  size += ch_n * sizeof (CADET_ChannelNumber);

  resp = GNUNET_malloc (size);
  resp->header.type = htons (GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_TUNNEL);
  resp->header.size = htons (size);
  GCT_iterate_connections (t, &iter_connection, resp);
  GCT_iterate_channels (t, &iter_channel, resp);
  /* Do not interleave with iterators, iter_channel needs conn in HBO */
  resp->destination = msg->peer;
  resp->connections = htonl (resp->connections);
  resp->channels = htonl (resp->channels);
  resp->cstate = htons (GCT_get_cstate (t));
  resp->estate = htons (GCT_get_estate (t));
  GNUNET_SERVER_notification_context_unicast (nc, c->handle,
                                              &resp->header, GNUNET_NO);
  GNUNET_free (resp);

  LOG (GNUNET_ERROR_TYPE_INFO,
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

  GCP_iterate_all (&show_peer_iterator, NULL);

  LOG (GNUNET_ERROR_TYPE_ERROR,
       "**************************** DUMP END ****************************\n");

  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Functions to handle messages from clients
 */
static struct GNUNET_SERVER_MessageHandler client_handlers[] = {
  {&handle_new_client, NULL, GNUNET_MESSAGE_TYPE_CADET_LOCAL_CONNECT, 0},
  {&handle_channel_create, NULL, GNUNET_MESSAGE_TYPE_CADET_CHANNEL_CREATE,
   sizeof (struct GNUNET_CADET_ChannelMessage)},
  {&handle_channel_destroy, NULL, GNUNET_MESSAGE_TYPE_CADET_CHANNEL_DESTROY,
   sizeof (struct GNUNET_CADET_ChannelMessage)},
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
  ports = GNUNET_CONTAINER_multihashmap32_create (32);
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
GML_channel_get (struct CadetClient *c, CADET_ChannelNumber chid)
{
  struct GNUNET_CONTAINER_MultiHashMap32 *map;

  if (0 == (chid & GNUNET_CADET_LOCAL_CHANNEL_ID_CLI))
  {
    GNUNET_break_op (0);
    LOG (GNUNET_ERROR_TYPE_DEBUG, "CHID %X not a local chid\n", chid);
    return NULL;
  }

  if (chid >= GNUNET_CADET_LOCAL_CHANNEL_ID_SERV)
    map = c->incoming_channels;
  else if (chid >= GNUNET_CADET_LOCAL_CHANNEL_ID_CLI)
    map = c->own_channels;
  else
  {
    GNUNET_break (0);
    map = NULL;
  }
  if (NULL == map)
  {
    GNUNET_break (0);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Client %s does no t have a valid map for CHID %X\n",
         GML_2s (c), chid);
    return NULL;
  }
  return GNUNET_CONTAINER_multihashmap32_get (map, chid);
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
                 uint32_t chid,
                 struct CadetChannel *ch)
{
  if (chid >= GNUNET_CADET_LOCAL_CHANNEL_ID_SERV)
    GNUNET_CONTAINER_multihashmap32_put (client->incoming_channels, chid, ch,
                                         GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
  else if (chid >= GNUNET_CADET_LOCAL_CHANNEL_ID_CLI)
    GNUNET_CONTAINER_multihashmap32_put (client->own_channels, chid, ch,
                                         GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
  else
    GNUNET_break (0);
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
                    uint32_t chid,
                    struct CadetChannel *ch)
{
  if (GNUNET_CADET_LOCAL_CHANNEL_ID_SERV <= chid)
    GNUNET_break (GNUNET_YES ==
                  GNUNET_CONTAINER_multihashmap32_remove (client->incoming_channels,
                                                          chid, ch));
  else if (GNUNET_CADET_LOCAL_CHANNEL_ID_CLI <= chid)
    GNUNET_break (GNUNET_YES ==
                  GNUNET_CONTAINER_multihashmap32_remove (client->own_channels,
                                                          chid, ch));
  else
    GNUNET_break (0);
}


/**
 * Get the tunnel's next free local channel ID.
 *
 * @param c Client.
 *
 * @return LID of a channel free to use.
 */
CADET_ChannelNumber
GML_get_next_chid (struct CadetClient *c)
{
  CADET_ChannelNumber chid;

  while (NULL != GML_channel_get (c, c->next_chid))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Channel %u exists...\n", c->next_chid);
    c->next_chid = (c->next_chid + 1) | GNUNET_CADET_LOCAL_CHANNEL_ID_SERV;
  }
  chid = c->next_chid;
  c->next_chid = (c->next_chid + 1) | GNUNET_CADET_LOCAL_CHANNEL_ID_SERV;

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
  return GNUNET_SERVER_client_get_user_context (client, struct CadetClient);
}

/**
 * Find a client that has opened a port
 *
 * @param port Port to check.
 *
 * @return non-NULL if a client has the port.
 */
struct CadetClient *
GML_client_get_by_port (uint32_t port)
{
  return GNUNET_CONTAINER_multihashmap32_get (ports, port);
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
                           CADET_ChannelNumber id)
{
  int res;

  if (GNUNET_CADET_LOCAL_CHANNEL_ID_SERV <= id)
  {
    res = GNUNET_CONTAINER_multihashmap32_remove (c->incoming_channels,
                                                  id, ch);
    if (GNUNET_YES != res)
      LOG (GNUNET_ERROR_TYPE_DEBUG, "client_delete_channel dest KO\n");
  }
  else if (GNUNET_CADET_LOCAL_CHANNEL_ID_CLI <= id)
  {
    res = GNUNET_CONTAINER_multihashmap32_remove (c->own_channels,
                                                  id, ch);
    if (GNUNET_YES != res)
      LOG (GNUNET_ERROR_TYPE_DEBUG, "client_delete_tunnel root KO\n");
  }
  else
  {
    GNUNET_break (0);
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
GML_send_ack (struct CadetClient *c, CADET_ChannelNumber id)
{
  struct GNUNET_CADET_LocalAck msg;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
              "send local %s ack on %X towards %p\n",
              id < GNUNET_CADET_LOCAL_CHANNEL_ID_SERV ? "FWD" : "BCK", id, c);

  msg.header.size = htons (sizeof (msg));
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_CADET_LOCAL_ACK);
  msg.channel_id = htonl (id);
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
                         uint32_t id, uint32_t port, uint32_t opt,
                         const struct GNUNET_PeerIdentity *peer)
{
  struct GNUNET_CADET_ChannelMessage msg;

  msg.header.size = htons (sizeof (msg));
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_CADET_CHANNEL_CREATE);
  msg.channel_id = htonl (id);
  msg.port = htonl (port);
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
GML_send_channel_nack (struct CadetClient *c, CADET_ChannelNumber id)
{
  struct GNUNET_CADET_LocalAck msg;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "send local nack on %X towards %p\n",
       id, c);

  msg.header.size = htons (sizeof (msg));
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_CADET_CHANNEL_NACK);
  msg.channel_id = htonl (id);
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
GML_send_channel_destroy (struct CadetClient *c, uint32_t id)
{
  struct GNUNET_CADET_ChannelMessage msg;

  if (NULL == c)
  {
    GNUNET_break (0);
    return;
  }
  if (GNUNET_YES == c->shutting_down)
    return;
  msg.header.size = htons (sizeof (msg));
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_CADET_CHANNEL_DESTROY);
  msg.channel_id = htonl (id);
  msg.port = htonl (0);
  memset (&msg.peer, 0, sizeof (msg.peer));
  msg.opt = htonl (0);
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
               CADET_ChannelNumber id)
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
  memcpy (&copy[1], &msg[1], size);
  copy->header.size = htons (sizeof (struct GNUNET_CADET_LocalData) + size);
  copy->header.type = htons (GNUNET_MESSAGE_TYPE_CADET_LOCAL_DATA);
  copy->id = htonl (id);
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
