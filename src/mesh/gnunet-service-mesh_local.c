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

#include "mesh_enc.h"
#include "mesh_protocol_enc.h" // GNUNET_MESH_Data is shared

#include "gnunet-service-mesh_local.h"
#include "gnunet-service-mesh_tunnel.h"

#define LOG(level, ...) GNUNET_log_from(level,"mesh-loc",__VA_ARGS__)

/******************************************************************************/
/********************************   STRUCTS  **********************************/
/******************************************************************************/

/**
 * Struct containing information about a client of the service
 *
 * TODO: add a list of 'waiting' ports
 */
struct MeshClient
{
    /**
     * Linked list next
     */
  struct MeshClient *next;

    /**
     * Linked list prev
     */
  struct MeshClient *prev;

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
  MESH_ChannelNumber next_chid;

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
static struct MeshClient *clients_head;

/**
 * DLL with all the clients, tail.
 */
static struct MeshClient *clients_tail;

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
  struct MeshClient *c;

  if (NULL == client)
    return;
  c = GNUNET_new (struct MeshClient);
  c->handle = client;
  c->id = next_client_id++; /* overflow not important: just for debug */
  c->next_chid = GNUNET_MESH_LOCAL_CHANNEL_ID_SERV;
  GNUNET_SERVER_client_keep (client);
  GNUNET_SERVER_client_set_user_context (client, c);
  GNUNET_CONTAINER_DLL_insert (clients_head, clients_tail, c);
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
  struct MeshClient *c;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "client disconnected: %p\n", client);
  if (client == NULL)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "   (SERVER DOWN)\n");
    return;
  }

  c = client_get (client);
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
  struct GNUNET_MESH_ClientConnect *cc_msg;
  struct MeshClient *c;
  unsigned int size;
  uint32_t *p;
  unsigned int i;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "new client connected %p\n", client);

  /* Check data sanity */
  size = ntohs (message->size) - sizeof (struct GNUNET_MESH_ClientConnect);
  cc_msg = (struct GNUNET_MESH_ClientConnect *) message;
  if (0 != (size % sizeof (uint32_t)))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  size /= sizeof (uint32_t);

  /* Initialize new client structure */
  c = GNUNET_SERVER_client_get_user_context (client, struct MeshClient);
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
  struct GNUNET_MESH_ChannelMessage *msg;
  struct MeshPeer *peer;
  struct MeshTunnel2 *t;
  struct MeshChannel *ch;
  struct MeshClient *c;
  MESH_ChannelNumber chid;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "new channel requested\n");

  /* Sanity check for client registration */
  if (NULL == (c = client_get (client)))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  by client %u\n", c->id);

  /* Message size sanity check */
  if (sizeof (struct GNUNET_MESH_ChannelMessage) != ntohs (message->size))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  msg = (struct GNUNET_MESH_ChannelMessage *) message;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  towards %s:%u\n",
              GNUNET_i2s (&msg->peer), ntohl (msg->port));
  chid = ntohl (msg->channel_id);

  /* Sanity check for duplicate channel IDs */
  if (NULL != channel_get_by_local_id (c, chid))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  peer = peer_get (&msg->peer);
  if (NULL == peer->tunnel)
  {
    peer->tunnel = tunnel_new ();
    peer->tunnel->peer = peer;
    if (peer->id == myid)
    {
      tunnel_change_state (peer->tunnel, MESH_TUNNEL_READY);
    }
    else
    {
      peer_connect (peer);
    }
  }
  t = peer->tunnel;

  /* Create channel */
  ch = channel_new (t, c, chid);
  if (NULL == ch)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  ch->port = ntohl (msg->port);
  channel_set_options (ch, ntohl (msg->opt));

  /* In unreliable channels, we'll use the DLL to buffer BCK data */
  ch->root_rel = GNUNET_new (struct MeshChannelReliability);
  ch->root_rel->ch = ch;
  ch->root_rel->expected_delay = MESH_RETRANSMIT_TIME;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "CREATED CHANNEL %s[%x]:%u (%x)\n",
              peer2s (t->peer), ch->gid, ch->port, ch->lid_root);

  /* Send create channel */
  {
    struct GNUNET_MESH_ChannelCreate msgcc;

    msgcc.header.size = htons (sizeof (msgcc));
    msgcc.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_CHANNEL_CREATE);
    msgcc.chid = htonl (ch->gid);
    msgcc.port = msg->port;
    msgcc.opt = msg->opt;

    GMT_queue_data (t, ch, &msgcc.header, GNUNET_YES);
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
  struct GNUNET_MESH_ChannelMessage *msg;
  struct MeshClient *c;
  struct MeshChannel *ch;
  struct MeshTunnel2 *t;
  MESH_ChannelNumber chid;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
              "Got a DESTROY CHANNEL from client!\n");

  /* Sanity check for client registration */
  if (NULL == (c = client_get (client)))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  by client %u\n", c->id);

  /* Message sanity check */
  if (sizeof (struct GNUNET_MESH_ChannelMessage) != ntohs (message->size))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  msg = (struct GNUNET_MESH_ChannelMessage *) message;

  /* Retrieve tunnel */
  chid = ntohl (msg->channel_id);
  ch = channel_get_by_local_id (c, chid);
  if (NULL == ch)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR, "  channel %X not found\n", chid);
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  /* Cleanup after the tunnel */
  client_delete_channel (c, ch);
  if (c == ch->dest && GNUNET_MESH_LOCAL_CHANNEL_ID_SERV <= chid)
  {
    ch->dest = NULL;
  }
  else if (c == ch->root && GNUNET_MESH_LOCAL_CHANNEL_ID_SERV > chid)
  {
    ch->root = NULL;
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
                "  channel %X client %p (%p, %p)\n",
                chid, c, ch->root, ch->dest);
    GNUNET_break (0);
  }

  t = ch->t;
  channel_destroy (ch);
  tunnel_destroy_if_empty (t);

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
  struct GNUNET_MESH_LocalData *msg;
  struct MeshClient *c;
  struct MeshChannel *ch;
  struct MeshChannelReliability *rel;
  MESH_ChannelNumber chid;
  size_t size;
  int fwd;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
              "Got data from a client!\n");

  /* Sanity check for client registration */
  if (NULL == (c = client_get (client)))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  by client %u\n", c->id);

  msg = (struct GNUNET_MESH_LocalData *) message;

  /* Sanity check for message size */
  size = ntohs (message->size) - sizeof (struct GNUNET_MESH_LocalData);
  if (size < sizeof (struct GNUNET_MessageHeader))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  /* Channel exists? */
  chid = ntohl (msg->id);
  fwd = chid < GNUNET_MESH_LOCAL_CHANNEL_ID_SERV;
  ch = channel_get_by_local_id (c, chid);
  if (NULL == ch)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  /* Is the client in the channel? */
  if ( !( (fwd &&
           ch->root &&
           ch->root->handle == client)
         ||
          (!fwd &&
           ch->dest &&
           ch->dest->handle == client) ) )
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  rel = fwd ? ch->root_rel : ch->dest_rel;
  rel->client_ready = GNUNET_NO;

  /* Ok, everything is correct, send the message. */
  {
    struct GNUNET_MESH_Data *payload;
    uint16_t p2p_size = sizeof(struct GNUNET_MESH_Data) + size;
    unsigned char cbuf[p2p_size];

    payload = (struct GNUNET_MESH_Data *) cbuf;
    payload->mid = htonl (rel->mid_send);
    rel->mid_send++;
    memcpy (&payload[1], &msg[1], size);
    payload->header.size = htons (p2p_size);
    payload->header.type = htons (GNUNET_MESSAGE_TYPE_MESH_DATA);
    payload->chid = htonl (ch->gid);
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  sending on channel...\n");
    send_prebuilt_message_channel (&payload->header, ch, fwd);

    if (GNUNET_YES == ch->reliable)
      channel_save_copy (ch, &payload->header, fwd);
  }
  if (tunnel_get_buffer (ch->t, fwd) > 0)
    send_local_ack (ch, fwd);
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
  struct GNUNET_MESH_LocalAck *msg;
  struct MeshChannelReliability *rel;
  struct MeshChannel *ch;
  struct MeshClient *c;
  MESH_ChannelNumber chid;
  int fwd;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Got a local ACK\n");

  /* Sanity check for client registration */
  if (NULL == (c = client_get (client)))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  by client %u\n", c->id);

  msg = (struct GNUNET_MESH_LocalAck *) message;

  /* Channel exists? */
  chid = ntohl (msg->channel_id);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  on channel %X\n", chid);
  ch = channel_get_by_local_id (c, chid);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "   -- ch %p\n", ch);
  if (NULL == ch)
  {
    GNUNET_break (0);
    LOG (GNUNET_ERROR_TYPE_WARNING, "Channel %X unknown.\n", chid);
    LOG (GNUNET_ERROR_TYPE_WARNING, "  for client %u.\n", c->id);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  /* If client is root, the ACK is going FWD, therefore this is "BCK". */
  /* If client is dest, the ACK is going BCK, therefore this is "FWD" */
  fwd = chid >= GNUNET_MESH_LOCAL_CHANNEL_ID_SERV;
  rel = fwd ? ch->dest_rel : ch->root_rel;

  rel->client_ready = GNUNET_YES;
  channel_send_client_buffered_data (ch, c, fwd);
  send_ack (NULL, ch, fwd);

  GNUNET_SERVER_receive_done (client, GNUNET_OK);

  return;
}


/*
 * Iterator over all tunnels to send a monitoring client info about each tunnel.
 *
 * @param cls Closure (client handle).
 * @param key Key (hashed tunnel ID, unused).
 * @param value Tunnel info.
 *
 * @return GNUNET_YES, to keep iterating.
 */
// static int
// monitor_all_tunnels_iterator (void *cls,
//                               const struct GNUNET_HashCode * key,
//                               void *value)
// {
//   struct GNUNET_SERVER_Client *client = cls;
//   struct MeshChannel *ch = value;
//   struct GNUNET_MESH_LocalMonitor *msg;
//
//   msg = GNUNET_malloc (sizeof(struct GNUNET_MESH_LocalMonitor));
//   msg->channel_id = htonl (ch->gid);
//   msg->header.size = htons (sizeof (struct GNUNET_MESH_LocalMonitor));
//   msg->header.type = htons (GNUNET_MESSAGE_TYPE_MESH_LOCAL_INFO_TUNNELS);
//
//   LOG (GNUNET_ERROR_TYPE_INFO,
//               "*  sending info about tunnel %s\n",
//               GNUNET_i2s (&msg->owner));
//
//   GNUNET_SERVER_notification_context_unicast (nc, client,
//                                               &msg->header, GNUNET_NO);
//   return GNUNET_YES;
// }


/**
 * Handler for client's MONITOR request.
 *
 * @param cls Closure (unused).
 * @param client Identification of the client.
 * @param message The actual message.
 */
static void
handle_get_tunnels (void *cls, struct GNUNET_SERVER_Client *client,
                    const struct GNUNET_MessageHeader *message)
{
  struct MeshClient *c;

  /* Sanity check for client registration */
  if (NULL == (c = client_get (client)))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  LOG (GNUNET_ERROR_TYPE_INFO,
              "Received get tunnels request from client %u\n",
              c->id);
//   GNUNET_CONTAINER_multihashmap_iterate (tunnels,
//                                          monitor_all_tunnels_iterator,
//                                          client);
  LOG (GNUNET_ERROR_TYPE_INFO,
              "Get tunnels request from client %u completed\n",
              c->id);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Handler for client's MONITOR_TUNNEL request.
 *
 * @param cls Closure (unused).
 * @param client Identification of the client.
 * @param message The actual message.
 */
void
handle_show_tunnel (void *cls, struct GNUNET_SERVER_Client *client,
                    const struct GNUNET_MessageHeader *message)
{
  const struct GNUNET_MESH_LocalMonitor *msg;
  struct GNUNET_MESH_LocalMonitor *resp;
  struct MeshClient *c;
  struct MeshChannel *ch;

  /* Sanity check for client registration */
  if (NULL == (c = client_get (client)))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  msg = (struct GNUNET_MESH_LocalMonitor *) message;
  LOG (GNUNET_ERROR_TYPE_INFO,
              "Received tunnel info request from client %u for tunnel %s[%X]\n",
              c->id,
              &msg->owner,
              ntohl (msg->channel_id));
//   ch = channel_get (&msg->owner, ntohl (msg->channel_id));
  ch = NULL; // FIXME
  if (NULL == ch)
  {
    /* We don't know the tunnel */
    struct GNUNET_MESH_LocalMonitor warn;

    warn = *msg;
    GNUNET_SERVER_notification_context_unicast (nc, client,
                                                &warn.header,
                                                GNUNET_NO);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }

  /* Initialize context */
  resp = GNUNET_malloc (sizeof (struct GNUNET_MESH_LocalMonitor));
  *resp = *msg;
  resp->header.size = htons (sizeof (struct GNUNET_MESH_LocalMonitor));
  GNUNET_SERVER_notification_context_unicast (nc, c->handle,
                                              &resp->header, GNUNET_NO);
  GNUNET_free (resp);

  LOG (GNUNET_ERROR_TYPE_INFO,
              "Monitor tunnel request from client %u completed\n",
              c->id);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Functions to handle messages from clients
 */
static struct GNUNET_SERVER_MessageHandler client_handlers[] = {
  {&handle_new_client, NULL, GNUNET_MESSAGE_TYPE_MESH_LOCAL_CONNECT, 0},
  {&handle_channel_create, NULL, GNUNET_MESSAGE_TYPE_MESH_CHANNEL_CREATE,
   sizeof (struct GNUNET_MESH_ChannelMessage)},
  {&handle_channel_destroy, NULL, GNUNET_MESSAGE_TYPE_MESH_CHANNEL_DESTROY,
   sizeof (struct GNUNET_MESH_ChannelMessage)},
  {&handle_data, NULL, GNUNET_MESSAGE_TYPE_MESH_LOCAL_DATA, 0},
  {&handle_ack, NULL, GNUNET_MESSAGE_TYPE_MESH_LOCAL_ACK,
   sizeof (struct GNUNET_MESH_LocalAck)},
  {&handle_get_tunnels, NULL, GNUNET_MESSAGE_TYPE_MESH_LOCAL_INFO_TUNNELS,
   sizeof (struct GNUNET_MessageHeader)},
  {&handle_show_tunnel, NULL, GNUNET_MESSAGE_TYPE_MESH_LOCAL_INFO_TUNNEL,
   sizeof (struct GNUNET_MESH_LocalMonitor)},
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
 * Get a chennel from a client
 *
 * @param c the client to check
 * @param chid Channel ID, must be local (> 0x800...)
 *
 * @return non-NULL if channel exists in the clients lists
 */
struct MeshChannel *
GML_channel_get (struct MeshClient *c, MESH_ChannelNumber chid)
{
  if (0 == (chid & GNUNET_MESH_LOCAL_CHANNEL_ID_CLI))
  {
    GNUNET_break_op (0);
    LOG (GNUNET_ERROR_TYPE_DEBUG, "CHID %X not a local chid\n", chid);
    return NULL;
  }
  if (chid >= GNUNET_MESH_LOCAL_CHANNEL_ID_SERV)
    return GNUNET_CONTAINER_multihashmap32_get (c->incoming_channels, chid);
  return GNUNET_CONTAINER_multihashmap32_get (c->own_channels, chid);
}


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
                 struct MeshChannel *ch)
{
  if (chid >= GNUNET_MESH_LOCAL_CHANNEL_ID_SERV)
    GNUNET_CONTAINER_multihashmap32_put (client->incoming_channels, chid, ch,
                                         GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
  else if (chid >= GNUNET_MESH_LOCAL_CHANNEL_ID_CLI)
    GNUNET_CONTAINER_multihashmap32_put (client->own_channels, chid, ch,
                                         GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
  else
    GNUNET_break (0);
}


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
                    struct MeshChannel *ch)
{
  if (chid >= GNUNET_MESH_LOCAL_CHANNEL_ID_SERV)
    GNUNET_CONTAINER_multihashmap32_remove (c->incoming_channels, chid, ch);
  else if (chid >= GNUNET_MESH_LOCAL_CHANNEL_ID_CLI)
    GNUNET_CONTAINER_multihashmap32_remove (c->own_channels, chid, ch);
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
MESH_ChannelNumber
GML_get_next_chid (struct MeshClient *c)
{
  MESH_ChannelNumber chid;

  while (NULL != GML_channel_get (c, c->next_chid))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Channel %u exists...\n", c->next_chid);
    c->next_chid = (c->next_chid + 1) | GNUNET_MESH_LOCAL_CHANNEL_ID_SERV;
  }
  chid = c->next_chid;
  c->next_chid = (c->next_chid + 1) | GNUNET_MESH_LOCAL_CHANNEL_ID_SERV;

  return chid;
}


/**
 * Check if client has registered with the service and has not disconnected
 *
 * @param client the client to check
 *
 * @return non-NULL if client exists in the global DLL
 */
struct MeshClient *
GML_client_get (struct GNUNET_SERVER_Client *client)
{
  return GNUNET_SERVER_client_get_user_context (client, struct MeshClient);
}

/**
 * Find a client that has opened a port
 *
 * @param port Port to check.
 *
 * @return non-NULL if a client has the port.
 */
struct MeshClient *
GML_client_get_by_port (uint32_t port)
{
  return GNUNET_CONTAINER_multihashmap32_get (ports, port);
}


/**
 * Deletes a tunnel from a client (either owner or destination).
 *
 * @param c Client whose tunnel to delete.
 * @param ch Channel which should be deleted.
 */
void
GML_client_delete_channel (struct MeshClient *c, struct MeshChannel *ch)
{
  int res;

  if (c == ch->root)
  {
    res = GNUNET_CONTAINER_multihashmap32_remove (c->own_channels,
                                                  ch->lid_root, ch);
    if (GNUNET_YES != res)
      LOG (GNUNET_ERROR_TYPE_DEBUG, "client_delete_channel owner KO\n");
  }
  if (c == ch->dest)
  {
    res = GNUNET_CONTAINER_multihashmap32_remove (c->incoming_channels,
                                                  ch->lid_dest, ch);
    if (GNUNET_YES != res)
      LOG (GNUNET_ERROR_TYPE_DEBUG, "client_delete_tunnel client KO\n");
  }
}

/**
 * Build a local ACK message and send it to a local client, if needed.
 *
 * If the client was already allowed to send data, do nothing.
 *
 * @param ch Channel on which to send the ACK.
 * @param c Client to whom send the ACK.
 * @param fwd Set to GNUNET_YES for FWD ACK (dest->root)
 */
void
GML_send_ack (struct MeshChannel *ch, int fwd)
{
  struct GNUNET_MESH_LocalAck msg;
  struct MeshChannelReliability *rel;
  struct MeshClient *c;

  c   = fwd ? ch->root     : ch->dest;
  rel = fwd ? ch->root_rel : ch->dest_rel;

  if (GNUNET_YES == rel->client_ready)
    return; /* don't send double ACKs to client */

  rel->client_ready = GNUNET_YES;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
              "send local %s ack on %s:%X towards %p\n",
              fwd ? "FWD" : "BCK", peer2s (ch->t->peer), ch->gid, c);

  if (NULL == c
      || ( fwd && (0 == ch->lid_root || c != ch->root))
      || (!fwd && (0 == ch->lid_dest || c != ch->dest)) )
  {
    GNUNET_break (0);
    return;
  }
  msg.header.size = htons (sizeof (msg));
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_LOCAL_ACK);
  msg.channel_id = htonl (fwd ? ch->lid_root : ch->lid_dest);
  GNUNET_SERVER_notification_context_unicast (nc,
                                              c->handle,
                                              &msg.header,
                                              GNUNET_NO);

}


/**
 * Notify the client that a new incoming channel was created.
 *
 * @param ch Channel that was created.
 */
void
GML_send_channel_create (struct MeshClient *c,
                         uint32_t id, uint32_t port, uint32_t opt,
                         const struct GNUNET_PeerIdentity *peer)
{
  struct GNUNET_MESH_ChannelMessage msg;

  msg.header.size = htons (sizeof (msg));
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_LOCAL_TUNNEL_CREATE);
  msg.channel_id = htonl (id);
  msg.port = htonl (port);
  msg.opt = htonl (opt);
  msg.peer = *peer;
  GNUNET_SERVER_notification_context_unicast (nc, c->handle,
                                              &msg.header, GNUNET_NO);
}


/**
 * Notify a client that a channel is no longer valid.
 *
 * @param c Client.
 * @param id ID of the channel that is destroyed.
 */
void
GML_send_channel_destroy (struct MeshClient *c, uint32_t id)
{
  struct GNUNET_MESH_ChannelMessage msg;

  if (NULL == c)
  {
    GNUNET_break (0);
    return;
  }
  msg.header.size = htons (sizeof (msg));
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_LOCAL_TUNNEL_DESTROY);
  msg.channel_id = htonl (id);
  msg.port = htonl (0);
  memset (&msg.peer, 0, sizeof (msg.peer));
  msg.opt = htonl (0);
  GNUNET_SERVER_notification_context_unicast (nc, c->handle,
                                              &msg.header, GNUNET_NO);
}


/**
 * Modify the mesh message ID from global to local and send to client.
 *
 * @param msg Message to modify and send.
 * @param c Client to send to.
 * @param tid Tunnel ID to use (c can be both owner and client).
 */
static void
GML_send_data (struct MeshClient *c,
               const struct GNUNET_MESH_Data *msg,
               MESH_ChannelNumber id)
{
  struct GNUNET_MESH_LocalData *copy;
  uint16_t size = ntohs (msg->header.size) - sizeof (struct GNUNET_MESH_Data);
  char cbuf[size + sizeof (struct GNUNET_MESH_LocalData)];

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
  copy = (struct GNUNET_MESH_LocalData *) cbuf;
  memcpy (&copy[1], &msg[1], size);
  copy->header.size = htons (sizeof (struct GNUNET_MESH_LocalData) + size);
  copy->header.type = htons (GNUNET_MESSAGE_TYPE_MESH_LOCAL_DATA);
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
GML_2s (const struct MeshClient *c)
{
  static char buf[32];

  sprintf (buf, "%u", c->id);
  return buf;
}
