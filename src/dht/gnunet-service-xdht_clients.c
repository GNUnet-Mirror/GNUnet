/*
     This file is part of GNUnet.
     (C) 2009, 2010, 2011 Christian Grothoff (and other contributing authors)

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
 * @file dht/gnunet-service-dht_clients.c
 * @brief GNUnet DHT service's client management code
 * @author Supriti Singh
 */

#include "platform.h"
#include "gnunet_constants.h"
#include "gnunet_protocols.h"
#include "gnunet_statistics_service.h"
#include "gnunet-service-xdht.h"
#include "gnunet-service-xdht_clients.h"
#include "gnunet-service-xdht_datacache.h"
#include "gnunet-service-xdht_neighbours.h"
#include "dht.h"

/**
 * Linked list of messages to send to clients.
 */
struct PendingMessage
{
  /**
   * Pointer to next item in the list
   */
  struct PendingMessage *next;

  /**
   * Pointer to previous item in the list
   */
  struct PendingMessage *prev;

  /**
   * Actual message to be sent, allocated at the end of the struct:
   * // msg = (cast) &pm[1];
   * // memcpy (&pm[1], data, len);
   */
  const struct GNUNET_MessageHeader *msg;

};

/**
 * Struct containing information about a client,
 * handle to connect to it, and any pending messages
 * that need to be sent to it.
 */
struct ClientList
{
  /**
   * Linked list of active clients
   */
  struct ClientList *next;

  /**
   * Linked list of active clients
   */
  struct ClientList *prev;

  /**
   * The handle to this client
   */
  struct GNUNET_SERVER_Client *client_handle;

  /**
   * Handle to the current transmission request, NULL
   * if none pending.
   */
  struct GNUNET_SERVER_TransmitHandle *transmit_handle;

  /**
   * Linked list of pending messages for this client
   */
  struct PendingMessage *pending_head;

  /**
   * Tail of linked list of pending messages for this client
   */
  struct PendingMessage *pending_tail;

};


/**
 * List of active clients.
 */
static struct ClientList *client_head;

/**
 * List of active clients.
 */
static struct ClientList *client_tail;

/**
 * Task run to check for messages that need to be sent to a client.
 *
 * @param client a ClientList, containing the client and any messages to be sent to it
 */
static void process_pending_messages (struct ClientList *client);
/**
 * Callback called as a result of issuing a GNUNET_SERVER_notify_transmit_ready
 * request.  A ClientList is passed as closure, take the head of the list
 * and copy it into buf, which has the result of sending the message to the
 * client.
 *
 * @param cls closure to this call
 * @param size maximum number of bytes available to send
 * @param buf where to copy the actual message to
 *
 * @return the number of bytes actually copied, 0 indicates failure
 */
static size_t
send_reply_to_client (void *cls, size_t size, void *buf)
{
  struct ClientList *client = cls;
  char *cbuf = buf;
  struct PendingMessage *reply;
  size_t off;
  size_t msize;

  client->transmit_handle = NULL;
  if (buf == NULL)
  {
    /* client disconnected */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Client %p disconnected, pending messages will be discarded\n",
                client->client_handle);
    return 0;
  }
  off = 0;
  while ((NULL != (reply = client->pending_head)) &&
         (size >= off + (msize = ntohs (reply->msg->size))))
  {
    GNUNET_CONTAINER_DLL_remove (client->pending_head, client->pending_tail,
                                 reply);
    memcpy (&cbuf[off], reply->msg, msize);
    GNUNET_free (reply);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Transmitting %u bytes to client %p\n",
                msize, client->client_handle);
    off += msize;
  }
  process_pending_messages (client);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Transmitted %u/%u bytes to client %p\n",
              (unsigned int) off, (unsigned int) size, client->client_handle);
  return off;
}


/**
 * Task run to check for messages that need to be sent to a client.
 *
 * @param client a ClientList, containing the client and any messages to be sent to it
 */
static void
process_pending_messages (struct ClientList *client)
{
  if ((client->pending_head == NULL) || (client->transmit_handle != NULL))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Not asking for transmission to %p now: %s\n",
                client->client_handle,
                client->pending_head ==
                NULL ? "no more messages" : "request already pending");
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Asking for transmission of %u bytes to client %p\n",
              ntohs (client->pending_head->msg->size), client->client_handle);
  client->transmit_handle =
      GNUNET_SERVER_notify_transmit_ready (client->client_handle,
                                           ntohs (client->pending_head->
                                                  msg->size),
                                           GNUNET_TIME_UNIT_FOREVER_REL,
                                           &send_reply_to_client, client);
}


/**
 * Add a PendingMessage to the clients list of messages to be sent
 *
 * @param client the active client to send the message to
 * @param pending_message the actual message to send
 */
static void
add_pending_message (struct ClientList *client,
                     struct PendingMessage *pending_message)
{
  GNUNET_CONTAINER_DLL_insert_tail (client->pending_head, client->pending_tail,
                                    pending_message);
  process_pending_messages (client);
}

/**
 * Find a client if it exists, add it otherwise.
 *
 * @param client the server handle to the client
 *
 * @return the client if found, a new client otherwise
 */
static struct ClientList *
find_active_client (struct GNUNET_SERVER_Client *client)
{
  struct ClientList *pos = client_head;
  struct ClientList *ret;

  while (pos != NULL)
  {
    if (pos->client_handle == client)
      return pos;
    pos = pos->next;
  }
  ret = GNUNET_new (struct ClientList);
  ret->client_handle = client;
  GNUNET_CONTAINER_DLL_insert (client_head, client_tail, ret);
  return ret;
}


/**
 * SUPU: Call made from dht_api.c
 * Handler for monitor stop messages
 *
 * @param cls closure for the service
 * @param client the client we received this message from
 * @param message the actual message received
 *
 */
static void
handle_dht_local_monitor_stop (void *cls, struct GNUNET_SERVER_Client *client,
                               const struct GNUNET_MessageHeader *message)
{
  //const struct GNUNET_DHT_MonitorStartStopMessage *msg;
}


/**
 * SUPU: Monitor call made from dht_api.c
 * Handler for monitor start messages
 *
 * @param cls closure for the service
 * @param client the client we received this message from
 * @param message the actual message received
 *
 */
static void
handle_dht_local_monitor (void *cls, struct GNUNET_SERVER_Client *client,
                          const struct GNUNET_MessageHeader *message)
{
  //const struct GNUNET_DHT_MonitorStartStopMessage *msg;
  /* FIXME: At the moment I don't know exact usage of monitor message. But most
   probably it will be just copy and paste from old implementation. */
}


/**SUPU: Call to this function is made whenever a client does not want the
 * get request any more. There is a function in dht_api.c but I don't know
 * yet how the call is made to this function. 
 * Handler for any generic DHT stop messages, calls the appropriate handler
 * depending on message type (if processed locally)
 *
 * @param cls closure for the service
 * @param client the client we received this message from
 * @param message the actual message received
 *
 */
static void
handle_dht_local_get_stop (void *cls, struct GNUNET_SERVER_Client *client,
                           const struct GNUNET_MessageHeader *message)
{
   //const struct GNUNET_DHT_ClientGetStopMessage *dht_stop_msg;
  /* FIXME: Whats the use of get_stop. A client notifies the server to stop asking
   for the get message. But in case of x-vine, it asks for get only once. So,
   when it has already send the get message, after that if client asks it to
   stop, it really can't do anything. Its better to wait for the result, discard
   it and don't communicate with client about the result instead of generating
   more traffic.*/
}

/**
 * FIXME: Call to this function is made whenever we have a get request. 
 * Handler for DHT GET messages from the client.
 *
 * @param cls closure for the service
 * @param client the client we received this message from
 * @param message the actual message received
 */
static void
handle_dht_local_get (void *cls, struct GNUNET_SERVER_Client *client,
                      const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_DHT_ClientGetMessage *get_msg;
  struct GNUNET_PeerIdentity *get_path;
  struct GNUNET_PeerIdentity *my_identity;
  unsigned int get_path_length;
  uint16_t size;
  
  size = ntohs (message->size);
  if (size < sizeof (struct GNUNET_DHT_ClientGetMessage))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  
  get_msg = (struct GNUNET_DHT_ClientGetMessage *) message;
  
  /* FIXME: Search locally? Why should we always search locally? 
   Current implementation of datacache needs to be modified. If found here, then
   notify the requesting client. */
  
  /* FIXME: Call GDS_NEIGHBOURS_handle_get
   Here you need to remember the whole path because you need to travel that path
   and reach back here with the result. So, you should send your own id, client
   id, get path, get path length. You also need to add yourself to the get path.  */
  my_identity = GDS_NEIGHBOURS_get_id();
  get_path = GNUNET_malloc (sizeof (struct GNUNET_PeerIdentity));
  memcpy (get_path, &my_identity, sizeof (struct GNUNET_PeerIdentity));
  get_path_length = 1;
  
  /* FIXME:
   * 1. Find some unique identifier for the client.
   * 2. Also, I don't know the usage of block, replication and type. So, I
   * am not sending the parameters now.  */
  GDS_NEIGHBOURS_handle_get (my_identity, get_path, get_path_length,
                             &(get_msg->key), NULL, NULL, NULL);
  
}


/**
 * Handler for PUT messages.
 * @param cls closure for the service
 * @param client the client we received this message from
 * @param message the actual message received
 */
static void
handle_dht_local_put (void *cls, struct GNUNET_SERVER_Client *client,
                      const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_DHT_ClientPutMessage *put_msg;
  struct GNUNET_DHT_ClientPutConfirmationMessage *conf;
  struct PendingMessage *pm;
  uint16_t size; /* FIXME: When to use size_t and when uint16_t */
  
  size = ntohs (message->size);
  if (size < sizeof (struct GNUNET_DHT_ClientPutMessage))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  
  /* FIXME:Should we define put_msg as const? */
  put_msg = (struct GNUNET_DHT_ClientPutMessage *) message;
  
  /* store locally. FIXME: Is it secure to allow each peer to store the data? */
  GDS_DATACACHE_handle_put (GNUNET_TIME_absolute_ntoh (put_msg->expiration),
                            &put_msg->key, 0, NULL, ntohl (put_msg->type),
                            size - sizeof (struct GNUNET_DHT_ClientPutMessage),
                            &put_msg[1]);
  
  /* FIXME: Right now I have just kept all the fields from the old function.
   It may be possible that most of them are not needed. Check and remove if
   not needed. Usage of replication, options and type is still not clear. */
  GDS_NEIGHBOURS_handle_put (ntohl (put_msg->type), ntohl (put_msg->options),
                             ntohl (put_msg->desired_replication_level),
                             GNUNET_TIME_absolute_ntoh (put_msg->expiration),
                             0 /* hop count */ ,
                             &put_msg->key, 0, NULL, &put_msg[1],
                             size -
                             sizeof (struct GNUNET_DHT_ClientPutMessage),
                             NULL, NULL, NULL);
  
  /* FIXME: Here we send back the confirmation before verifying if put was successful
   or not. */
  pm = GNUNET_malloc (sizeof (struct PendingMessage) +
		      sizeof (struct GNUNET_DHT_ClientPutConfirmationMessage));
  conf = (struct GNUNET_DHT_ClientPutConfirmationMessage *) &pm[1];
  conf->header.size = htons (sizeof (struct GNUNET_DHT_ClientPutConfirmationMessage));
  conf->header.type = htons (GNUNET_MESSAGE_TYPE_DHT_CLIENT_PUT_OK);
  conf->reserved = htonl (0);
  conf->unique_id = put_msg->unique_id;
  pm->msg = &conf->header;
  add_pending_message (find_active_client (client), pm);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}

/**
 * Functions with this signature are called whenever a client
 * is disconnected on the network level.
 *
 * @param cls closure (NULL for dht)
 * @param client identification of the client; NULL
 *        for the last call when the server is destroyed
 */
static void
handle_client_disconnect (void *cls,
			  struct GNUNET_SERVER_Client *client)
{
  /* You should maintain a list of client attached to this service. Then
   search for the correct client and stop all its ongoing activites and
   delete it from the list. */
}


/**
 * Get result from neighbours file. 
 */
void
GDS_CLIENTS_process_get_result()
{
  
}


/**
 * SUPU: Call to this function is made from gnunet-service-xdht.c
 * Here we register handlers for each possible kind of message the service
 * receives from the clients. 
 * Initialize client subsystem.
 *
 * @param server the initialized server
 */
void
GDS_CLIENTS_init (struct GNUNET_SERVER_Handle *server)
{
  static struct GNUNET_SERVER_MessageHandler plugin_handlers[] = {
    {&handle_dht_local_put, NULL,
     GNUNET_MESSAGE_TYPE_DHT_CLIENT_PUT, 0},
    {&handle_dht_local_get, NULL,
     GNUNET_MESSAGE_TYPE_DHT_CLIENT_GET, 0},
    {&handle_dht_local_get_stop, NULL,
     GNUNET_MESSAGE_TYPE_DHT_CLIENT_GET_STOP,
     sizeof (struct GNUNET_DHT_ClientGetStopMessage)},
    {&handle_dht_local_monitor, NULL,
     GNUNET_MESSAGE_TYPE_DHT_MONITOR_START,
     sizeof (struct GNUNET_DHT_MonitorStartStopMessage)},
    {&handle_dht_local_monitor_stop, NULL,
     GNUNET_MESSAGE_TYPE_DHT_MONITOR_STOP,
     sizeof (struct GNUNET_DHT_MonitorStartStopMessage)},
    {NULL, NULL, 0, 0}
  };
  
  GNUNET_SERVER_add_handlers (server, plugin_handlers);
  GNUNET_SERVER_disconnect_notify (server, &handle_client_disconnect, NULL);
}

/**
 * SUPU: Call made from gnunet-service-dht.c
 * Shutdown client subsystem.
 */
void
GDS_CLIENTS_done ()
{
  
}