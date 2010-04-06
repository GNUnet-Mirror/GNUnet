/*
     This file is part of GNUnet.
     (C) 2009, 2010 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
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
 * @file dht/gnunet-service-dht.c
 * @brief main DHT service shell, building block for DHT implementations
 * @author Christian Grothoff
 * @author Nathan Evans
 */

#include "platform.h"
#include "gnunet_client_lib.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_os_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_service_lib.h"
#include "gnunet_core_service.h"
#include "gnunet_signal_lib.h"
#include "gnunet_util_lib.h"
#include "gnunet_datacache_lib.h"
#include "gnunet_transport_service.h"
#include "gnunet_hello_lib.h"
#include "dht.h"

/**
 * Handle to the datacache service (for inserting/retrieving data)
 */
struct GNUNET_DATACACHE_Handle *datacache;

/**
 * The main scheduler to use for the DHT service
 */
static struct GNUNET_SCHEDULER_Handle *sched;

/**
 * The configuration the DHT service is running with
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Timeout for transmissions to clients
 */
static struct GNUNET_TIME_Relative client_transmit_timeout;

/**
 * Handle to the core service
 */
static struct GNUNET_CORE_Handle *coreAPI;

/**
 * Handle to the transport service, for getting our hello
 */
static struct GNUNET_TRANSPORT_Handle *transport_handle;

/**
 * The identity of our peer.
 */
static struct GNUNET_PeerIdentity my_identity;

/**
 * Our HELLO
 */
static struct GNUNET_MessageHeader *my_hello;

/**
 * Task to run when we shut down, cleaning up all our trash
 */
static GNUNET_SCHEDULER_TaskIdentifier cleanup_task;


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
   * Actual message to be sent
   */
  struct GNUNET_MessageHeader *msg;

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
   * The handle to this client
   */
  struct GNUNET_SERVER_Client *client_handle;

  /**
   * Handle to the current transmission request, NULL
   * if none pending.
   */
  struct GNUNET_CONNECTION_TransmitHandle *transmit_handle;

  /**
   * Linked list of pending messages for this client
   */
  struct PendingMessage *pending_head;

};

/**
 * Context for handling results from a get request.
 */
struct DatacacheGetContext
{
  /**
   * The client to send the result to.
   */
  struct ClientList *client;

  /**
   * The unique id of this request
   */
  unsigned long long unique_id;
};

/**
 * Context containing information about a DHT message received.
 */
struct DHT_MessageContext
{
  /**
   * The client this request was received from.
   */
  struct ClientList *client;

  /**
   * The key this request was about
   */
  GNUNET_HashCode *key;

  /**
   * The unique identifier of this request
   */
  unsigned long long unique_id;

  /**
   * Desired replication level
   */
  size_t replication;

  /**
   * Any message options for this request
   */
  size_t msg_options;
};

/**
 * List of active clients.
 */
static struct ClientList *client_list;


/**
 * Server handlers for handling locally received dht requests
 */
static void
handle_dht_start_message (void *cls, struct GNUNET_SERVER_Client *client,
                          const struct GNUNET_MessageHeader *message);

static void
handle_dht_stop_message (void *cls, struct GNUNET_SERVER_Client *client,
                         const struct GNUNET_MessageHeader *message);

static struct GNUNET_SERVER_MessageHandler plugin_handlers[] = {
  {&handle_dht_start_message, NULL, GNUNET_MESSAGE_TYPE_DHT, 0},
  {&handle_dht_stop_message, NULL, GNUNET_MESSAGE_TYPE_DHT_STOP, 0},
  {NULL, NULL, 0, 0}
};


/**
 * Core handler for p2p dht get requests.
 */
static int handle_dht_p2p_get (void *cls,
                               const struct GNUNET_PeerIdentity *peer,
                               const struct GNUNET_MessageHeader *message,
                               struct GNUNET_TIME_Relative latency,
                               uint32_t distance);

/**
 * Core handler for p2p dht put requests.
 */
static int handle_dht_p2p_put (void *cls,
                               const struct GNUNET_PeerIdentity *peer,
                               const struct GNUNET_MessageHeader *message,
                               struct GNUNET_TIME_Relative latency,
                               uint32_t distance);

/**
 * Core handler for p2p dht find peer requests.
 */
static int handle_dht_p2p_find_peer (void *cls,
                                     const struct GNUNET_PeerIdentity *peer,
                                     const struct GNUNET_MessageHeader
                                     *message,
                                     struct GNUNET_TIME_Relative latency,
                                     uint32_t distance);

static struct GNUNET_CORE_MessageHandler core_handlers[] = {
  {&handle_dht_p2p_get, GNUNET_MESSAGE_TYPE_DHT_GET, 0},
  {&handle_dht_p2p_put, GNUNET_MESSAGE_TYPE_DHT_PUT, 0},
  {&handle_dht_p2p_find_peer, GNUNET_MESSAGE_TYPE_DHT_FIND_PEER, 0},
  {NULL, 0, 0}
};

/**
 * Forward declaration.
 */
static size_t send_generic_reply (void *cls, size_t size, void *buf);

/**
 * Task run to check for messages that need to be sent to a client.
 *
 * @param cls a ClientList, containing the client and any messages to be sent to it
 * @param tc reason this was called
 */
static void
process_pending_messages (void *cls,
                          const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ClientList *client = cls;

  if (client->pending_head == NULL)     /* No messages queued */
    {
#if DEBUG_DHT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "`%s': Have no pending messages for client.\n", "DHT");
#endif
      return;
    }

  if (client->transmit_handle == NULL)  /* No current pending messages, we can try to send! */
    client->transmit_handle =
      GNUNET_SERVER_notify_transmit_ready (client->client_handle,
                                           ntohs (client->pending_head->msg->
                                                  size),
                                           GNUNET_TIME_relative_multiply
                                           (GNUNET_TIME_UNIT_SECONDS, 5),
                                           &send_generic_reply, client);
  else
    {
#if DEBUG_DHT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "`%s': Transmit handle is non-null.\n", "DHT");
#endif
    }
}

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
send_generic_reply (void *cls, size_t size, void *buf)
{
  struct ClientList *client = cls;
  struct PendingMessage *reply = client->pending_head;
  int ret;

  client->transmit_handle = NULL;
  if (buf == NULL)              /* Message timed out, that's crappy... */
    {
#if DEBUG_DHT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "`%s': buffer was NULL\n", "DHT");
#endif
      client->pending_head = reply->next;
      GNUNET_free (reply->msg);
      GNUNET_free (reply);
      return 0;
    }

  if (size >= ntohs (reply->msg->size))
    {
#if DEBUG_DHT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "`%s': Copying reply to buffer, REALLY SENT\n", "DHT");
#endif
      memcpy (buf, reply->msg, ntohs (reply->msg->size));

      ret = ntohs (reply->msg->size);
    }
  else
    ret = 0;

  client->pending_head = reply->next;
  GNUNET_free (reply->msg);
  GNUNET_free (reply);

  GNUNET_SCHEDULER_add_now (sched, &process_pending_messages, client);
  return ret;
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
  struct PendingMessage *pos;
  struct PendingMessage *prev;

  pos = client->pending_head;

#if DEBUG_DHT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "`%s': Adding pending message for client.\n", "DHT");
#endif

  if (pos == NULL)
    {
      client->pending_head = pending_message;
    }
  else                          /* This means another request is already queued, rely on send_reply to process all pending messages */
    {
      while (pos != NULL)       /* Find end of list */
        {
          prev = pos;
          pos = pos->next;
        }

      GNUNET_assert (prev != NULL);
      prev->next = pending_message;
    }

  GNUNET_SCHEDULER_add_now (sched, &process_pending_messages, client);

}

/**
 * Called when a reply needs to be sent to a client, either as
 * a result it found to a GET or FIND PEER request.
 *
 * @param client the client to send the reply to
 * @param message the encapsulated message to send
 * @param uid the unique identifier of this request
 */
static void
send_reply_to_client (struct ClientList *client,
                      struct GNUNET_MessageHeader *message,
                      unsigned long long uid)
{
  struct GNUNET_DHT_Message *reply;
  struct PendingMessage *pending_message;

  size_t msize;
  size_t tsize;
#if DEBUG_DHT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "`%s': Sending reply to client.\n", "DHT");
#endif
  msize = ntohs (message->size);
  tsize = sizeof (struct GNUNET_DHT_Message) + msize;
  reply = GNUNET_malloc (tsize);
  reply->header.type = htons (GNUNET_MESSAGE_TYPE_DHT);
  reply->header.size = htons (tsize);
  if (uid != 0)
    reply->unique = htons (GNUNET_YES);
  reply->unique_id = GNUNET_htonll (uid);
  memcpy (&reply[1], message, msize);

  pending_message = GNUNET_malloc (sizeof (struct PendingMessage));
  pending_message->msg = &reply->header;

  add_pending_message (client, pending_message);
}


/**
 * Iterator for local get request results,
 *
 * @param cls closure for iterator, a DatacacheGetContext
 * @param exp when does this value expire?
 * @param key the key this data is stored under
 * @param size the size of the data identified by key
 * @param data the actual data
 * @param type the type of the data
 *
 * @return GNUNET_OK to continue iteration, anything else
 * to stop iteration.
 */
static int
datacache_get_iterator (void *cls,
                        struct GNUNET_TIME_Absolute exp,
                        const GNUNET_HashCode * key,
                        uint32_t size, const char *data, uint32_t type)
{
  struct DatacacheGetContext *datacache_get_ctx = cls;
  struct GNUNET_DHT_GetResultMessage *get_result;
#if DEBUG_DHT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "`%s': Received `%s' response from datacache\n", "DHT", "GET");
#endif
  get_result =
    GNUNET_malloc (sizeof (struct GNUNET_DHT_GetResultMessage) + size);
  get_result->header.type = htons (GNUNET_MESSAGE_TYPE_DHT_GET_RESULT);
  get_result->header.size =
    htons (sizeof (struct GNUNET_DHT_GetResultMessage) + size);
  get_result->data_size = htons (size);
  get_result->expiration = exp;
  memcpy (&get_result->key, key, sizeof (GNUNET_HashCode));
  get_result->type = htons (type);
  memcpy (&get_result[1], data, size);

  send_reply_to_client (datacache_get_ctx->client, &get_result->header,
                        datacache_get_ctx->unique_id);

  GNUNET_free (get_result);
  return GNUNET_OK;
}

/**
 * Server handler for initiating local dht get requests
 *
 * @param cls closure for service
 * @param get_msg the actual get message
 * @param message_context struct containing pertinent information about the get request
 *
 */
static void
handle_dht_get (void *cls, struct GNUNET_DHT_GetMessage *get_msg,
                struct DHT_MessageContext *message_context)
{
  size_t get_type;
  unsigned int results;
  struct DatacacheGetContext *datacache_get_context;

  GNUNET_assert (ntohs (get_msg->header.size) >=
                 sizeof (struct GNUNET_DHT_GetMessage));
  get_type = ntohs (get_msg->type);

#if DEBUG_DHT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "`%s': Received `%s' request from client, message type %d, key %s, uid %llu\n",
              "DHT", "GET", get_type, GNUNET_h2s (message_context->key),
              message_context->unique_id);
#endif

  datacache_get_context = GNUNET_malloc (sizeof (struct DatacacheGetContext));
  datacache_get_context->client = message_context->client;
  datacache_get_context->unique_id = message_context->unique_id;

  results = 0;
  if (datacache != NULL)
    results =
      GNUNET_DATACACHE_get (datacache, message_context->key, get_type,
                            &datacache_get_iterator, datacache_get_context);

#if DEBUG_DHT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "`%s': Found %d results for local `%s' request\n", "DHT",
              results, "GET");
#endif
  GNUNET_free (datacache_get_context);
  /* FIXME: Implement get functionality here */
}


/**
 * Server handler for initiating local dht find peer requests
 *
 * @param cls closure for service
 * @param find_msg the actual find peer message
 * @param message_context struct containing pertinent information about the request
 *
 */
static void
handle_dht_find_peer (void *cls, struct GNUNET_DHT_FindPeerMessage *find_msg,
                      struct DHT_MessageContext *message_context)
{
  struct GNUNET_DHT_FindPeerResultMessage *find_peer_result;
  size_t hello_size;
  size_t tsize;
#if DEBUG_DHT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "`%s': Received `%s' request from client, key %s (msg size %d, we expected %d)\n",
              "DHT", "FIND PEER", GNUNET_h2s (message_context->key),
              ntohs (find_msg->header.size),
              sizeof (struct GNUNET_DHT_FindPeerMessage));
#endif

  GNUNET_assert (ntohs (find_msg->header.size) >=
                 sizeof (struct GNUNET_DHT_FindPeerMessage));

  if (my_hello == NULL)
  {
#if DEBUG_DHT
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "`%s': Our HELLO is null, can't return.\n",
                "DHT");
#endif

    return;
  }

  /* Simplistic find_peer functionality, always return our hello */
  hello_size = ntohs(my_hello->size);
  tsize = hello_size + sizeof (struct GNUNET_DHT_FindPeerResultMessage);
  find_peer_result = GNUNET_malloc (tsize);
  find_peer_result->header.type = htons (GNUNET_MESSAGE_TYPE_DHT_FIND_PEER_RESULT);
  find_peer_result->header.size = htons (tsize);
  find_peer_result->data_size = htons (hello_size);
  memcpy(&find_peer_result->peer, &my_identity, sizeof(struct GNUNET_PeerIdentity));
  memcpy (&find_peer_result[1], &my_hello, hello_size);

  send_reply_to_client(message_context->client, &find_peer_result->header, message_context->unique_id);
  GNUNET_free(find_peer_result);
  /* FIXME: Implement find peer functionality here */
}


/**
 * Server handler for initiating local dht put requests
 *
 * @param cls closure for service
 * @param put_msg the actual put message
 * @param message_context struct containing pertinent information about the request
 */
static void
handle_dht_put (void *cls, struct GNUNET_DHT_PutMessage *put_msg,
                struct DHT_MessageContext *message_context)
{
  size_t put_type;
  size_t data_size;

  GNUNET_assert (ntohs (put_msg->header.size) >=
                 sizeof (struct GNUNET_DHT_PutMessage));

  put_type = ntohs (put_msg->type);
  data_size = ntohs (put_msg->data_size);
#if DEBUG_DHT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "`%s': %s msg total size is %d, data size %d, struct size %d\n",
              "DHT", "PUT", ntohs (put_msg->header.size), data_size,
              sizeof (struct GNUNET_DHT_PutMessage));
#endif
  GNUNET_assert (ntohs (put_msg->header.size) ==
                 sizeof (struct GNUNET_DHT_PutMessage) + data_size);

#if DEBUG_DHT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "`%s': Received `%s' request from client, message type %d, key %s\n",
              "DHT", "PUT", put_type, GNUNET_h2s (message_context->key));
#endif

  /**
   * Simplest DHT functionality, store any message we receive a put request for.
   */
  if (datacache != NULL)
    GNUNET_DATACACHE_put (datacache, message_context->key, data_size,
                          (char *) &put_msg[1], put_type,
                          put_msg->expiration);
  /**
   * FIXME: Implement dht put request functionality here!
   */

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
  struct ClientList *pos = client_list;
  struct ClientList *ret;

  while (pos != NULL)
    {
      if (pos->client_handle == client)
        return pos;
      pos = pos->next;
    }

  ret = GNUNET_malloc (sizeof (struct ClientList));
  ret->client_handle = client;
  ret->next = client_list;
  client_list = ret;
  ret->pending_head = NULL;

  return ret;
}

/**
 * Construct a message receipt confirmation for a particular uid.
 * Receipt confirmations are used for any requests that don't expect
 * a reply otherwise (i.e. put requests, stop requests).
 *
 * @param client the handle for the client
 * @param uid the unique identifier of this message
 */
static void
send_client_receipt_confirmation (struct GNUNET_SERVER_Client *client,
                                  uint64_t uid)
{
  struct GNUNET_DHT_StopMessage *confirm_message;
  struct ClientList *active_client;
  struct PendingMessage *pending_message;

#if DEBUG_DHT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "`%s': Sending receipt confirmation for uid %llu\n", "DHT",
              uid);
#endif
  confirm_message = GNUNET_malloc (sizeof (struct GNUNET_DHT_StopMessage));
  confirm_message->header.type = htons (GNUNET_MESSAGE_TYPE_DHT_STOP);
  confirm_message->header.size =
    htons (sizeof (struct GNUNET_DHT_StopMessage));
  confirm_message->unique_id = GNUNET_htonll (uid);

  active_client = find_active_client (client);
  pending_message = GNUNET_malloc (sizeof (struct PendingMessage));
  pending_message->msg = &confirm_message->header;

  add_pending_message (active_client, pending_message);

}

/**
 * Handler for any generic DHT messages, calls the appropriate handler
 * depending on message type, sends confirmation if responses aren't otherwise
 * expected.
 *
 * @param cls closure for the service
 * @param client the client we received this message from
 * @param message the actual message received
 */
static void
handle_dht_start_message (void *cls, struct GNUNET_SERVER_Client *client,
                          const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_DHT_Message *dht_msg = (struct GNUNET_DHT_Message *) message;
  struct GNUNET_MessageHeader *enc_msg;
  struct DHT_MessageContext *message_context;

  size_t enc_type;

  enc_msg = (struct GNUNET_MessageHeader *) &dht_msg[1];
  enc_type = ntohs (enc_msg->type);


#if DEBUG_DHT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "`%s': Received `%s' request from client, message type %d, key %s, uid %llu\n",
              "DHT", "GENERIC", enc_type, GNUNET_h2s (&dht_msg->key),
              GNUNET_ntohll (dht_msg->unique_id));
#endif

  message_context = GNUNET_malloc (sizeof (struct DHT_MessageContext));
  message_context->client = find_active_client (client);
  message_context->key = &dht_msg->key;
  message_context->unique_id = GNUNET_ntohll (dht_msg->unique_id);
  message_context->replication = ntohs (dht_msg->desired_replication_level);
  message_context->msg_options = ntohs (dht_msg->options);

  switch (enc_type)
    {
    case GNUNET_MESSAGE_TYPE_DHT_GET:
      handle_dht_get (cls, (struct GNUNET_DHT_GetMessage *) enc_msg,
                      message_context);
      break;
    case GNUNET_MESSAGE_TYPE_DHT_PUT:
      handle_dht_put (cls, (struct GNUNET_DHT_PutMessage *) enc_msg,
                      message_context);
      send_client_receipt_confirmation (client,
                                        GNUNET_ntohll (dht_msg->unique_id));
      break;
    case GNUNET_MESSAGE_TYPE_DHT_FIND_PEER:
      handle_dht_find_peer (cls,
                            (struct GNUNET_DHT_FindPeerMessage *) enc_msg,
                            message_context);
      break;
    default:
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "`%s': Message type (%d) not handled\n", "DHT", enc_type);
    }

  GNUNET_free (message_context);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);

}

/**
 * Handler for any generic DHT stop messages, calls the appropriate handler
 * depending on message type, sends confirmation by default (stop messages
 * do not otherwise expect replies)
 *
 * @param cls closure for the service
 * @param client the client we received this message from
 * @param message the actual message received
 *
 * TODO: add demultiplexing for stop message types.
 */
static void
handle_dht_stop_message (void *cls, struct GNUNET_SERVER_Client *client,
                         const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_DHT_StopMessage *dht_stop_msg =
    (struct GNUNET_DHT_StopMessage *) message;

#if DEBUG_DHT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "`%s': Received `%s' request from client, uid %llu\n", "DHT",
              "GENERIC STOP", GNUNET_ntohll (dht_stop_msg->unique_id));
#endif

  /* TODO: Put in demultiplexing here */

  send_client_receipt_confirmation (client,
                                    GNUNET_ntohll (dht_stop_msg->unique_id));
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Core handler for p2p dht get requests.
 */
static int
handle_dht_p2p_get (void *cls,
                    const struct GNUNET_PeerIdentity *peer,
                    const struct GNUNET_MessageHeader *message,
                    struct GNUNET_TIME_Relative latency, uint32_t distance)
{
#if DEBUG_DHT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "`%s': Received `%s' request from another peer\n", "DHT",
              "GET");
#endif

  return GNUNET_YES;
}

/**
 * Core handler for p2p dht put requests.
 */
static int
handle_dht_p2p_put (void *cls,
                    const struct GNUNET_PeerIdentity *peer,
                    const struct GNUNET_MessageHeader *message,
                    struct GNUNET_TIME_Relative latency, uint32_t distance)
{
#if DEBUG_DHT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "`%s': Received `%s' request from another peer\n", "DHT",
              "PUT");
#endif

  return GNUNET_YES;
}

/**
 * Core handler for p2p dht find peer requests.
 */
static int
handle_dht_p2p_find_peer (void *cls,
                          const struct GNUNET_PeerIdentity *peer,
                          const struct GNUNET_MessageHeader *message,
                          struct GNUNET_TIME_Relative latency,
                          uint32_t distance)
{
#if DEBUG_DHT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "`%s': Received `%s' request from another peer\n", "DHT",
              "FIND PEER");
#endif

  return GNUNET_YES;
}


/**
 * Receive the HELLO from transport service,
 * free current and replace if necessary.
 *
 * @param cls NULL
 * @param message HELLO message of peer
 */
static void
process_hello (void *cls, const struct GNUNET_MessageHeader *message)
{
#if DEBUG_DHT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received our `%s' from transport service\n",
              "HELLO");
#endif

  GNUNET_assert (message != NULL);
  GNUNET_free_non_null(my_hello);
  my_hello = GNUNET_malloc(ntohs(message->size));
  memcpy(my_hello, message, ntohs(message->size));
}

/**
 * Task run during shutdown.
 *
 * @param cls unused
 * @param tc unused
 */
static void
shutdown_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (transport_handle != NULL)
  {
    GNUNET_free_non_null(my_hello);
    GNUNET_TRANSPORT_get_hello_cancel(transport_handle, &process_hello, NULL);
    GNUNET_TRANSPORT_disconnect(transport_handle);
  }
  if (coreAPI != NULL)
    GNUNET_CORE_disconnect (coreAPI);
}


/**
 * To be called on core init/fail.
 *
 * @param cls service closure
 * @param server handle to the server for this service
 * @param identity the public identity of this peer
 * @param publicKey the public key of this peer
 */
void
core_init (void *cls,
           struct GNUNET_CORE_Handle *server,
           const struct GNUNET_PeerIdentity *identity,
           const struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *publicKey)
{

  if (server == NULL)
    {
#if DEBUG_DHT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%s: Connection to core FAILED!\n", "dht",
              GNUNET_i2s (identity));
#endif
      GNUNET_SCHEDULER_cancel (sched, cleanup_task);
      GNUNET_SCHEDULER_add_now (sched, &shutdown_task, NULL);
      return;
    }
#if DEBUG_DHT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "%s: Core connection initialized, I am peer: %s\n", "dht",
              GNUNET_i2s (identity));
#endif
  /* Copy our identity so we can use it */
  memcpy (&my_identity, identity, sizeof (struct GNUNET_PeerIdentity));
  /* Set the server to local variable */
  coreAPI = server;
}


/**
 * Process dht requests.
 *
 * @param cls closure
 * @param scheduler scheduler to use
 * @param server the initialized server
 * @param c configuration to use
 */
static void
run (void *cls,
     struct GNUNET_SCHEDULER_Handle *scheduler,
     struct GNUNET_SERVER_Handle *server,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  sched = scheduler;
  cfg = c;

  datacache = GNUNET_DATACACHE_create (sched, cfg, "dhtcache");

  client_transmit_timeout =
    GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5);
  GNUNET_SERVER_add_handlers (server, plugin_handlers);

  coreAPI = GNUNET_CORE_connect (sched, /* Main scheduler */
                                 cfg,   /* Main configuration */
                                 client_transmit_timeout,       /* Delay for connecting */
                                 NULL,  /* FIXME: anything we want to pass around? */
                                 &core_init,    /* Call core_init once connected */
                                 NULL,  /* Don't care about pre-connects */
                                 NULL,  /* Don't care about connects */
                                 NULL,  /* Don't care about disconnects */
                                 NULL,  /* Don't want notified about all incoming messages */
                                 GNUNET_NO,     /* For header only inbound notification */
                                 NULL,  /* Don't want notified about all outbound messages */
                                 GNUNET_NO,     /* For header only outbound notification */
                                 core_handlers);        /* Register these handlers */

  transport_handle = GNUNET_TRANSPORT_connect(sched, cfg, NULL, NULL, NULL, NULL);

  if (transport_handle != NULL)
    GNUNET_TRANSPORT_get_hello (transport_handle, &process_hello, NULL);
  else
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "Failed to connect to transport service!\n");


  if (coreAPI == NULL)
    return;

  /* Scheduled the task to clean up when shutdown is called */
  cleanup_task = GNUNET_SCHEDULER_add_delayed (sched,
                                               GNUNET_TIME_UNIT_FOREVER_REL,
                                               &shutdown_task, NULL);
}


/**
 * The main function for the dht service.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  return (GNUNET_OK ==
          GNUNET_SERVICE_run (argc,
                              argv,
                              "dht",
                              GNUNET_SERVICE_OPTION_NONE,
                              &run, NULL)) ? 0 : 1;
}
