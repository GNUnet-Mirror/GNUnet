/*
      This file is part of GNUnet
      (C) 2013 Christian Grothoff (and other contributing authors)

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
 * @file set/gnunet-service-set.c
 * @brief two-peer set operations
 * @author Florian Dold
 */


#include "gnunet-service-set.h"
#include "set_protocol.h"


/**
 * Configuration of our local peer.
 */
const struct GNUNET_CONFIGURATION_Handle *configuration;

/**
 * Socket listening for other peers via stream.
 */
static struct GNUNET_STREAM_ListenSocket *stream_listen_socket;

/**
 * Sets are held in a doubly linked list.
 */
static struct Set *sets_head;

/**
 * Sets are held in a doubly linked list.
 */
static struct Set *sets_tail;

/**
 * Listeners are held in a doubly linked list.
 */
static struct Listener *listeners_head;

/**
 * Listeners are held in a doubly linked list.
 */
static struct Listener *listeners_tail;

/**
 * Incoming sockets from remote peers are
 * held in a doubly linked list.
 */
static struct Incoming *incoming_head;

/**
 * Incoming sockets from remote peers are
 * held in a doubly linked list.
 */
static struct Incoming *incoming_tail;

/**
 * Counter for allocating unique request IDs for clients.
 */
static uint32_t request_id = 1;


/**
 * Disconnect a client and free all resources
 * that the client allocated (e.g. Sets or Listeners)
 *
 * @param client the client to disconnect
 */
void
_GSS_client_disconnect (struct GNUNET_SERVER_Client *client)
{
  /* FIXME: clean up any data structures belonging to the client */
  GNUNET_SERVER_client_disconnect (client);
}


/**
 * Get set that is owned by the client, if any.
 *
 * @param client client to look for
 * @return set that the client owns, NULL if the client
 *         does not own a set
 */
static struct Set *
get_set (struct GNUNET_SERVER_Client *client)
{
  struct Set *set;
  for (set = sets_head; NULL != set; set = set->next)
    if (set->client == client)
      return set;
  return NULL;
}


/**
 * Get the listener associated to a client, if any.
 *
 * @param client the client
 * @return listener associated with the client, NULL
 *         if there isn't any
 */
static struct Listener *
get_listener (struct GNUNET_SERVER_Client *client)
{
  struct Listener *listener;
  for (listener = listeners_head; NULL != listener; listener = listener->next)
    if (listener->client == client)
      return listener;
  return NULL;
}


/**
 * Get the incoming socket associated with the given id
 *
 * @param id id to look for
 * @return the incoming socket associated with the id,
 *         or NULL if there is none
 */
static struct Incoming *
get_incoming (uint32_t id)
{
  struct Incoming *incoming;
  for (incoming = incoming_head; NULL != incoming; incoming = incoming->next)
    if (incoming->request_id == id)
      return incoming;
  return NULL;
}


static void
destroy_incoming (struct Incoming *incoming)
{
  if (NULL != incoming->mq)
  {
    GNUNET_MQ_destroy (incoming->mq);
    incoming->mq = NULL;
  }
  if (NULL != incoming->socket)
  {
    GNUNET_STREAM_close (incoming->socket);
    incoming->socket = NULL;
  }
  GNUNET_CONTAINER_DLL_remove (incoming_head, incoming_tail, incoming);
  GNUNET_free (incoming);
}


/**
 * Handle a request for a set operation for
 * another peer.
 *
 * @param cls the incoming socket
 * @param mh the message
 */

static void
handle_p2p_operation_request (void *cls, const struct GNUNET_MessageHeader *mh)
{
  struct Incoming *incoming = cls;
  const struct OperationRequestMessage *msg = (const struct OperationRequestMessage *) mh;
  struct GNUNET_MQ_Message *mqm;
  struct RequestMessage *cmsg;
  struct Listener *listener;
  const struct GNUNET_MessageHeader *context_msg;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "got operation request\n");

  if (ntohs (mh->size) < sizeof *msg)
  {
    GNUNET_break (0);
    destroy_incoming (incoming);
    return;
  }
  else if (ntohs (mh->size) == sizeof *msg)
  {
    context_msg = NULL;
  }
  else
  {
    context_msg = &msg[1].header;
    if ((ntohs (context_msg->size) + sizeof *msg) != ntohs (msg->header.size))
    {
      /* size of context message is invalid */
      GNUNET_break (0);
      destroy_incoming (incoming);
      return;
    }
  }
  /* find the appropriate listener */
  for (listener = listeners_head;
       listener != NULL;
       listener = listener->next)
  {
    if ( (0 != GNUNET_CRYPTO_hash_cmp (&msg->app_id, &listener->app_id)) ||
         (htons (msg->operation) != listener->operation) )
      continue;
    mqm = GNUNET_MQ_msg (cmsg, GNUNET_MESSAGE_TYPE_SET_REQUEST);
    if (GNUNET_OK !=
        GNUNET_MQ_nest (mqm, context_msg))
    {
      /* FIXME: disconnect the peer */
      GNUNET_MQ_discard (mqm);
      GNUNET_break (0);
    }
    incoming->request_id = request_id++;
    cmsg->request_id = htonl (incoming->request_id);
    GNUNET_MQ_send (listener->client_mq, mqm);
    return;
  }
  /* FIXME: send a reject message */
}


/**
 * Called when a client wants to create a new set.
 *
 * @param cls unused
 * @param client client that sent the message
 * @param m message sent by the client
 */
static void
handle_client_create (void *cls,
                      struct GNUNET_SERVER_Client *client,
                      const struct GNUNET_MessageHeader *m)
{
  struct SetCreateMessage *msg = (struct SetCreateMessage *) m;
  struct Set *set;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "new set created\n");

  if (NULL != get_set (client))
  {
    GNUNET_break (0);
    GNUNET_SERVER_client_disconnect (client);
    return;
  }

  set = GNUNET_new (struct Set);

  switch (ntohs (msg->operation))
  {
    case GNUNET_SET_OPERATION_INTERSECTION:
      /* FIXME: cfuchs */
      GNUNET_assert (0);
      break;
    case GNUNET_SET_OPERATION_UNION:
      set = _GSS_union_set_create ();
      break;
    default:
      GNUNET_free (set);
      GNUNET_break (0);
      GNUNET_SERVER_client_disconnect (client);
      return;
  }

  set->client = client;
  set->client_mq = GNUNET_MQ_queue_for_server_client (client);
  GNUNET_CONTAINER_DLL_insert (sets_head, sets_tail, set);
  
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Called when a client wants to create a new set.
 *
 * @param cls unused
 * @param client client that sent the message
 * @param m message sent by the client
 */
static void
handle_client_listen (void *cls,
                      struct GNUNET_SERVER_Client *client,
                      const struct GNUNET_MessageHeader *m)
{
  struct ListenMessage *msg = (struct ListenMessage *) m;
  struct Listener *listener;
  
  if (NULL != get_listener (client))
  {
    GNUNET_break (0);
    GNUNET_SERVER_client_disconnect (client);
    return;
  }
  
  listener = GNUNET_new (struct Listener);
  listener->app_id = msg->app_id;
  listener->operation = msg->operation;
  GNUNET_CONTAINER_DLL_insert_tail (listeners_head, listeners_tail, listener);

  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Called when a client wants to create a new set.
 *
 * @param cls unused
 * @param client client that sent the message
 * @param m message sent by the client
 */
static void
handle_client_add (void *cls,
                      struct GNUNET_SERVER_Client *client,
                      const struct GNUNET_MessageHeader *m)
{
  struct Set *set;

  set = get_set (client);
  if (NULL == set)
  {
    GNUNET_break (0);
    _GSS_client_disconnect (client);
    return;
  }
  switch (set->operation)
  {
    case GNUNET_SET_OPERATION_UNION:
      _GSS_union_add ((struct ElementMessage *) m, set);
    case GNUNET_SET_OPERATION_INTERSECTION:
      /* FIXME: cfuchs */
      break;
    default:
      GNUNET_assert (0);
      break;
  }

  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Called when a client wants to evaluate a set operation with another peer.
 *
 * @param cls unused
 * @param client client that sent the message
 * @param m message sent by the client
 */
static void
handle_client_evaluate (void *cls,
                        struct GNUNET_SERVER_Client *client,
                        const struct GNUNET_MessageHeader *m)
{
  struct Set *set;

  set = get_set (client);
  if (NULL == set)
  {
    GNUNET_break (0);
    _GSS_client_disconnect (client);
    return;
  }


  switch (set->operation)
  {
    case GNUNET_SET_OPERATION_INTERSECTION:
      /* FIXME: cfuchs */
      break;
    case GNUNET_SET_OPERATION_UNION:
      _GSS_union_evaluate ((struct EvaluateMessage *) m, set);
      break;
    default:
      GNUNET_assert (0);
      break;
  }

  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Handle a cancel request from a client.
 *
 * @param cls unused
 * @param client the client
 * @param m the cancel message
 */
static void
handle_client_cancel (void *cls,
                      struct GNUNET_SERVER_Client *client,
                      const struct GNUNET_MessageHeader *m)
{
  /* FIXME: implement */
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Handle an ack from a client.
 *
 * @param cls unused
 * @param client the client
 * @param m the message
 */
static void
handle_client_ack (void *cls,
                   struct GNUNET_SERVER_Client *client,
                   const struct GNUNET_MessageHeader *m)
{
  /* FIXME: implement */
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Handle a request from the client to accept
 * a set operation.
 *
 * @param cls unused
 * @param client the client
 * @param m the message
 */
static void
handle_client_accept (void *cls,
                      struct GNUNET_SERVER_Client *client,
                      const struct GNUNET_MessageHeader *mh)
{
  struct Set *set;
  struct Incoming *incoming;
  struct AcceptMessage *msg = (struct AcceptMessage *) mh;

  set = get_set (client);
  

  if (NULL == set)
  {
    GNUNET_break (0);
    _GSS_client_disconnect (client);
    return;
  }

  incoming = get_incoming (ntohl (msg->request_id));

  if ( (NULL == incoming) ||
       (incoming->operation != set->operation) )
  {
    GNUNET_break (0);
    _GSS_client_disconnect (client);
    return;
  }

  switch (set->operation)
  {
    case GNUNET_SET_OPERATION_INTERSECTION:
      /* FIXME: cfuchs*/
      GNUNET_assert (0);
      break;
    case GNUNET_SET_OPERATION_UNION:
      _GSS_union_accept (msg, set, incoming);
      break;
    default:
      GNUNET_assert (0);
      break;
  }
  /* FIXME: destroy incoming */

  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Functions of this type are called upon new stream connection from other peers
 * or upon binding error which happen when the app_port given in
 * GNUNET_STREAM_listen() is already taken.
 *
 * @param cls the closure from GNUNET_STREAM_listen
 * @param socket the socket representing the stream; NULL on binding error
 * @param initiator the identity of the peer who wants to establish a stream
 *            with us; NULL on binding error
 * @return GNUNET_OK to keep the socket open, GNUNET_SYSERR to close the
 *             stream (the socket will be invalid after the call)
 */
static int
stream_listen_cb (void *cls,
                  struct GNUNET_STREAM_Socket *socket,
                  const struct GNUNET_PeerIdentity *initiator)
{
  struct Incoming *incoming;
  static const struct GNUNET_MQ_Handler handlers[] = {
    {handle_p2p_operation_request, GNUNET_MESSAGE_TYPE_SET_P2P_OPERATION_REQUEST},
    GNUNET_MQ_HANDLERS_END
  };

  if (NULL == socket)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }

  incoming = GNUNET_new (struct Incoming);
  incoming->peer = *initiator;
  incoming->socket = socket;
  incoming->mq = GNUNET_MQ_queue_for_stream_socket (incoming->socket, handlers, incoming);
  /* FIXME: timeout for peers that only connect but don't send anything */
  GNUNET_CONTAINER_DLL_insert_tail (incoming_head, incoming_tail, incoming);
  return GNUNET_OK;
}


/**
 * Called to clean up, after a shutdown has been requested.
 *
 * @param cls closure
 * @param tc context information (why was this task triggered now)
 */
static void
shutdown_task (void *cls,
               const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (NULL != stream_listen_socket)
  {
    GNUNET_STREAM_listen_close (stream_listen_socket);
    stream_listen_socket = NULL;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "handled shutdown request\n");
}


/**
 * Function called by the service's run
 * method to run service-specific setup code.
 *
 * @param cls closure
 * @param server the initialized server
 * @param cfg configuration to use
 */
static void
run (void *cls, struct GNUNET_SERVER_Handle *server, const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  static const struct GNUNET_SERVER_MessageHandler server_handlers[] = {
    {handle_client_create, NULL, GNUNET_MESSAGE_TYPE_SET_CREATE, 0},
    {handle_client_listen, NULL, GNUNET_MESSAGE_TYPE_SET_LISTEN, 0},
    {handle_client_add, NULL, GNUNET_MESSAGE_TYPE_SET_ADD, 0},
    {handle_client_cancel, NULL, GNUNET_MESSAGE_TYPE_SET_CANCEL, 0},
    {handle_client_evaluate, NULL, GNUNET_MESSAGE_TYPE_SET_EVALUATE, 0},
    {handle_client_ack, NULL, GNUNET_MESSAGE_TYPE_SET_ACK, 0},
    {handle_client_accept, NULL, GNUNET_MESSAGE_TYPE_SET_ACCEPT, 0},
    {NULL, NULL, 0, 0}
  };

  configuration = cfg;
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &shutdown_task, NULL);
  GNUNET_SERVER_add_handlers (server, server_handlers);
  stream_listen_socket = GNUNET_STREAM_listen (cfg, GNUNET_APPLICATION_TYPE_SET,
                                               &stream_listen_cb, NULL,
                                               GNUNET_STREAM_OPTION_END);
}


/**
 * The main function for the set service.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  int ret;
  ret = GNUNET_SERVICE_run (argc, argv, "set", GNUNET_SERVICE_OPTION_NONE, &run, NULL);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "exit\n");
  return (GNUNET_OK == ret) ? 0 : 1;
}

