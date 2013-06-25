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
 * (Not declared 'static' as also needed in gnunet-service-set_union.c)
 */
const struct GNUNET_CONFIGURATION_Handle *configuration;

/**
 * Handle to the mesh service, used
 * to listen for and connect to remote peers.
 * (Not declared 'static' as also needed in gnunet-service-set_union.c)
 */
struct GNUNET_MESH_Handle *mesh;

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
 * Counter for allocating unique IDs for clients,
 * used to identify incoming operation requests from remote peers,
 * that the client can choose to accept or refuse.
 */
static uint32_t accept_id = 1;


/**
 * Get set that is owned by the given client, if any.
 *
 * @param client client to look for
 * @return set that the client owns, NULL if the client
 *         does not own a set
 */
static struct Set *
set_get (struct GNUNET_SERVER_Client *client)
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
 * Get the incoming socket associated with the given id.
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
    if (incoming->accept_id == id)
      return incoming;
  return NULL;
}


/**
 * Destroy a listener, free all resources associated with it.
 *
 * @param listener listener to destroy
 */
static void
listener_destroy (struct Listener *listener)
{
  if (NULL != listener->client_mq)
  {
    GNUNET_MQ_destroy (listener->client_mq);
    listener->client_mq = NULL;
  }
  GNUNET_CONTAINER_DLL_remove (listeners_head, listeners_tail, listener);
  GNUNET_free (listener);
}


/**
 * Destroy a set, and free all resources associated with it.
 *
 * @param set the set to destroy
 */
static void
set_destroy (struct Set *set)
{
  switch (set->operation)
  {
    case GNUNET_SET_OPERATION_INTERSECTION:
      GNUNET_assert (0);
      break;
    case GNUNET_SET_OPERATION_UNION:
      _GSS_union_set_destroy (set);
      break;
    default:
      GNUNET_assert (0);
      break;
  }
  GNUNET_CONTAINER_DLL_remove (sets_head, sets_tail, set);
  GNUNET_free (set);
}


/**
 * Clean up after a client after it is
 * disconnected (either by us or by itself)
 *
 * @param cls closure, unused
 * @param client the client to clean up after
 */
static void
handle_client_disconnect (void *cls, struct GNUNET_SERVER_Client *client)
{
  struct Set *set;
  struct Listener *listener;

  set = set_get (client);
  if (NULL != set)
    set_destroy (set);
  listener = get_listener (client);
  if (NULL != listener)
    listener_destroy (listener);
}


/**
 * Destroy an incoming request from a remote peer
 *
 * @param incoming remote request to destroy
 */
static void
incoming_destroy (struct Incoming *incoming)
{
  if (NULL != incoming->tc)
  {
    GNUNET_free (incoming->tc);
    GNUNET_assert (NULL != incoming->tc->tunnel);
    GNUNET_MESH_tunnel_destroy (incoming->tc->tunnel);
    incoming->tc = NULL;
  }
  GNUNET_CONTAINER_DLL_remove (incoming_head, incoming_tail, incoming);
  GNUNET_free (incoming);
}


static struct Listener *
get_listener_by_target (enum GNUNET_SET_OperationType op,
                        const struct GNUNET_HashCode *app_id)
{
  struct Listener *l;

  for (l = listeners_head; NULL != l; l = l->next)
  {
    if (l->operation != op)
      continue;
    if (0 != GNUNET_CRYPTO_hash_cmp (app_id, &l->app_id))
      continue;
    return l;
  }
  return NULL;
}



static void
tunnel_context_destroy (struct TunnelContext *tc)
{
  GNUNET_free (tc);
  /* FIXME destroy the rest */
}


/**
 * Handle a request for a set operation from
 * another peer.
 *
 * @param cls the incoming socket
 * @param mh the message
 */
static int
handle_p2p_operation_request (void *cls,
                              struct GNUNET_MESH_Tunnel *tunnel,
                              void **tunnel_ctx,
                              const struct GNUNET_MessageHeader *mh)
{
  struct TunnelContext *tc = *tunnel_ctx;
  struct Incoming *incoming;
  const struct OperationRequestMessage *msg = (const struct OperationRequestMessage *) mh;
  struct GNUNET_MQ_Envelope *mqm;
  struct GNUNET_SET_RequestMessage *cmsg;
  struct Listener *listener;
  const struct GNUNET_MessageHeader *context_msg;

  if (CONTEXT_INCOMING != tc->type)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "unexpected operation request\n");
    tunnel_context_destroy (tc);
    /* don't kill the whole mesh connection */
    return GNUNET_OK;
  }

  incoming = tc->data;

  context_msg = GNUNET_MQ_extract_nested_mh (msg);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "received P2P operation request (op %u, app %s)\n",
              ntohs (msg->operation), GNUNET_h2s (&msg->app_id));
  listener = get_listener_by_target (ntohs (msg->operation), &msg->app_id);
  if (NULL == listener)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "set operation request from peer failed: "
                "no set with matching application ID and operation type\n");
    tunnel_context_destroy (tc);
    /* don't kill the whole mesh connection */
    return GNUNET_OK;
  }
  mqm = GNUNET_MQ_msg_nested_mh (cmsg, GNUNET_MESSAGE_TYPE_SET_REQUEST, context_msg);
  if (NULL == mqm)
  {
    /* FIXME: disconnect the peer */
    GNUNET_break_op (0);
    tunnel_context_destroy (tc);
    /* don't kill the whole mesh connection */
    return GNUNET_OK;
  }
  incoming->accept_id = accept_id++;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "sending request with accept id %u\n", incoming->accept_id);
  cmsg->accept_id = htonl (incoming->accept_id);
  cmsg->peer_id = incoming->tc->peer;
  GNUNET_MQ_send (listener->client_mq, mqm);

  return GNUNET_OK;
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
  struct GNUNET_SET_CreateMessage *msg = (struct GNUNET_SET_CreateMessage *) m;
  struct Set *set;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "client created new set (operation %u)\n",
              ntohs (msg->operation));

  if (NULL != set_get (client))
  {
    GNUNET_break (0);
    GNUNET_SERVER_client_disconnect (client);
    return;
  }

  set = NULL;

  switch (ntohs (msg->operation))
  {
    case GNUNET_SET_OPERATION_INTERSECTION:
      //set = _GSS_intersection_set_create ();
      break;
    case GNUNET_SET_OPERATION_UNION:
      set = _GSS_union_set_create ();
      break;
    default:
      GNUNET_break (0);
      GNUNET_SERVER_client_disconnect (client);
      return;
  }

  GNUNET_assert (NULL != set);

  set->client = client;
  set->client_mq = GNUNET_MQ_queue_for_server_client (client);
  GNUNET_CONTAINER_DLL_insert (sets_head, sets_tail, set);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Called when a client wants to create a new listener.
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
  struct GNUNET_SET_ListenMessage *msg = (struct GNUNET_SET_ListenMessage *) m;
  struct Listener *listener;

  if (NULL != get_listener (client))
  {
    GNUNET_break (0);
    GNUNET_SERVER_client_disconnect (client);
    return;
  }
  listener = GNUNET_new (struct Listener);
  listener->client = client;
  listener->client_mq = GNUNET_MQ_queue_for_server_client (client);
  listener->app_id = msg->app_id;
  listener->operation = ntohs (msg->operation);
  GNUNET_CONTAINER_DLL_insert_tail (listeners_head, listeners_tail, listener);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "new listener created (op %u, app %s)\n",
              listener->operation, GNUNET_h2s (&listener->app_id));
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Called when a client wants to remove an element
 * from the set it inhabits.
 *
 * @param cls unused
 * @param client client that sent the message
 * @param m message sent by the client
 */
static void
handle_client_remove (void *cls,
                      struct GNUNET_SERVER_Client *client,
                      const struct GNUNET_MessageHeader *m)
{
  struct Set *set;

  set = set_get (client);
  if (NULL == set)
  {
    GNUNET_break (0);
    GNUNET_SERVER_client_disconnect (client);
    return;
  }
  switch (set->operation)
  {
    case GNUNET_SET_OPERATION_UNION:
      _GSS_union_remove ((struct GNUNET_SET_ElementMessage *) m, set);
      break;
    case GNUNET_SET_OPERATION_INTERSECTION:
      //_GSS_intersection_remove ((struct GNUNET_SET_ElementMessage *) m, set);
      break;
    default:
      GNUNET_assert (0);
      break;
  }

  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}



/**
 * Called when the client wants to reject an operation
 * request from another peer.
 *
 * @param cls unused
 * @param client client that sent the message
 * @param m message sent by the client
 */
static void
handle_client_reject (void *cls,
                      struct GNUNET_SERVER_Client *client,
                      const struct GNUNET_MessageHeader *m)
{
  struct Incoming *incoming;
  struct GNUNET_SET_AcceptRejectMessage *msg = (struct GNUNET_SET_AcceptRejectMessage *) m;

  GNUNET_break (0 == ntohl (msg->request_id));

  incoming = get_incoming (ntohl (msg->accept_reject_id));
  if (NULL == incoming)
  {
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "peer request rejected by client\n");
  incoming_destroy (incoming);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}



/**
 * Called when a client wants to add an element to a
 * set it inhabits.
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

  set = set_get (client);
  if (NULL == set)
  {
    GNUNET_break (0);
    GNUNET_SERVER_client_disconnect (client);
    return;
  }
  switch (set->operation)
  {
    case GNUNET_SET_OPERATION_UNION:
      _GSS_union_add ((struct GNUNET_SET_ElementMessage *) m, set);
      break;
    case GNUNET_SET_OPERATION_INTERSECTION:
      //_GSS_intersection_add ((struct GNUNET_SET_ElementMessage *) m, set);
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

  set = set_get (client);
  if (NULL == set)
  {
    GNUNET_break (0);
    GNUNET_SERVER_client_disconnect (client);
    return;
  }


  switch (set->operation)
  {
    case GNUNET_SET_OPERATION_INTERSECTION:
      //_GSS_intersection_evaluate ((struct GNUNET_SET_EvaluateMessage *) m, set);
      break;
    case GNUNET_SET_OPERATION_UNION:
      _GSS_union_evaluate ((struct GNUNET_SET_EvaluateMessage *) m, set);
      break;
    default:
      GNUNET_assert (0);
      break;
  }

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
 * a set operation that came from a remote peer.
 *
 * @param cls unused
 * @param client the client
 * @param mh the message
 */
static void
handle_client_accept (void *cls,
                      struct GNUNET_SERVER_Client *client,
                      const struct GNUNET_MessageHeader *mh)
{
  struct Set *set;
  struct Incoming *incoming;
  struct GNUNET_SET_AcceptRejectMessage *msg = (struct GNUNET_SET_AcceptRejectMessage *) mh;

  incoming = get_incoming (ntohl (msg->accept_reject_id));

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "client accepting %u\n", ntohl (msg->accept_reject_id));

  if (NULL == incoming)
  {

    GNUNET_break (0);
    GNUNET_SERVER_client_disconnect (client);
    return;
  }

  set = set_get (client);

  if (NULL == set)
  {
    GNUNET_break (0);
    GNUNET_SERVER_client_disconnect (client);
    return;
  }

  switch (set->operation)
  {
    case GNUNET_SET_OPERATION_INTERSECTION:
      // _GSS_intersection_accept (msg, set, incoming);
      break;
    case GNUNET_SET_OPERATION_UNION:
      _GSS_union_accept (msg, set, incoming);
      break;
    default:
      GNUNET_assert (0);
      break;
  }

  /* note: _GSS_*_accept has to make sure the socket and mq are set to NULL,
   * otherwise they will be destroyed and disconnected */
  incoming_destroy (incoming);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
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
  if (NULL != mesh)
  {
    GNUNET_MESH_disconnect (mesh);
    mesh = NULL;
  }

  while (NULL != incoming_head)
  {
    incoming_destroy (incoming_head);
  }

  while (NULL != listeners_head)
  {
    listener_destroy (listeners_head);
  }

  while (NULL != sets_head)
  {
    set_destroy (sets_head);
  }

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "handled shutdown request\n");
}



/**
 * Signature of the main function of a task.
 *
 * @param cls closure
 * @param tc context information (why was this task triggered now)
 */
static void
incoming_timeout_cb (void *cls,
                     const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Incoming *incoming = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "remote peer timed out");
  incoming_destroy (incoming);
}


/**
 * Method called whenever another peer has added us to a tunnel
 * the other peer initiated.
 * Only called (once) upon reception of data with a message type which was
 * subscribed to in GNUNET_MESH_connect. A call to GNUNET_MESH_tunnel_destroy
 * causes te tunnel to be ignored and no further notifications are sent about
 * the same tunnel.
 *
 * @param cls closure
 * @param tunnel new handle to the tunnel
 * @param initiator peer that started the tunnel
 * @param port Port this tunnel is for.
 * @return initial tunnel context for the tunnel
 *         (can be NULL -- that's not an error)
 */
static void *
tunnel_new_cb (void *cls,
               struct GNUNET_MESH_Tunnel *tunnel,
               const struct GNUNET_PeerIdentity *initiator,
               uint32_t port)
{
  struct Incoming *incoming;
  struct TunnelContext *tc;

  GNUNET_assert (port == GNUNET_APPLICATION_TYPE_SET);
  tc = GNUNET_new (struct TunnelContext);
  incoming = GNUNET_new (struct Incoming);
  incoming->tc = tc;
  tc->peer = *initiator;
  tc->tunnel = tunnel;
  tc->mq = GNUNET_MESH_mq_create (tunnel);
  tc->data = incoming;
  tc->type = CONTEXT_INCOMING;
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_MINUTES, incoming_timeout_cb, incoming);
  GNUNET_CONTAINER_DLL_insert_tail (incoming_head, incoming_tail, incoming);

  return tc;
}


/**
 * Function called whenever a tunnel is destroyed.  Should clean up
 * any associated state.  This function is NOT called if the client has
 * explicitly asked for the tunnel to be destroyed using
 * GNUNET_MESH_tunnel_destroy. It must NOT call GNUNET_MESH_tunnel_destroy on
 * the tunnel.
 *
 * @param cls closure (set from GNUNET_MESH_connect)
 * @param tunnel connection to the other end (henceforth invalid)
 * @param tunnel_ctx place where local state associated
 *                   with the tunnel is stored
 */
static void
tunnel_end_cb (void *cls,
               const struct GNUNET_MESH_Tunnel *tunnel, void *tunnel_ctx)
{
  struct TunnelContext *ctx = tunnel_ctx;

  switch (ctx->type)
  {
    case CONTEXT_INCOMING:
      incoming_destroy ((struct Incoming *) ctx->data);
      break;
    case CONTEXT_OPERATION_UNION:
      _GSS_union_operation_destroy ((struct UnionEvaluateOperation *) ctx->data);
      break;
    case CONTEXT_OPERATION_INTERSECTION:
      GNUNET_assert (0);
      /* FIXME: cfuchs */
      break;
    default:
      GNUNET_assert (0);
  }

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
run (void *cls, struct GNUNET_SERVER_Handle *server,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  static const struct GNUNET_SERVER_MessageHandler server_handlers[] = {
    {handle_client_accept, NULL, GNUNET_MESSAGE_TYPE_SET_ACCEPT, 0},
    {handle_client_ack, NULL, GNUNET_MESSAGE_TYPE_SET_ACK, 0},
    {handle_client_add, NULL, GNUNET_MESSAGE_TYPE_SET_ADD, 0},
    {handle_client_create, NULL, GNUNET_MESSAGE_TYPE_SET_CREATE, 0},
    {handle_client_evaluate, NULL, GNUNET_MESSAGE_TYPE_SET_EVALUATE, 0},
    {handle_client_listen, NULL, GNUNET_MESSAGE_TYPE_SET_LISTEN, 0},
    {handle_client_reject, NULL, GNUNET_MESSAGE_TYPE_SET_REJECT, 0},
    {handle_client_remove, NULL, GNUNET_MESSAGE_TYPE_SET_REMOVE, 0},
    {NULL, NULL, 0, 0}
  };
  static const struct GNUNET_MESH_MessageHandler mesh_handlers[] = {
    {handle_p2p_operation_request,
      GNUNET_MESSAGE_TYPE_SET_P2P_OPERATION_REQUEST, 0},
    /* messages for the union operation */
    {_GSS_union_handle_p2p_message,
      GNUNET_MESSAGE_TYPE_SET_P2P_IBF, 0},
    {_GSS_union_handle_p2p_message,
      GNUNET_MESSAGE_TYPE_SET_P2P_ELEMENTS, 0},
    {_GSS_union_handle_p2p_message,
      GNUNET_MESSAGE_TYPE_SET_P2P_DONE, 0},
    {_GSS_union_handle_p2p_message,
      GNUNET_MESSAGE_TYPE_SET_P2P_ELEMENT_REQUESTS, 0},
    {_GSS_union_handle_p2p_message,
      GNUNET_MESSAGE_TYPE_SET_P2P_SE, 0},
    /* FIXME: messages for intersection operation */
    {NULL, 0, 0}
  };
  static const uint32_t mesh_ports[] = {GNUNET_APPLICATION_TYPE_SET, 0};

  configuration = cfg;
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
                                &shutdown_task, NULL);
  GNUNET_SERVER_disconnect_notify (server, &handle_client_disconnect, NULL);
  GNUNET_SERVER_add_handlers (server, server_handlers);

  mesh = GNUNET_MESH_connect (cfg, NULL, tunnel_new_cb, tunnel_end_cb,
                              mesh_handlers, mesh_ports);
  if (NULL == mesh)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "could not connect to mesh\n");
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "service started\n");
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
  ret = GNUNET_SERVICE_run (argc, argv, "set",
                            GNUNET_SERVICE_OPTION_NONE, &run, NULL);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "exit\n");
  return (GNUNET_OK == ret) ? 0 : 1;
}

