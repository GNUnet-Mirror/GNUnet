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
 * Peer that has connected to us, but is not yet evaluating a set operation.
 * Once the peer has sent a request, and the client has
 * accepted or rejected it, this information will be deleted.
 */
struct Incoming
{
  /**
   * Incoming peers are held in a linked list
   */
  struct Incoming *next;

  /**
   * Incoming peers are held in a linked list
   */
  struct Incoming *prev;

  /**
   * Detail information about the operation.
   * NULL as long as we did not receive the operation
   * request from the remote peer.
   */
  struct OperationSpecification *spec;

  /**
   * The identity of the requesting peer.  Needs to
   * be stored here as the op spec might not have been created yet.
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * Tunnel to the peer.
   */
  struct GNUNET_MESH_Tunnel *tunnel;

  /**
   * Unique request id for the request from
   * a remote peer, sent to the client, which will
   * accept or reject the request.
   * Set to '0' iff the request has not been
   * suggested yet.
   */
  uint32_t suggest_id;

  /**
   * Timeout task, if the incoming peer has not been accepted
   * after the timeout, it will be disconnected.
   */
  GNUNET_SCHEDULER_TaskIdentifier timeout_task;

  /**
   * Tunnel context, needs to be stored here as a client's accept will change
   * the tunnel context.
   */
  struct TunnelContext *tc;
};


/**
 * A listener is inhabited by a client, and
 * waits for evaluation requests from remote peers.
 */
struct Listener
{
  /**
   * Listeners are held in a doubly linked list.
   */
  struct Listener *next;

  /**
   * Listeners are held in a doubly linked list.
   */
  struct Listener *prev;

  /**
   * Client that owns the listener.
   * Only one client may own a listener.
   */
  struct GNUNET_SERVER_Client *client;

  /**
   * Message queue for the client
   */
  struct GNUNET_MQ_Handle *client_mq;

  /**
   * The type of the operation.
   */
  enum GNUNET_SET_OperationType operation;

  /**
   * Application ID for the operation, used to distinguish
   * multiple operations of the same type with the same peer.
   */
  struct GNUNET_HashCode app_id;
};


/**
 * Configuration of our local peer.
 */
static const struct GNUNET_CONFIGURATION_Handle *configuration;

/**
 * Handle to the mesh service, used
 * to listen for and connect to remote peers.
 */
static struct GNUNET_MESH_Handle *mesh;

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
static uint32_t suggest_id = 1;


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
 * Get the listener associated with the given client, if any.
 *
 * @param client the client
 * @return listener associated with the client, NULL
 *         if there isn't any
 */
static struct Listener *
listener_get (struct GNUNET_SERVER_Client *client)
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
    if (incoming->suggest_id == id)
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
  /* If the client is not dead yet, destroy it.
   * The client's destroy callback will destroy the listener again. */
  if (NULL != listener->client)
  {
    struct GNUNET_SERVER_Client *client = listener->client;
    listener->client = NULL;
    GNUNET_SERVER_client_disconnect (client);
    return;
  }
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
  /* If the client is not dead yet, destroy it.
   * The client's destroy callback will destroy the set again. */
  if (NULL != set->client)
  {
    struct GNUNET_SERVER_Client *client = set->client;
    set->client = NULL;
    GNUNET_SERVER_client_disconnect (client);
    return;
  }
  if (NULL != set->client_mq)
  {
    GNUNET_MQ_destroy (set->client_mq);
    set->client_mq = NULL;
  }
  GNUNET_assert (NULL != set->state);
  set->vt->destroy_set (set->state);
  set->state = NULL;
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

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "client disconnected, cleaning up\n");

  set = set_get (client);
  if (NULL != set)
  {
    set->client = NULL;
    set_destroy (set);
  }
  listener = listener_get (client);
  if (NULL != listener)
  {
    listener->client = NULL;
    listener_destroy (listener);
  }
}


/**
 * Destroy an incoming request from a remote peer
 *
 * @param incoming remote request to destroy
 */
static void
incoming_destroy (struct Incoming *incoming)
{
  GNUNET_CONTAINER_DLL_remove (incoming_head, incoming_tail, incoming);
  if (NULL != incoming->tunnel)
  {
    struct GNUNET_MESH_Tunnel *t = incoming->tunnel;
    incoming->tunnel = NULL;
    GNUNET_MESH_tunnel_destroy (t);
    return;
  }
  GNUNET_free (incoming);
}


static struct Listener *
listener_get_by_target (enum GNUNET_SET_OperationType op,
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


/**
 * Suggest the given request to the listener,
 * who can accept or reject the request.
 *
 * @param incoming the incoming peer with the request to suggest
 * @param listener the listener to suggest the request to
 */
static void
incoming_suggest (struct Incoming *incoming, struct Listener *listener)
{
  struct GNUNET_MQ_Envelope *mqm;
  struct GNUNET_SET_RequestMessage *cmsg;

  GNUNET_assert (0 == incoming->suggest_id);
  GNUNET_assert (NULL != incoming->spec);
  incoming->suggest_id = suggest_id++;

  GNUNET_SCHEDULER_cancel (incoming->timeout_task);
  mqm = GNUNET_MQ_msg_nested_mh (cmsg, GNUNET_MESSAGE_TYPE_SET_REQUEST,
                                 incoming->spec->context_msg);
  GNUNET_assert (NULL != mqm);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "suggesting request with accept id %u\n", incoming->suggest_id);
  cmsg->accept_id = htonl (incoming->suggest_id);
  cmsg->peer_id = incoming->spec->peer;
  GNUNET_MQ_send (listener->client_mq, mqm);

}


/**
 * Handle a request for a set operation from
 * another peer.
 *
 * @param op the operation state
 * @param mh the received message
 * @return GNUNET_OK if the tunnel should be kept alive,
 *         GNUNET_SYSERR to destroy the tunnel
 */
static int
handle_incoming_msg (struct OperationState *op,
                     const struct GNUNET_MessageHeader *mh)
{
  struct Incoming *incoming = (struct Incoming *) op;
  const struct OperationRequestMessage *msg = (const struct OperationRequestMessage *) mh;
  struct Listener *listener;
  struct OperationSpecification *spec;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "got op request\n");

  if (GNUNET_MESSAGE_TYPE_SET_P2P_OPERATION_REQUEST != ntohs (mh->type))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }

  if (NULL != incoming->spec)
  {
    /* double operation request */
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }

  spec = GNUNET_new (struct OperationSpecification);
  spec->context_msg = GNUNET_MQ_extract_nested_mh (msg);
  if (NULL != spec->context_msg)
    spec->context_msg = GNUNET_copy_message (spec->context_msg);
  spec->operation = ntohl (msg->operation);
  spec->app_id = msg->app_id;
  spec->salt = ntohl (msg->salt);
  spec->peer = incoming->peer;

  incoming->spec = spec;

  if ( (NULL != spec->context_msg) &&
       (ntohs (spec->context_msg->size) > GNUNET_SET_CONTEXT_MESSAGE_MAX_SIZE) )
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "received P2P operation request (op %u, app %s)\n",
              ntohs (msg->operation), GNUNET_h2s (&msg->app_id));
  listener = listener_get_by_target (ntohs (msg->operation), &msg->app_id);
  if (NULL == listener)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "no listener matches incoming request, waiting with timeout\n");
    return GNUNET_OK;
  }
  incoming_suggest (incoming, listener);
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

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "client created new set (operation %u)\n",
              ntohs (msg->operation));

  if (NULL != set_get (client))
  {
    GNUNET_break (0);
    GNUNET_SERVER_client_disconnect (client);
    return;
  }

  set = NULL;
  set = GNUNET_new (struct Set);

  switch (ntohs (msg->operation))
  {
    case GNUNET_SET_OPERATION_INTERSECTION:
      // FIXME
      break;
    case GNUNET_SET_OPERATION_UNION:
      set->vt = _GSS_union_vt ();
      break;
    default:
      GNUNET_break (0);
      GNUNET_SERVER_client_disconnect (client);
      return;
  }

  set->state = set->vt->create ();
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
  struct Incoming *incoming;

  if (NULL != listener_get (client))
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
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "new listener created (op %u, app %s)\n",
              listener->operation, GNUNET_h2s (&listener->app_id));
  for (incoming = incoming_head; NULL != incoming; incoming = incoming->next)
  {
    if ( (NULL == incoming->spec) ||
         (0 != incoming->suggest_id) )
      continue;
    if (listener->operation != incoming->spec->operation)
      continue;
    if (0 != GNUNET_CRYPTO_hash_cmp (&listener->app_id, &incoming->spec->app_id))
      continue;
    incoming_suggest (incoming, listener);
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
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "peer request rejected by client\n");
  GNUNET_MESH_tunnel_destroy (incoming->tunnel);
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
handle_client_add_remove (void *cls,
                          struct GNUNET_SERVER_Client *client,
                          const struct GNUNET_MessageHeader *m)
{
  struct Set *set;
  const struct GNUNET_SET_ElementMessage *msg;
  struct GNUNET_SET_Element el;

  set = set_get (client);
  if (NULL == set)
  {
    GNUNET_break (0);
    GNUNET_SERVER_client_disconnect (client);
    return;
  }
  msg = (const struct GNUNET_SET_ElementMessage *) m;
  el.size = ntohs (m->size) - sizeof *msg;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "client ins/rem element of size %u\n", el.size);
  el.data = &msg[1];
  if (GNUNET_MESSAGE_TYPE_SET_REMOVE == ntohs (m->type))
    set->vt->remove (set->state, &el);
  else
    set->vt->add (set->state, &el);
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
  struct TunnelContext *tc;
  struct GNUNET_MESH_Tunnel *tunnel;
  struct GNUNET_SET_EvaluateMessage *msg;
  struct OperationSpecification *spec;

  set = set_get (client);
  if (NULL == set)
  {
    GNUNET_break (0);
    GNUNET_SERVER_client_disconnect (client);
    return;
  }

  msg = (struct GNUNET_SET_EvaluateMessage *) m;
  tc = GNUNET_new (struct TunnelContext);
  spec = GNUNET_new (struct OperationSpecification);
  spec->operation = set->operation;
  spec->app_id = msg->app_id;
  spec->salt = ntohl (msg->salt);
  spec->peer = msg->target_peer;
  spec->set = set;
  spec->client_request_id = ntohl (msg->request_id);

  tunnel = GNUNET_MESH_tunnel_create (mesh, tc, &msg->target_peer,
                                      GNUNET_APPLICATION_TYPE_SET,
                                      GNUNET_YES,
                                      GNUNET_YES);

  set->vt->evaluate (spec, tunnel, tc);

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
handle_client_cancel (void *cls,
                      struct GNUNET_SERVER_Client *client,
                      const struct GNUNET_MessageHeader *mh)
{
  const struct GNUNET_SET_CancelMessage *msg =
      (const struct GNUNET_SET_CancelMessage *) mh;
  struct Set *set;

  set = set_get (client);
  if (NULL == set)
  {
    GNUNET_break (0);
    GNUNET_SERVER_client_disconnect (client);
    return;
  }
  /* FIXME: maybe cancel should return success/error code? */
  set->vt->cancel (set->state, ntohl (msg->request_id));
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

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "client accepting %u\n", ntohl (msg->accept_reject_id));

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

  incoming->spec->set = set;
  incoming->spec->client_request_id = ntohl (msg->request_id);
  set->vt->accept (incoming->spec, incoming->tunnel, incoming->tc);
  /* tunnel ownership goes to operation */
  incoming->tunnel = NULL;
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
  while (NULL != incoming_head)
    incoming_destroy (incoming_head);

  while (NULL != listeners_head)
    listener_destroy (listeners_head);

  while (NULL != sets_head)
    set_destroy (sets_head);


  /* it's important to destroy mesh at the end, as tunnels
   * must be destroyed first! */
  if (NULL != mesh)
  {
    GNUNET_MESH_disconnect (mesh);
    mesh = NULL;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "handled shutdown request\n");
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

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "remote peer timed out\n");
  incoming_destroy (incoming);
}


static void
handle_incoming_disconnect (struct OperationState *op_state)
{
  struct Incoming *incoming = (struct Incoming *) op_state;
  if (NULL == incoming->tunnel)
    return;

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
  static const struct SetVT incoming_vt = {
    .msg_handler = handle_incoming_msg,
    .peer_disconnect = handle_incoming_disconnect
  };

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "new incoming tunnel\n");

  GNUNET_assert (port == GNUNET_APPLICATION_TYPE_SET);
  incoming = GNUNET_new (struct Incoming);
  incoming->peer = *initiator;
  incoming->tunnel = tunnel;
  incoming->tc = GNUNET_new (struct TunnelContext);;
  incoming->tc->vt = &incoming_vt;
  incoming->tc->op = (struct OperationState *) incoming;
  incoming->timeout_task = 
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_MINUTES, incoming_timeout_cb, incoming);
  GNUNET_CONTAINER_DLL_insert_tail (incoming_head, incoming_tail, incoming);

  return incoming->tc;
}


/**
 * Function called whenever a tunnel is destroyed.  Should clean up
 * any associated state.
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

  ctx->vt->peer_disconnect (ctx->op);
  /* mesh will never call us with the context again! */
  GNUNET_free (tunnel_ctx);
}


/**
 * Functions with this signature are called whenever a message is
 * received.
 * 
 * Each time the function must call GNUNET_MESH_receive_done on the tunnel
 * in order to receive the next message. This doesn't need to be immediate:
 * can be delayed if some processing is done on the message.
 *
 * @param cls Closure (set from GNUNET_MESH_connect).
 * @param tunnel Connection to the other end.
 * @param tunnel_ctx Place to store local state associated with the tunnel.
 * @param message The actual message.
 * 
 * @return GNUNET_OK to keep the tunnel open,
 *         GNUNET_SYSERR to close it (signal serious error).
 */
static int
dispatch_p2p_message (void *cls,
                      struct GNUNET_MESH_Tunnel *tunnel,
                      void **tunnel_ctx,
                      const struct GNUNET_MessageHeader *message)
{
  struct TunnelContext *tc = *tunnel_ctx;
  int ret;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "dispatching mesh message\n");
  ret = tc->vt->msg_handler (tc->op, message);
  GNUNET_MESH_receive_done (tunnel);

  return ret;
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
    {handle_client_accept, NULL, GNUNET_MESSAGE_TYPE_SET_ACCEPT,
        sizeof (struct GNUNET_SET_AcceptRejectMessage)},
    {handle_client_ack, NULL, GNUNET_MESSAGE_TYPE_SET_ACK, 0},
    {handle_client_add_remove, NULL, GNUNET_MESSAGE_TYPE_SET_ADD, 0},
    {handle_client_create, NULL, GNUNET_MESSAGE_TYPE_SET_CREATE,
        sizeof (struct GNUNET_SET_CreateMessage)},
    {handle_client_evaluate, NULL, GNUNET_MESSAGE_TYPE_SET_EVALUATE, 0},
    {handle_client_listen, NULL, GNUNET_MESSAGE_TYPE_SET_LISTEN,
        sizeof (struct GNUNET_SET_ListenMessage)},
    {handle_client_reject, NULL, GNUNET_MESSAGE_TYPE_SET_REJECT,
        sizeof (struct GNUNET_SET_AcceptRejectMessage)},
    {handle_client_add_remove, NULL, GNUNET_MESSAGE_TYPE_SET_REMOVE, 0},
    {handle_client_cancel, NULL, GNUNET_MESSAGE_TYPE_SET_REMOVE,
        sizeof (struct GNUNET_SET_CancelMessage)},
    {NULL, NULL, 0, 0}
  };
  static const struct GNUNET_MESH_MessageHandler mesh_handlers[] = {
    {dispatch_p2p_message, GNUNET_MESSAGE_TYPE_SET_P2P_OPERATION_REQUEST, 0},
    {dispatch_p2p_message, GNUNET_MESSAGE_TYPE_SET_P2P_IBF, 0},
    {dispatch_p2p_message, GNUNET_MESSAGE_TYPE_SET_P2P_ELEMENTS, 0},
    {dispatch_p2p_message, GNUNET_MESSAGE_TYPE_SET_P2P_DONE, 0},
    {dispatch_p2p_message, GNUNET_MESSAGE_TYPE_SET_P2P_ELEMENT_REQUESTS, 0},
    {dispatch_p2p_message, GNUNET_MESSAGE_TYPE_SET_P2P_SE, 0},
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

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "started\n");
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

