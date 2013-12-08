/*
      This file is part of GNUnet
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

/**
 * @file set/gnunet-service-set.c
 * @brief two-peer set operations
 * @author Florian Dold
 */
#include "gnunet-service-set.h"
#include "set_protocol.h"


/**
 * State of an operation where the peer has connected to us, but is not yet
 * evaluating a set operation.  Once the peer has sent a concrete request, and
 * the client has accepted or rejected it, this information will be deleted
 * and replaced by the real set operation state.
 */
struct OperationState
{
  /**
   * The identity of the requesting peer.  Needs to
   * be stored here as the op spec might not have been created yet.
   */
  struct GNUNET_PeerIdentity peer;

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
static struct Operation *incoming_head;

/**
 * Incoming sockets from remote peers are
 * held in a doubly linked list.
 */
static struct Operation *incoming_tail;

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
static struct Operation *
get_incoming (uint32_t id)
{
  struct Operation *op;

  for (op = incoming_head; NULL != op; op = op->next)
    if (op->state->suggest_id == id)
      return op;
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
 * Collect and destroy elements that are not needed anymore, because
 * their lifetime (as determined by their generation) does not overlap with any active
 * set operation.
 *
 * We hereby replace the old element hashmap with a new one, instead of removing elements.
 */
void
collect_generation_garbage (struct Set *set)
{
  struct GNUNET_CONTAINER_MultiHashMapIterator *iter;
  struct ElementEntry *ee;
  struct GNUNET_CONTAINER_MultiHashMap *new_elements;
  int res;
  struct Operation *op;

  new_elements = GNUNET_CONTAINER_multihashmap_create (1, GNUNET_NO);
  iter = GNUNET_CONTAINER_multihashmap_iterator_create (set->elements);
  while (GNUNET_OK ==
         (res = GNUNET_CONTAINER_multihashmap_iterator_next (iter, NULL, (const void **) &ee)))
  {
    if (GNUNET_NO == ee->removed)
      goto still_needed;
    for (op = set->ops_head; NULL != op; op = op->next)
      if ((op->generation_created >= ee->generation_added) &&
          (op->generation_created < ee->generation_removed))
        goto still_needed;
    GNUNET_free (ee);
    continue;
still_needed:
    // we don't expect collisions, thus the replace option
    GNUNET_CONTAINER_multihashmap_put (new_elements, &ee->element_hash, ee,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_REPLACE);
  }
  GNUNET_CONTAINER_multihashmap_iterator_destroy (iter);
  GNUNET_CONTAINER_multihashmap_destroy (set->elements);
  set->elements = new_elements;
}


/**
 * Destroy the given operation.  Call the implementation-specific cancel function
 * of the operation.  Disconnects from the remote peer.
 * Does not disconnect the client, as there may be multiple operations per set.
 *
 * @param op operation to destroy
 */
void
_GSS_operation_destroy (struct Operation *op)
{
  struct Set *set;
  struct GNUNET_MESH_Channel *channel;

  if (NULL == op->vt)
    return;

  set = op->spec->set;

  GNUNET_assert (GNUNET_NO == op->is_incoming);
  GNUNET_assert (NULL != op->spec);
  GNUNET_CONTAINER_DLL_remove (op->spec->set->ops_head,
                               op->spec->set->ops_tail,
                               op);

  op->vt->cancel (op);
  op->vt = NULL;

  if (NULL != op->spec)
  {
    if (NULL != op->spec->context_msg)
    {
      GNUNET_free (op->spec->context_msg);
      op->spec->context_msg = NULL;
    }
    GNUNET_free (op->spec);
    op->spec = NULL;
  }

  if (NULL != op->mq)
  {
    GNUNET_MQ_destroy (op->mq);
    op->mq = NULL;
  }

  if (NULL != (channel = op->channel))
  {
    op->channel = NULL;
    GNUNET_MESH_channel_destroy (channel);
  }

  collect_generation_garbage (set);

  /* We rely on the channel end handler to free 'op'. When 'op->channel' was NULL,
   * there was a channel end handler that will free 'op' on the call stack. */
}


/**
 * Iterator over hash map entries to free
 * element entries.
 *
 * @param cls closure
 * @param key current key code
 * @param value a `struct ElementEntry *` to be free'd
 * @return #GNUNET_YES if we should continue to
 *         iterate,
 *         #GNUNET_NO if not.
 */
static int
destroy_elements_iterator (void *cls,
                           const struct GNUNET_HashCode * key,
                           void *value)
{
  struct ElementEntry *ee = value;

  GNUNET_free (ee);
  return GNUNET_YES;
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
   * The client's destroy callback will destroy the set again.
   * We do this so that the channel end handler still has a valid set handle
   * to destroy. */
  if (NULL != set->client)
  {
    struct GNUNET_SERVER_Client *client = set->client;
    set->client = NULL;
    GNUNET_SERVER_client_disconnect (client);
    return;
  }
  GNUNET_assert (NULL != set->state);
  while (NULL != set->ops_head)
    _GSS_operation_destroy (set->ops_head);
  set->vt->destroy_set (set->state);
  set->state = NULL;
  if (NULL != set->client_mq)
  {
    GNUNET_MQ_destroy (set->client_mq);
    set->client_mq = NULL;
  }
  if (NULL != set->iter)
  {
    GNUNET_CONTAINER_multihashmap_iterator_destroy (set->iter);
    set->iter = NULL;
  }
  GNUNET_CONTAINER_DLL_remove (sets_head, sets_tail, set);
  if (NULL != set->elements)
  {
    // free all elements in the hashtable, before destroying the table
    GNUNET_CONTAINER_multihashmap_iterate (set->elements,
                                           destroy_elements_iterator, NULL);
    GNUNET_CONTAINER_multihashmap_destroy (set->elements);
    set->elements = NULL;
  }
  GNUNET_free (set);
}


/**
 * Clean up after a client has disconnected
 *
 * @param cls closure, unused
 * @param client the client to clean up after
 */
static void
handle_client_disconnect (void *cls, struct GNUNET_SERVER_Client *client)
{
  struct Set *set;
  struct Listener *listener;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "client disconnected, cleaning up\n");
  set = set_get (client);
  if (NULL != set)
  {
    set->client = NULL;
    set_destroy (set);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "(client's set destroyed)\n");
  }
  listener = listener_get (client);
  if (NULL != listener)
  {
    listener->client = NULL;
    listener_destroy (listener);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "(client's listener destroyed)\n");
  }
}


/**
 * Destroy an incoming request from a remote peer
 *
 * @param incoming remote request to destroy
 */
static void
incoming_destroy (struct Operation *incoming)
{
  GNUNET_CONTAINER_DLL_remove (incoming_head, incoming_tail, incoming);
  if (GNUNET_SCHEDULER_NO_TASK != incoming->state->timeout_task)
  {
    GNUNET_SCHEDULER_cancel (incoming->state->timeout_task);
    incoming->state->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  }
  GNUNET_free (incoming->state);
}


/**
 * remove & free state of the operation from the incoming list
 *
 * @param incoming the element to remove
 */
static void
incoming_retire (struct Operation *incoming)
{
  incoming->is_incoming = GNUNET_NO;
  GNUNET_free (incoming->state);
  incoming->state = NULL;
  GNUNET_CONTAINER_DLL_remove (incoming_head, incoming_tail, incoming);
}


/**
 * Find a listener that is interested in the given operation type
 * and application id.
 *
 * @param op operation type to look for
 * @param app_id application id to look for
 * @return a matching listener, or NULL if no listener matches the
 *         given operation and application id
 */
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
 * Suggest the given request to the listener. The listening client can then
 * accept or reject the remote request.
 *
 * @param incoming the incoming peer with the request to suggest
 * @param listener the listener to suggest the request to
 */
static void
incoming_suggest (struct Operation *incoming, struct Listener *listener)
{
  struct GNUNET_MQ_Envelope *mqm;
  struct GNUNET_SET_RequestMessage *cmsg;

  GNUNET_assert (NULL != incoming->spec);
  GNUNET_assert (0 == incoming->state->suggest_id);
  incoming->state->suggest_id = suggest_id++;

  GNUNET_assert (GNUNET_SCHEDULER_NO_TASK != incoming->state->timeout_task);
  GNUNET_SCHEDULER_cancel (incoming->state->timeout_task);
  incoming->state->timeout_task = GNUNET_SCHEDULER_NO_TASK;

  mqm = GNUNET_MQ_msg_nested_mh (cmsg, GNUNET_MESSAGE_TYPE_SET_REQUEST,
                                 incoming->spec->context_msg);
  GNUNET_assert (NULL != mqm);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "suggesting request with accept id %u\n",
              incoming->state->suggest_id);
  cmsg->accept_id = htonl (incoming->state->suggest_id);
  cmsg->peer_id = incoming->spec->peer;
  GNUNET_MQ_send (listener->client_mq, mqm);
}


/**
 * Handle a request for a set operation from
 * another peer.
 *
 * This msg is expected as the first and only msg handled through the
 * non-operation bound virtual table, acceptance of this operation replaces
 * our virtual table and subsequent msgs would be routed differently.
 *
 * @param op the operation state
 * @param mh the received message
 * @return #GNUNET_OK if the channel should be kept alive,
 *         #GNUNET_SYSERR to destroy the channel
 */
static int
handle_incoming_msg (struct Operation *op,
                     const struct GNUNET_MessageHeader *mh)
{
  const struct OperationRequestMessage *msg = (const struct OperationRequestMessage *) mh;
  struct Listener *listener;
  struct OperationSpecification *spec;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "got op request\n");

  if (GNUNET_MESSAGE_TYPE_SET_P2P_OPERATION_REQUEST != ntohs (mh->type))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }

  /* double operation request */
  if (NULL != op->spec)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }

  spec = GNUNET_new (struct OperationSpecification);
  spec->context_msg = GNUNET_MQ_extract_nested_mh (msg);
  // for simplicity we just backup the context msg instead of rebuilding it later on
  if (NULL != spec->context_msg)
    spec->context_msg = GNUNET_copy_message (spec->context_msg);
  spec->operation = ntohl (msg->operation);
  spec->app_id = msg->app_id;
  spec->salt = ntohl (msg->salt);
  spec->peer = op->state->peer;
  spec->remote_element_count = ntohl (msg->element_count);

  op->spec = spec;

  if ( (NULL != spec->context_msg) &&
       (ntohs (spec->context_msg->size) > GNUNET_SET_CONTEXT_MESSAGE_MAX_SIZE) )
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "received P2P operation request (op %u, app %s)\n",
              ntohl (msg->operation), GNUNET_h2s (&msg->app_id));
  listener = listener_get_by_target (ntohl (msg->operation), &msg->app_id);
  if (NULL == listener)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "no listener matches incoming request, waiting with timeout\n");
    return GNUNET_OK;
  }
  incoming_suggest (op, listener);
  return GNUNET_OK;
}


/**
 * Send the next element of a set to the set's client.  The next element is given by
 * the set's current hashmap iterator.  The set's iterator will be set to NULL if there
 * are no more elements in the set.  The caller must ensure that the set's iterator is
 * valid.
 *
 * @param set set that should send its next element to its client
 */
static void
send_client_element (struct Set *set)
{
  int ret;
  struct ElementEntry *ee;
  struct GNUNET_MQ_Envelope *ev;

  GNUNET_assert (NULL != set->iter);
  ret = GNUNET_CONTAINER_multihashmap_iterator_next (set->iter, NULL, (const void **) &ee);
  if (GNUNET_NO == ret)
  {
    ev = GNUNET_MQ_msg_header (GNUNET_MESSAGE_TYPE_SET_ITER_DONE);
    GNUNET_CONTAINER_multihashmap_iterator_destroy (set->iter);
    set->iter = NULL;
  }
  else
  {
    struct GNUNET_SET_IterResponseMessage *msg;

    GNUNET_assert (NULL != ee);
    ev = GNUNET_MQ_msg_extra (msg, ee->element.size, GNUNET_MESSAGE_TYPE_SET_ITER_ELEMENT);
    memcpy (&msg[1], ee->element.data, ee->element.size);
    msg->element_type = ee->element.type;
  }
  GNUNET_MQ_send (set->client_mq, ev);
}


/**
 * Called when a client wants to iterate the elements of a set.
 *
 * @param cls unused
 * @param client client that sent the message
 * @param m message sent by the client
 */
static void
handle_client_iterate (void *cls,
                       struct GNUNET_SERVER_Client *client,
                       const struct GNUNET_MessageHeader *m)
{
  struct Set *set;

  // iterate over a non existing set
  set = set_get (client);
  if (NULL == set)
  {
    GNUNET_break (0);
    GNUNET_SERVER_client_disconnect (client);
    return;
  }

  // only one concurrent iterate-action per set
  if (NULL != set->iter)
  {
    GNUNET_break (0);
    GNUNET_SERVER_client_disconnect (client);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "iterating union set with %u elements\n",
              GNUNET_CONTAINER_multihashmap_size (set->elements));
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
  set->iter = GNUNET_CONTAINER_multihashmap_iterator_create (set->elements);
  send_client_element (set);
}


/**
 * Called when a client wants to create a new set.
 *
 * @param cls unused
 * @param client client that sent the message
 * @param m message sent by the client
 */
static void
handle_client_create_set (void *cls,
                          struct GNUNET_SERVER_Client *client,
                          const struct GNUNET_MessageHeader *m)
{
  const struct GNUNET_SET_CreateMessage *msg;
  struct Set *set;

  msg = (const struct GNUNET_SET_CreateMessage *) m;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "client created new set (operation %u)\n",
              ntohs (msg->operation));

  // max. one set per client!
  if (NULL != set_get (client))
  {
    GNUNET_break (0);
    GNUNET_SERVER_client_disconnect (client);
    return;
  }

  set = GNUNET_new (struct Set);

  switch (ntohs (msg->operation))
  {
  case GNUNET_SET_OPERATION_INTERSECTION:
    // FIXME: implement intersection vt
    // set->vt = _GSS_intersection_vt ();
    break;
  case GNUNET_SET_OPERATION_UNION:
    set->vt = _GSS_union_vt ();
    break;
  default:
    GNUNET_free (set);
    GNUNET_break (0);
    GNUNET_SERVER_client_disconnect (client);
    return;
  }

  set->state = set->vt->create ();
  set->elements = GNUNET_CONTAINER_multihashmap_create (1, GNUNET_YES);
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
  const struct GNUNET_SET_ListenMessage *msg;
  struct Listener *listener;
  struct Operation *op;

  msg = (const struct GNUNET_SET_ListenMessage *) m;
  /* max. one per client! */
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
  listener->operation = ntohl (msg->operation);
  GNUNET_CONTAINER_DLL_insert_tail (listeners_head, listeners_tail, listener);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "new listener created (op %u, app %s)\n",
              listener->operation,
              GNUNET_h2s (&listener->app_id));

  /* check for incoming requests the listener is interested in */
  for (op = incoming_head; NULL != op; op = op->next)
  {
    if (NULL == op->spec)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "request has no spec yet\n");
      continue;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "considering (op: %u, app: %s, suggest: %u)\n",
                op->spec->operation,
                GNUNET_h2s (&op->spec->app_id),
                op->state->suggest_id);

    /* don't consider the incoming request if it has been already suggested to a listener */
    if (0 != op->state->suggest_id)
      continue;
    if (listener->operation != op->spec->operation)
      continue;
    if (0 != GNUNET_CRYPTO_hash_cmp (&listener->app_id, &op->spec->app_id))
      continue;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "request suggested\n");
    incoming_suggest (op, listener);
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "considered all incoming requests\n");
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Called when the listening client rejects an operation
 * request by another peer.
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
  struct Operation *incoming;
  const struct GNUNET_SET_AcceptRejectMessage *msg;

  msg = (const struct GNUNET_SET_AcceptRejectMessage *) m;
  GNUNET_break (0 == ntohl (msg->request_id));

  // no matching incoming operation for this reject
  incoming = get_incoming (ntohl (msg->accept_reject_id));
  if (NULL == incoming)
  {
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "peer request rejected by client\n");

  GNUNET_MESH_channel_destroy (incoming->channel);
  //channel destruction handler called immediately upon destruction
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Called when a client wants to add/remove an element to/from a
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
  struct ElementEntry *ee;

  // client without a set requested an operation
  set = set_get (client);
  if (NULL == set)
  {
    GNUNET_break (0);
    GNUNET_SERVER_client_disconnect (client);
    return;
  }
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
  msg = (const struct GNUNET_SET_ElementMessage *) m;
  el.size = ntohs (m->size) - sizeof *msg;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "client ins/rem element of size %u\n", el.size);
  el.data = &msg[1];
  if (GNUNET_MESSAGE_TYPE_SET_REMOVE == ntohs (m->type))
  {
    struct GNUNET_HashCode hash;

    GNUNET_CRYPTO_hash (el.data, el.size, &hash);
    ee = GNUNET_CONTAINER_multihashmap_get (set->elements, &hash);
    if (NULL == ee)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "client tried to remove non-existing element\n");
      return;
    }
    if (GNUNET_YES == ee->removed)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "client tried to remove element twice\n");
      return;
    }
    ee->removed = GNUNET_YES;
    ee->generation_removed = set->current_generation;
    set->vt->remove (set->state, ee);
  }
  else
  {
    struct ElementEntry *ee_dup;

    ee = GNUNET_malloc (el.size + sizeof *ee);
    ee->element.size = el.size;
    memcpy (&ee[1], el.data, el.size);
    ee->element.data = &ee[1];
    ee->generation_added = set->current_generation;
    ee->remote = GNUNET_NO;
    GNUNET_CRYPTO_hash (ee->element.data, el.size, &ee->element_hash);
    ee_dup = GNUNET_CONTAINER_multihashmap_get (set->elements,
                                                &ee->element_hash);
    if (NULL != ee_dup)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "element inserted twice, ignoring\n");
      GNUNET_free (ee);
      return;
    }
    GNUNET_CONTAINER_multihashmap_put (set->elements, &ee->element_hash, ee,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
    set->vt->add (set->state, ee);
  }
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
  const struct GNUNET_SET_EvaluateMessage *msg;
  struct OperationSpecification *spec;
  struct Operation *op;

  set = set_get (client);
  if (NULL == set)
  {
    GNUNET_break (0);
    GNUNET_SERVER_client_disconnect (client);
    return;
  }

  msg = (const struct GNUNET_SET_EvaluateMessage *) m;
  spec = GNUNET_new (struct OperationSpecification);
  spec->operation = set->operation;
  spec->app_id = msg->app_id;
  spec->salt = ntohl (msg->salt);
  spec->peer = msg->target_peer;
  spec->set = set;
  spec->result_mode = ntohs (msg->result_mode);
  spec->client_request_id = ntohl (msg->request_id);
  spec->context_msg = GNUNET_MQ_extract_nested_mh (msg);

  // for simplicity we just backup the context msg instead of rebuilding it later on
  if (NULL != spec->context_msg)
    spec->context_msg = GNUNET_copy_message (spec->context_msg);

  op = GNUNET_new (struct Operation);
  op->spec = spec;
  op->generation_created = set->current_generation++;
  op->vt = set->vt;
  GNUNET_CONTAINER_DLL_insert (set->ops_head, set->ops_tail, op);

  op->channel = GNUNET_MESH_channel_create (mesh, op, &msg->target_peer,
                                          GNUNET_APPLICATION_TYPE_SET,
                                          GNUNET_MESH_OPTION_RELIABLE);

  op->mq = GNUNET_MESH_mq_create (op->channel);

  set->vt->evaluate (op);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Handle an ack from a client, and send the next element.
 *
 * @param cls unused
 * @param client the client
 * @param m the message
 */
static void
handle_client_iter_ack (void *cls,
                   struct GNUNET_SERVER_Client *client,
                   const struct GNUNET_MessageHeader *m)
{
  struct Set *set;

  // client without a set requested an operation
  set = set_get (client);
  if (NULL == set)
  {
    GNUNET_break (0);
    GNUNET_SERVER_client_disconnect (client);
    return;
  }

  // client sent an ack, but we were not expecting one
  if (NULL == set->iter)
  {
    GNUNET_break (0);
    GNUNET_SERVER_client_disconnect (client);
    return;
  }

  GNUNET_SERVER_receive_done (client, GNUNET_OK);
  send_client_element (set);
}


/**
 * Handle a request from the client to
 * cancel a running set operation.
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
  struct Operation *op;
  int found;

  // client without a set requested an operation
  set = set_get (client);
  if (NULL == set)
  {
    GNUNET_break (0);
    GNUNET_SERVER_client_disconnect (client);
    return;
  }
  found = GNUNET_NO;
  for (op = set->ops_head; NULL != op; op = op->next)
  {
    if (op->spec->client_request_id == msg->request_id)
    {
      found = GNUNET_YES;
      break;
    }
  }

  if (GNUNET_NO == found)
  {
    GNUNET_break (0);
    GNUNET_SERVER_client_disconnect (client);
    return;
  }

  _GSS_operation_destroy (op);
}


/**
 * Handle a request from the client to accept
 * a set operation that came from a remote peer.
 * We forward the accept to the associated operation for handling
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
  const struct GNUNET_SET_AcceptRejectMessage *msg;
  struct Operation *op;

  msg = (const struct GNUNET_SET_AcceptRejectMessage *) mh;
  op = get_incoming (ntohl (msg->accept_reject_id));

  // incoming operation does not exist
  if (NULL == op)
  {
    GNUNET_break (0);
    GNUNET_SERVER_client_disconnect (client);
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "client accepting %u\n",
              ntohl (msg->accept_reject_id));

  GNUNET_assert (GNUNET_YES == op->is_incoming);

  // client without a set requested an operation
  set = set_get (client);

  if (NULL == set)
  {
    GNUNET_break (0);
    GNUNET_SERVER_client_disconnect (client);
    return;
  }

  op->spec->set = set;

  incoming_retire (op);

  GNUNET_assert (NULL != op->spec->set);
  GNUNET_assert (NULL != op->spec->set->vt);

  GNUNET_CONTAINER_DLL_insert (set->ops_head, set->ops_tail, op);

  op->spec->client_request_id = ntohl (msg->request_id);
  op->spec->result_mode = ntohs (msg->result_mode);
  op->generation_created = set->current_generation++;
  op->vt = op->spec->set->vt;
  GNUNET_assert (NULL != op->vt->accept);
  set->vt->accept (op);
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

  /* it's important to destroy mesh at the end, as all channels
   * must be destroyed before the mesh handle! */
  if (NULL != mesh)
  {
    GNUNET_MESH_disconnect (mesh);
    mesh = NULL;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "handled shutdown request\n");
}


/**
 * Timeout happens iff:
 *  - we suggested an operation to our listener,
 *    but did not receive a response in time
 *  - we got the channel from a peer but no #GNUNET_MESSAGE_TYPE_SET_P2P_OPERATION_REQUEST
 *  - shutdown (obviously)
 *
 * @param cls channel context
 * @param tc context information (why was this task triggered now)
 */
static void
incoming_timeout_cb (void *cls,
                     const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Operation *incoming = cls;

  incoming->state->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_assert (GNUNET_YES == incoming->is_incoming);
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "remote peer timed out\n");
  incoming_destroy (incoming);
}


/**
 * Terminates an incoming operation in case we have not yet received an
 * operation request. Called by the channel destruction handler.
 *
 * @param op the channel context
 */
static void
handle_incoming_disconnect (struct Operation *op)
{
  GNUNET_assert (GNUNET_YES == op->is_incoming);
  if (NULL == op->channel)
    return;
  incoming_destroy (op);
}


/**
 * Method called whenever another peer has added us to a channel
 * the other peer initiated.
 * Only called (once) upon reception of data with a message type which was
 * subscribed to in GNUNET_MESH_connect().
 *
 * The channel context represents the operation itself and gets added to a DLL,
 * from where it gets looked up when our local listener client responds
 * to a proposed/suggested operation or connects and associates with this operation.
 *
 * @param cls closure
 * @param channel new handle to the channel
 * @param initiator peer that started the channel
 * @param port Port this channel is for.
 * @param options Unused.
 * @return initial channel context for the channel
 *         (can be NULL -- that's not an error)
 */
static void *
channel_new_cb (void *cls,
               struct GNUNET_MESH_Channel *channel,
               const struct GNUNET_PeerIdentity *initiator,
               uint32_t port, enum MeshOption options)
{
  struct Operation *incoming;
  static const struct SetVT incoming_vt = {
    .msg_handler = handle_incoming_msg,
    .peer_disconnect = handle_incoming_disconnect
  };

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "new incoming channel\n");

  if (GNUNET_APPLICATION_TYPE_SET != port)
  {
    GNUNET_break (0);
    GNUNET_MESH_channel_destroy (channel);
    return NULL;
  }

  incoming = GNUNET_new (struct Operation);
  incoming->is_incoming = GNUNET_YES;
  incoming->state = GNUNET_new (struct OperationState);
  incoming->state->peer = *initiator;
  incoming->channel = channel;
  incoming->mq = GNUNET_MESH_mq_create (incoming->channel);
  incoming->vt = &incoming_vt;
  incoming->state->timeout_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_MINUTES,
                                    &incoming_timeout_cb, incoming);
  GNUNET_CONTAINER_DLL_insert_tail (incoming_head, incoming_tail, incoming);

  return incoming;
}


/**
 * Function called whenever a channel is destroyed.  Should clean up
 * any associated state.  It must NOT call
 * GNUNET_MESH_channel_destroy() on the channel.
 *
 * The peer_disconnect function is part of a a virtual table set initially either
 * when a peer creates a new channel with us (channel_new_cb), or once we create
 * a new channel ourselves (evaluate).
 *
 * Once we know the exact type of operation (union/intersection), the vt is
 * replaced with an operation specific instance (_GSS_[op]_vt).
 *
 * @param cls closure (set from GNUNET_MESH_connect())
 * @param channel connection to the other end (henceforth invalid)
 * @param channel_ctx place where local state associated
 *                   with the channel is stored
 */
static void
channel_end_cb (void *cls,
               const struct GNUNET_MESH_Channel *channel, void *channel_ctx)
{
  struct Operation *op = channel_ctx;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "channel end cb called\n");
  op->channel = NULL;
  if (NULL != op->vt)
    op->vt->peer_disconnect (op);
  /* mesh will never call us with the context again! */
  GNUNET_free (channel_ctx);
}


/**
 * Functions with this signature are called whenever any message is
 * received via the mesh channel.
 *
 * The msg_handler is a virtual table set in initially either when a peer
 * creates a new channel with us (channel_new_cb), or once we create a new channel
 * ourselves (evaluate).
 *
 * Once we know the exact type of operation (union/intersection), the vt is
 * replaced with an operation specific instance (_GSS_[op]_vt).
 *
 * @param cls Closure (set from GNUNET_MESH_connect()).
 * @param channel Connection to the other end.
 * @param channel_ctx Place to store local state associated with the channel.
 * @param message The actual message.
 * @return #GNUNET_OK to keep the channel open,
 *         #GNUNET_SYSERR to close it (signal serious error).
 */
static int
dispatch_p2p_message (void *cls,
                      struct GNUNET_MESH_Channel *channel,
                      void **channel_ctx,
                      const struct GNUNET_MessageHeader *message)
{
  struct Operation *op = *channel_ctx;
  int ret;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "dispatching mesh message (type: %u)\n",
              ntohs (message->type));
  /* do this before the handler, as the handler might kill the channel */
  GNUNET_MESH_receive_done (channel);
  ret = op->vt->msg_handler (op, message);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "handled mesh message (type: %u)\n",
              ntohs (message->type));
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
    {handle_client_iter_ack, NULL, GNUNET_MESSAGE_TYPE_SET_ITER_ACK, 0},
    {handle_client_add_remove, NULL, GNUNET_MESSAGE_TYPE_SET_ADD, 0},
    {handle_client_create_set, NULL, GNUNET_MESSAGE_TYPE_SET_CREATE,
        sizeof (struct GNUNET_SET_CreateMessage)},
    {handle_client_iterate, NULL, GNUNET_MESSAGE_TYPE_SET_ITER_REQUEST,
        sizeof (struct GNUNET_MessageHeader)},
    {handle_client_evaluate, NULL, GNUNET_MESSAGE_TYPE_SET_EVALUATE, 0},
    {handle_client_listen, NULL, GNUNET_MESSAGE_TYPE_SET_LISTEN,
        sizeof (struct GNUNET_SET_ListenMessage)},
    {handle_client_reject, NULL, GNUNET_MESSAGE_TYPE_SET_REJECT,
        sizeof (struct GNUNET_SET_AcceptRejectMessage)},
    {handle_client_add_remove, NULL, GNUNET_MESSAGE_TYPE_SET_REMOVE, 0},
    {handle_client_cancel, NULL, GNUNET_MESSAGE_TYPE_SET_CANCEL,
        sizeof (struct GNUNET_SET_CancelMessage)},
    {NULL, NULL, 0, 0}
  };
  static const struct GNUNET_MESH_MessageHandler mesh_handlers[] = {
    {dispatch_p2p_message, GNUNET_MESSAGE_TYPE_SET_P2P_OPERATION_REQUEST, 0},
    {dispatch_p2p_message, GNUNET_MESSAGE_TYPE_SET_UNION_P2P_IBF, 0},
    {dispatch_p2p_message, GNUNET_MESSAGE_TYPE_SET_P2P_ELEMENTS, 0},
    {dispatch_p2p_message, GNUNET_MESSAGE_TYPE_SET_P2P_DONE, 0},
    {dispatch_p2p_message, GNUNET_MESSAGE_TYPE_SET_P2P_ELEMENT_REQUESTS, 0},
    {dispatch_p2p_message, GNUNET_MESSAGE_TYPE_SET_UNION_P2P_SE, 0},
    {dispatch_p2p_message, GNUNET_MESSAGE_TYPE_SET_INTERSECTION_P2P_ELEMENT_INFO, 0},
    {dispatch_p2p_message, GNUNET_MESSAGE_TYPE_SET_INTERSECTION_P2P_BF, 0},
    {NULL, 0, 0}
  };
  static const uint32_t mesh_ports[] = {GNUNET_APPLICATION_TYPE_SET, 0};

  configuration = cfg;
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
                                &shutdown_task, NULL);
  GNUNET_SERVER_disconnect_notify (server, &handle_client_disconnect, NULL);
  GNUNET_SERVER_add_handlers (server, server_handlers);

  mesh = GNUNET_MESH_connect (cfg, NULL, channel_new_cb, channel_end_cb,
                              mesh_handlers, mesh_ports);
  if (NULL == mesh)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Could not connect to mesh service\n"));
    return;
  }
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
  return (GNUNET_OK == ret) ? 0 : 1;
}

/* end of gnunet-service-set.c */

