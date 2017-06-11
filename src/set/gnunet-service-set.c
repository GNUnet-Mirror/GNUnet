/*
      This file is part of GNUnet
      Copyright (C) 2013-2017 GNUnet e.V.

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
 * @file set/gnunet-service-set.c
 * @brief two-peer set operations
 * @author Florian Dold
 * @author Christian Grothoff
 */
#include "gnunet-service-set.h"
#include "gnunet-service-set_union.h"
#include "gnunet-service-set_intersection.h"
#include "gnunet-service-set_protocol.h"
#include "gnunet_statistics_service.h"

/**
 * How long do we hold on to an incoming channel if there is
 * no local listener before giving up?
 */
#define INCOMING_CHANNEL_TIMEOUT GNUNET_TIME_UNIT_MINUTES


/**
 * Lazy copy requests made by a client.
 */
struct LazyCopyRequest
{
  /**
   * Kept in a DLL.
   */
  struct LazyCopyRequest *prev;

  /**
   * Kept in a DLL.
   */
  struct LazyCopyRequest *next;

  /**
   * Which set are we supposed to copy?
   */
  struct Set *source_set;

  /**
   * Cookie identifying the request.
   */
  uint32_t cookie;

};


/**
 * A listener is inhabited by a client, and waits for evaluation
 * requests from remote peers.
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
   * Head of DLL of operations this listener is responsible for.
   * Once the client has accepted/declined the operation, the
   * operation is moved to the respective set's operation DLLS.
   */
  struct Operation *op_head;

  /**
   * Tail of DLL of operations this listener is responsible for.
   * Once the client has accepted/declined the operation, the
   * operation is moved to the respective set's operation DLLS.
   */
  struct Operation *op_tail;

  /**
   * Client that owns the listener.
   * Only one client may own a listener.
   */
  struct ClientState *cs;

  /**
   * The port we are listening on with CADET.
   */
  struct GNUNET_CADET_Port *open_port;

  /**
   * Application ID for the operation, used to distinguish
   * multiple operations of the same type with the same peer.
   */
  struct GNUNET_HashCode app_id;

  /**
   * The type of the operation.
   */
  enum GNUNET_SET_OperationType operation;
};


/**
 * Handle to the cadet service, used to listen for and connect to
 * remote peers.
 */
static struct GNUNET_CADET_Handle *cadet;

/**
 * DLL of lazy copy requests by this client.
 */
static struct LazyCopyRequest *lazy_copy_head;

/**
 * DLL of lazy copy requests by this client.
 */
static struct LazyCopyRequest *lazy_copy_tail;

/**
 * Generator for unique cookie we set per lazy copy request.
 */
static uint32_t lazy_copy_cookie;

/**
 * Statistics handle.
 */
struct GNUNET_STATISTICS_Handle *_GSS_statistics;

/**
 * Listeners are held in a doubly linked list.
 */
static struct Listener *listener_head;

/**
 * Listeners are held in a doubly linked list.
 */
static struct Listener *listener_tail;

/**
 * Counter for allocating unique IDs for clients, used to identify
 * incoming operation requests from remote peers, that the client can
 * choose to accept or refuse.  0 must not be used (reserved for
 * uninitialized).
 */
static uint32_t suggest_id;


/**
 * Get the incoming socket associated with the given id.
 *
 * @param listener the listener to look in
 * @param id id to look for
 * @return the incoming socket associated with the id,
 *         or NULL if there is none
 */
static struct Operation *
get_incoming (uint32_t id)
{
  for (struct Listener *listener = listener_head;
       NULL != listener;
       listener = listener->next)
  {
    for (struct Operation *op = listener->op_head; NULL != op; op = op->next)
      if (op->suggest_id == id)
        return op;
  }
  return NULL;
}


/**
 * Destroy an incoming request from a remote peer
 *
 * @param op remote request to destroy
 */
static void
incoming_destroy (struct Operation *op)
{
  struct Listener *listener;
  struct GNUNET_CADET_Channel *channel;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Destroying incoming operation %p\n",
              op);
  if (NULL != (listener = op->listener))
  {
    GNUNET_CONTAINER_DLL_remove (listener->op_head,
                                 listener->op_tail,
                                 op);
    op->listener = NULL;
  }
  if (NULL != op->timeout_task)
  {
    GNUNET_SCHEDULER_cancel (op->timeout_task);
    op->timeout_task = NULL;
  }
  if (NULL != (channel = op->channel))
  {
    op->channel = NULL;
    GNUNET_CADET_channel_destroy (channel);
  }
}


/**
 * Context for the #garbage_collect_cb().
 */
struct GarbageContext
{

  /**
   * Map for which we are garbage collecting removed elements.
   */
  struct GNUNET_CONTAINER_MultiHashMap *map;

  /**
   * Lowest generation for which an operation is still pending.
   */
  unsigned int min_op_generation;

  /**
   * Largest generation for which an operation is still pending.
   */
  unsigned int max_op_generation;

};


/**
 * Function invoked to check if an element can be removed from
 * the set's history because it is no longer needed.
 *
 * @param cls the `struct GarbageContext *`
 * @param key key of the element in the map
 * @param value the `struct ElementEntry *`
 * @return #GNUNET_OK (continue to iterate)
 */
static int
garbage_collect_cb (void *cls,
                    const struct GNUNET_HashCode *key,
                    void *value)
{
  //struct GarbageContext *gc = cls;
  //struct ElementEntry *ee = value;

  //if (GNUNET_YES != ee->removed)
  //  return GNUNET_OK;
  //if ( (gc->max_op_generation < ee->generation_added) ||
  //     (ee->generation_removed > gc->min_op_generation) )
  //{
  //  GNUNET_assert (GNUNET_YES ==
  //                 GNUNET_CONTAINER_multihashmap_remove (gc->map,
  //                                                       key,
  //                                                       ee));
  //  GNUNET_free (ee);
  //}
  return GNUNET_OK;
}


/**
 * Collect and destroy elements that are not needed anymore, because
 * their lifetime (as determined by their generation) does not overlap
 * with any active set operation.
 *
 * @param set set to garbage collect
 */
static void
collect_generation_garbage (struct Set *set)
{
  struct GarbageContext gc;

  gc.min_op_generation = UINT_MAX;
  gc.max_op_generation = 0;
  for (struct Operation *op = set->ops_head; NULL != op; op = op->next)
  {
    gc.min_op_generation = GNUNET_MIN (gc.min_op_generation,
                                       op->generation_created);
    gc.max_op_generation = GNUNET_MAX (gc.max_op_generation,
                                       op->generation_created);
  }
  gc.map = set->content->elements;
  GNUNET_CONTAINER_multihashmap_iterate (set->content->elements,
                                         &garbage_collect_cb,
                                         &gc);
}


/**
 * Is @a generation in the range of exclusions?
 *
 * @param generation generation to query
 * @param excluded array of generations where the element is excluded
 * @param excluded_size length of the @a excluded array
 * @return #GNUNET_YES if @a generation is in any of the ranges
 */
static int
is_excluded_generation (unsigned int generation,
                        struct GenerationRange *excluded,
                        unsigned int excluded_size)
{
  for (unsigned int i = 0; i < excluded_size; i++)
    if ( (generation >= excluded[i].start) &&
         (generation < excluded[i].end) )
      return GNUNET_YES;
  return GNUNET_NO;
}


/**
 * Is element @a ee part of the set during @a query_generation?
 *
 * @param ee element to test
 * @param query_generation generation to query
 * @param excluded array of generations where the element is excluded
 * @param excluded_size length of the @a excluded array
 * @return #GNUNET_YES if the element is in the set, #GNUNET_NO if not
 */
static int
is_element_of_generation (struct ElementEntry *ee,
                          unsigned int query_generation,
                          struct GenerationRange *excluded,
                          unsigned int excluded_size)
{
  struct MutationEvent *mut;
  int is_present;

  GNUNET_assert (NULL != ee->mutations);
  if (GNUNET_YES ==
      is_excluded_generation (query_generation,
                              excluded,
                              excluded_size))
  {
    GNUNET_break (0);
    return GNUNET_NO;
  }

  is_present = GNUNET_NO;

  /* Could be made faster with binary search, but lists
     are small, so why bother. */
  for (unsigned int i = 0; i < ee->mutations_size; i++)
  {
    mut = &ee->mutations[i];

    if (mut->generation > query_generation)
    {
      /* The mutation doesn't apply to our generation
         anymore.  We can'b break here, since mutations aren't
         sorted by generation. */
      continue;
    }

    if (GNUNET_YES ==
        is_excluded_generation (mut->generation,
                                excluded,
                                excluded_size))
    {
      /* The generation is excluded (because it belongs to another
         fork via a lazy copy) and thus mutations aren't considered
         for membership testing. */
      continue;
    }

    /* This would be an inconsistency in how we manage mutations. */
    if ( (GNUNET_YES == is_present) &&
         (GNUNET_YES == mut->added) )
      GNUNET_assert (0);
    /* Likewise. */
    if ( (GNUNET_NO == is_present) &&
         (GNUNET_NO == mut->added) )
      GNUNET_assert (0);

    is_present = mut->added;
  }

  return is_present;
}


/**
 * Is element @a ee part of the set used by @a op?
 *
 * @param ee element to test
 * @param op operation the defines the set and its generation
 * @return #GNUNET_YES if the element is in the set, #GNUNET_NO if not
 */
int
_GSS_is_element_of_operation (struct ElementEntry *ee,
                              struct Operation *op)
{
  return is_element_of_generation (ee,
                                   op->generation_created,
                                   op->set->excluded_generations,
                                   op->set->excluded_generations_size);
}


/**
 * Destroy the given operation.  Used for any operation where both
 * peers were known and that thus actually had a vt and channel.  Must
 * not be used for operations where 'listener' is still set and we do
 * not know the other peer.
 *
 * Call the implementation-specific cancel function of the operation.
 * Disconnects from the remote peer.  Does not disconnect the client,
 * as there may be multiple operations per set.
 *
 * @param op operation to destroy
 * @param gc #GNUNET_YES to perform garbage collection on the set
 */
void
_GSS_operation_destroy (struct Operation *op,
                        int gc)
{
  struct Set *set = op->set;
  struct GNUNET_CADET_Channel *channel;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Destroying operation %p\n",
              op);
  GNUNET_assert (NULL == op->listener);
  if (NULL != op->state)
  {
    set->vt->cancel (op);
    op->state = NULL;
  }
  if (NULL != set)
  {
    GNUNET_CONTAINER_DLL_remove (set->ops_head,
                                 set->ops_tail,
                                 op);
    op->set = NULL;
  }
  if (NULL != op->context_msg)
  {
    GNUNET_free (op->context_msg);
    op->context_msg = NULL;
  }
  if (NULL != (channel = op->channel))
  {
    /* This will free op; called conditionally as this helper function
       is also called from within the channel disconnect handler. */
    op->channel = NULL;
    GNUNET_CADET_channel_destroy (channel);
  }
  if ( (NULL != set) &&
       (GNUNET_YES == gc) )
    collect_generation_garbage (set);
  /* We rely on the channel end handler to free 'op'. When 'op->channel' was NULL,
   * there was a channel end handler that will free 'op' on the call stack. */
}


/**
 * Callback called when a client connects to the service.
 *
 * @param cls closure for the service
 * @param c the new client that connected to the service
 * @param mq the message queue used to send messages to the client
 * @return @a `struct ClientState`
 */
static void *
client_connect_cb (void *cls,
		   struct GNUNET_SERVICE_Client *c,
		   struct GNUNET_MQ_Handle *mq)
{
  struct ClientState *cs;

  cs = GNUNET_new (struct ClientState);
  cs->client = c;
  cs->mq = mq;
  return cs;
}


/**
 * Iterator over hash map entries to free element entries.
 *
 * @param cls closure
 * @param key current key code
 * @param value a `struct ElementEntry *` to be free'd
 * @return #GNUNET_YES (continue to iterate)
 */
static int
destroy_elements_iterator (void *cls,
                           const struct GNUNET_HashCode *key,
                           void *value)
{
  struct ElementEntry *ee = value;

  GNUNET_free_non_null (ee->mutations);
  GNUNET_free (ee);
  return GNUNET_YES;
}


/**
 * Clean up after a client has disconnected
 *
 * @param cls closure, unused
 * @param client the client to clean up after
 * @param internal_cls the `struct ClientState`
 */
static void
client_disconnect_cb (void *cls,
                      struct GNUNET_SERVICE_Client *client,
                      void *internal_cls)
{
  struct ClientState *cs = internal_cls;
  struct Operation *op;
  struct Listener *listener;
  struct Set *set;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Client disconnected, cleaning up\n");
  if (NULL != (set = cs->set))
  {
    struct SetContent *content = set->content;
    struct PendingMutation *pm;
    struct PendingMutation *pm_current;
    struct LazyCopyRequest *lcr;

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Destroying client's set\n");
    /* Destroy pending set operations */
    while (NULL != set->ops_head)
      _GSS_operation_destroy (set->ops_head,
                              GNUNET_NO);

    /* Destroy operation-specific state */
    GNUNET_assert (NULL != set->state);
    set->vt->destroy_set (set->state);
    set->state = NULL;

    /* Clean up ongoing iterations */
    if (NULL != set->iter)
    {
      GNUNET_CONTAINER_multihashmap_iterator_destroy (set->iter);
      set->iter = NULL;
      set->iteration_id++;
    }

    /* discard any pending mutations that reference this set */
    pm = content->pending_mutations_head;
    while (NULL != pm)
    {
      pm_current = pm;
      pm = pm->next;
      if (pm_current->set == set)
      {
        GNUNET_CONTAINER_DLL_remove (content->pending_mutations_head,
                                     content->pending_mutations_tail,
                                     pm_current);
        GNUNET_free (pm_current);
      }
    }

    /* free set content (or at least decrement RC) */
    set->content = NULL;
    GNUNET_assert (0 != content->refcount);
    content->refcount--;
    if (0 == content->refcount)
    {
      GNUNET_assert (NULL != content->elements);
      GNUNET_CONTAINER_multihashmap_iterate (content->elements,
                                             &destroy_elements_iterator,
                                             NULL);
      GNUNET_CONTAINER_multihashmap_destroy (content->elements);
      content->elements = NULL;
      GNUNET_free (content);
    }
    GNUNET_free_non_null (set->excluded_generations);
    set->excluded_generations = NULL;

    /* remove set from pending copy requests */
    lcr = lazy_copy_head;
    while (NULL != lcr)
    {
      struct LazyCopyRequest *lcr_current = lcr;

      lcr = lcr->next;
      if (lcr_current->source_set == set)
      {
        GNUNET_CONTAINER_DLL_remove (lazy_copy_head,
                                     lazy_copy_tail,
                                     lcr_current);
        GNUNET_free (lcr_current);
      }
    }
    GNUNET_free (set);
  }

  if (NULL != (listener = cs->listener))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Destroying client's listener\n");
    GNUNET_CADET_close_port (listener->open_port);
    listener->open_port = NULL;
    while (NULL != (op = listener->op_head))
      incoming_destroy (op);
    GNUNET_CONTAINER_DLL_remove (listener_head,
                                 listener_tail,
                                 listener);
    GNUNET_free (listener);
  }
  GNUNET_free (cs);
}


/**
 * Check a request for a set operation from another peer.
 *
 * @param cls the operation state
 * @param msg the received message
 * @return #GNUNET_OK if the channel should be kept alive,
 *         #GNUNET_SYSERR to destroy the channel
 */
static int
check_incoming_msg (void *cls,
                    const struct OperationRequestMessage *msg)
{
  struct Operation *op = cls;
  struct Listener *listener = op->listener;
  const struct GNUNET_MessageHeader *nested_context;

  /* double operation request */
  if (0 != op->suggest_id)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  /* This should be equivalent to the previous condition, but can't hurt to check twice */
  if (NULL == op->listener)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (listener->operation != (enum GNUNET_SET_OperationType) ntohl (msg->operation))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  nested_context = GNUNET_MQ_extract_nested_mh (msg);
  if ( (NULL != nested_context) &&
       (ntohs (nested_context->size) > GNUNET_SET_CONTEXT_MESSAGE_MAX_SIZE) )
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handle a request for a set operation from another peer.  Checks if we
 * have a listener waiting for such a request (and in that case initiates
 * asking the listener about accepting the connection). If no listener
 * is waiting, we queue the operation request in hope that a listener
 * shows up soon (before timeout).
 *
 * This msg is expected as the first and only msg handled through the
 * non-operation bound virtual table, acceptance of this operation replaces
 * our virtual table and subsequent msgs would be routed differently (as
 * we then know what type of operation this is).
 *
 * @param cls the operation state
 * @param msg the received message
 * @return #GNUNET_OK if the channel should be kept alive,
 *         #GNUNET_SYSERR to destroy the channel
 */
static void
handle_incoming_msg (void *cls,
                     const struct OperationRequestMessage *msg)
{
  struct Operation *op = cls;
  struct Listener *listener = op->listener;
  const struct GNUNET_MessageHeader *nested_context;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_SET_RequestMessage *cmsg;

  nested_context = GNUNET_MQ_extract_nested_mh (msg);
  /* Make a copy of the nested_context (application-specific context
     information that is opaque to set) so we can pass it to the
     listener later on */
  if (NULL != nested_context)
    op->context_msg = GNUNET_copy_message (nested_context);
  op->remote_element_count = ntohl (msg->element_count);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received P2P operation request (op %u, port %s) for active listener\n",
              (uint32_t) ntohl (msg->operation),
              GNUNET_h2s (&op->listener->app_id));
  GNUNET_assert (0 == op->suggest_id);
  if (0 == suggest_id)
    suggest_id++;
  op->suggest_id = suggest_id++;
  GNUNET_assert (NULL != op->timeout_task);
  GNUNET_SCHEDULER_cancel (op->timeout_task);
  op->timeout_task = NULL;
  env = GNUNET_MQ_msg_nested_mh (cmsg,
                                 GNUNET_MESSAGE_TYPE_SET_REQUEST,
                                 op->context_msg);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Suggesting incoming request with accept id %u to listener %p of client %p\n",
              op->suggest_id,
              listener,
              listener->cs);
  cmsg->accept_id = htonl (op->suggest_id);
  cmsg->peer_id = op->peer;
  GNUNET_MQ_send (listener->cs->mq,
                  env);
  /* NOTE: GNUNET_CADET_receive_done() will be called in
     #handle_client_accept() */
}


/**
 * Add an element to @a set as specified by @a msg
 *
 * @param set set to manipulate
 * @param msg message specifying the change
 */
static void
execute_add (struct Set *set,
             const struct GNUNET_SET_ElementMessage *msg)
{
  struct GNUNET_SET_Element el;
  struct ElementEntry *ee;
  struct GNUNET_HashCode hash;

  GNUNET_assert (GNUNET_MESSAGE_TYPE_SET_ADD == ntohs (msg->header.type));
  el.size = ntohs (msg->header.size) - sizeof (*msg);
  el.data = &msg[1];
  el.element_type = ntohs (msg->element_type);
  GNUNET_SET_element_hash (&el,
                           &hash);
  ee = GNUNET_CONTAINER_multihashmap_get (set->content->elements,
                                          &hash);
  if (NULL == ee)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Client inserts element %s of size %u\n",
                GNUNET_h2s (&hash),
                el.size);
    ee = GNUNET_malloc (el.size + sizeof (*ee));
    ee->element.size = el.size;
    GNUNET_memcpy (&ee[1],
            el.data,
            el.size);
    ee->element.data = &ee[1];
    ee->element.element_type = el.element_type;
    ee->remote = GNUNET_NO;
    ee->mutations = NULL;
    ee->mutations_size = 0;
    ee->element_hash = hash;
    GNUNET_break (GNUNET_YES ==
                  GNUNET_CONTAINER_multihashmap_put (set->content->elements,
                                                     &ee->element_hash,
                                                     ee,
                                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  }
  else if (GNUNET_YES ==
           is_element_of_generation (ee,
                                     set->current_generation,
                                     set->excluded_generations,
                                     set->excluded_generations_size))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Client inserted element %s of size %u twice (ignored)\n",
                GNUNET_h2s (&hash),
                el.size);

    /* same element inserted twice */
    return;
  }

  {
    struct MutationEvent mut = {
      .generation = set->current_generation,
      .added = GNUNET_YES
    };
    GNUNET_array_append (ee->mutations,
                         ee->mutations_size,
                         mut);
  }
  set->vt->add (set->state,
                ee);
}


/**
 * Remove an element from @a set as specified by @a msg
 *
 * @param set set to manipulate
 * @param msg message specifying the change
 */
static void
execute_remove (struct Set *set,
                const struct GNUNET_SET_ElementMessage *msg)
{
  struct GNUNET_SET_Element el;
  struct ElementEntry *ee;
  struct GNUNET_HashCode hash;

  GNUNET_assert (GNUNET_MESSAGE_TYPE_SET_REMOVE == ntohs (msg->header.type));
  el.size = ntohs (msg->header.size) - sizeof (*msg);
  el.data = &msg[1];
  el.element_type = ntohs (msg->element_type);
  GNUNET_SET_element_hash (&el, &hash);
  ee = GNUNET_CONTAINER_multihashmap_get (set->content->elements,
                                          &hash);
  if (NULL == ee)
  {
    /* Client tried to remove non-existing element. */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Client removes non-existing element of size %u\n",
                el.size);
    return;
  }
  if (GNUNET_NO ==
      is_element_of_generation (ee,
                                set->current_generation,
                                set->excluded_generations,
                                set->excluded_generations_size))
  {
    /* Client tried to remove element twice */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Client removed element of size %u twice (ignored)\n",
                el.size);
    return;
  }
  else
  {
    struct MutationEvent mut = {
      .generation = set->current_generation,
      .added = GNUNET_NO
    };

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Client removes element of size %u\n",
                el.size);

    GNUNET_array_append (ee->mutations,
                         ee->mutations_size,
                         mut);
  }
  set->vt->remove (set->state,
                   ee);
}


/**
 * Perform a mutation on a set as specified by the @a msg
 *
 * @param set the set to mutate
 * @param msg specification of what to change
 */
static void
execute_mutation (struct Set *set,
                  const struct GNUNET_SET_ElementMessage *msg)
{
  switch (ntohs (msg->header.type))
  {
    case GNUNET_MESSAGE_TYPE_SET_ADD:
      execute_add (set, msg);
      break;
    case GNUNET_MESSAGE_TYPE_SET_REMOVE:
      execute_remove (set, msg);
      break;
    default:
      GNUNET_break (0);
  }
}


/**
 * Execute mutations that were delayed on a set because of
 * pending operations.
 *
 * @param set the set to execute mutations on
 */
static void
execute_delayed_mutations (struct Set *set)
{
  struct PendingMutation *pm;

  if (0 != set->content->iterator_count)
    return; /* still cannot do this */
  while (NULL != (pm = set->content->pending_mutations_head))
  {
    GNUNET_CONTAINER_DLL_remove (set->content->pending_mutations_head,
                                 set->content->pending_mutations_tail,
                                 pm);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Executing pending mutation on %p.\n",
                pm->set);
    execute_mutation (pm->set,
                      pm->msg);
    GNUNET_free (pm->msg);
    GNUNET_free (pm);
  }
}


/**
 * Send the next element of a set to the set's client.  The next element is given by
 * the set's current hashmap iterator.  The set's iterator will be set to NULL if there
 * are no more elements in the set.  The caller must ensure that the set's iterator is
 * valid.
 *
 * The client will acknowledge each received element with a
 * #GNUNET_MESSAGE_TYPE_SET_ITER_ACK message.  Our
 * #handle_client_iter_ack() will then trigger the next transmission.
 * Note that the #GNUNET_MESSAGE_TYPE_SET_ITER_DONE is not acknowledged.
 *
 * @param set set that should send its next element to its client
 */
static void
send_client_element (struct Set *set)
{
  int ret;
  struct ElementEntry *ee;
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_SET_IterResponseMessage *msg;

  GNUNET_assert (NULL != set->iter);
  do {
    ret = GNUNET_CONTAINER_multihashmap_iterator_next (set->iter,
                                                       NULL,
                                                       (const void **) &ee);
    if (GNUNET_NO == ret)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Iteration on %p done.\n",
                  set);
      ev = GNUNET_MQ_msg_header (GNUNET_MESSAGE_TYPE_SET_ITER_DONE);
      GNUNET_CONTAINER_multihashmap_iterator_destroy (set->iter);
      set->iter = NULL;
      set->iteration_id++;
      GNUNET_assert (set->content->iterator_count > 0);
      set->content->iterator_count--;
      execute_delayed_mutations (set);
      GNUNET_MQ_send (set->cs->mq,
                      ev);
      return;
    }
    GNUNET_assert (NULL != ee);
  } while (GNUNET_NO ==
           is_element_of_generation (ee,
                                     set->iter_generation,
                                     set->excluded_generations,
                                     set->excluded_generations_size));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending iteration element on %p.\n",
              set);
  ev = GNUNET_MQ_msg_extra (msg,
                            ee->element.size,
                            GNUNET_MESSAGE_TYPE_SET_ITER_ELEMENT);
  GNUNET_memcpy (&msg[1],
                 ee->element.data,
                 ee->element.size);
  msg->element_type = htons (ee->element.element_type);
  msg->iteration_id = htons (set->iteration_id);
  GNUNET_MQ_send (set->cs->mq,
                  ev);
}


/**
 * Called when a client wants to iterate the elements of a set.
 * Checks if we have a set associated with the client and if we
 * can right now start an iteration. If all checks out, starts
 * sending the elements of the set to the client.
 *
 * @param cls client that sent the message
 * @param m message sent by the client
 */
static void
handle_client_iterate (void *cls,
                       const struct GNUNET_MessageHeader *m)
{
  struct ClientState *cs = cls;
  struct Set *set;

  if (NULL == (set = cs->set))
  {
    /* attempt to iterate over a non existing set */
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (cs->client);
    return;
  }
  if (NULL != set->iter)
  {
    /* Only one concurrent iterate-action allowed per set */
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (cs->client);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Iterating set %p in gen %u with %u content elements\n",
              (void *) set,
              set->current_generation,
              GNUNET_CONTAINER_multihashmap_size (set->content->elements));
  GNUNET_SERVICE_client_continue (cs->client);
  set->content->iterator_count++;
  set->iter = GNUNET_CONTAINER_multihashmap_iterator_create (set->content->elements);
  set->iter_generation = set->current_generation;
  send_client_element (set);
}


/**
 * Called when a client wants to create a new set.  This is typically
 * the first request from a client, and includes the type of set
 * operation to be performed.
 *
 * @param cls client that sent the message
 * @param m message sent by the client
 */
static void
handle_client_create_set (void *cls,
                          const struct GNUNET_SET_CreateMessage *msg)
{
  struct ClientState *cs = cls;
  struct Set *set;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Client created new set (operation %u)\n",
              (uint32_t) ntohl (msg->operation));
  if (NULL != cs->set)
  {
    /* There can only be one set per client */
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (cs->client);
    return;
  }
  set = GNUNET_new (struct Set);
  switch (ntohl (msg->operation))
  {
  case GNUNET_SET_OPERATION_INTERSECTION:
    set->vt = _GSS_intersection_vt ();
    break;
  case GNUNET_SET_OPERATION_UNION:
    set->vt = _GSS_union_vt ();
    break;
  default:
    GNUNET_free (set);
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (cs->client);
    return;
  }
  set->operation = (enum GNUNET_SET_OperationType) ntohl (msg->operation);
  set->state = set->vt->create ();
  if (NULL == set->state)
  {
    /* initialization failed (i.e. out of memory) */
    GNUNET_free (set);
    GNUNET_SERVICE_client_drop (cs->client);
    return;
  }
  set->content = GNUNET_new (struct SetContent);
  set->content->refcount = 1;
  set->content->elements = GNUNET_CONTAINER_multihashmap_create (1,
                                                                 GNUNET_YES);
  set->cs = cs;
  cs->set = set;
  GNUNET_SERVICE_client_continue (cs->client);
}


/**
 * Timeout happens iff:
 *  - we suggested an operation to our listener,
 *    but did not receive a response in time
 *  - we got the channel from a peer but no #GNUNET_MESSAGE_TYPE_SET_P2P_OPERATION_REQUEST
 *
 * @param cls channel context
 * @param tc context information (why was this task triggered now)
 */
static void
incoming_timeout_cb (void *cls)
{
  struct Operation *op = cls;

  op->timeout_task = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Remote peer's incoming request timed out\n");
  incoming_destroy (op);
}


/**
 * Method called whenever another peer has added us to a channel the
 * other peer initiated.  Only called (once) upon reception of data
 * from a channel we listen on.
 *
 * The channel context represents the operation itself and gets added
 * to a DLL, from where it gets looked up when our local listener
 * client responds to a proposed/suggested operation or connects and
 * associates with this operation.
 *
 * @param cls closure
 * @param channel new handle to the channel
 * @param source peer that started the channel
 * @return initial channel context for the channel
 *         returns NULL on error
 */
static void *
channel_new_cb (void *cls,
                struct GNUNET_CADET_Channel *channel,
                const struct GNUNET_PeerIdentity *source)
{
  struct Listener *listener = cls;
  struct Operation *op;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "New incoming channel\n");
  op = GNUNET_new (struct Operation);
  op->listener = listener;
  op->peer = *source;
  op->channel = channel;
  op->mq = GNUNET_CADET_get_mq (op->channel);
  op->salt = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_NONCE,
                                       UINT32_MAX);
  op->timeout_task
    = GNUNET_SCHEDULER_add_delayed (INCOMING_CHANNEL_TIMEOUT,
                                    &incoming_timeout_cb,
                                    op);
  GNUNET_CONTAINER_DLL_insert (listener->op_head,
                               listener->op_tail,
                               op);
  return op;
}


/**
 * Function called whenever a channel is destroyed.  Should clean up
 * any associated state.  It must NOT call
 * GNUNET_CADET_channel_destroy() on the channel.
 *
 * The peer_disconnect function is part of a a virtual table set initially either
 * when a peer creates a new channel with us, or once we create
 * a new channel ourselves (evaluate).
 *
 * Once we know the exact type of operation (union/intersection), the vt is
 * replaced with an operation specific instance (_GSS_[op]_vt).
 *
 * @param channel_ctx place where local state associated
 *                   with the channel is stored
 * @param channel connection to the other end (henceforth invalid)
 */
static void
channel_end_cb (void *channel_ctx,
                const struct GNUNET_CADET_Channel *channel)
{
  struct Operation *op = channel_ctx;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "channel_end_cb called\n");
  op->channel = NULL;
  if (NULL != op->listener)
    incoming_destroy (op);
  else if (NULL != op->set)
    op->set->vt->channel_death (op);
  else
    _GSS_operation_destroy (op,
                            GNUNET_YES);
  GNUNET_free (op);
}


/**
 * Function called whenever an MQ-channel's transmission window size changes.
 *
 * The first callback in an outgoing channel will be with a non-zero value
 * and will mean the channel is connected to the destination.
 *
 * For an incoming channel it will be called immediately after the
 * #GNUNET_CADET_ConnectEventHandler, also with a non-zero value.
 *
 * @param cls Channel closure.
 * @param channel Connection to the other end (henceforth invalid).
 * @param window_size New window size. If the is more messages than buffer size
 *                    this value will be negative..
 */
static void
channel_window_cb (void *cls,
                   const struct GNUNET_CADET_Channel *channel,
                   int window_size)
{
  /* FIXME: not implemented, we could do flow control here... */
}


/**
 * Called when a client wants to create a new listener.
 *
 * @param cls client that sent the message
 * @param msg message sent by the client
 */
static void
handle_client_listen (void *cls,
                      const struct GNUNET_SET_ListenMessage *msg)
{
  struct ClientState *cs = cls;
  struct GNUNET_MQ_MessageHandler cadet_handlers[] = {
    GNUNET_MQ_hd_var_size (incoming_msg,
                           GNUNET_MESSAGE_TYPE_SET_P2P_OPERATION_REQUEST,
                           struct OperationRequestMessage,
                           NULL),
    GNUNET_MQ_hd_var_size (union_p2p_ibf,
                           GNUNET_MESSAGE_TYPE_SET_UNION_P2P_IBF,
                           struct IBFMessage,
                           NULL),
    GNUNET_MQ_hd_var_size (union_p2p_elements,
                           GNUNET_MESSAGE_TYPE_SET_P2P_ELEMENTS,
                           struct GNUNET_SET_ElementMessage,
                           NULL),
    GNUNET_MQ_hd_var_size (union_p2p_offer,
                           GNUNET_MESSAGE_TYPE_SET_UNION_P2P_OFFER,
                           struct GNUNET_MessageHeader,
                           NULL),
    GNUNET_MQ_hd_var_size (union_p2p_inquiry,
                           GNUNET_MESSAGE_TYPE_SET_UNION_P2P_INQUIRY,
                           struct InquiryMessage,
                           NULL),
    GNUNET_MQ_hd_var_size (union_p2p_demand,
                           GNUNET_MESSAGE_TYPE_SET_UNION_P2P_DEMAND,
                           struct GNUNET_MessageHeader,
                           NULL),
    GNUNET_MQ_hd_fixed_size (union_p2p_done,
                             GNUNET_MESSAGE_TYPE_SET_UNION_P2P_DONE,
                             struct GNUNET_MessageHeader,
                             NULL),
    GNUNET_MQ_hd_fixed_size (union_p2p_over,
                             GNUNET_MESSAGE_TYPE_SET_UNION_P2P_OVER,
                             struct GNUNET_MessageHeader,
                             NULL),
    GNUNET_MQ_hd_fixed_size (union_p2p_full_done,
                             GNUNET_MESSAGE_TYPE_SET_UNION_P2P_FULL_DONE,
                             struct GNUNET_MessageHeader,
                             NULL),
    GNUNET_MQ_hd_fixed_size (union_p2p_request_full,
                             GNUNET_MESSAGE_TYPE_SET_UNION_P2P_REQUEST_FULL,
                             struct GNUNET_MessageHeader,
                             NULL),
    GNUNET_MQ_hd_var_size (union_p2p_strata_estimator,
                           GNUNET_MESSAGE_TYPE_SET_UNION_P2P_SE,
                           struct StrataEstimatorMessage,
                           NULL),
    GNUNET_MQ_hd_var_size (union_p2p_strata_estimator,
                           GNUNET_MESSAGE_TYPE_SET_UNION_P2P_SEC,
                           struct StrataEstimatorMessage,
                           NULL),
    GNUNET_MQ_hd_var_size (union_p2p_full_element,
                           GNUNET_MESSAGE_TYPE_SET_UNION_P2P_FULL_ELEMENT,
                           struct GNUNET_SET_ElementMessage,
                           NULL),
    GNUNET_MQ_hd_fixed_size (intersection_p2p_element_info,
                             GNUNET_MESSAGE_TYPE_SET_INTERSECTION_P2P_ELEMENT_INFO,
                             struct IntersectionElementInfoMessage,
                             NULL),
    GNUNET_MQ_hd_var_size (intersection_p2p_bf,
                           GNUNET_MESSAGE_TYPE_SET_INTERSECTION_P2P_BF,
                           struct BFMessage,
                           NULL),
    GNUNET_MQ_hd_fixed_size (intersection_p2p_done,
                             GNUNET_MESSAGE_TYPE_SET_INTERSECTION_P2P_DONE,
                             struct IntersectionDoneMessage,
                             NULL),
    GNUNET_MQ_handler_end ()
  };
  struct Listener *listener;

  if (NULL != cs->listener)
  {
    /* max. one active listener per client! */
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (cs->client);
    return;
  }
  listener = GNUNET_new (struct Listener);
  listener->cs = cs;
  listener->app_id = msg->app_id;
  listener->operation = (enum GNUNET_SET_OperationType) ntohl (msg->operation);
  GNUNET_CONTAINER_DLL_insert (listener_head,
                               listener_tail,
                               listener);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "New listener created (op %u, port %s)\n",
              listener->operation,
              GNUNET_h2s (&listener->app_id));
  listener->open_port
    = GNUNET_CADET_open_port (cadet,
                              &msg->app_id,
                              &channel_new_cb,
                              listener,
                              &channel_window_cb,
                              &channel_end_cb,
                              cadet_handlers);
  GNUNET_SERVICE_client_continue (cs->client);
}


/**
 * Called when the listening client rejects an operation
 * request by another peer.
 *
 * @param cls client that sent the message
 * @param msg message sent by the client
 */
static void
handle_client_reject (void *cls,
                      const struct GNUNET_SET_RejectMessage *msg)
{
  struct ClientState *cs = cls;
  struct Operation *op;

  op = get_incoming (ntohl (msg->accept_reject_id));
  if (NULL == op)
  {
    /* no matching incoming operation for this reject;
       could be that the other peer already disconnected... */
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Client rejected unknown operation %u\n",
                (unsigned int) ntohl (msg->accept_reject_id));
    GNUNET_SERVICE_client_continue (cs->client);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Peer request (op %u, app %s) rejected by client\n",
              op->listener->operation,
              GNUNET_h2s (&cs->listener->app_id));
  GNUNET_CADET_channel_destroy (op->channel);
  GNUNET_SERVICE_client_continue (cs->client);
}


/**
 * Called when a client wants to add or remove an element to a set it inhabits.
 *
 * @param cls client that sent the message
 * @param msg message sent by the client
 */
static int
check_client_mutation (void *cls,
                       const struct GNUNET_SET_ElementMessage *msg)
{
  /* NOTE: Technically, we should probably check with the
     block library whether the element we are given is well-formed */
  return GNUNET_OK;
}


/**
 * Called when a client wants to add or remove an element to a set it inhabits.
 *
 * @param cls client that sent the message
 * @param msg message sent by the client
 */
static void
handle_client_mutation (void *cls,
                        const struct GNUNET_SET_ElementMessage *msg)
{
  struct ClientState *cs = cls;
  struct Set *set;

  if (NULL == (set = cs->set))
  {
    /* client without a set requested an operation */
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (cs->client);
    return;
  }
  GNUNET_SERVICE_client_continue (cs->client);

  if (0 != set->content->iterator_count)
  {
    struct PendingMutation *pm;

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Scheduling mutation on set\n");
    pm = GNUNET_new (struct PendingMutation);
    pm->msg = (struct GNUNET_SET_ElementMessage *) GNUNET_copy_message (&msg->header);
    pm->set = set;
    GNUNET_CONTAINER_DLL_insert_tail (set->content->pending_mutations_head,
                                      set->content->pending_mutations_tail,
                                      pm);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Executing mutation on set\n");
  execute_mutation (set,
                    msg);
}


/**
 * Advance the current generation of a set,
 * adding exclusion ranges if necessary.
 *
 * @param set the set where we want to advance the generation
 */
static void
advance_generation (struct Set *set)
{
  struct GenerationRange r;

  if (set->current_generation == set->content->latest_generation)
  {
    set->content->latest_generation++;
    set->current_generation++;
    return;
  }

  GNUNET_assert (set->current_generation < set->content->latest_generation);

  r.start = set->current_generation + 1;
  r.end = set->content->latest_generation + 1;
  set->content->latest_generation = r.end;
  set->current_generation = r.end;
  GNUNET_array_append (set->excluded_generations,
                       set->excluded_generations_size,
                       r);
}


/**
 * Called when a client wants to initiate a set operation with another
 * peer.  Initiates the CADET connection to the listener and sends the
 * request.
 *
 * @param cls client that sent the message
 * @param msg message sent by the client
 * @return #GNUNET_OK if the message is well-formed
 */
static int
check_client_evaluate (void *cls,
                        const struct GNUNET_SET_EvaluateMessage *msg)
{
  /* FIXME: suboptimal, even if the context below could be NULL,
     there are malformed messages this does not check for... */
  return GNUNET_OK;
}


/**
 * Called when a client wants to initiate a set operation with another
 * peer.  Initiates the CADET connection to the listener and sends the
 * request.
 *
 * @param cls client that sent the message
 * @param msg message sent by the client
 */
static void
handle_client_evaluate (void *cls,
                        const struct GNUNET_SET_EvaluateMessage *msg)
{
  struct ClientState *cs = cls;
  struct Operation *op = GNUNET_new (struct Operation);
  const struct GNUNET_MQ_MessageHandler cadet_handlers[] = {
    GNUNET_MQ_hd_var_size (incoming_msg,
                           GNUNET_MESSAGE_TYPE_SET_P2P_OPERATION_REQUEST,
                           struct OperationRequestMessage,
                           op),
    GNUNET_MQ_hd_var_size (union_p2p_ibf,
                           GNUNET_MESSAGE_TYPE_SET_UNION_P2P_IBF,
                           struct IBFMessage,
                           op),
    GNUNET_MQ_hd_var_size (union_p2p_elements,
                           GNUNET_MESSAGE_TYPE_SET_P2P_ELEMENTS,
                           struct GNUNET_SET_ElementMessage,
                           op),
    GNUNET_MQ_hd_var_size (union_p2p_offer,
                           GNUNET_MESSAGE_TYPE_SET_UNION_P2P_OFFER,
                           struct GNUNET_MessageHeader,
                           op),
    GNUNET_MQ_hd_var_size (union_p2p_inquiry,
                           GNUNET_MESSAGE_TYPE_SET_UNION_P2P_INQUIRY,
                           struct InquiryMessage,
                           op),
    GNUNET_MQ_hd_var_size (union_p2p_demand,
                           GNUNET_MESSAGE_TYPE_SET_UNION_P2P_DEMAND,
                           struct GNUNET_MessageHeader,
                           op),
    GNUNET_MQ_hd_fixed_size (union_p2p_done,
                             GNUNET_MESSAGE_TYPE_SET_UNION_P2P_DONE,
                             struct GNUNET_MessageHeader,
                             op),
    GNUNET_MQ_hd_fixed_size (union_p2p_over,
                             GNUNET_MESSAGE_TYPE_SET_UNION_P2P_OVER,
                             struct GNUNET_MessageHeader,
                             op),
    GNUNET_MQ_hd_fixed_size (union_p2p_full_done,
                             GNUNET_MESSAGE_TYPE_SET_UNION_P2P_FULL_DONE,
                             struct GNUNET_MessageHeader,
                             op),
    GNUNET_MQ_hd_fixed_size (union_p2p_request_full,
                             GNUNET_MESSAGE_TYPE_SET_UNION_P2P_REQUEST_FULL,
                             struct GNUNET_MessageHeader,
                             op),
    GNUNET_MQ_hd_var_size (union_p2p_strata_estimator,
                           GNUNET_MESSAGE_TYPE_SET_UNION_P2P_SE,
                           struct StrataEstimatorMessage,
                           op),
    GNUNET_MQ_hd_var_size (union_p2p_strata_estimator,
                           GNUNET_MESSAGE_TYPE_SET_UNION_P2P_SEC,
                           struct StrataEstimatorMessage,
                           op),
    GNUNET_MQ_hd_var_size (union_p2p_full_element,
                           GNUNET_MESSAGE_TYPE_SET_UNION_P2P_FULL_ELEMENT,
                           struct GNUNET_SET_ElementMessage,
                           op),
    GNUNET_MQ_hd_fixed_size (intersection_p2p_element_info,
                             GNUNET_MESSAGE_TYPE_SET_INTERSECTION_P2P_ELEMENT_INFO,
                             struct IntersectionElementInfoMessage,
                             op),
    GNUNET_MQ_hd_var_size (intersection_p2p_bf,
                           GNUNET_MESSAGE_TYPE_SET_INTERSECTION_P2P_BF,
                           struct BFMessage,
                           op),
    GNUNET_MQ_hd_fixed_size (intersection_p2p_done,
                             GNUNET_MESSAGE_TYPE_SET_INTERSECTION_P2P_DONE,
                             struct IntersectionDoneMessage,
                             op),
    GNUNET_MQ_handler_end ()
  };
  struct Set *set;
  const struct GNUNET_MessageHeader *context;

  if (NULL == (set = cs->set))
  {
    GNUNET_break (0);
    GNUNET_free (op);
    GNUNET_SERVICE_client_drop (cs->client);
    return;
  }
  op->salt = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_NONCE,
                                       UINT32_MAX);
  op->peer = msg->target_peer;
  op->result_mode = ntohl (msg->result_mode);
  op->client_request_id = ntohl (msg->request_id);
  op->byzantine = msg->byzantine;
  op->byzantine_lower_bound = msg->byzantine_lower_bound;
  op->force_full = msg->force_full;
  op->force_delta = msg->force_delta;
  context = GNUNET_MQ_extract_nested_mh (msg);

  /* Advance generation values, so that
     mutations won't interfer with the running operation. */
  op->set = set;
  op->generation_created = set->current_generation;
  advance_generation (set);
  GNUNET_CONTAINER_DLL_insert (set->ops_head,
                               set->ops_tail,
                               op);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Creating new CADET channel to port %s for set operation type %u\n",
              GNUNET_h2s (&msg->app_id),
              set->operation);
  op->channel = GNUNET_CADET_channel_create (cadet,
                                             op,
                                             &msg->target_peer,
                                             &msg->app_id,
                                             GNUNET_CADET_OPTION_RELIABLE,
                                             &channel_window_cb,
                                             &channel_end_cb,
                                             cadet_handlers);
  op->mq = GNUNET_CADET_get_mq (op->channel);
  op->state = set->vt->evaluate (op,
                                 context);
  if (NULL == op->state)
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (cs->client);
    return;
  }
  GNUNET_SERVICE_client_continue (cs->client);
}


/**
 * Handle an ack from a client, and send the next element. Note
 * that we only expect acks for set elements, not after the
 * #GNUNET_MESSAGE_TYPE_SET_ITER_DONE message.
 *
 * @param cls client the client
 * @param ack the message
 */
static void
handle_client_iter_ack (void *cls,
                        const struct GNUNET_SET_IterAckMessage *ack)
{
  struct ClientState *cs = cls;
  struct Set *set;

  if (NULL == (set = cs->set))
  {
    /* client without a set acknowledged receiving a value */
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (cs->client);
    return;
  }
  if (NULL == set->iter)
  {
    /* client sent an ack, but we were not expecting one (as
       set iteration has finished) */
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (cs->client);
    return;
  }
  GNUNET_SERVICE_client_continue (cs->client);
  if (ntohl (ack->send_more))
  {
    send_client_element (set);
  }
  else
  {
    GNUNET_CONTAINER_multihashmap_iterator_destroy (set->iter);
    set->iter = NULL;
    set->iteration_id++;
  }
}


/**
 * Handle a request from the client to copy a set.
 *
 * @param cls the client
 * @param mh the message
 */
static void
handle_client_copy_lazy_prepare (void *cls,
                                 const struct GNUNET_MessageHeader *mh)
{
  struct ClientState *cs = cls;
  struct Set *set;
  struct LazyCopyRequest *cr;
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_SET_CopyLazyResponseMessage *resp_msg;

  if (NULL == (set = cs->set))
  {
    /* client without a set requested an operation */
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (cs->client);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Client requested creation of lazy copy\n");
  cr = GNUNET_new (struct LazyCopyRequest);
  cr->cookie = ++lazy_copy_cookie;
  cr->source_set = set;
  GNUNET_CONTAINER_DLL_insert (lazy_copy_head,
                               lazy_copy_tail,
                               cr);
  ev = GNUNET_MQ_msg (resp_msg,
                      GNUNET_MESSAGE_TYPE_SET_COPY_LAZY_RESPONSE);
  resp_msg->cookie = cr->cookie;
  GNUNET_MQ_send (set->cs->mq,
                  ev);
  GNUNET_SERVICE_client_continue (cs->client);
}


/**
 * Handle a request from the client to connect to a copy of a set.
 *
 * @param cls the client
 * @param msg the message
 */
static void
handle_client_copy_lazy_connect (void *cls,
                                 const struct GNUNET_SET_CopyLazyConnectMessage *msg)
{
  struct ClientState *cs = cls;
  struct LazyCopyRequest *cr;
  struct Set *set;
  int found;

  if (NULL != cs->set)
  {
    /* There can only be one set per client */
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (cs->client);
    return;
  }
  found = GNUNET_NO;
  for (cr = lazy_copy_head; NULL != cr; cr = cr->next)
  {
    if (cr->cookie == msg->cookie)
    {
      found = GNUNET_YES;
      break;
    }
  }
  if (GNUNET_NO == found)
  {
    /* client asked for copy with cookie we don't know */
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (cs->client);
    return;
  }
  GNUNET_CONTAINER_DLL_remove (lazy_copy_head,
                               lazy_copy_tail,
                               cr);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Client %p requested use of lazy copy\n",
              cs);
  set = GNUNET_new (struct Set);
  switch (cr->source_set->operation)
  {
  case GNUNET_SET_OPERATION_INTERSECTION:
    set->vt = _GSS_intersection_vt ();
    break;
  case GNUNET_SET_OPERATION_UNION:
    set->vt = _GSS_union_vt ();
    break;
  default:
    GNUNET_assert (0);
    return;
  }

  if (NULL == set->vt->copy_state)
  {
    /* Lazy copy not supported for this set operation */
    GNUNET_break (0);
    GNUNET_free (set);
    GNUNET_free (cr);
    GNUNET_SERVICE_client_drop (cs->client);
    return;
  }

  set->operation = cr->source_set->operation;
  set->state = set->vt->copy_state (cr->source_set->state);
  set->content = cr->source_set->content;
  set->content->refcount++;

  set->current_generation = cr->source_set->current_generation;
  set->excluded_generations_size = cr->source_set->excluded_generations_size;
  set->excluded_generations
    = GNUNET_memdup (cr->source_set->excluded_generations,
                     set->excluded_generations_size * sizeof (struct GenerationRange));

  /* Advance the generation of the new set, so that mutations to the
     of the cloned set and the source set are independent. */
  advance_generation (set);
  set->cs = cs;
  cs->set = set;
  GNUNET_free (cr);
  GNUNET_SERVICE_client_continue (cs->client);
}


/**
 * Handle a request from the client to cancel a running set operation.
 *
 * @param cls the client
 * @param msg the message
 */
static void
handle_client_cancel (void *cls,
                      const struct GNUNET_SET_CancelMessage *msg)
{
  struct ClientState *cs = cls;
  struct Set *set;
  struct Operation *op;
  int found;

  if (NULL == (set = cs->set))
  {
    /* client without a set requested an operation */
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (cs->client);
    return;
  }
  found = GNUNET_NO;
  for (op = set->ops_head; NULL != op; op = op->next)
  {
    if (op->client_request_id == ntohl (msg->request_id))
    {
      found = GNUNET_YES;
      break;
    }
  }
  if (GNUNET_NO == found)
  {
    /* It may happen that the operation was already destroyed due to
     * the other peer disconnecting.  The client may not know about this
     * yet and try to cancel the (just barely non-existent) operation.
     * So this is not a hard error.
     */
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Client canceled non-existent op %u\n",
                (uint32_t) ntohl (msg->request_id));
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Client requested cancel for op %u\n",
                (uint32_t) ntohl (msg->request_id));
    _GSS_operation_destroy (op,
                            GNUNET_YES);
  }
  GNUNET_SERVICE_client_continue (cs->client);
}


/**
 * Handle a request from the client to accept a set operation that
 * came from a remote peer.  We forward the accept to the associated
 * operation for handling
 *
 * @param cls the client
 * @param msg the message
 */
static void
handle_client_accept (void *cls,
                      const struct GNUNET_SET_AcceptMessage *msg)
{
  struct ClientState *cs = cls;
  struct Set *set;
  struct Operation *op;
  struct GNUNET_SET_ResultMessage *result_message;
  struct GNUNET_MQ_Envelope *ev;
  struct Listener *listener;

  if (NULL == (set = cs->set))
  {
    /* client without a set requested to accept */
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (cs->client);
    return;
  }
  op = get_incoming (ntohl (msg->accept_reject_id));
  if (NULL == op)
  {
    /* It is not an error if the set op does not exist -- it may
     * have been destroyed when the partner peer disconnected. */
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Client %p accepted request %u of listener %p that is no longer active\n",
                cs,
                ntohl (msg->accept_reject_id),
                cs->listener);
    ev = GNUNET_MQ_msg (result_message,
                        GNUNET_MESSAGE_TYPE_SET_RESULT);
    result_message->request_id = msg->request_id;
    result_message->result_status = htons (GNUNET_SET_STATUS_FAILURE);
    GNUNET_MQ_send (set->cs->mq,
                    ev);
    GNUNET_SERVICE_client_continue (cs->client);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Client accepting request %u\n",
              (uint32_t) ntohl (msg->accept_reject_id));
  listener = op->listener;
  op->listener = NULL;
  GNUNET_CONTAINER_DLL_remove (listener->op_head,
                               listener->op_tail,
                               op);
  op->set = set;
  GNUNET_CONTAINER_DLL_insert (set->ops_head,
                               set->ops_tail,
                               op);
  op->client_request_id = ntohl (msg->request_id);
  op->result_mode = ntohl (msg->result_mode);
  op->byzantine = msg->byzantine;
  op->byzantine_lower_bound = msg->byzantine_lower_bound;
  op->force_full = msg->force_full;
  op->force_delta = msg->force_delta;

  /* Advance generation values, so that future mutations do not
     interfer with the running operation. */
  op->generation_created = set->current_generation;
  advance_generation (set);
  GNUNET_assert (NULL == op->state);
  op->state = set->vt->accept (op);
  if (NULL == op->state)
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (cs->client);
    return;
  }
  /* Now allow CADET to continue, as we did not do this in
     #handle_incoming_msg (as we wanted to first see if the
     local client would accept the request). */
  GNUNET_CADET_receive_done (op->channel);
  GNUNET_SERVICE_client_continue (cs->client);
}


/**
 * Called to clean up, after a shutdown has been requested.
 *
 * @param cls closure, NULL
 */
static void
shutdown_task (void *cls)
{
  /* Delay actual shutdown to allow service to disconnect clients */
  if (NULL != cadet)
  {
    GNUNET_CADET_disconnect (cadet);
    cadet = NULL;
  }
  GNUNET_STATISTICS_destroy (_GSS_statistics,
                             GNUNET_YES);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "handled shutdown request\n");
}


/**
 * Function called by the service's run
 * method to run service-specific setup code.
 *
 * @param cls closure
 * @param cfg configuration to use
 * @param service the initialized service
 */
static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_SERVICE_Handle *service)
{
  /* FIXME: need to modify SERVICE (!) API to allow
     us to run a shutdown task *after* clients were
     forcefully disconnected! */
  GNUNET_SCHEDULER_add_shutdown (&shutdown_task,
                                 NULL);
  _GSS_statistics = GNUNET_STATISTICS_create ("set",
                                              cfg);
  cadet = GNUNET_CADET_connect (cfg);
  if (NULL == cadet)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Could not connect to CADET service\n"));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
}


/**
 * Define "main" method using service macro.
 */
GNUNET_SERVICE_MAIN
("set",
 GNUNET_SERVICE_OPTION_NONE,
 &run,
 &client_connect_cb,
 &client_disconnect_cb,
 NULL,
 GNUNET_MQ_hd_fixed_size (client_accept,
                          GNUNET_MESSAGE_TYPE_SET_ACCEPT,
                          struct GNUNET_SET_AcceptMessage,
                          NULL),
 GNUNET_MQ_hd_fixed_size (client_iter_ack,
                          GNUNET_MESSAGE_TYPE_SET_ITER_ACK,
                          struct GNUNET_SET_IterAckMessage,
                          NULL),
 GNUNET_MQ_hd_var_size (client_mutation,
                        GNUNET_MESSAGE_TYPE_SET_ADD,
                        struct GNUNET_SET_ElementMessage,
                        NULL),
 GNUNET_MQ_hd_fixed_size (client_create_set,
                          GNUNET_MESSAGE_TYPE_SET_CREATE,
                          struct GNUNET_SET_CreateMessage,
                          NULL),
 GNUNET_MQ_hd_fixed_size (client_iterate,
                          GNUNET_MESSAGE_TYPE_SET_ITER_REQUEST,
                          struct GNUNET_MessageHeader,
                          NULL),
 GNUNET_MQ_hd_var_size (client_evaluate,
                        GNUNET_MESSAGE_TYPE_SET_EVALUATE,
                        struct GNUNET_SET_EvaluateMessage,
                        NULL),
 GNUNET_MQ_hd_fixed_size (client_listen,
                          GNUNET_MESSAGE_TYPE_SET_LISTEN,
                          struct GNUNET_SET_ListenMessage,
                          NULL),
 GNUNET_MQ_hd_fixed_size (client_reject,
                          GNUNET_MESSAGE_TYPE_SET_REJECT,
                          struct GNUNET_SET_RejectMessage,
                          NULL),
 GNUNET_MQ_hd_var_size (client_mutation,
                        GNUNET_MESSAGE_TYPE_SET_REMOVE,
                        struct GNUNET_SET_ElementMessage,
                        NULL),
 GNUNET_MQ_hd_fixed_size (client_cancel,
                          GNUNET_MESSAGE_TYPE_SET_CANCEL,
                          struct GNUNET_SET_CancelMessage,
                          NULL),
 GNUNET_MQ_hd_fixed_size (client_copy_lazy_prepare,
                          GNUNET_MESSAGE_TYPE_SET_COPY_LAZY_PREPARE,
                          struct GNUNET_MessageHeader,
                          NULL),
 GNUNET_MQ_hd_fixed_size (client_copy_lazy_connect,
                          GNUNET_MESSAGE_TYPE_SET_COPY_LAZY_CONNECT,
                          struct GNUNET_SET_CopyLazyConnectMessage,
                          NULL),
 GNUNET_MQ_handler_end ());


/* end of gnunet-service-set.c */
