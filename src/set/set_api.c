/*
     This file is part of GNUnet.
     Copyright (C) 2012-2014 Christian Grothoff (and other contributing authors)

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
 * @file set/set_api.c
 * @brief api for the set service
 * @author Florian Dold
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_client_lib.h"
#include "gnunet_set_service.h"
#include "set.h"


#define LOG(kind,...) GNUNET_log_from (kind, "set-api",__VA_ARGS__)

struct SetCopyRequest
{
  struct SetCopyRequest *next;

  struct SetCopyRequest *prev;

  void *cls;

  GNUNET_SET_CopyReadyCallback cb;
};

/**
 * Opaque handle to a set.
 */
struct GNUNET_SET_Handle
{
  /**
   * Client connected to the set service.
   */
  struct GNUNET_CLIENT_Connection *client;

  /**
   * Message queue for @e client.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Linked list of operations on the set.
   */
  struct GNUNET_SET_OperationHandle *ops_head;

  /**
   * Linked list of operations on the set.
   */
  struct GNUNET_SET_OperationHandle *ops_tail;

  /**
   * Callback for the current iteration over the set,
   * NULL if no iterator is active.
   */
  GNUNET_SET_ElementIterator iterator;

  /**
   * Closure for @e iterator
   */
  void *iterator_cls;

  /**
   * Should the set be destroyed once all operations are gone?
   */
  int destroy_requested;

  /**
   * Has the set become invalid (e.g. service died)?
   */
  int invalid;

  /**
   * Both client and service count the number of iterators
   * created so far to match replies with iterators.
   */
  uint16_t iteration_id;

  /**
   * Configuration, needed when creating (lazy) copies.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Doubly linked list of copy requests.
   */
  struct SetCopyRequest *copy_req_head;

  /**
   * Doubly linked list of copy requests.
   */
  struct SetCopyRequest *copy_req_tail;
};


/**
 * Handle for a set operation request from another peer.
 */
struct GNUNET_SET_Request
{
  /**
   * Id of the request, used to identify the request when
   * accepting/rejecting it.
   */
  uint32_t accept_id;

  /**
   * Has the request been accepted already?
   * #GNUNET_YES/#GNUNET_NO
   */
  int accepted;
};


/**
 * Handle to an operation.  Only known to the service after committing
 * the handle with a set.
 */
struct GNUNET_SET_OperationHandle
{
  /**
   * Function to be called when we have a result,
   * or an error.
   */
  GNUNET_SET_ResultIterator result_cb;

  /**
   * Closure for @e result_cb.
   */
  void *result_cls;

  /**
   * Local set used for the operation,
   * NULL if no set has been provided by conclude yet.
   */
  struct GNUNET_SET_Handle *set;

  /**
   * Message sent to the server on calling conclude,
   * NULL if conclude has been called.
   */
  struct GNUNET_MQ_Envelope *conclude_mqm;

  /**
   * Address of the request if in the conclude message,
   * used to patch the request id into the message when the set is known.
   */
  uint32_t *request_id_addr;

  /**
   * Handles are kept in a linked list.
   */
  struct GNUNET_SET_OperationHandle *prev;

  /**
   * Handles are kept in a linked list.
   */
  struct GNUNET_SET_OperationHandle *next;

  /**
   * Request ID to identify the operation within the set.
   */
  uint32_t request_id;
};


/**
 * Opaque handle to a listen operation.
 */
struct GNUNET_SET_ListenHandle
{
  /**
   * Connection to the service.
   */
  struct GNUNET_CLIENT_Connection *client;

  /**
   * Message queue for the client.
   */
  struct GNUNET_MQ_Handle* mq;

  /**
   * Configuration handle for the listener, stored
   * here to be able to reconnect transparently on
   * connection failure.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Function to call on a new incoming request,
   * or on error.
   */
  GNUNET_SET_ListenCallback listen_cb;

  /**
   * Closure for @e listen_cb.
   */
  void *listen_cls;

  /**
   * Application ID we listen for.
   */
  struct GNUNET_HashCode app_id;

  /**
   * Time to wait until we try to reconnect on failure.
   */
  struct GNUNET_TIME_Relative reconnect_backoff;

  /**
   * Task for reconnecting when the listener fails.
   */
  struct GNUNET_SCHEDULER_Task * reconnect_task;

  /**
   * Operation we listen for.
   */
  enum GNUNET_SET_OperationType operation;
};


/* mutual recursion with handle_copy_lazy */
static struct GNUNET_SET_Handle *
create_internal (const struct GNUNET_CONFIGURATION_Handle *cfg,
                 enum GNUNET_SET_OperationType op,
                 uint32_t *cookie);


/**
 * Handle element for iteration over the set.  Notifies the
 * iterator and sends an acknowledgement to the service.
 *
 * @param cls the `struct GNUNET_SET_Handle *`
 * @param mh the message
 */
static void
handle_copy_lazy (void *cls,
                  const struct GNUNET_MessageHeader *mh)
{
  struct GNUNET_SET_CopyLazyResponseMessage *msg;
  struct GNUNET_SET_Handle *set = cls;
  struct SetCopyRequest *req;
  struct GNUNET_SET_Handle *new_set;

  msg = (struct GNUNET_SET_CopyLazyResponseMessage *) mh;

  req = set->copy_req_head;

  if (NULL == req)
  {
    /* Service sent us unsolicited lazy copy response */
    GNUNET_break (0);
    return;
  }

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Handling response to lazy copy\n");
  
  GNUNET_CONTAINER_DLL_remove (set->copy_req_head,
                               set->copy_req_tail,
                               req);

  
  // We pass none as operation here, since it doesn't matter when
  // cloning.
  new_set = create_internal (set->cfg, GNUNET_SET_OPERATION_NONE, &msg->cookie);

  req->cb (req->cls, new_set);

  GNUNET_free (req);
}


/**
 * Handle element for iteration over the set.  Notifies the
 * iterator and sends an acknowledgement to the service.
 *
 * @param cls the `struct GNUNET_SET_Handle *`
 * @param mh the message
 */
static void
handle_iter_element (void *cls,
                     const struct GNUNET_MessageHeader *mh)
{
  struct GNUNET_SET_Handle *set = cls;
  GNUNET_SET_ElementIterator iter = set->iterator;
  struct GNUNET_SET_Element element;
  const struct GNUNET_SET_IterResponseMessage *msg;
  struct GNUNET_SET_IterAckMessage *ack_msg;
  struct GNUNET_MQ_Envelope *ev;
  uint16_t msize;

  msize = ntohs (mh->size);
  if (msize < sizeof (sizeof (struct GNUNET_SET_IterResponseMessage)))
  {
    /* message malformed */
    GNUNET_break (0);
    set->iterator = NULL;
    set->iteration_id++;
    iter (set->iterator_cls,
          NULL);
    iter = NULL;
  }
  msg = (const struct GNUNET_SET_IterResponseMessage *) mh;
  if (set->iteration_id != ntohs (msg->iteration_id))
  {
    /* element from a previous iteration, skip! */
    iter = NULL;
  }
  if (NULL != iter)
  {
    element.size = msize - sizeof (struct GNUNET_SET_IterResponseMessage);
    element.element_type = htons (msg->element_type);
    element.data = &msg[1];
    iter (set->iterator_cls,
          &element);
  }
  ev = GNUNET_MQ_msg (ack_msg,
                      GNUNET_MESSAGE_TYPE_SET_ITER_ACK);
  ack_msg->send_more = htonl ((NULL != iter));
  GNUNET_MQ_send (set->mq, ev);
}


/**
 * Handle message signalling conclusion of iteration over the set.
 * Notifies the iterator that we are done.
 *
 * @param cls the set
 * @param mh the message
 */
static void
handle_iter_done (void *cls,
                  const struct GNUNET_MessageHeader *mh)
{
  struct GNUNET_SET_Handle *set = cls;
  GNUNET_SET_ElementIterator iter = set->iterator;

  if (NULL == iter)
    return;
  set->iterator = NULL;
  set->iteration_id++;
  iter (set->iterator_cls,
        NULL);
}


/**
 * Handle result message for a set operation.
 *
 * @param cls the set
 * @param mh the message
 */
static void
handle_result (void *cls,
               const struct GNUNET_MessageHeader *mh)
{
  struct GNUNET_SET_Handle *set = cls;
  const struct GNUNET_SET_ResultMessage *msg;
  struct GNUNET_SET_OperationHandle *oh;
  struct GNUNET_SET_Element e;
  enum GNUNET_SET_Status result_status;

  msg = (const struct GNUNET_SET_ResultMessage *) mh;
  GNUNET_assert (NULL != set->mq);
  result_status = ntohs (msg->result_status);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Got result message with status %d\n",
       result_status);

  oh = GNUNET_MQ_assoc_get (set->mq,
                            ntohl (msg->request_id));
  if (NULL == oh)
  {
    /* 'oh' can be NULL if we canceled the operation, but the service
       did not get the cancel message yet. */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Ignoring result from canceled operation\n");
    return;
  }

  switch (result_status)
  {
    case GNUNET_SET_STATUS_OK:
    case GNUNET_SET_STATUS_ADD_LOCAL:
    case GNUNET_SET_STATUS_ADD_REMOTE:
      goto do_element;
    case GNUNET_SET_STATUS_FAILURE:
    case GNUNET_SET_STATUS_DONE:
      goto do_final;
    case GNUNET_SET_STATUS_HALF_DONE:
      /* not used anymore */
      GNUNET_assert (0);
  }

do_final:
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Treating result as final status\n");
  GNUNET_MQ_assoc_remove (set->mq,
                          ntohl (msg->request_id));
  GNUNET_CONTAINER_DLL_remove (set->ops_head,
                               set->ops_tail,
                               oh);
  if (NULL != oh->result_cb)
  {
    oh->result_cb (oh->result_cls,
                   NULL,
                   result_status);
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "No callback for final status\n");
  }
  if ( (GNUNET_YES == set->destroy_requested) &&
       (NULL == set->ops_head) )
    GNUNET_SET_destroy (set);
  GNUNET_free (oh);
  return;

do_element:
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Treating result as element\n");
  e.data = &msg[1];
  e.size = ntohs (mh->size) - sizeof (struct GNUNET_SET_ResultMessage);
  e.element_type = msg->element_type;
  if (NULL != oh->result_cb)
    oh->result_cb (oh->result_cls,
                   &e,
                   result_status);
}


/**
 * Destroy the given set operation.
 *
 * @param oh set operation to destroy
 */
static void
set_operation_destroy (struct GNUNET_SET_OperationHandle *oh)
{
  struct GNUNET_SET_Handle *set = oh->set;
  struct GNUNET_SET_OperationHandle *h_assoc;

  if (NULL != oh->conclude_mqm)
    GNUNET_MQ_discard (oh->conclude_mqm);
  /* is the operation already commited? */
  if (NULL != set)
  {
    GNUNET_CONTAINER_DLL_remove (set->ops_head,
                                 set->ops_tail,
                                 oh);
    h_assoc = GNUNET_MQ_assoc_remove (set->mq,
                                      oh->request_id);
    GNUNET_assert ((NULL == h_assoc) || (h_assoc == oh));
  }
  GNUNET_free (oh);
}


/**
 * Cancel the given set operation.  We need to send an explicit cancel
 * message, as all operations one one set communicate using one
 * handle.
 *
 * @param oh set operation to cancel
 */
void
GNUNET_SET_operation_cancel (struct GNUNET_SET_OperationHandle *oh)
{
  struct GNUNET_SET_Handle *set = oh->set;
  struct GNUNET_SET_CancelMessage *m;
  struct GNUNET_MQ_Envelope *mqm;

  if (NULL != set)
  {
    mqm = GNUNET_MQ_msg (m, GNUNET_MESSAGE_TYPE_SET_CANCEL);
    m->request_id = htonl (oh->request_id);
    GNUNET_MQ_send (set->mq, mqm);
  }
  set_operation_destroy (oh);
  if ( (NULL != set) &&
       (GNUNET_YES == set->destroy_requested) &&
       (NULL == set->ops_head) )
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Destroying set after operation cancel\n");
    GNUNET_SET_destroy (set);
  }
}


/**
 * We encountered an error communicating with the set service while
 * performing a set operation. Report to the application.
 *
 * @param cls the `struct GNUNET_SET_Handle`
 * @param error error code
 */
static void
handle_client_set_error (void *cls,
                         enum GNUNET_MQ_Error error)
{
  struct GNUNET_SET_Handle *set = cls;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Handling client set error %d\n",
       error);
  while (NULL != set->ops_head)
  {
    if (NULL != set->ops_head->result_cb)
      set->ops_head->result_cb (set->ops_head->result_cls,
                                NULL,
                                GNUNET_SET_STATUS_FAILURE);
    set_operation_destroy (set->ops_head);
  }
  set->invalid = GNUNET_YES;
  if (GNUNET_YES == set->destroy_requested)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Destroying set after operation failure\n");
    GNUNET_SET_destroy (set);
  }
}


static struct GNUNET_SET_Handle *
create_internal (const struct GNUNET_CONFIGURATION_Handle *cfg,
                 enum GNUNET_SET_OperationType op,
                 uint32_t *cookie)
{
  static const struct GNUNET_MQ_MessageHandler mq_handlers[] = {
    { &handle_result,
      GNUNET_MESSAGE_TYPE_SET_RESULT,
      0 },
    { &handle_iter_element,
      GNUNET_MESSAGE_TYPE_SET_ITER_ELEMENT,
      0 },
    { &handle_iter_done,
      GNUNET_MESSAGE_TYPE_SET_ITER_DONE,
      sizeof (struct GNUNET_MessageHeader) },
    { &handle_copy_lazy,
      GNUNET_MESSAGE_TYPE_SET_COPY_LAZY_RESPONSE,
      sizeof (struct GNUNET_SET_CopyLazyResponseMessage) },
    GNUNET_MQ_HANDLERS_END
  };
  struct GNUNET_SET_Handle *set;
  struct GNUNET_MQ_Envelope *mqm;
  struct GNUNET_SET_CreateMessage *create_msg;
  struct GNUNET_SET_CopyLazyConnectMessage *copy_msg;

  set = GNUNET_new (struct GNUNET_SET_Handle);
  set->client = GNUNET_CLIENT_connect ("set", cfg);
  set->cfg = cfg;
  if (NULL == set->client)
  {
    GNUNET_free (set);
    return NULL;
  }
  set->mq = GNUNET_MQ_queue_for_connection_client (set->client,
                                                   mq_handlers,
                                                   &handle_client_set_error,
                                                   set);
  GNUNET_assert (NULL != set->mq);

  if (NULL == cookie)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Creating new set (operation %u)\n",
         op);
    mqm = GNUNET_MQ_msg (create_msg,
                         GNUNET_MESSAGE_TYPE_SET_CREATE);
    create_msg->operation = htonl (op);
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Creating new set (lazy copy)\n",
         op);
    mqm = GNUNET_MQ_msg (copy_msg,
                         GNUNET_MESSAGE_TYPE_SET_COPY_LAZY_CONNECT);
    copy_msg->cookie = *cookie;
  }
  GNUNET_MQ_send (set->mq, mqm);
  return set;
}


/**
 * Create an empty set, supporting the specified operation.
 *
 * @param cfg configuration to use for connecting to the
 *        set service
 * @param op operation supported by the set
 *        Note that the operation has to be specified
 *        beforehand, as certain set operations need to maintain
 *        data structures spefific to the operation
 * @return a handle to the set
 */
struct GNUNET_SET_Handle *
GNUNET_SET_create (const struct GNUNET_CONFIGURATION_Handle *cfg,
                   enum GNUNET_SET_OperationType op)
{
  return create_internal (cfg, op, NULL);
}


/**
 * Add an element to the given set.  After the element has been added
 * (in the sense of being transmitted to the set service), @a cont
 * will be called.  Multiple calls to GNUNET_SET_add_element() can be
 * queued.
 *
 * @param set set to add element to
 * @param element element to add to the set
 * @param cont continuation called after the element has been added
 * @param cont_cls closure for @a cont
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if the
 *         set is invalid (e.g. the set service crashed)
 */
int
GNUNET_SET_add_element (struct GNUNET_SET_Handle *set,
                        const struct GNUNET_SET_Element *element,
                        GNUNET_SET_Continuation cont,
                        void *cont_cls)
{
  struct GNUNET_MQ_Envelope *mqm;
  struct GNUNET_SET_ElementMessage *msg;

  if (GNUNET_YES == set->invalid)
  {
    if (NULL != cont)
      cont (cont_cls);
    return GNUNET_SYSERR;
  }
  mqm = GNUNET_MQ_msg_extra (msg, element->size,
                             GNUNET_MESSAGE_TYPE_SET_ADD);
  msg->element_type = element->element_type;
  memcpy (&msg[1],
          element->data,
          element->size);
  GNUNET_MQ_notify_sent (mqm,
                         cont, cont_cls);
  GNUNET_MQ_send (set->mq, mqm);
  return GNUNET_OK;
}


/**
 * Remove an element to the given set.  After the element has been
 * removed (in the sense of the request being transmitted to the set
 * service), @a cont will be called.  Multiple calls to
 * GNUNET_SET_remove_element() can be queued
 *
 * @param set set to remove element from
 * @param element element to remove from the set
 * @param cont continuation called after the element has been removed
 * @param cont_cls closure for @a cont
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if the
 *         set is invalid (e.g. the set service crashed)
 */
int
GNUNET_SET_remove_element (struct GNUNET_SET_Handle *set,
                           const struct GNUNET_SET_Element *element,
                           GNUNET_SET_Continuation cont,
                           void *cont_cls)
{
  struct GNUNET_MQ_Envelope *mqm;
  struct GNUNET_SET_ElementMessage *msg;

  if (GNUNET_YES == set->invalid)
  {
    if (NULL != cont)
      cont (cont_cls);
    return GNUNET_SYSERR;
  }
  mqm = GNUNET_MQ_msg_extra (msg,
                             element->size,
                             GNUNET_MESSAGE_TYPE_SET_REMOVE);
  msg->element_type = element->element_type;
  memcpy (&msg[1],
          element->data,
          element->size);
  GNUNET_MQ_notify_sent (mqm,
                         cont, cont_cls);
  GNUNET_MQ_send (set->mq, mqm);
  return GNUNET_OK;
}


/**
 * Destroy the set handle if no operations are left, mark the set
 * for destruction otherwise.
 *
 * @param set set handle to destroy
 */
void
GNUNET_SET_destroy (struct GNUNET_SET_Handle *set)
{
  /* destroying set while iterator is active is currently
     not supported; we should expand the API to allow
     clients to explicitly cancel the iteration! */
  GNUNET_assert (NULL == set->iterator);
  if (NULL != set->ops_head)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Set operations are pending, delaying set destruction\n");
    set->destroy_requested = GNUNET_YES;
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Really destroying set\n");
  if (NULL != set->client)
  {
    GNUNET_CLIENT_disconnect (set->client);
    set->client = NULL;
  }
  if (NULL != set->mq)
  {
    GNUNET_MQ_destroy (set->mq);
    set->mq = NULL;
  }
  GNUNET_free (set);
}


/**
 * Prepare a set operation to be evaluated with another peer.
 * The evaluation will not start until the client provides
 * a local set with #GNUNET_SET_commit().
 *
 * @param other_peer peer with the other set
 * @param app_id hash for the application using the set
 * @param context_msg additional information for the request
 * @param result_mode specified how results will be returned,
 *        see `enum GNUNET_SET_ResultMode`.
 * @param result_cb called on error or success
 * @param result_cls closure for @e result_cb
 * @return a handle to cancel the operation
 */
struct GNUNET_SET_OperationHandle *
GNUNET_SET_prepare (const struct GNUNET_PeerIdentity *other_peer,
                    const struct GNUNET_HashCode *app_id,
                    const struct GNUNET_MessageHeader *context_msg,
                    enum GNUNET_SET_ResultMode result_mode,
                    GNUNET_SET_ResultIterator result_cb,
                    void *result_cls)
{
  struct GNUNET_MQ_Envelope *mqm;
  struct GNUNET_SET_OperationHandle *oh;
  struct GNUNET_SET_EvaluateMessage *msg;

  oh = GNUNET_new (struct GNUNET_SET_OperationHandle);
  oh->result_cb = result_cb;
  oh->result_cls = result_cls;
  mqm = GNUNET_MQ_msg_nested_mh (msg,
                                 GNUNET_MESSAGE_TYPE_SET_EVALUATE,
                                 context_msg);
  msg->app_id = *app_id;
  msg->result_mode = htonl (result_mode);
  msg->target_peer = *other_peer;
  oh->conclude_mqm = mqm;
  oh->request_id_addr = &msg->request_id;

  return oh;
}


/**
 * Connect to the set service in order to listen for requests.
 *
 * @param cls the `struct GNUNET_SET_ListenHandle *` to connect
 * @param tc task context if invoked as a task, NULL otherwise
 */
static void
listen_connect (void *cls,
                const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Handle request message for a listen operation
 *
 * @param cls the listen handle
 * @param mh the message
 */
static void
handle_request (void *cls,
                const struct GNUNET_MessageHeader *mh)
{
  struct GNUNET_SET_ListenHandle *lh = cls;
  const struct GNUNET_SET_RequestMessage *msg;
  struct GNUNET_SET_Request req;
  const struct GNUNET_MessageHeader *context_msg;
  uint16_t msize;
  struct GNUNET_MQ_Envelope *mqm;
  struct GNUNET_SET_RejectMessage *rmsg;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Processing incoming operation request\n");
  msize = ntohs (mh->size);
  if (msize < sizeof (struct GNUNET_SET_RequestMessage))
  {
    GNUNET_break (0);
    GNUNET_CLIENT_disconnect (lh->client);
    lh->client = NULL;
    GNUNET_MQ_destroy (lh->mq);
    lh->mq = NULL;
    lh->reconnect_task = GNUNET_SCHEDULER_add_delayed (lh->reconnect_backoff,
                                                       &listen_connect, lh);
    lh->reconnect_backoff = GNUNET_TIME_STD_BACKOFF (lh->reconnect_backoff);
    return;
  }
  /* we got another valid request => reset the backoff */
  lh->reconnect_backoff = GNUNET_TIME_UNIT_MILLISECONDS;
  msg = (const struct GNUNET_SET_RequestMessage *) mh;
  req.accept_id = ntohl (msg->accept_id);
  req.accepted = GNUNET_NO;
  context_msg = GNUNET_MQ_extract_nested_mh (msg);
  /* calling #GNUNET_SET_accept() in the listen cb will set req->accepted */
  lh->listen_cb (lh->listen_cls,
                 &msg->peer_id,
                 context_msg,
                 &req);
  if (GNUNET_YES == req.accepted)
    return; /* the accept-case is handled in #GNUNET_SET_accept() */
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Rejecting request\n");
  mqm = GNUNET_MQ_msg (rmsg,
                       GNUNET_MESSAGE_TYPE_SET_REJECT);
  rmsg->accept_reject_id = msg->accept_id;
  GNUNET_MQ_send (lh->mq, mqm);
}


/**
 * Our connection with the set service encountered an error,
 * re-initialize with exponential back-off.
 *
 * @param cls the `struct GNUNET_SET_ListenHandle *`
 * @param error reason for the disconnect
 */
static void
handle_client_listener_error (void *cls,
                              enum GNUNET_MQ_Error error)
{
  struct GNUNET_SET_ListenHandle *lh = cls;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Listener broke down (%d), re-connecting\n",
       (int) error);
  GNUNET_CLIENT_disconnect (lh->client);
  lh->client = NULL;
  GNUNET_MQ_destroy (lh->mq);
  lh->mq = NULL;
  lh->reconnect_task = GNUNET_SCHEDULER_add_delayed (lh->reconnect_backoff,
                                                     &listen_connect, lh);
  lh->reconnect_backoff = GNUNET_TIME_STD_BACKOFF (lh->reconnect_backoff);
}


/**
 * Connect to the set service in order to listen for requests.
 *
 * @param cls the `struct GNUNET_SET_ListenHandle *` to connect
 * @param tc task context if invoked as a task, NULL otherwise
 */
static void
listen_connect (void *cls,
                const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  static const struct GNUNET_MQ_MessageHandler mq_handlers[] = {
    { &handle_request, GNUNET_MESSAGE_TYPE_SET_REQUEST },
    GNUNET_MQ_HANDLERS_END
  };
  struct GNUNET_SET_ListenHandle *lh = cls;
  struct GNUNET_MQ_Envelope *mqm;
  struct GNUNET_SET_ListenMessage *msg;

  if ( (NULL != tc) &&
       (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN)) )
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Listener not reconnecting due to shutdown\n");
    return;
  }
  lh->reconnect_task = NULL;
  GNUNET_assert (NULL == lh->client);
  lh->client = GNUNET_CLIENT_connect ("set", lh->cfg);
  if (NULL == lh->client)
    return;
  GNUNET_assert (NULL == lh->mq);
  lh->mq = GNUNET_MQ_queue_for_connection_client (lh->client,
                                                  mq_handlers,
                                                  &handle_client_listener_error, lh);
  mqm = GNUNET_MQ_msg (msg, GNUNET_MESSAGE_TYPE_SET_LISTEN);
  msg->operation = htonl (lh->operation);
  msg->app_id = lh->app_id;
  GNUNET_MQ_send (lh->mq, mqm);
}


/**
 * Wait for set operation requests for the given application id
 *
 * @param cfg configuration to use for connecting to
 *            the set service, needs to be valid for the lifetime of the listen handle
 * @param operation operation we want to listen for
 * @param app_id id of the application that handles set operation requests
 * @param listen_cb called for each incoming request matching the operation
 *                  and application id
 * @param listen_cls handle for @a listen_cb
 * @return a handle that can be used to cancel the listen operation
 */
struct GNUNET_SET_ListenHandle *
GNUNET_SET_listen (const struct GNUNET_CONFIGURATION_Handle *cfg,
                   enum GNUNET_SET_OperationType operation,
                   const struct GNUNET_HashCode *app_id,
                   GNUNET_SET_ListenCallback listen_cb,
                   void *listen_cls)
{
  struct GNUNET_SET_ListenHandle *lh;

  lh = GNUNET_new (struct GNUNET_SET_ListenHandle);
  lh->listen_cb = listen_cb;
  lh->listen_cls = listen_cls;
  lh->cfg = cfg;
  lh->operation = operation;
  lh->app_id = *app_id;
  lh->reconnect_backoff = GNUNET_TIME_UNIT_MILLISECONDS;
  listen_connect (lh, NULL);
  if (NULL == lh->client)
  {
    GNUNET_free (lh);
    return NULL;
  }
  return lh;
}


/**
 * Cancel the given listen operation.
 *
 * @param lh handle for the listen operation
 */
void
GNUNET_SET_listen_cancel (struct GNUNET_SET_ListenHandle *lh)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Canceling listener\n");
  if (NULL != lh->mq)
  {
    GNUNET_MQ_destroy (lh->mq);
    lh->mq = NULL;
  }
  if (NULL != lh->client)
  {
    GNUNET_CLIENT_disconnect (lh->client);
    lh->client = NULL;
  }
  if (NULL != lh->reconnect_task)
  {
    GNUNET_SCHEDULER_cancel (lh->reconnect_task);
    lh->reconnect_task = NULL;
  }
  GNUNET_free (lh);
}


/**
 * Accept a request we got via #GNUNET_SET_listen.  Must be called during
 * #GNUNET_SET_listen, as the 'struct GNUNET_SET_Request' becomes invalid
 * afterwards.
 * Call #GNUNET_SET_commit to provide the local set to use for the operation,
 * and to begin the exchange with the remote peer.
 *
 * @param request request to accept
 * @param result_mode specified how results will be returned,
 *        see `enum GNUNET_SET_ResultMode`.
 * @param result_cb callback for the results
 * @param result_cls closure for @a result_cb
 * @return a handle to cancel the operation
 */
struct GNUNET_SET_OperationHandle *
GNUNET_SET_accept (struct GNUNET_SET_Request *request,
                   enum GNUNET_SET_ResultMode result_mode,
                   GNUNET_SET_ResultIterator result_cb,
                   void *result_cls)
{
  struct GNUNET_MQ_Envelope *mqm;
  struct GNUNET_SET_OperationHandle *oh;
  struct GNUNET_SET_AcceptMessage *msg;

  GNUNET_assert (GNUNET_NO == request->accepted);
  request->accepted = GNUNET_YES;
  mqm = GNUNET_MQ_msg (msg, GNUNET_MESSAGE_TYPE_SET_ACCEPT);
  msg->accept_reject_id = htonl (request->accept_id);
  msg->result_mode = htonl (result_mode);
  oh = GNUNET_new (struct GNUNET_SET_OperationHandle);
  oh->result_cb = result_cb;
  oh->result_cls = result_cls;
  oh->conclude_mqm = mqm;
  oh->request_id_addr = &msg->request_id;
  return oh;
}


/**
 * Commit a set to be used with a set operation.
 * This function is called once we have fully constructed
 * the set that we want to use for the operation.  At this
 * time, the P2P protocol can then begin to exchange the
 * set information and call the result callback with the
 * result information.
 *
 * @param oh handle to the set operation
 * @param set the set to use for the operation
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if the
 *         set is invalid (e.g. the set service crashed)
 */
int
GNUNET_SET_commit (struct GNUNET_SET_OperationHandle *oh,
                   struct GNUNET_SET_Handle *set)
{
  GNUNET_assert (NULL == oh->set);
  if (GNUNET_YES == set->invalid)
    return GNUNET_SYSERR;
  GNUNET_assert (NULL != oh->conclude_mqm);
  oh->set = set;
  GNUNET_CONTAINER_DLL_insert (set->ops_head,
                               set->ops_tail,
                               oh);
  oh->request_id = GNUNET_MQ_assoc_add (set->mq, oh);
  *oh->request_id_addr = htonl (oh->request_id);
  GNUNET_MQ_send (set->mq, oh->conclude_mqm);
  oh->conclude_mqm = NULL;
  oh->request_id_addr = NULL;
  return GNUNET_OK;
}


/**
 * Iterate over all elements in the given set.  Note that this
 * operation involves transferring every element of the set from the
 * service to the client, and is thus costly.
 *
 * @param set the set to iterate over
 * @param iter the iterator to call for each element
 * @param iter_cls closure for @a iter
 * @return #GNUNET_YES if the iteration started successfuly,
 *         #GNUNET_NO if another iteration is active
 *         #GNUNET_SYSERR if the set is invalid (e.g. the server crashed, disconnected)
 */
int
GNUNET_SET_iterate (struct GNUNET_SET_Handle *set,
                    GNUNET_SET_ElementIterator iter,
                    void *iter_cls)
{
  struct GNUNET_MQ_Envelope *ev;

  GNUNET_assert (NULL != iter);
  if (GNUNET_YES == set->invalid)
    return GNUNET_SYSERR;
  if (NULL != set->iterator)
    return GNUNET_NO;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Iterating over set\n");
  set->iterator = iter;
  set->iterator_cls = iter_cls;
  ev = GNUNET_MQ_msg_header (GNUNET_MESSAGE_TYPE_SET_ITER_REQUEST);
  GNUNET_MQ_send (set->mq, ev);
  return GNUNET_YES;
}


void
GNUNET_SET_copy_lazy (struct GNUNET_SET_Handle *set,
                      GNUNET_SET_CopyReadyCallback cb,
                      void *cls)
{
  struct GNUNET_MQ_Envelope *ev;
  struct SetCopyRequest *req;

  ev = GNUNET_MQ_msg_header (GNUNET_MESSAGE_TYPE_SET_COPY_LAZY_PREPARE);
  GNUNET_MQ_send (set->mq, ev);

  req = GNUNET_new (struct SetCopyRequest);
  req->cb = cb;
  req->cls = cls;
  GNUNET_CONTAINER_DLL_insert (set->copy_req_head,
                               set->copy_req_tail,
                               req);
}


/**
 * Create a copy of an element.  The copy
 * must be GNUNET_free-d by the caller.
 *
 * @param element the element to copy
 * @return the copied element
 */
struct GNUNET_SET_Element *
GNUNET_SET_element_dup (const struct GNUNET_SET_Element *element)
{
  struct GNUNET_SET_Element *copy;

  copy = GNUNET_malloc (element->size + sizeof (struct GNUNET_SET_Element));
  copy->size = element->size;
  copy->element_type = element->element_type;
  copy->data = &copy[1];
  memcpy ((void *) copy->data, element->data, copy->size);

  return copy;
}


/**
 * Hash a set element.
 *
 * @param element the element that should be hashed
 * @param ret_hash a pointer to where the hash of @a element
 *        should be stored
 */
void
GNUNET_SET_element_hash (const struct GNUNET_SET_Element *element, struct GNUNET_HashCode *ret_hash)
{
  /* FIXME: The element type should also be hashed. */
  GNUNET_CRYPTO_hash (element->data, element->size, ret_hash);
}

/* end of set_api.c */
