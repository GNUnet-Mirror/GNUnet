/*
     This file is part of GNUnet.
     (C) 2012, 2013 Christian Grothoff (and other contributing authors)

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
 * @file set/set_api.c
 * @brief api for the set service
 * @author Florian Dold
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_client_lib.h"
#include "gnunet_set_service.h"
#include "set.h"


#define LOG(kind,...) GNUNET_log_from (kind, "set-api",__VA_ARGS__)

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
   * Message queue for 'client'.
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
   * Should the set be destroyed once all operations are gone?
   */
  int destroy_requested;

  /**
   * Has the set become invalid (e.g. service died)?
   */
  int invalid;

  /**
   * Callback for the current iteration over the set,
   * NULL if no iterator is active.
   */
  GNUNET_SET_ElementIterator iterator;

  /**
   * Closure for 'iterator'
   */
  void *iterator_cls;
};


/**
 * Opaque handle to a set operation request from another peer.
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
   * GNUNET_YES/GNUNET_NO
   */
  int accepted;
};


/**
 * Handle to an operation.
 * Only known to the service after commiting
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
   * Closure for result_cb.
   */
  void *result_cls;

  /**
   * Local set used for the operation,
   * NULL if no set has been provided by conclude yet.
   */
  struct GNUNET_SET_Handle *set;

  /**
   * Request ID to identify the operation within the set.
   */
  uint32_t request_id;

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
   * Closure for listen_cb.
   */
  void *listen_cls;

  /**
   * Operation we listen for.
   */
  enum GNUNET_SET_OperationType operation;

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
  GNUNET_SCHEDULER_TaskIdentifier reconnect_task;
};


/* forward declaration */
static void
listen_connect (void *cls,
                const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Handle element for iteration over the set.
 *
 * @param cls the set
 * @param mh the message
 */
static void
handle_iter_element (void *cls, const struct GNUNET_MessageHeader *mh)
{
  struct GNUNET_SET_Handle *set = cls;
  struct GNUNET_SET_Element element;
  const struct GNUNET_SET_IterResponseMessage *msg =
    (const struct GNUNET_SET_IterResponseMessage *) mh;
  struct GNUNET_SET_IterAckMessage *ack_msg;
  struct GNUNET_MQ_Envelope *ev;

  if (NULL == set->iterator)
    return;

  element.size = ntohs (mh->size) - sizeof (struct GNUNET_SET_IterResponseMessage);
  element.element_type = htons (msg->element_type);
  element.data = &msg[1];
  set->iterator (set->iterator_cls, &element);
  ev = GNUNET_MQ_msg (ack_msg, GNUNET_MESSAGE_TYPE_SET_ITER_ACK);
  ack_msg->send_more = htonl (1);
  GNUNET_MQ_send (set->mq, ev);
}


/**
 * Handle element for iteration over the set.
 *
 * @param cls the set
 * @param mh the message
 */
static void
handle_iter_done (void *cls, const struct GNUNET_MessageHeader *mh)
{
  struct GNUNET_SET_Handle *set = cls;

  if (NULL == set->iterator)
    return;

  set->iterator (set->iterator_cls, NULL);
}


/**
 * Handle result message for a set operation.
 *
 * @param cls the set
 * @param mh the message
 */
static void
handle_result (void *cls, const struct GNUNET_MessageHeader *mh)
{
  const struct GNUNET_SET_ResultMessage *msg;
  struct GNUNET_SET_Handle *set = cls;
  struct GNUNET_SET_OperationHandle *oh;
  struct GNUNET_SET_Element e;
  enum GNUNET_SET_Status result_status;

  msg = (const struct GNUNET_SET_ResultMessage *) mh;
  GNUNET_assert (NULL != set);
  GNUNET_assert (NULL != set->mq);

  result_status = ntohs (msg->result_status);

  oh = GNUNET_MQ_assoc_get (set->mq, ntohl (msg->request_id));
  // 'oh' can be NULL if we canceled the operation, but the service
  // did not get the cancel message yet.
  if (NULL == oh)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "ignoring result from canceled operation\n");
    return;
  }
  /* status is not STATUS_OK => there's no attached element,
   * and this is the last result message we get */
  if (GNUNET_SET_STATUS_OK != result_status)
  {
    GNUNET_MQ_assoc_remove (set->mq, ntohl (msg->request_id));
    GNUNET_CONTAINER_DLL_remove (oh->set->ops_head, oh->set->ops_tail, oh);
    if (GNUNET_YES == oh->set->destroy_requested)
      GNUNET_SET_destroy (oh->set);
    if (NULL != oh->result_cb)
      oh->result_cb (oh->result_cls, NULL, result_status);
    GNUNET_free (oh);
    return;
  }

  e.data = &msg[1];
  e.size = ntohs (mh->size) - sizeof (struct GNUNET_SET_ResultMessage);
  e.element_type = msg->element_type;
  if (NULL != oh->result_cb)
    oh->result_cb (oh->result_cls, &e, result_status);
}


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
  const struct GNUNET_SET_RequestMessage *msg = (const struct GNUNET_SET_RequestMessage *) mh;
  struct GNUNET_SET_ListenHandle *lh = cls;
  struct GNUNET_SET_Request *req;
  const struct GNUNET_MessageHeader *context_msg;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "processing operation request\n");
  req = GNUNET_new (struct GNUNET_SET_Request);
  req->accept_id = ntohl (msg->accept_id);
  context_msg = GNUNET_MQ_extract_nested_mh (msg);
  /* calling #GNUNET_SET_accept() in the listen cb will set req->accepted */
  lh->listen_cb (lh->listen_cls, &msg->peer_id, context_msg, req);

  /* we got another request => reset the backoff */
  lh->reconnect_backoff = GNUNET_TIME_UNIT_MILLISECONDS;

  if (GNUNET_NO == req->accepted)
  {
    struct GNUNET_MQ_Envelope *mqm;
    struct GNUNET_SET_RejectMessage *rmsg;

    mqm = GNUNET_MQ_msg (rmsg,
                         GNUNET_MESSAGE_TYPE_SET_REJECT);
    rmsg->accept_reject_id = msg->accept_id;
    GNUNET_MQ_send (lh->mq, mqm);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "rejecting request\n");
  }
  GNUNET_free (req);

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "processed op request from service\n");

  /* the accept-case is handled in GNUNET_SET_accept,
   * as we have the accept message available there */
}


static void
handle_client_listener_error (void *cls,
                              enum GNUNET_MQ_Error error)
{
  struct GNUNET_SET_ListenHandle *lh = cls;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "listener broke down, re-connecting\n");
  GNUNET_CLIENT_disconnect (lh->client);
  lh->client = NULL;
  GNUNET_MQ_destroy (lh->mq);
  lh->mq = NULL;
  lh->reconnect_task = GNUNET_SCHEDULER_add_delayed (lh->reconnect_backoff,
                                                     &listen_connect, lh);
  lh->reconnect_backoff = GNUNET_TIME_STD_BACKOFF (lh->reconnect_backoff);
}


/**
 * Destroy the set handle if no operations are left, mark the set
 * for destruction otherwise.
 *
 * @param set set handle to destroy
 */
static int
set_destroy (struct GNUNET_SET_Handle *set)
{
  if (NULL != set->ops_head)
  {
    set->destroy_requested = GNUNET_YES;
    return GNUNET_NO;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Really destroying set\n");
  GNUNET_CLIENT_disconnect (set->client);
  set->client = NULL;
  GNUNET_MQ_destroy (set->mq);
  set->mq = NULL;
  GNUNET_free (set);
  return GNUNET_YES;
}




/**
 * Cancel the given set operation.  We need to send an explicit cancel message,
 * as all operations one one set communicate using one handle.
 *
 * In contrast to GNUNET_SET_operation_cancel, this function indicates whether
 * the set of the operation has been destroyed because all operations are done and
 * the set's destruction was requested before.
 *
 * @param oh set operation to cancel
 * @return GNUNET_YES if the set of the operation was destroyed
 */
static int
set_operation_cancel (struct GNUNET_SET_OperationHandle *oh)
{
  int ret = GNUNET_NO;

  if (NULL != oh->conclude_mqm)
    GNUNET_MQ_discard (oh->conclude_mqm);

  /* is the operation already commited? */
  if (NULL != oh->set)
  {
    struct GNUNET_SET_OperationHandle *h_assoc;
    struct GNUNET_SET_CancelMessage *m;
    struct GNUNET_MQ_Envelope *mqm;

    GNUNET_CONTAINER_DLL_remove (oh->set->ops_head, oh->set->ops_tail, oh);
    h_assoc = GNUNET_MQ_assoc_remove (oh->set->mq, oh->request_id);
    GNUNET_assert ((h_assoc == NULL) || (h_assoc == oh));
    mqm = GNUNET_MQ_msg (m, GNUNET_MESSAGE_TYPE_SET_CANCEL);
    m->request_id = htonl (oh->request_id);
    GNUNET_MQ_send (oh->set->mq, mqm);

    if (GNUNET_YES == oh->set->destroy_requested)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, "destroying set after operation cancel\n");
      ret = set_destroy (oh->set);
    }
  }

  GNUNET_free (oh);

  return ret;
}


/**
 * Cancel the given set operation.  We need to send an explicit cancel message,
 * as all operations one one set communicate using one handle.
 *
 * @param oh set operation to cancel
 */
void
GNUNET_SET_operation_cancel (struct GNUNET_SET_OperationHandle *oh)
{
  (void) set_operation_cancel (oh);
}


static void
handle_client_set_error (void *cls, enum GNUNET_MQ_Error error)
{
  struct GNUNET_SET_Handle *set = cls;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "handling client set error\n");

  while (NULL != set->ops_head)
  {
    if (NULL != set->ops_head->result_cb)
      set->ops_head->result_cb (set->ops_head->result_cls, NULL,
                                GNUNET_SET_STATUS_FAILURE);
    if (GNUNET_YES == set_operation_cancel (set->ops_head))
      return; /* stop if the set is destroyed */
  }
  set->invalid = GNUNET_YES;
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
  static const struct GNUNET_MQ_MessageHandler mq_handlers[] = {
    {handle_result, GNUNET_MESSAGE_TYPE_SET_RESULT, 0},
    {handle_iter_element, GNUNET_MESSAGE_TYPE_SET_ITER_ELEMENT, 0},
    {handle_iter_done, GNUNET_MESSAGE_TYPE_SET_ITER_DONE, 0},
    GNUNET_MQ_HANDLERS_END
  };
  struct GNUNET_SET_Handle *set;
  struct GNUNET_MQ_Envelope *mqm;
  struct GNUNET_SET_CreateMessage *msg;

  set = GNUNET_new (struct GNUNET_SET_Handle);
  set->client = GNUNET_CLIENT_connect ("set", cfg);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "set client created\n");
  GNUNET_assert (NULL != set->client);
  set->mq = GNUNET_MQ_queue_for_connection_client (set->client, mq_handlers,
                                                   handle_client_set_error, set);
  GNUNET_assert (NULL != set->mq);
  mqm = GNUNET_MQ_msg (msg, GNUNET_MESSAGE_TYPE_SET_CREATE);
  msg->operation = htonl (op);
  GNUNET_MQ_send (set->mq, mqm);
  return set;
}


/**
 * Add an element to the given set.
 * After the element has been added (in the sense of being
 * transmitted to the set service), cont will be called.
 * Calls to add_element can be queued
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

  mqm = GNUNET_MQ_msg_extra (msg, element->size, GNUNET_MESSAGE_TYPE_SET_ADD);
  msg->element_type = element->element_type;
  memcpy (&msg[1], element->data, element->size);
  GNUNET_MQ_notify_sent (mqm, cont, cont_cls);
  GNUNET_MQ_send (set->mq, mqm);
  return GNUNET_OK;
}


/**
 * Remove an element to the given set.
 * After the element has been removed (in the sense of the
 * request being transmitted to the set service), cont will be called.
 * Calls to remove_element can be queued
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

  mqm = GNUNET_MQ_msg_extra (msg, element->size, GNUNET_MESSAGE_TYPE_SET_REMOVE);
  msg->element_type = element->element_type;
  memcpy (&msg[1], element->data, element->size);
  GNUNET_MQ_notify_sent (mqm, cont, cont_cls);
  GNUNET_MQ_send (set->mq, mqm);
  return GNUNET_OK;
}


/**
 * Destroy the set handle, and free all associated resources.
 *
 * @param set set handle to destroy
 */
void
GNUNET_SET_destroy (struct GNUNET_SET_Handle *set)
{
  (void) set_destroy (set);
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
 * Connect to the set service in order to listen
 * for request.
 *
 * @param cls the listen handle to connect
 * @param tc task context if invoked as a task, NULL otherwise
 */
static void
listen_connect (void *cls,
                const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_MQ_Envelope *mqm;
  struct GNUNET_SET_ListenMessage *msg;
  struct GNUNET_SET_ListenHandle *lh = cls;
  static const struct GNUNET_MQ_MessageHandler mq_handlers[] = {
    {handle_request, GNUNET_MESSAGE_TYPE_SET_REQUEST},
    GNUNET_MQ_HANDLERS_END
  };

  if ((tc != NULL) &&(tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) != 0)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "listener not reconnecting due to shutdown\n");
    return;
  }

  lh->reconnect_task = GNUNET_SCHEDULER_NO_TASK;

  GNUNET_assert (NULL == lh->client);
  lh->client = GNUNET_CLIENT_connect ("set", lh->cfg);
  if (NULL == lh->client)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "could not connect to set (wrong configuration?), giving up listening\n");
    return;
  }
  GNUNET_assert (NULL == lh->mq);
  lh->mq = GNUNET_MQ_queue_for_connection_client (lh->client, mq_handlers,
                                                  handle_client_listener_error, lh);
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
 * @param listen_cls handle for listen_cb
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
  LOG (GNUNET_ERROR_TYPE_DEBUG, "canceling listener\n");
  /* listener's connection may have failed, thus mq/client could be NULL */
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
  if (GNUNET_SCHEDULER_NO_TASK != lh->reconnect_task)
  {
    GNUNET_SCHEDULER_cancel (lh->reconnect_task);
    lh->reconnect_task = GNUNET_SCHEDULER_NO_TASK;
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

  GNUNET_assert (NULL != request);
  GNUNET_assert (GNUNET_NO == request->accepted);
  request->accepted = GNUNET_YES;

  oh = GNUNET_new (struct GNUNET_SET_OperationHandle);
  oh->result_cb = result_cb;
  oh->result_cls = result_cls;

  mqm = GNUNET_MQ_msg (msg, GNUNET_MESSAGE_TYPE_SET_ACCEPT);
  msg->accept_reject_id = htonl (request->accept_id);
  msg->result_mode = htonl (result_mode);

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
 * Iterate over all elements in the given set.
 * Note that this operation involves transferring every element of the set
 * from the service to the client, and is thus costly.
 *
 * @param set the set to iterate over
 * @param iter the iterator to call for each element
 * @param cls closure for @a iter
 * @return #GNUNET_YES if the iteration started successfuly,
 *         #GNUNET_NO if another iteration is active
 *         #GNUNET_SYSERR if the set is invalid (e.g. the server crashed, disconnected)
 */
int
GNUNET_SET_iterate (struct GNUNET_SET_Handle *set, GNUNET_SET_ElementIterator iter, void *cls)
{
  struct GNUNET_MQ_Envelope *ev;


  GNUNET_assert (NULL != iter);

  if (GNUNET_YES == set->invalid)
    return GNUNET_SYSERR;
  if (NULL != set->iterator)
    return GNUNET_NO;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "iterating set\n");

  set->iterator = iter;
  set->iterator_cls = cls;
  ev = GNUNET_MQ_msg_header (GNUNET_MESSAGE_TYPE_SET_ITER_REQUEST);
  GNUNET_MQ_send (set->mq, ev);
  return GNUNET_YES;
}

/* end of set_api.c */
