/*
     This file is part of GNUnet.
     Copyright (C) 2012-2016 GNUnet e.V.

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
   * #GNUNET_SYSERR if #GNUNET_SET_destroy() must raise this flag,
   * #GNUNET_YES if #GNUNET_SET_destroy() did raise this flag.
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
  struct GNUNET_SCHEDULER_Task *reconnect_task;

  /**
   * Operation we listen for.
   */
  enum GNUNET_SET_OperationType operation;
};


/* mutual recursion with handle_copy_lazy */
static struct GNUNET_SET_Handle *
create_internal (const struct GNUNET_CONFIGURATION_Handle *cfg,
                 enum GNUNET_SET_OperationType op,
                 const uint32_t *cookie);


/**
 * Handle element for iteration over the set.  Notifies the
 * iterator and sends an acknowledgement to the service.
 *
 * @param cls the `struct GNUNET_SET_Handle *`
 * @param msg the message
 */
static void
handle_copy_lazy (void *cls,
                  const struct GNUNET_SET_CopyLazyResponseMessage *msg)
{
  struct GNUNET_SET_Handle *set = cls;
  struct SetCopyRequest *req;
  struct GNUNET_SET_Handle *new_set;

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
  new_set = create_internal (set->cfg,
			     GNUNET_SET_OPERATION_NONE,
			     &msg->cookie);
  req->cb (req->cls, new_set);
  GNUNET_free (req);
}


/**
 * Check that the given @a msg is well-formed.
 *
 * @param cls closure
 * @param msg message to check
 * @return #GNUNET_OK if message is well-formed
 */
static int
check_iter_element (void *cls,
		    const struct GNUNET_SET_IterResponseMessage *msg)
{
  /* minimum size was already checked, everything else is OK! */
  return GNUNET_OK;
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
                     const struct GNUNET_SET_IterResponseMessage *msg)
{
  struct GNUNET_SET_Handle *set = cls;
  GNUNET_SET_ElementIterator iter = set->iterator;
  struct GNUNET_SET_Element element;
  struct GNUNET_SET_IterAckMessage *ack_msg;
  struct GNUNET_MQ_Envelope *ev;
  uint16_t msize;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received element in set iteration\n");
  msize = ntohs (msg->header.size);
  if (set->iteration_id != ntohs (msg->iteration_id))
  {
    /* element from a previous iteration, skip! */
    iter = NULL;
  }
  if (NULL != iter)
  {
    element.size = msize - sizeof (struct GNUNET_SET_IterResponseMessage);
    element.element_type = ntohs (msg->element_type);
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
  {
    /* FIXME: if this is true, could cancel+start a fresh one
       cause elements to go to the wrong iteration? */
    LOG (GNUNET_ERROR_TYPE_INFO,
         "Service completed set iteration that was already cancelled\n");
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Set iteration completed\n");
  set->destroy_requested = GNUNET_SYSERR;
  set->iterator = NULL;
  set->iteration_id++;
  iter (set->iterator_cls,
        NULL);
  if (GNUNET_SYSERR == set->destroy_requested)
    set->destroy_requested = GNUNET_NO;
  if (GNUNET_YES == set->destroy_requested)
    GNUNET_SET_destroy (set);
}


/**
 * Check that the given @a msg is well-formed.
 *
 * @param cls closure
 * @param msg message to check
 * @return #GNUNET_OK if message is well-formed
 */
static int
check_result (void *cls,
	      const struct GNUNET_SET_ResultMessage *msg)
{
  /* minimum size was already checked, everything else is OK! */
  return GNUNET_OK;
}


/**
 * Handle result message for a set operation.
 *
 * @param cls the set
 * @param mh the message
 */
static void
handle_result (void *cls,
               const struct GNUNET_SET_ResultMessage *msg)
{
  struct GNUNET_SET_Handle *set = cls;
  struct GNUNET_SET_OperationHandle *oh;
  struct GNUNET_SET_Element e;
  enum GNUNET_SET_Status result_status;
  int destroy_set;

  GNUNET_assert (NULL != set->mq);
  result_status = (enum GNUNET_SET_Status) ntohs (msg->result_status);
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
  /* Need to do this calculation _before_ the result callback,
     as IF the application still has a valid set handle, it
     may trigger destruction of the set during the callback. */
  destroy_set = (GNUNET_YES == set->destroy_requested) &&
                (NULL == set->ops_head);
  if (NULL != oh->result_cb)
  {
    oh->result_cb (oh->result_cls,
                   NULL,
                   GNUNET_ntohll (msg->current_size),
                   result_status);
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "No callback for final status\n");
  }
  if (destroy_set)
    GNUNET_SET_destroy (set);
  GNUNET_free (oh);
  return;

do_element:
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Treating result as element\n");
  e.data = &msg[1];
  e.size = ntohs (msg->header.size) - sizeof (struct GNUNET_SET_ResultMessage);
  e.element_type = ntohs (msg->element_type);
  if (NULL != oh->result_cb)
    oh->result_cb (oh->result_cls,
                   &e,
                   GNUNET_ntohll (msg->current_size),
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

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Cancelling SET operation\n");
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
  GNUNET_SET_ElementIterator iter = set->iterator;

  LOG (GNUNET_ERROR_TYPE_ERROR,
       "Handling client set error %d\n",
       error);
  while (NULL != set->ops_head)
  {
    if (NULL != set->ops_head->result_cb)
      set->ops_head->result_cb (set->ops_head->result_cls,
                                NULL,
                                0,
                                GNUNET_SET_STATUS_FAILURE);
    set_operation_destroy (set->ops_head);
  }
  set->iterator = NULL;
  set->iteration_id++;
  set->invalid = GNUNET_YES;
  if (NULL != iter)
    iter (set->iterator_cls,
          NULL);
}


/**
 * FIXME.
 */
static struct GNUNET_SET_Handle *
create_internal (const struct GNUNET_CONFIGURATION_Handle *cfg,
                 enum GNUNET_SET_OperationType op,
                 const uint32_t *cookie)
{
  struct GNUNET_SET_Handle *set = GNUNET_new (struct GNUNET_SET_Handle);
  struct GNUNET_MQ_MessageHandler mq_handlers[] = {
    GNUNET_MQ_hd_var_size (result,
                           GNUNET_MESSAGE_TYPE_SET_RESULT,
                           struct GNUNET_SET_ResultMessage,
                           set),
    GNUNET_MQ_hd_var_size (iter_element,
                           GNUNET_MESSAGE_TYPE_SET_ITER_ELEMENT,
                           struct GNUNET_SET_IterResponseMessage,
                           set),
    GNUNET_MQ_hd_fixed_size (iter_done,
                             GNUNET_MESSAGE_TYPE_SET_ITER_DONE,
                             struct GNUNET_MessageHeader,
                             set),
    GNUNET_MQ_hd_fixed_size (copy_lazy,
                             GNUNET_MESSAGE_TYPE_SET_COPY_LAZY_RESPONSE,
                             struct GNUNET_SET_CopyLazyResponseMessage,
                             set),
    GNUNET_MQ_handler_end ()
  };
  struct GNUNET_MQ_Envelope *mqm;
  struct GNUNET_SET_CreateMessage *create_msg;
  struct GNUNET_SET_CopyLazyConnectMessage *copy_msg;

  set->cfg = cfg;
  set->mq = GNUNET_CLIENT_connect (cfg,
                                   "set",
                                   mq_handlers,
                                   &handle_client_set_error,
                                   set);
  if (NULL == set->mq)
  {
    GNUNET_free (set);
    return NULL;
  }
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
  GNUNET_MQ_send (set->mq,
                  mqm);
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
  struct GNUNET_SET_Handle *set;

  set = create_internal (cfg,
                          op,
                          NULL);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Creating set %p for operation %d\n",
       set,
       op);
  return set;
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

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "adding element of type %u to set %p\n",
       (unsigned int) element->element_type,
       set);
  if (GNUNET_YES == set->invalid)
  {
    if (NULL != cont)
      cont (cont_cls);
    return GNUNET_SYSERR;
  }
  mqm = GNUNET_MQ_msg_extra (msg,
                             element->size,
                             GNUNET_MESSAGE_TYPE_SET_ADD);
  msg->element_type = htons (element->element_type);
  GNUNET_memcpy (&msg[1],
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

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Removing element from set %p\n",
       set);
  if (GNUNET_YES == set->invalid)
  {
    if (NULL != cont)
      cont (cont_cls);
    return GNUNET_SYSERR;
  }
  mqm = GNUNET_MQ_msg_extra (msg,
                             element->size,
                             GNUNET_MESSAGE_TYPE_SET_REMOVE);
  msg->element_type = htons (element->element_type);
  GNUNET_memcpy (&msg[1],
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
  if ( (NULL != set->ops_head) ||
       (NULL != set->iterator) ||
       (GNUNET_SYSERR == set->destroy_requested) )
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Set operations are pending, delaying set destruction\n");
    set->destroy_requested = GNUNET_YES;
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Really destroying set\n");
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
                    struct GNUNET_SET_Option options[],
                    GNUNET_SET_ResultIterator result_cb,
                    void *result_cls)
{
  struct GNUNET_MQ_Envelope *mqm;
  struct GNUNET_SET_OperationHandle *oh;
  struct GNUNET_SET_EvaluateMessage *msg;
  struct GNUNET_SET_Option *opt;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Client prepares set operation (%d)\n",
       result_mode);
  oh = GNUNET_new (struct GNUNET_SET_OperationHandle);
  oh->result_cb = result_cb;
  oh->result_cls = result_cls;
  mqm = GNUNET_MQ_msg_nested_mh (msg,
                                 GNUNET_MESSAGE_TYPE_SET_EVALUATE,
                                 context_msg);
  msg->app_id = *app_id;
  msg->result_mode = htonl (result_mode);
  msg->target_peer = *other_peer;
  for (opt = options; opt->type != 0; opt++)
  {
    switch (opt->type)
    {
      case GNUNET_SET_OPTION_BYZANTINE:
        msg->byzantine = GNUNET_YES;
        msg->byzantine_lower_bound = opt->v.num;
        break;
      case GNUNET_SET_OPTION_FORCE_FULL:
        msg->force_full = GNUNET_YES;
        break;
      case GNUNET_SET_OPTION_FORCE_DELTA:
        msg->force_delta = GNUNET_YES;
        break;
      default:
        LOG (GNUNET_ERROR_TYPE_ERROR,
             "Option with type %d not recognized\n", (int) opt->type);
    }
  }
  oh->conclude_mqm = mqm;
  oh->request_id_addr = &msg->request_id;

  return oh;
}


/**
 * Connect to the set service in order to listen for requests.
 *
 * @param cls the `struct GNUNET_SET_ListenHandle *` to connect
 */
static void
listen_connect (void *cls);


/**
 * Check validity of request message for a listen operation
 *
 * @param cls the listen handle
 * @param msg the message
 * @return #GNUNET_OK if the message is well-formed
 */
static int
check_request (void *cls,
	       const struct GNUNET_SET_RequestMessage *msg)
{
  const struct GNUNET_MessageHeader *context_msg;

  if (ntohs (msg->header.size) == sizeof (*msg))
    return GNUNET_OK; /* no context message is OK */
  context_msg = GNUNET_MQ_extract_nested_mh (msg);
  if (NULL == context_msg)
  {
    /* malformed context message is NOT ok */
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handle request message for a listen operation
 *
 * @param cls the listen handle
 * @param msg the message
 */
static void
handle_request (void *cls,
                const struct GNUNET_SET_RequestMessage *msg)
{
  struct GNUNET_SET_ListenHandle *lh = cls;
  struct GNUNET_SET_Request req;
  const struct GNUNET_MessageHeader *context_msg;
  struct GNUNET_MQ_Envelope *mqm;
  struct GNUNET_SET_RejectMessage *rmsg;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Processing incoming operation request with id %u\n",
       ntohl (msg->accept_id));
  /* we got another valid request => reset the backoff */
  lh->reconnect_backoff = GNUNET_TIME_UNIT_MILLISECONDS;
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
       "Rejected request %u\n",
       ntohl (msg->accept_id));
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
  GNUNET_MQ_destroy (lh->mq);
  lh->mq = NULL;
  lh->reconnect_task = GNUNET_SCHEDULER_add_delayed (lh->reconnect_backoff,
                                                     &listen_connect,
						     lh);
  lh->reconnect_backoff = GNUNET_TIME_STD_BACKOFF (lh->reconnect_backoff);
}


/**
 * Connect to the set service in order to listen for requests.
 *
 * @param cls the `struct GNUNET_SET_ListenHandle *` to connect
 */
static void
listen_connect (void *cls)
{
  struct GNUNET_SET_ListenHandle *lh = cls;
  struct GNUNET_MQ_MessageHandler mq_handlers[] = {
    GNUNET_MQ_hd_var_size (request,
                           GNUNET_MESSAGE_TYPE_SET_REQUEST,
                           struct GNUNET_SET_RequestMessage,
                           lh),
    GNUNET_MQ_handler_end ()
  };
  struct GNUNET_MQ_Envelope *mqm;
  struct GNUNET_SET_ListenMessage *msg;

  lh->reconnect_task = NULL;
  GNUNET_assert (NULL == lh->mq);
  lh->mq = GNUNET_CLIENT_connect (lh->cfg,
                                  "set",
                                  mq_handlers,
                                  &handle_client_listener_error,
                                  lh);
  if (NULL == lh->mq)
    return;
  mqm = GNUNET_MQ_msg (msg, GNUNET_MESSAGE_TYPE_SET_LISTEN);
  msg->operation = htonl (lh->operation);
  msg->app_id = lh->app_id;
  GNUNET_MQ_send (lh->mq,
                  mqm);
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

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Starting listener for app %s\n",
       GNUNET_h2s (app_id));
  lh = GNUNET_new (struct GNUNET_SET_ListenHandle);
  lh->listen_cb = listen_cb;
  lh->listen_cls = listen_cls;
  lh->cfg = cfg;
  lh->operation = operation;
  lh->app_id = *app_id;
  lh->reconnect_backoff = GNUNET_TIME_UNIT_MILLISECONDS;
  listen_connect (lh);
  if (NULL == lh->mq)
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
       "Canceling listener %s\n",
       GNUNET_h2s (&lh->app_id));
  if (NULL != lh->mq)
  {
    GNUNET_MQ_destroy (lh->mq);
    lh->mq = NULL;
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
                   struct GNUNET_SET_Option options[],
                   GNUNET_SET_ResultIterator result_cb,
                   void *result_cls)
{
  struct GNUNET_MQ_Envelope *mqm;
  struct GNUNET_SET_OperationHandle *oh;
  struct GNUNET_SET_AcceptMessage *msg;

  GNUNET_assert (GNUNET_NO == request->accepted);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Client accepts set operation (%d) with id %u\n",
       result_mode,
       request->accept_id);
  request->accepted = GNUNET_YES;
  mqm = GNUNET_MQ_msg (msg,
                       GNUNET_MESSAGE_TYPE_SET_ACCEPT);
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
  if (NULL != oh->set)
  {
    /* Some other set was already commited for this
     * operation, there is a logic bug in the client of this API */
    GNUNET_break (0);
    return GNUNET_OK;
  }
  if (GNUNET_YES == set->invalid)
    return GNUNET_SYSERR;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Client commits to SET\n");
  GNUNET_assert (NULL != oh->conclude_mqm);
  oh->set = set;
  GNUNET_CONTAINER_DLL_insert (set->ops_head,
                               set->ops_tail,
                               oh);
  oh->request_id = GNUNET_MQ_assoc_add (set->mq,
                                        oh);
  *oh->request_id_addr = htonl (oh->request_id);
  GNUNET_MQ_send (set->mq,
                  oh->conclude_mqm);
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

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Creating lazy copy of set\n");
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
  GNUNET_memcpy (&copy[1],
                 element->data,
                 copy->size);
  return copy;
}


/**
 * Hash a set element.
 *
 * @param element the element that should be hashed
 * @param[out] ret_hash a pointer to where the hash of @a element
 *        should be stored
 */
void
GNUNET_SET_element_hash (const struct GNUNET_SET_Element *element,
			 struct GNUNET_HashCode *ret_hash)
{
  struct GNUNET_HashContext *ctx = GNUNET_CRYPTO_hash_context_start ();

  /* It's not guaranteed that the element data is always after the element header,
     so we need to hash the chunks separately. */
  GNUNET_CRYPTO_hash_context_read (ctx, &element->size, sizeof (uint16_t));
  GNUNET_CRYPTO_hash_context_read (ctx, &element->element_type, sizeof (uint16_t));
  GNUNET_CRYPTO_hash_context_read (ctx, element->data, element->size);
  GNUNET_CRYPTO_hash_context_finish (ctx, ret_hash);
}

/* end of set_api.c */
