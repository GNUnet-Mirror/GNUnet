/*
     This file is part of GNUnet.
     (C) 2012-2014 Christian Grothoff (and other contributing authors)

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
 * @author Florian Dold
 * @file util/mq.c
 * @brief general purpose request queue
 */
#include "platform.h"
#include "gnunet_util_lib.h"

#define LOG(kind,...) GNUNET_log_from (kind, "mq",__VA_ARGS__)


struct GNUNET_MQ_Envelope
{
  /**
   * Messages are stored in a linked list.
   * Each queue has its own list of envelopes.
   */
  struct GNUNET_MQ_Envelope *next;

  /**
   * Messages are stored in a linked list
   * Each queue has its own list of envelopes.
   */
  struct GNUNET_MQ_Envelope *prev;

  /**
   * Actual allocated message header,
   * usually points to the end of the containing GNUNET_MQ_Envelope
   */
  struct GNUNET_MessageHeader *mh;

  /**
   * Queue the message is queued in, NULL if message is not queued.
   */
  struct GNUNET_MQ_Handle *parent_queue;

  /**
   * Called after the message was sent irrevocably.
   */
  GNUNET_MQ_NotifyCallback sent_cb;

  /**
   * Closure for send_cb
   */
  void *sent_cls;
};


/**
 * Handle to a message queue.
 */
struct GNUNET_MQ_Handle
{
  /**
   * Handlers array, or NULL if the queue should not receive messages
   */
  const struct GNUNET_MQ_MessageHandler *handlers;

  /**
   * Closure for the handler callbacks,
   * as well as for the error handler.
   */
  void *handlers_cls;

  /**
   * Actual implementation of message sending,
   * called when a message is added
   */
  GNUNET_MQ_SendImpl send_impl;

  /**
   * Implementation-dependent queue destruction function
   */
  GNUNET_MQ_DestroyImpl destroy_impl;

  /**
   * Implementation-dependent send cancel function
   */
  GNUNET_MQ_CancelImpl cancel_impl;

  /**
   * Implementation-specific state
   */
  void *impl_state;

  /**
   * Callback will be called when an error occurs.
   */
  GNUNET_MQ_ErrorHandler error_handler;

  /**
   * Linked list of messages pending to be sent
   */
  struct GNUNET_MQ_Envelope *envelope_head;

  /**
   * Linked list of messages pending to be sent
   */
  struct GNUNET_MQ_Envelope *envelope_tail;

  /**
   * Message that is currently scheduled to be
   * sent. Not the head of the message queue, as the implementation
   * needs to know if sending has been already scheduled or not.
   */
  struct GNUNET_MQ_Envelope *current_envelope;

  /**
   * Map of associations, lazily allocated
   */
  struct GNUNET_CONTAINER_MultiHashMap32 *assoc_map;

  /**
   * Task scheduled during #GNUNET_MQ_impl_send_continue.
   */
  GNUNET_SCHEDULER_TaskIdentifier continue_task;

  /**
   * Next id that should be used for the assoc_map,
   * initialized lazily to a random value together with
   * assoc_map
   */
  uint32_t assoc_id;
};


/**
 * Implementation-specific state for connection to
 * client (MQ for server).
 */
struct ServerClientSocketState
{
  /**
   * Handle of the client that connected to the server.
   */
  struct GNUNET_SERVER_Client *client;

  /**
   * Active transmission request to the client.
   */
  struct GNUNET_SERVER_TransmitHandle* th;
};


/**
 * Implementation-specific state for connection to
 * service (MQ for clients).
 */
struct ClientConnectionState
{
  /**
   * Did we call receive alread alreadyy?
   */
  int receive_active;

  /**
   * Do we also want to receive?
   */
  int receive_requested;

  /**
   * Connection to the service.
   */
  struct GNUNET_CLIENT_Connection *connection;

  /**
   * Active transmission request (or NULL).
   */
  struct GNUNET_CLIENT_TransmitHandle *th;
};


/**
 * Call the message message handler that was registered
 * for the type of the given message in the given message queue.
 *
 * This function is indended to be used for the implementation
 * of message queues.
 *
 * @param mq message queue with the handlers
 * @param mh message to dispatch
 */
void
GNUNET_MQ_inject_message (struct GNUNET_MQ_Handle *mq,
                          const struct GNUNET_MessageHeader *mh)
{
  const struct GNUNET_MQ_MessageHandler *handler;
  int handled = GNUNET_NO;

  handler = mq->handlers;
  if (NULL == handler)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "No handler for message of type %d\n",
         ntohs (mh->type));
    return;
  }
  for (; NULL != handler->cb; handler++)
  {
    if (handler->type == ntohs (mh->type))
    {
      handler->cb (mq->handlers_cls, mh);
      handled = GNUNET_YES;
    }
  }

  if (GNUNET_NO == handled)
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "No handler for message of type %d\n",
         ntohs (mh->type));
}


/**
 * Call the error handler of a message queue with the given
 * error code.  If there is no error handler, log a warning.
 *
 * This function is intended to be used by the implementation
 * of message queues.
 *
 * @param mq message queue
 * @param error the error type
 */
void
GNUNET_MQ_inject_error (struct GNUNET_MQ_Handle *mq,
                        enum GNUNET_MQ_Error error)
{
  if (NULL == mq->error_handler)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "mq: got error %d, but no handler installed\n",
                (int) error);
    return;
  }
  mq->error_handler (mq->handlers_cls, error);
}


void
GNUNET_MQ_discard (struct GNUNET_MQ_Envelope *mqm)
{
  GNUNET_assert (NULL == mqm->parent_queue);
  GNUNET_free (mqm);
}


/**
 * Send a message with the give message queue.
 * May only be called once per message.
 *
 * @param mq message queue
 * @param ev the envelope with the message to send.
 */
void
GNUNET_MQ_send (struct GNUNET_MQ_Handle *mq,
                struct GNUNET_MQ_Envelope *ev)
{
  GNUNET_assert (NULL != mq);
  GNUNET_assert (NULL == ev->parent_queue);

  ev->parent_queue = mq;
  /* is the implementation busy? queue it! */
  if (NULL != mq->current_envelope)
  {
    GNUNET_CONTAINER_DLL_insert_tail (mq->envelope_head,
                                      mq->envelope_tail,
                                      ev);
    return;
  }
  mq->current_envelope = ev;
  mq->send_impl (mq, ev->mh, mq->impl_state);
}


/**
 * Task run to call the send implementation for the next queued
 * message, if any.  Only useful for implementing message queues,
 * results in undefined behavior if not used carefully.
 *
 * @param cls message queue to send the next message with
 * @param tc scheduler context
 */
static void
impl_send_continue (void *cls,
                    const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_MQ_Handle *mq = cls;
  struct GNUNET_MQ_Envelope *current_envelope;

  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;

  mq->continue_task = GNUNET_SCHEDULER_NO_TASK;
  /* call is only valid if we're actually currently sending
   * a message */
  current_envelope = mq->current_envelope;
  GNUNET_assert (NULL != current_envelope);
  current_envelope->parent_queue = NULL;
  if (NULL == mq->envelope_head)
  {
    mq->current_envelope = NULL;
  }
  else
  {
    mq->current_envelope = mq->envelope_head;
    GNUNET_CONTAINER_DLL_remove (mq->envelope_head,
                                 mq->envelope_tail,
                                 mq->current_envelope);
    mq->send_impl (mq, mq->current_envelope->mh, mq->impl_state);
  }
  if (NULL != current_envelope->sent_cb)
    current_envelope->sent_cb (current_envelope->sent_cls);
  GNUNET_free (current_envelope);
}


/**
 * Call the send implementation for the next queued message,
 * if any.
 * Only useful for implementing message queues,
 * results in undefined behavior if not used carefully.
 *
 * @param mq message queue to send the next message with
 */
void
GNUNET_MQ_impl_send_continue (struct GNUNET_MQ_Handle *mq)
{
  GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == mq->continue_task);
  mq->continue_task = GNUNET_SCHEDULER_add_now (&impl_send_continue,
                                                mq);
}


/**
 * Create a message queue for the specified handlers.
 *
 * @param send function the implements sending messages
 * @param destroy function that implements destroying the queue
 * @param cancel function that implements canceling a message
 * @param impl_state for the queue, passed to 'send' and 'destroy'
 * @param handlers array of message handlers
 * @param error_handler handler for read and write errors
 * @param cls closure for message handlers and error handler
 * @return a new message queue
 */
struct GNUNET_MQ_Handle *
GNUNET_MQ_queue_for_callbacks (GNUNET_MQ_SendImpl send,
                               GNUNET_MQ_DestroyImpl destroy,
                               GNUNET_MQ_CancelImpl cancel,
                               void *impl_state,
                               const struct GNUNET_MQ_MessageHandler *handlers,
                               GNUNET_MQ_ErrorHandler error_handler,
                               void *cls)
{
  struct GNUNET_MQ_Handle *mq;

  mq = GNUNET_new (struct GNUNET_MQ_Handle);
  mq->send_impl = send;
  mq->destroy_impl = destroy;
  mq->cancel_impl = cancel;
  mq->handlers = handlers;
  mq->handlers_cls = cls;
  mq->impl_state = impl_state;

  return mq;
}


/**
 * Get the message that should currently be sent.
 * Fails if there is no current message.
 * Only useful for implementing message queues,
 * results in undefined behavior if not used carefully.
 *
 * @param mq message queue with the current message
 * @return message to send, never NULL
 */
const struct GNUNET_MessageHeader *
GNUNET_MQ_impl_current (struct GNUNET_MQ_Handle *mq)
{
  if (NULL == mq->current_envelope)
    GNUNET_abort ();
  if (NULL == mq->current_envelope->mh)
    GNUNET_abort ();
  return mq->current_envelope->mh;
}


/**
 * Get the implementation state associated with the
 * message queue.
 *
 * While the GNUNET_MQ_Impl* callbacks receive the
 * implementation state, continuations that are scheduled
 * by the implementation function often only have one closure
 * argument, with this function it is possible to get at the
 * implementation state when only passing the GNUNET_MQ_Handle
 * as closure.
 *
 * @param mq message queue with the current message
 * @return message to send, never NULL
 */
void *
GNUNET_MQ_impl_state (struct GNUNET_MQ_Handle *mq)
{
  return mq->impl_state;
}


struct GNUNET_MQ_Envelope *
GNUNET_MQ_msg_ (struct GNUNET_MessageHeader **mhp,
                uint16_t size,
                uint16_t type)
{
  struct GNUNET_MQ_Envelope *mqm;

  mqm = GNUNET_malloc (sizeof *mqm + size);
  mqm->mh = (struct GNUNET_MessageHeader *) &mqm[1];
  mqm->mh->size = htons (size);
  mqm->mh->type = htons (type);
  if (NULL != mhp)
    *mhp = mqm->mh;
  return mqm;
}


/**
 * Implementation of the GNUNET_MQ_msg_nested_mh macro.
 *
 * @param mhp pointer to the message header pointer that will be changed to allocate at
 *        the newly allocated space for the message.
 * @param base_size size of the data before the nested message
 * @param type type of the message in the envelope
 * @param nested_mh the message to append to the message after base_size
 */
struct GNUNET_MQ_Envelope *
GNUNET_MQ_msg_nested_mh_ (struct GNUNET_MessageHeader **mhp,
                          uint16_t base_size,
                          uint16_t type,
                          const struct GNUNET_MessageHeader *nested_mh)
{
  struct GNUNET_MQ_Envelope *mqm;
  uint16_t size;

  if (NULL == nested_mh)
    return GNUNET_MQ_msg_ (mhp, base_size, type);

  size = base_size + ntohs (nested_mh->size);

  /* check for uint16_t overflow */
  if (size < base_size)
    return NULL;

  mqm = GNUNET_MQ_msg_ (mhp, size, type);
  memcpy ((char *) mqm->mh + base_size, nested_mh, ntohs (nested_mh->size));

  return mqm;
}


/**
 * Transmit a queued message to the session's client.
 *
 * @param cls consensus session
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t
transmit_queued (void *cls, size_t size,
                 void *buf)
{
  struct GNUNET_MQ_Handle *mq = cls;
  struct ServerClientSocketState *state = GNUNET_MQ_impl_state (mq);
  const struct GNUNET_MessageHeader *msg = GNUNET_MQ_impl_current (mq);
  size_t msg_size;

  GNUNET_assert (NULL != buf);

  msg_size = ntohs (msg->size);
  GNUNET_assert (size >= msg_size);
  memcpy (buf, msg, msg_size);
  state->th = NULL;

  GNUNET_MQ_impl_send_continue (mq);

  return msg_size;
}


static void
server_client_destroy_impl (struct GNUNET_MQ_Handle *mq,
                            void *impl_state)
{
  struct ServerClientSocketState *state = impl_state;

  if (NULL != state->th)
  {
    GNUNET_SERVER_notify_transmit_ready_cancel (state->th);
    state->th = NULL;
  }

  GNUNET_assert (NULL != mq);
  GNUNET_assert (NULL != state);
  GNUNET_SERVER_client_drop (state->client);
  GNUNET_free (state);
}


static void
server_client_send_impl (struct GNUNET_MQ_Handle *mq,
                         const struct GNUNET_MessageHeader *msg,
                         void *impl_state)
{
  struct ServerClientSocketState *state = impl_state;

  GNUNET_assert (NULL != mq);
  GNUNET_assert (NULL != state);
  state->th =
      GNUNET_SERVER_notify_transmit_ready (state->client, ntohs (msg->size),
                                           GNUNET_TIME_UNIT_FOREVER_REL,
                                           &transmit_queued, mq);
}


struct GNUNET_MQ_Handle *
GNUNET_MQ_queue_for_server_client (struct GNUNET_SERVER_Client *client)
{
  struct GNUNET_MQ_Handle *mq;
  struct ServerClientSocketState *scss;

  mq = GNUNET_new (struct GNUNET_MQ_Handle);
  scss = GNUNET_new (struct ServerClientSocketState);
  mq->impl_state = scss;
  scss->client = client;
  GNUNET_SERVER_client_keep (client);
  mq->send_impl = server_client_send_impl;
  mq->destroy_impl = server_client_destroy_impl;
  return mq;
}


/**
 * Type of a function to call when we receive a message
 * from the service.
 *
 * @param cls closure
 * @param msg message received, NULL on timeout or fatal error
 */
static void
handle_client_message (void *cls,
                       const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_MQ_Handle *mq = cls;
  struct ClientConnectionState *state;

  state = mq->impl_state;

  if (NULL == msg)
  {
    GNUNET_MQ_inject_error (mq, GNUNET_MQ_ERROR_READ);
    return;
  }

  GNUNET_CLIENT_receive (state->connection, handle_client_message, mq,
                         GNUNET_TIME_UNIT_FOREVER_REL);

  GNUNET_MQ_inject_message (mq, msg);
}


/**
 * Transmit a queued message to the session's client.
 *
 * @param cls consensus session
 * @param size number of bytes available in @a buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t
connection_client_transmit_queued (void *cls,
                                   size_t size,
                                   void *buf)
{
  struct GNUNET_MQ_Handle *mq = cls;
  const struct GNUNET_MessageHeader *msg;
  struct ClientConnectionState *state = mq->impl_state;
  size_t msg_size;

  GNUNET_assert (NULL != mq);
  msg = GNUNET_MQ_impl_current (mq);

  if (NULL == buf)
  {
    GNUNET_MQ_inject_error (mq, GNUNET_MQ_ERROR_READ);
    return 0;
  }

  if ( (GNUNET_YES == state->receive_requested) &&
       (GNUNET_NO == state->receive_active) )
  {
    state->receive_active = GNUNET_YES;
    GNUNET_CLIENT_receive (state->connection, handle_client_message, mq,
                           GNUNET_TIME_UNIT_FOREVER_REL);
  }

  msg_size = ntohs (msg->size);
  GNUNET_assert (size >= msg_size);
  memcpy (buf, msg, msg_size);
  state->th = NULL;

  GNUNET_MQ_impl_send_continue (mq);

  return msg_size;
}


static void
connection_client_destroy_impl (struct GNUNET_MQ_Handle *mq,
                                void *impl_state)
{
  GNUNET_free (impl_state);
}


static void
connection_client_send_impl (struct GNUNET_MQ_Handle *mq,
                             const struct GNUNET_MessageHeader *msg,
                             void *impl_state)
{
  struct ClientConnectionState *state = impl_state;

  GNUNET_assert (NULL != state);
  GNUNET_assert (NULL == state->th);
  state->th =
      GNUNET_CLIENT_notify_transmit_ready (state->connection, ntohs (msg->size),
                                           GNUNET_TIME_UNIT_FOREVER_REL, GNUNET_NO,
                                           &connection_client_transmit_queued, mq);
  GNUNET_assert (NULL != state->th);
}


static void
connection_client_cancel_impl (struct GNUNET_MQ_Handle *mq,
                               void *impl_state)
{
  struct ClientConnectionState *state = impl_state;
  GNUNET_assert (NULL != state->th);
  GNUNET_CLIENT_notify_transmit_ready_cancel (state->th);
  state->th = NULL;
}


struct GNUNET_MQ_Handle *
GNUNET_MQ_queue_for_connection_client (struct GNUNET_CLIENT_Connection *connection,
                                       const struct GNUNET_MQ_MessageHandler *handlers,
                                       GNUNET_MQ_ErrorHandler error_handler,
                                       void *cls)
{
  struct GNUNET_MQ_Handle *mq;
  struct ClientConnectionState *state;

  GNUNET_assert (NULL != connection);

  mq = GNUNET_new (struct GNUNET_MQ_Handle);
  mq->handlers = handlers;
  mq->error_handler = error_handler;
  mq->handlers_cls = cls;
  state = GNUNET_new (struct ClientConnectionState);
  state->connection = connection;
  mq->impl_state = state;
  mq->send_impl = connection_client_send_impl;
  mq->destroy_impl = connection_client_destroy_impl;
  mq->cancel_impl = connection_client_cancel_impl;
  if (NULL != handlers)
    state->receive_requested = GNUNET_YES;

  return mq;
}


void
GNUNET_MQ_replace_handlers (struct GNUNET_MQ_Handle *mq,
                            const struct GNUNET_MQ_MessageHandler *new_handlers,
                            void *cls)
{
  /* FIXME: notify implementation? */
  /* FIXME: what about NULL handlers? abort receive? */
  mq->handlers = new_handlers;
  mq->handlers_cls = cls;
}


/**
 * Associate the assoc_data in mq with a unique request id.
 *
 * @param mq message queue, id will be unique for the queue
 * @param assoc_data to associate
 */
uint32_t
GNUNET_MQ_assoc_add (struct GNUNET_MQ_Handle *mq,
                     void *assoc_data)
{
  uint32_t id;

  if (NULL == mq->assoc_map)
  {
    mq->assoc_map = GNUNET_CONTAINER_multihashmap32_create (8);
    mq->assoc_id = 1;
  }
  id = mq->assoc_id++;
  GNUNET_CONTAINER_multihashmap32_put (mq->assoc_map, id, assoc_data,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
  return id;
}


void *
GNUNET_MQ_assoc_get (struct GNUNET_MQ_Handle *mq,
                     uint32_t request_id)
{
  if (NULL == mq->assoc_map)
    return NULL;
  return GNUNET_CONTAINER_multihashmap32_get (mq->assoc_map, request_id);
}


void *
GNUNET_MQ_assoc_remove (struct GNUNET_MQ_Handle *mq,
                        uint32_t request_id)
{
  void *val;

  if (NULL == mq->assoc_map)
    return NULL;
  val = GNUNET_CONTAINER_multihashmap32_get (mq->assoc_map, request_id);
  GNUNET_CONTAINER_multihashmap32_remove_all (mq->assoc_map, request_id);
  return val;
}


void
GNUNET_MQ_notify_sent (struct GNUNET_MQ_Envelope *mqm,
                       GNUNET_MQ_NotifyCallback cb,
                       void *cls)
{
  mqm->sent_cb = cb;
  mqm->sent_cls = cls;
}


void
GNUNET_MQ_destroy (struct GNUNET_MQ_Handle *mq)
{
  if (NULL != mq->destroy_impl)
  {
    mq->destroy_impl (mq, mq->impl_state);
  }
  if (GNUNET_SCHEDULER_NO_TASK != mq->continue_task)
  {
    GNUNET_SCHEDULER_cancel (mq->continue_task);
    mq->continue_task = GNUNET_SCHEDULER_NO_TASK;
  }
  while (NULL != mq->envelope_head)
  {
    struct GNUNET_MQ_Envelope *ev;
    ev = mq->envelope_head;
    ev->parent_queue = NULL;
    GNUNET_CONTAINER_DLL_remove (mq->envelope_head, mq->envelope_tail, ev);
    GNUNET_MQ_discard (ev);
  }

  if (NULL != mq->current_envelope)
  {
    /* we can only discard envelopes that
     * are not queued! */
    mq->current_envelope->parent_queue = NULL;
    GNUNET_MQ_discard (mq->current_envelope);
    mq->current_envelope = NULL;
  }

  if (NULL != mq->assoc_map)
  {
    GNUNET_CONTAINER_multihashmap32_destroy (mq->assoc_map);
    mq->assoc_map = NULL;
  }

  GNUNET_free (mq);
}


const struct GNUNET_MessageHeader *
GNUNET_MQ_extract_nested_mh_ (const struct GNUNET_MessageHeader *mh,
                              uint16_t base_size)
{
  uint16_t whole_size;
  uint16_t nested_size;
  const struct GNUNET_MessageHeader *nested_msg;

  whole_size = ntohs (mh->size);
  GNUNET_assert (whole_size >= base_size);
  nested_size = whole_size - base_size;
  if (0 == nested_size)
    return NULL;
  if (nested_size < sizeof (struct GNUNET_MessageHeader))
  {
    GNUNET_break_op (0);
    return NULL;
  }
  nested_msg = (const struct GNUNET_MessageHeader *) ((char *) mh + base_size);
  if (ntohs (nested_msg->size) != nested_size)
  {
    GNUNET_break_op (0);
    return NULL;
  }
  return nested_msg;
}


/**
 * Cancel sending the message. Message must have been sent with
 * #GNUNET_MQ_send before.  May not be called after the notify sent
 * callback has been called
 *
 * @param ev queued envelope to cancel
 */
void
GNUNET_MQ_send_cancel (struct GNUNET_MQ_Envelope *ev)
{
  struct GNUNET_MQ_Handle *mq = ev->parent_queue;

  GNUNET_assert (NULL != mq);
  GNUNET_assert (NULL != mq->cancel_impl);

  if (mq->current_envelope == ev) {
    // complex case, we already started with transmitting
    // the message
    mq->cancel_impl (mq, mq->impl_state);
    // continue sending the next message, if any
    if (NULL == mq->envelope_head)
    {
      mq->current_envelope = NULL;
    }
    else
    {
      mq->current_envelope = mq->envelope_head;
      GNUNET_CONTAINER_DLL_remove (mq->envelope_head,
                                   mq->envelope_tail,
                                   mq->current_envelope);
      mq->send_impl (mq, mq->current_envelope->mh, mq->impl_state);
    }
  } else {
    // simple case, message is still waiting in the queue
    GNUNET_CONTAINER_DLL_remove (mq->envelope_head, mq->envelope_tail, ev);
  }

  ev->parent_queue = NULL;
  ev->mh = NULL;
  GNUNET_free (ev);
}

/* end of mq.c */
