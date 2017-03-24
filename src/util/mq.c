/*
     This file is part of GNUnet.
     Copyright (C) 2012-2017 GNUnet e.V.

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
 * @author Florian Dold
 * @file util/mq.c
 * @brief general purpose request queue
 */
#include "platform.h"
#include "gnunet_util_lib.h"

#define LOG(kind,...) GNUNET_log_from (kind, "util-mq",__VA_ARGS__)


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
   * Actual allocated message header.
   * The GNUNET_MQ_Envelope header is allocated at
   * the end of the message.
   */
  struct GNUNET_MessageHeader *mh;

  /**
   * Queue the message is queued in, NULL if message is not queued.
   */
  struct GNUNET_MQ_Handle *parent_queue;

  /**
   * Called after the message was sent irrevocably.
   */
  GNUNET_SCHEDULER_TaskCallback sent_cb;

  /**
   * Closure for @e send_cb
   */
  void *sent_cls;

  /**
   * Flags that were set for this envelope by
   * #GNUNET_MQ_env_set_options().   Only valid if
   * @e have_custom_options is set.
   */
  uint64_t flags;

  /**
   * Additional options buffer set for this envelope by
   * #GNUNET_MQ_env_set_options().  Only valid if
   * @e have_custom_options is set.
   */
  const void *extra;

  /**
   * Did the application call #GNUNET_MQ_env_set_options()?
   */
  int have_custom_options;
};


/**
 * Handle to a message queue.
 */
struct GNUNET_MQ_Handle
{
  /**
   * Handlers array, or NULL if the queue should not receive messages
   */
  struct GNUNET_MQ_MessageHandler *handlers;

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
   * Closure for the error handler.
   */
  void *error_handler_cls;

  /**
   * Task to asynchronously run #impl_send_continue().
   */
  struct GNUNET_SCHEDULER_Task *send_task;

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
   * Functions to call on queue destruction; kept in a DLL.
   */
  struct GNUNET_MQ_DestroyNotificationHandle *dnh_head;

  /**
   * Functions to call on queue destruction; kept in a DLL.
   */
  struct GNUNET_MQ_DestroyNotificationHandle *dnh_tail;

  /**
   * Additional options buffer set for this queue by
   * #GNUNET_MQ_set_options().  Default is 0.
   */
  const void *default_extra;

  /**
   * Flags that were set for this queue by
   * #GNUNET_MQ_set_options().   Default is 0.
   */
  uint64_t default_flags;

  /**
   * Next id that should be used for the @e assoc_map,
   * initialized lazily to a random value together with
   * @e assoc_map
   */
  uint32_t assoc_id;

  /**
   * Number of entries we have in the envelope-DLL.
   */
  unsigned int queue_length;

  /**
   * #GNUNET_YES if GNUNET_MQ_impl_evacuate was called.
   * FIXME: is this dead?
   */
  int evacuate_called;

  /**
   * #GNUNET_YES if GNUNET_MQ_impl_send_in_flight() was called.
   */
  int in_flight;
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
  uint16_t msize = ntohs (mh->size);
  uint16_t mtype = ntohs (mh->type);

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received message of type %u and size %u\n",
       mtype, msize);

  if (NULL == mq->handlers)
    goto done;
  for (handler = mq->handlers; NULL != handler->cb; handler++)
  {
    if (handler->type == mtype)
    {
      handled = GNUNET_YES;
      if ( (handler->expected_size > msize) ||
	   ( (handler->expected_size != msize) &&
	     (NULL == handler->mv) ) )
      {
	/* Too small, or not an exact size and
	   no 'mv' handler to check rest */
        LOG (GNUNET_ERROR_TYPE_ERROR,
             "Received malformed message of type %u\n",
             (unsigned int) handler->type);
	GNUNET_MQ_inject_error (mq,
				GNUNET_MQ_ERROR_MALFORMED);
	break;
      }
      if ( (NULL == handler->mv) ||
	   (GNUNET_OK ==
	    handler->mv (handler->cls, mh)) )
      {
	/* message well-formed, pass to handler */
	handler->cb (handler->cls, mh);
      }
      else
      {
	/* Message rejected by check routine */
        LOG (GNUNET_ERROR_TYPE_ERROR,
             "Received malformed message of type %u\n",
             (unsigned int) handler->type);
	GNUNET_MQ_inject_error (mq,
				GNUNET_MQ_ERROR_MALFORMED);
      }
      break;
    }
  }
 done:
  if (GNUNET_NO == handled)
    LOG (GNUNET_ERROR_TYPE_INFO,
         "No handler for message of type %u and size %u\n",
         mtype, msize);
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
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Got error %d, but no handler installed\n",
         (int) error);
    return;
  }
  mq->error_handler (mq->error_handler_cls,
                     error);
}


/**
 * Discard the message queue message, free all
 * allocated resources. Must be called in the event
 * that a message is created but should not actually be sent.
 *
 * @param mqm the message to discard
 */
void
GNUNET_MQ_discard (struct GNUNET_MQ_Envelope *ev)
{
  GNUNET_assert (NULL == ev->parent_queue);
  GNUNET_free (ev);
}


/**
 * Obtain the current length of the message queue.
 *
 * @param mq queue to inspect
 * @return number of queued, non-transmitted messages
 */
unsigned int
GNUNET_MQ_get_length (struct GNUNET_MQ_Handle *mq)
{
  if (GNUNET_YES != mq->in_flight)
  {
    return mq->queue_length;
  }
  return mq->queue_length - 1;
}


/**
 * Send a message with the given message queue.
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

  mq->queue_length++;
  GNUNET_break (mq->queue_length < 10000); /* This would seem like a bug... */
  ev->parent_queue = mq;
  /* is the implementation busy? queue it! */
  if ( (NULL != mq->current_envelope) ||
       (NULL != mq->send_task) )
  {
    GNUNET_CONTAINER_DLL_insert_tail (mq->envelope_head,
                                      mq->envelope_tail,
                                      ev);
    return;
  }
  GNUNET_assert (NULL == mq->envelope_head);
  mq->current_envelope = ev;
  mq->send_impl (mq,
		 ev->mh,
		 mq->impl_state);
}


/**
 * Remove the first envelope that has not yet been sent from the message
 * queue and return it.
 *
 * @param mq queue to remove envelope from
 * @return NULL if queue is empty (or has no envelope that is not under transmission)
 */
struct GNUNET_MQ_Envelope *
GNUNET_MQ_unsent_head (struct GNUNET_MQ_Handle *mq)
{
  struct GNUNET_MQ_Envelope *env;

  env = mq->envelope_head;
  GNUNET_CONTAINER_DLL_remove (mq->envelope_head,
                               mq->envelope_tail,
                               env);
  mq->queue_length--;
  env->parent_queue = NULL;
  return env;
}


/**
 * Function to copy an envelope.  The envelope must not yet
 * be in any queue or have any options or callbacks set.
 *
 * @param env envelope to copy
 * @return copy of @a env
 */
struct GNUNET_MQ_Envelope *
GNUNET_MQ_env_copy (struct GNUNET_MQ_Envelope *env)
{
  GNUNET_assert (NULL == env->next);
  GNUNET_assert (NULL == env->parent_queue);
  GNUNET_assert (NULL == env->sent_cb);
  GNUNET_assert (GNUNET_NO == env->have_custom_options);
  return GNUNET_MQ_msg_copy (env->mh);
}


/**
 * Send a copy of a message with the given message queue.
 * Can be called repeatedly on the same envelope.
 *
 * @param mq message queue
 * @param ev the envelope with the message to send.
 */
void
GNUNET_MQ_send_copy (struct GNUNET_MQ_Handle *mq,
                     const struct GNUNET_MQ_Envelope *ev)
{
  struct GNUNET_MQ_Envelope *env;
  uint16_t msize;

  msize = ntohs (ev->mh->size);
  env = GNUNET_malloc (sizeof (struct GNUNET_MQ_Envelope) +
                       msize);
  env->mh = (struct GNUNET_MessageHeader *) &env[1];
  env->sent_cb = ev->sent_cb;
  env->sent_cls = ev->sent_cls;
  GNUNET_memcpy (&env[1],
          ev->mh,
          msize);
  GNUNET_MQ_send (mq,
                  env);
}


/**
 * Task run to call the send implementation for the next queued
 * message, if any.  Only useful for implementing message queues,
 * results in undefined behavior if not used carefully.
 *
 * @param cls message queue to send the next message with
 */
static void
impl_send_continue (void *cls)
{
  struct GNUNET_MQ_Handle *mq = cls;

  mq->send_task = NULL;
  /* call is only valid if we're actually currently sending
   * a message */
  if (NULL == mq->envelope_head)
    return;
  mq->current_envelope = mq->envelope_head;
  GNUNET_CONTAINER_DLL_remove (mq->envelope_head,
			       mq->envelope_tail,
			       mq->current_envelope);
  mq->send_impl (mq,
		 mq->current_envelope->mh,
		 mq->impl_state);
}


/**
 * Call the send implementation for the next queued message, if any.
 * Only useful for implementing message queues, results in undefined
 * behavior if not used carefully.
 *
 * @param mq message queue to send the next message with
 */
void
GNUNET_MQ_impl_send_continue (struct GNUNET_MQ_Handle *mq)
{
  struct GNUNET_MQ_Envelope *current_envelope;
  GNUNET_SCHEDULER_TaskCallback cb;

  GNUNET_assert (0 < mq->queue_length);
  mq->queue_length--;
  mq->in_flight = GNUNET_NO;
  current_envelope = mq->current_envelope;
  current_envelope->parent_queue = NULL;
  mq->current_envelope = NULL;
  GNUNET_assert (NULL == mq->send_task);
  mq->send_task = GNUNET_SCHEDULER_add_now (&impl_send_continue,
					    mq);
  if (NULL != (cb = current_envelope->sent_cb))
  {
    current_envelope->sent_cb = NULL;
    cb (current_envelope->sent_cls);
  }
  GNUNET_free (current_envelope);
}


/**
 * Call the send notification for the current message, but do not
 * try to send the next message until #GNUNET_MQ_impl_send_continue
 * is called.
 *
 * Only useful for implementing message queues, results in undefined
 * behavior if not used carefully.
 *
 * @param mq message queue to send the next message with
 */
void
GNUNET_MQ_impl_send_in_flight (struct GNUNET_MQ_Handle *mq)
{
  struct GNUNET_MQ_Envelope *current_envelope;
  GNUNET_SCHEDULER_TaskCallback cb;

  mq->in_flight = GNUNET_YES;
  /* call is only valid if we're actually currently sending
   * a message */
  current_envelope = mq->current_envelope;
  GNUNET_assert (NULL != current_envelope);
  /* can't call cancel from now on anymore */
  current_envelope->parent_queue = NULL;
  if (NULL != (cb = current_envelope->sent_cb))
  {
    current_envelope->sent_cb = NULL;
    cb (current_envelope->sent_cls);
  }
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
 * @param error_handler_cls closure for @a error_handler
 * @return a new message queue
 */
struct GNUNET_MQ_Handle *
GNUNET_MQ_queue_for_callbacks (GNUNET_MQ_SendImpl send,
                               GNUNET_MQ_DestroyImpl destroy,
                               GNUNET_MQ_CancelImpl cancel,
                               void *impl_state,
                               const struct GNUNET_MQ_MessageHandler *handlers,
                               GNUNET_MQ_ErrorHandler error_handler,
                               void *error_handler_cls)
{
  struct GNUNET_MQ_Handle *mq;

  mq = GNUNET_new (struct GNUNET_MQ_Handle);
  mq->send_impl = send;
  mq->destroy_impl = destroy;
  mq->cancel_impl = cancel;
  mq->handlers = GNUNET_MQ_copy_handlers (handlers);
  mq->error_handler = error_handler;
  mq->error_handler_cls = error_handler_cls;
  mq->impl_state = impl_state;

  return mq;
}


/**
 * Change the closure argument in all of the `handlers` of the
 * @a mq.
 *
 * @param mq to modify
 * @param handlers_cls new closure to use
 */
void
GNUNET_MQ_set_handlers_closure (struct GNUNET_MQ_Handle *mq,
                                void *handlers_cls)
{
  unsigned int i;

  if (NULL == mq->handlers)
    return;
  for (i=0;NULL != mq->handlers[i].cb; i++)
    mq->handlers[i].cls = handlers_cls;
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
  GNUNET_assert (NULL != mq->current_envelope);
  GNUNET_assert (NULL != mq->current_envelope->mh);
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
  struct GNUNET_MQ_Envelope *ev;

  ev = GNUNET_malloc (size + sizeof (struct GNUNET_MQ_Envelope));
  ev->mh = (struct GNUNET_MessageHeader *) &ev[1];
  ev->mh->size = htons (size);
  ev->mh->type = htons (type);
  if (NULL != mhp)
    *mhp = ev->mh;
  return ev;
}


/**
 * Create a new envelope by copying an existing message.
 *
 * @param hdr header of the message to copy
 * @return envelope containing @a hdr
 */
struct GNUNET_MQ_Envelope *
GNUNET_MQ_msg_copy (const struct GNUNET_MessageHeader *hdr)
{
  struct GNUNET_MQ_Envelope *mqm;
  uint16_t size = ntohs (hdr->size);

  mqm = GNUNET_malloc (sizeof (*mqm) + size);
  mqm->mh = (struct GNUNET_MessageHeader *) &mqm[1];
  GNUNET_memcpy (mqm->mh,
          hdr,
          size);
  return mqm;
}


/**
 * Implementation of the #GNUNET_MQ_msg_nested_mh macro.
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
  GNUNET_memcpy ((char *) mqm->mh + base_size,
		 nested_mh,
		 ntohs (nested_mh->size));

  return mqm;
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
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multihashmap32_put (mq->assoc_map,
                                                      id,
                                                      assoc_data,
                                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  return id;
}


/**
 * Get the data associated with a @a request_id in a queue
 *
 * @param mq the message queue with the association
 * @param request_id the request id we are interested in
 * @return the associated data
 */
void *
GNUNET_MQ_assoc_get (struct GNUNET_MQ_Handle *mq,
                     uint32_t request_id)
{
  if (NULL == mq->assoc_map)
    return NULL;
  return GNUNET_CONTAINER_multihashmap32_get (mq->assoc_map,
                                              request_id);
}


/**
 * Remove the association for a @a request_id
 *
 * @param mq the message queue with the association
 * @param request_id the request id we want to remove
 * @return the associated data
 */
void *
GNUNET_MQ_assoc_remove (struct GNUNET_MQ_Handle *mq,
                        uint32_t request_id)
{
  void *val;

  if (NULL == mq->assoc_map)
    return NULL;
  val = GNUNET_CONTAINER_multihashmap32_get (mq->assoc_map,
					     request_id);
  GNUNET_CONTAINER_multihashmap32_remove_all (mq->assoc_map,
					      request_id);
  return val;
}


/**
 * Call a callback once the envelope has been sent, that is,
 * sending it can not be canceled anymore.
 * There can be only one notify sent callback per envelope.
 *
 * @param ev message to call the notify callback for
 * @param cb the notify callback
 * @param cb_cls closure for the callback
 */
void
GNUNET_MQ_notify_sent (struct GNUNET_MQ_Envelope *ev,
                       GNUNET_SCHEDULER_TaskCallback cb,
                       void *cb_cls)
{
  GNUNET_assert (NULL == ev->sent_cb);
  ev->sent_cb = cb;
  ev->sent_cls = cb_cls;
}


/**
 * Handle we return for callbacks registered to be
 * notified when #GNUNET_MQ_destroy() is called on a queue.
 */
struct GNUNET_MQ_DestroyNotificationHandle
{
  /**
   * Kept in a DLL.
   */
  struct GNUNET_MQ_DestroyNotificationHandle *prev;

  /**
   * Kept in a DLL.
   */
  struct GNUNET_MQ_DestroyNotificationHandle *next;

  /**
   * Queue to notify about.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Function to call.
   */
  GNUNET_SCHEDULER_TaskCallback cb;

  /**
   * Closure for @e cb.
   */
  void *cb_cls;
};


/**
 * Destroy the message queue.
 *
 * @param mq message queue to destroy
 */
void
GNUNET_MQ_destroy (struct GNUNET_MQ_Handle *mq)
{
  struct GNUNET_MQ_DestroyNotificationHandle *dnh;

  if (NULL != mq->destroy_impl)
  {
    mq->destroy_impl (mq, mq->impl_state);
  }
  if (NULL != mq->send_task)
  {
    GNUNET_SCHEDULER_cancel (mq->send_task);
    mq->send_task = NULL;
  }
  while (NULL != mq->envelope_head)
  {
    struct GNUNET_MQ_Envelope *ev;

    ev = mq->envelope_head;
    ev->parent_queue = NULL;
    GNUNET_CONTAINER_DLL_remove (mq->envelope_head,
				 mq->envelope_tail,
				 ev);
    GNUNET_assert (0 < mq->queue_length);
    mq->queue_length--;
    GNUNET_MQ_discard (ev);
  }
  if (NULL != mq->current_envelope)
  {
    /* we can only discard envelopes that
     * are not queued! */
    mq->current_envelope->parent_queue = NULL;
    GNUNET_MQ_discard (mq->current_envelope);
    mq->current_envelope = NULL;
    GNUNET_assert (0 < mq->queue_length);
    mq->queue_length--;
  }
  GNUNET_assert (0 == mq->queue_length);
  while (NULL != (dnh = mq->dnh_head))
  {
    dnh->cb (dnh->cb_cls);
    GNUNET_MQ_destroy_notify_cancel (dnh);
  }
  if (NULL != mq->assoc_map)
  {
    GNUNET_CONTAINER_multihashmap32_destroy (mq->assoc_map);
    mq->assoc_map = NULL;
  }
  GNUNET_free_non_null (mq->handlers);
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

  mq->evacuate_called = GNUNET_NO;

  if (mq->current_envelope == ev)
  {
    /* complex case, we already started with transmitting
       the message using the callbacks. */
    GNUNET_assert (0 < mq->queue_length);
    mq->queue_length--;
    mq->cancel_impl (mq,
		     mq->impl_state);
    /* continue sending the next message, if any */
    mq->current_envelope = mq->envelope_head;
    if (NULL != mq->current_envelope)
    {
      GNUNET_CONTAINER_DLL_remove (mq->envelope_head,
                                   mq->envelope_tail,
                                   mq->current_envelope);
      mq->send_impl (mq,
		     mq->current_envelope->mh,
		     mq->impl_state);
    }
  }
  else
  {
    /* simple case, message is still waiting in the queue */
    GNUNET_CONTAINER_DLL_remove (mq->envelope_head,
				 mq->envelope_tail,
				 ev);
    GNUNET_assert (0 < mq->queue_length);
    mq->queue_length--;
  }

  if (GNUNET_YES != mq->evacuate_called)
  {
    ev->parent_queue = NULL;
    ev->mh = NULL;
    /* also frees ev */
    GNUNET_free (ev);
  }
}


/**
 * Function to obtain the current envelope
 * from within #GNUNET_MQ_SendImpl implementations.
 *
 * @param mq message queue to interrogate
 * @return the current envelope
 */
struct GNUNET_MQ_Envelope *
GNUNET_MQ_get_current_envelope (struct GNUNET_MQ_Handle *mq)
{
  return mq->current_envelope;
}


/**
 * Function to obtain the last envelope in the queue.
 *
 * @param mq message queue to interrogate
 * @return the last envelope in the queue
 */
struct GNUNET_MQ_Envelope *
GNUNET_MQ_get_last_envelope (struct GNUNET_MQ_Handle *mq)
{
  if (NULL != mq->envelope_tail)
    return mq->envelope_tail;

  return mq->current_envelope;
}


/**
 * Set application-specific options for this envelope.
 * Overrides the options set for the queue with
 * #GNUNET_MQ_set_options() for this message only.
 *
 * @param env message to set options for
 * @param flags flags to use (meaning is queue-specific)
 * @param extra additional buffer for further data (also queue-specific)
 */
void
GNUNET_MQ_env_set_options (struct GNUNET_MQ_Envelope *env,
			   uint64_t flags,
			   const void *extra)
{
  env->flags = flags;
  env->extra = extra;
  env->have_custom_options = GNUNET_YES;
}


/**
 * Get application-specific options for this envelope.
 *
 * @param env message to set options for
 * @param[out] flags set to flags to use (meaning is queue-specific)
 * @return extra additional buffer for further data (also queue-specific)
 */
const void *
GNUNET_MQ_env_get_options (struct GNUNET_MQ_Envelope *env,
			   uint64_t *flags)
{
  struct GNUNET_MQ_Handle *mq = env->parent_queue;

  if (GNUNET_YES == env->have_custom_options)
  {
    *flags = env->flags;
    return env->extra;
  }
  if (NULL == mq)
  {
    *flags = 0;
    return NULL;
  }
  *flags = mq->default_flags;
  return mq->default_extra;
}


/**
 * Set application-specific options for this queue.
 *
 * @param mq message queue to set options for
 * @param flags flags to use (meaning is queue-specific)
 * @param extra additional buffer for further data (also queue-specific)
 */
void
GNUNET_MQ_set_options (struct GNUNET_MQ_Handle *mq,
		       uint64_t flags,
		       const void *extra)
{
  mq->default_flags = flags;
  mq->default_extra = extra;
}


/**
 * Register function to be called whenever @a mq is being
 * destroyed.
 *
 * @param mq message queue to watch
 * @param cb function to call on @a mq destruction
 * @param cb_cls closure for @a cb
 * @return handle for #GNUNET_MQ_destroy_notify_cancel().
 */
struct GNUNET_MQ_DestroyNotificationHandle *
GNUNET_MQ_destroy_notify (struct GNUNET_MQ_Handle *mq,
			  GNUNET_SCHEDULER_TaskCallback cb,
			  void *cb_cls)
{
  struct GNUNET_MQ_DestroyNotificationHandle *dnh;

  dnh = GNUNET_new (struct GNUNET_MQ_DestroyNotificationHandle);
  dnh->mq = mq;
  dnh->cb = cb;
  dnh->cb_cls = cb_cls;
  GNUNET_CONTAINER_DLL_insert (mq->dnh_head,
			       mq->dnh_tail,
			       dnh);
  return dnh;
}


/**
 * Cancel registration from #GNUNET_MQ_destroy_notify().
 *
 * @param dnh handle for registration to cancel
 */
void
GNUNET_MQ_destroy_notify_cancel (struct GNUNET_MQ_DestroyNotificationHandle *dnh)
{
  struct GNUNET_MQ_Handle *mq = dnh->mq;

  GNUNET_CONTAINER_DLL_remove (mq->dnh_head,
			       mq->dnh_tail,
			       dnh);
  GNUNET_free (dnh);
}


/**
 * Insert @a env into the envelope DLL starting at @a env_head
 * Note that @a env must not be in any MQ while this function
 * is used with DLLs defined outside of the MQ module.  This
 * is just in case some application needs to also manage a
 * FIFO of envelopes independent of MQ itself and wants to
 * re-use the pointers internal to @a env.  Use with caution.
 *
 * @param[in|out] env_head of envelope DLL
 * @param[in|out] env_tail tail of envelope DLL
 * @param[in|out] env element to insert at the tail
 */
void
GNUNET_MQ_dll_insert_tail (struct GNUNET_MQ_Envelope **env_head,
                           struct GNUNET_MQ_Envelope **env_tail,
                           struct GNUNET_MQ_Envelope *env)
{
  GNUNET_CONTAINER_DLL_insert_tail (*env_head,
                                    *env_tail,
                                    env);
}


/**
 * Remove @a env from the envelope DLL starting at @a env_head.
 * Note that @a env must not be in any MQ while this function
 * is used with DLLs defined outside of the MQ module. This
 * is just in case some application needs to also manage a
 * FIFO of envelopes independent of MQ itself and wants to
 * re-use the pointers internal to @a env.  Use with caution.
 *
 * @param[in|out] env_head of envelope DLL
 * @param[in|out] env_tail tail of envelope DLL
 * @param[in|out] env element to remove from the DLL
 */
void
GNUNET_MQ_dll_remove (struct GNUNET_MQ_Envelope **env_head,
                      struct GNUNET_MQ_Envelope **env_tail,
                      struct GNUNET_MQ_Envelope *env)
{
  GNUNET_CONTAINER_DLL_remove (*env_head,
                               *env_tail,
                               env);
}


/**
 * Copy an array of handlers.
 *
 * Useful if the array has been delared in local memory and needs to be
 * persisted for future use.
 *
 * @param handlers Array of handlers to be copied. Can be NULL (nothing done).
 * @return A newly allocated array of handlers.
 *         Needs to be freed with #GNUNET_free.
 */
struct GNUNET_MQ_MessageHandler *
GNUNET_MQ_copy_handlers (const struct GNUNET_MQ_MessageHandler *handlers)
{
  struct GNUNET_MQ_MessageHandler *copy;
  unsigned int count;

  if (NULL == handlers)
    return NULL;

  count = GNUNET_MQ_count_handlers (handlers);
  copy = GNUNET_new_array (count + 1,
                           struct GNUNET_MQ_MessageHandler);
  GNUNET_memcpy (copy,
                 handlers,
                 count * sizeof (struct GNUNET_MQ_MessageHandler));
  return copy;
}


/**
 * Count the handlers in a handler array.
 *
 * @param handlers Array of handlers to be counted.
 * @return The number of handlers in the array.
 */
unsigned int
GNUNET_MQ_count_handlers (const struct GNUNET_MQ_MessageHandler *handlers)
{
  unsigned int i;

  if (NULL == handlers)
    return 0;

  for (i=0; NULL != handlers[i].cb; i++) ;

  return i;
}



/* end of mq.c */
