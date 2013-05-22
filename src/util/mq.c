/*
     This file is part of GNUnet.
     (C) 2012 Christian Grothoff (and other contributing authors)

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
 * @author Florian Dold
 * @file util/mq.c
 * @brief general purpose request queue
 */

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_util_lib.h"

#define LOG(kind,...) GNUNET_log_from (kind, "mq",__VA_ARGS__)



struct ServerClientSocketState
{
  struct GNUNET_SERVER_Client *client;
  struct GNUNET_SERVER_TransmitHandle* th;
};


struct ClientConnectionState
{
  /**
   * Did we call receive?
   */
  int receive_active;
  struct GNUNET_CLIENT_Connection *connection;
  struct GNUNET_CLIENT_TransmitHandle *th;
};




/**
 * Call the right callback for a message.
 *
 * @param mq message queue with the handlers
 * @param mh message to dispatch
 */
void
GNUNET_MQ_dispatch (struct GNUNET_MQ_MessageQueue *mq, const struct GNUNET_MessageHeader *mh)
{
  const struct GNUNET_MQ_Handler *handler;
  int handled = GNUNET_NO;

  handler = mq->handlers;
  if (NULL == handler)
    return;
  for (; NULL != handler->cb; handler++)
  {
    if (handler->type == ntohs (mh->type))
    {
      handler->cb (mq->handlers_cls, mh);
      handled = GNUNET_YES;
    }
  }
  
  if (GNUNET_NO == handled)
    LOG (GNUNET_ERROR_TYPE_WARNING, "no handler for message of type %d\n", ntohs (mh->type));
}


void
GNUNET_MQ_discard (struct GNUNET_MQ_Message *mqm)
{
  GNUNET_assert (NULL == mqm->parent_queue);
  GNUNET_free (mqm);
}


/**
 * Send a message with the give message queue.
 * May only be called once per message.
 * 
 * @param mq message queue
 * @param mqm the message to send.
 */
void
GNUNET_MQ_send (struct GNUNET_MQ_MessageQueue *mq, struct GNUNET_MQ_Message *mqm)
{
  GNUNET_assert (NULL != mq);
  mq->send_impl (mq, mqm);
}


struct GNUNET_MQ_Message *
GNUNET_MQ_msg_ (struct GNUNET_MessageHeader **mhp, uint16_t size, uint16_t type)
{
  struct GNUNET_MQ_Message *mqm;

  mqm = GNUNET_malloc (sizeof *mqm + size);
  mqm->mh = (struct GNUNET_MessageHeader *) &mqm[1];
  mqm->mh->size = htons (size);
  mqm->mh->type = htons (type);
  if (NULL != mhp)
    *mhp = mqm->mh;
  return mqm;
}


int
GNUNET_MQ_nest_ (struct GNUNET_MQ_Message **mqmp,
                 const void *data, uint16_t len)
{
  size_t new_size;
  size_t old_size;

  GNUNET_assert (NULL != mqmp);
  /* there's no data to append => do nothing */
  if (NULL == data)
    return GNUNET_OK;
  old_size = ntohs ((*mqmp)->mh->size);
  /* message too large to concatenate? */
  if (((uint16_t) (old_size + len)) < len)
    return GNUNET_SYSERR;
  new_size = old_size + len;
  *mqmp = GNUNET_realloc (*mqmp, sizeof (struct GNUNET_MQ_Message) + new_size);
  (*mqmp)->mh = (struct GNUNET_MessageHeader *) &(*mqmp)[1];
  memcpy (((void *) (*mqmp)->mh) + old_size, data, new_size - old_size);
  (*mqmp)->mh->size = htons (new_size);
  return GNUNET_OK;
}




/*** Transmit a queued message to the session's client.
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
  struct GNUNET_MQ_MessageQueue *mq = cls;
  struct GNUNET_MQ_Message *mqm = mq->current_msg;
  struct ServerClientSocketState *state = mq->impl_state;
  size_t msg_size;

  GNUNET_assert (NULL != buf);

  if (NULL != mqm->sent_cb)
  {
    mqm->sent_cb (mqm->sent_cls);
  }

  mq->current_msg = NULL;
  GNUNET_assert (NULL != mqm);
  msg_size = ntohs (mqm->mh->size);
  GNUNET_assert (size >= msg_size);
  memcpy (buf, mqm->mh, msg_size);
  GNUNET_free (mqm);
  state->th = NULL;

  if (NULL != mq->msg_head)
  {
    mq->current_msg = mq->msg_head;
    GNUNET_CONTAINER_DLL_remove (mq->msg_head, mq->msg_tail, mq->current_msg);
    state->th = 
        GNUNET_SERVER_notify_transmit_ready (state->client, msg_size, 
                                             GNUNET_TIME_UNIT_FOREVER_REL,
                                             &transmit_queued, mq);
  }
  return msg_size;
}



static void
server_client_destroy_impl (struct GNUNET_MQ_MessageQueue *mq)
{
  struct ServerClientSocketState *state;
  
  GNUNET_assert (NULL != mq);
  state = mq->impl_state;
  GNUNET_assert (NULL != state);
  GNUNET_SERVER_client_drop (state->client);
  GNUNET_free (state);
}

static void
server_client_send_impl (struct GNUNET_MQ_MessageQueue *mq, struct GNUNET_MQ_Message *mqm)
{
  struct ServerClientSocketState *state;
  int msize;

  GNUNET_assert (NULL != mq);
  state = mq->impl_state;
  GNUNET_assert (NULL != state);

  if (NULL != state->th)
  {
    GNUNET_CONTAINER_DLL_insert_tail (mq->msg_head, mq->msg_tail, mqm);
    return;
  }
  GNUNET_assert (NULL == mq->msg_head);
  GNUNET_assert (NULL == mq->current_msg);
  msize = ntohs (mqm->mh->size);
  mq->current_msg = mqm;
  state->th = 
      GNUNET_SERVER_notify_transmit_ready (state->client, msize, 
                                           GNUNET_TIME_UNIT_FOREVER_REL,
                                           &transmit_queued, mq);
}


struct GNUNET_MQ_MessageQueue *
GNUNET_MQ_queue_for_server_client (struct GNUNET_SERVER_Client *client)
{
  struct GNUNET_MQ_MessageQueue *mq;
  struct ServerClientSocketState *scss;

  mq = GNUNET_new (struct GNUNET_MQ_MessageQueue);
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
  struct GNUNET_MQ_MessageQueue *mq = cls;
  struct ClientConnectionState *state;

  state = mq->impl_state;
  
  if (NULL == msg)
  {
    if (NULL == mq->error_handler)
      LOG (GNUNET_ERROR_TYPE_WARNING, "ignoring read error (no handler installed)\n");
    mq->error_handler (mq->handlers_cls, GNUNET_MQ_ERROR_READ);
    return;
  }

  GNUNET_CLIENT_receive (state->connection, handle_client_message, mq,
                         GNUNET_TIME_UNIT_FOREVER_REL);

  GNUNET_MQ_dispatch (mq, msg);
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
connection_client_transmit_queued (void *cls, size_t size,
                 void *buf)
{
  struct GNUNET_MQ_MessageQueue *mq = cls;
  struct GNUNET_MQ_Message *mqm = mq->current_msg;
  struct ClientConnectionState *state = mq->impl_state;
  size_t msg_size;

  if (NULL == buf)
  {
    if (NULL == mq->error_handler)
    {
      LOG (GNUNET_ERROR_TYPE_WARNING, "read error, but no error handler installed\n");
      return 0;
    }
    mq->error_handler (mq->handlers_cls, GNUNET_MQ_ERROR_READ);
    return 0;
  }

  if ((NULL != mq->handlers) && (GNUNET_NO == state->receive_active))
  {
    state->receive_active = GNUNET_YES;
    GNUNET_CLIENT_receive (state->connection, handle_client_message, mq,
                           GNUNET_TIME_UNIT_FOREVER_REL);
  }


  GNUNET_assert (NULL != mqm);

  if (NULL != mqm->sent_cb)
  {
    mqm->sent_cb (mqm->sent_cls);
  }

  mq->current_msg = NULL;
  GNUNET_assert (NULL != buf);
  msg_size = ntohs (mqm->mh->size);
  GNUNET_assert (size >= msg_size);
  memcpy (buf, mqm->mh, msg_size);
  GNUNET_free (mqm);
  state->th = NULL;
  if (NULL != mq->msg_head)
  {
    mq->current_msg = mq->msg_head;
    GNUNET_CONTAINER_DLL_remove (mq->msg_head, mq->msg_tail, mq->current_msg);
    state->th = 
      GNUNET_CLIENT_notify_transmit_ready (state->connection, ntohs (mq->current_msg->mh->size), 
                                             GNUNET_TIME_UNIT_FOREVER_REL, GNUNET_NO,
                                             &connection_client_transmit_queued, mq);
  }
  return msg_size;
}



static void
connection_client_destroy_impl (struct GNUNET_MQ_MessageQueue *mq)
{
  GNUNET_free (mq->impl_state);
}

static void
connection_client_send_impl (struct GNUNET_MQ_MessageQueue *mq,
                             struct GNUNET_MQ_Message *mqm)
{
  struct ClientConnectionState *state = mq->impl_state;
  int msize;

  GNUNET_assert (NULL != state);

  if (NULL != state->th)
  {
    GNUNET_CONTAINER_DLL_insert_tail (mq->msg_head, mq->msg_tail, mqm);
    return;
  }
  GNUNET_assert (NULL == mq->current_msg);
  mq->current_msg = mqm;
  msize = ntohs (mqm->mh->size);
  state->th = 
      GNUNET_CLIENT_notify_transmit_ready (state->connection, msize, 
                                           GNUNET_TIME_UNIT_FOREVER_REL, GNUNET_NO,
                                           &connection_client_transmit_queued, mq);
}





struct GNUNET_MQ_MessageQueue *
GNUNET_MQ_queue_for_connection_client (struct GNUNET_CLIENT_Connection *connection,
                                       const struct GNUNET_MQ_Handler *handlers,
                                       void *cls)
{
  struct GNUNET_MQ_MessageQueue *mq;
  struct ClientConnectionState *state;

  GNUNET_assert (NULL != connection);

  mq = GNUNET_new (struct GNUNET_MQ_MessageQueue);
  mq->handlers = handlers;
  mq->handlers_cls = cls;
  state = GNUNET_new (struct ClientConnectionState);
  state->connection = connection;
  mq->impl_state = state;
  mq->send_impl = connection_client_send_impl;
  mq->destroy_impl = connection_client_destroy_impl;

  return mq;
}


void
GNUNET_MQ_replace_handlers (struct GNUNET_MQ_MessageQueue *mq,
                            const struct GNUNET_MQ_Handler *new_handlers,
                            void *cls)
{
  mq->handlers = new_handlers;
  mq->handlers_cls = cls;
}


/**
 * Associate the assoc_data in mq with a unique request id.
 *
 * @param mq message queue, id will be unique for the queue
 * @param mqm message to associate
 * @param assoc_data to associate
 */
uint32_t
GNUNET_MQ_assoc_add (struct GNUNET_MQ_MessageQueue *mq,
                     struct GNUNET_MQ_Message *mqm,
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
GNUNET_MQ_assoc_get (struct GNUNET_MQ_MessageQueue *mq, uint32_t request_id)
{
  if (NULL == mq->assoc_map)
    return NULL;
  return GNUNET_CONTAINER_multihashmap32_get (mq->assoc_map, request_id);
}


void *
GNUNET_MQ_assoc_remove (struct GNUNET_MQ_MessageQueue *mq, uint32_t request_id)
{
  void *val;

  if (NULL == mq->assoc_map)
    return NULL;
  val = GNUNET_CONTAINER_multihashmap32_get (mq->assoc_map, request_id);
  GNUNET_assert (NULL != val);
  GNUNET_CONTAINER_multihashmap32_remove (mq->assoc_map, request_id, val);
  return val;
}


void
GNUNET_MQ_notify_sent (struct GNUNET_MQ_Message *mqm,
                       GNUNET_MQ_NotifyCallback cb,
                       void *cls)
{
  mqm->sent_cb = cb;
  mqm->sent_cls = cls;
}


void
GNUNET_MQ_destroy (struct GNUNET_MQ_MessageQueue *mq)
{
  /* FIXME: destroy all pending messages in the queue */

  if (NULL != mq->destroy_impl)
  {
    mq->destroy_impl (mq);
  }

  GNUNET_free (mq);
}

