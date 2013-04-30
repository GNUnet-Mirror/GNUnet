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
 * @file set/mq.c
 * @brief general purpose request queue
 */

#include "mq.h"


#define LOG(kind,...) GNUNET_log_from (kind, "mq",__VA_ARGS__)

/**
 * Signature of functions implementing the
 * sending part of a message queue
 *
 * @param q the message queue
 * @param m the message
 */
typedef void (*SendImpl) (struct GNUNET_MQ_MessageQueue *q, struct GNUNET_MQ_Message *m);


typedef void (*DestroyImpl) (struct GNUNET_MQ_MessageQueue *q);


/**
 * Collection of the state necessary to read and write gnunet messages 
 * to a stream socket. Should be used as closure for stream_data_processor.
 */
struct MessageStreamState
{
  struct GNUNET_SERVER_MessageStreamTokenizer *mst;
  struct MessageQueue *mq;
  struct GNUNET_STREAM_Socket *socket;
  struct GNUNET_STREAM_ReadHandle *rh;
  struct GNUNET_STREAM_WriteHandle *wh;
};


struct ServerClientSocketState
{
  struct GNUNET_SERVER_Client *client;
  struct GNUNET_SERVER_TransmitHandle* th;
};


struct ClientConnectionState
{
  struct GNUNET_CLIENT_Connection *connection;
  struct GNUNET_CLIENT_TransmitHandle *th;
};


struct GNUNET_MQ_MessageQueue
{
  /**
   * Handlers array, or NULL if the queue should not receive messages
   */
  const struct GNUNET_MQ_Handler *handlers;

  /**
   * Closure for the handler callbacks
   */
  void *handlers_cls;

  /**
   * Actual implementation of message sending,
   * called when a message is added
   */
  SendImpl send_impl;

  /**
   * Implementation-dependent queue destruction function
   */
  DestroyImpl destroy_impl;

  /**
   * Implementation-specific state
   */
  void *impl_state;

  /**
   * Callback will be called when the message queue is empty
   */
  GNUNET_MQ_NotifyCallback empty_cb;

  /**
   * Closure for empty_cb
   */
  void *empty_cls;

  /**
   * Callback will be called when a read error occurs.
   */
  GNUNET_MQ_NotifyCallback read_error_cb;

  /**
   * Closure for read_error_cb
   */
  void *read_error_cls;

  /**
   * Linked list of messages pending to be sent
   */
  struct GNUNET_MQ_Message *msg_head;

  /**
   * Linked list of messages pending to be sent
   */
  struct GNUNET_MQ_Message *msg_tail;

  /**
   * Message that is currently scheduled to be
   * sent. Not the head of the message queue, as the implementation
   * needs to know if sending has been already scheduled or not.
   */
  struct GNUNET_MQ_Message *current_msg;

  /**
   * Map of associations, lazily allocated
   */
  struct GNUNET_CONTAINER_MultiHashMap32 *assoc_map;

  /**
   * Next id that should be used for the assoc_map,
   * initialized lazily to a random value together with
   * assoc_map
   */
  uint32_t assoc_id;
};


struct GNUNET_MQ_Message
{
  /**
   * Messages are stored in a linked list
   */
  struct GNUNET_MQ_Message *next;

  /**
   * Messages are stored in a linked list
   */
  struct GNUNET_MQ_Message *prev;

  /**
   * Actual allocated message header,
   * usually points to the end of the containing GNUNET_MQ_Message
   */
  struct GNUNET_MessageHeader *mh;

  /**
   * Queue the message is queued in, NULL if message is not queued.
   */
  struct GNUNET_MQ_MessageQueue *parent_queue;

  /**
   * Called after the message was sent irrevokably
   */
  GNUNET_MQ_NotifyCallback sent_cb;

  /**
   * Closure for send_cb
   */
  void *sent_cls;
};


/**
 * Call the right callback for a message received
 * by a queue
 */
static void
dispatch_message (struct GNUNET_MQ_MessageQueue *mq, const struct GNUNET_MessageHeader *mh)
{
  const struct GNUNET_MQ_Handler *handler;

  handler = mq->handlers;
  if (NULL == handler)
    return;
  for (; NULL != handler->cb; handler++)
    if (handler->type == ntohs (mh->type))
      handler->cb (mq->handlers_cls, mh);
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

  if (NULL == data)
    return GNUNET_OK;
  GNUNET_assert (NULL != mqmp);
  old_size = ntohs ((*mqmp)->mh->size);
  /* message too large to concatenate? */
  if (ntohs ((*mqmp)->mh->size) + len < len)
    return GNUNET_SYSERR;
  new_size = old_size + len;
  *mqmp = GNUNET_realloc (mqmp, sizeof (struct GNUNET_MQ_Message) + new_size);
  memcpy ((*mqmp)->mh + old_size, data, new_size - old_size);
  (*mqmp)->mh->size = htons (new_size);
  return GNUNET_OK;
}


/**
 * Functions of this signature are called whenever writing operations
 * on a stream are executed
 *
 * @param cls the closure from GNUNET_STREAM_write
 * @param status the status of the stream at the time this function is called;
 *          GNUNET_STREAM_OK if writing to stream was completed successfully;
 *          GNUNET_STREAM_TIMEOUT if the given data is not sent successfully
 *          (this doesn't mean that the data is never sent, the receiver may
 *          have read the data but its ACKs may have been lost);
 *          GNUNET_STREAM_SHUTDOWN if the stream is shutdown for writing in the
 *          mean time; GNUNET_STREAM_SYSERR if the stream is broken and cannot
 *          be processed.
 * @param size the number of bytes written
 */
static void 
stream_write_queued (void *cls, enum GNUNET_STREAM_Status status, size_t size)
{
  struct GNUNET_MQ_MessageQueue *mq = cls;
  struct MessageStreamState *mss = (struct MessageStreamState *) mq->impl_state;
  struct GNUNET_MQ_Message *mqm;

  GNUNET_assert (GNUNET_STREAM_OK == status);
  
  /* call cb for message we finished sending */
  mqm = mq->current_msg;
  if (NULL != mqm)
  {
    if (NULL != mqm->sent_cb)
      mqm->sent_cb (mqm->sent_cls);
    GNUNET_free (mqm);
  }

  mss->wh = NULL;

  mqm = mq->msg_head;
  mq->current_msg = mqm;
  if (NULL == mqm)
  {
    if (NULL != mq->empty_cb)
      mq->empty_cb (mq->empty_cls);
    return;
  }
  GNUNET_CONTAINER_DLL_remove (mq->msg_head, mq->msg_tail, mqm);
  mss->wh = GNUNET_STREAM_write (mss->socket, mqm->mh, ntohs (mqm->mh->size),
                                 GNUNET_TIME_UNIT_FOREVER_REL,
                                 stream_write_queued, mq);
  GNUNET_assert (NULL != mss->wh);
}


static void
stream_socket_send_impl (struct GNUNET_MQ_MessageQueue *mq,
                         struct GNUNET_MQ_Message *mqm)
{
  struct MessageStreamState *mss = (struct MessageStreamState *) mq->impl_state;
  if (NULL != mq->current_msg)
  {
    GNUNET_CONTAINER_DLL_insert_tail (mq->msg_head, mq->msg_tail, mqm);
    return;
  }
  mq->current_msg = mqm;
  mss->wh = GNUNET_STREAM_write (mss->socket, mqm->mh, ntohs (mqm->mh->size),
                                 GNUNET_TIME_UNIT_FOREVER_REL,
                                 stream_write_queued, mq);
}


/**
 * Functions with this signature are called whenever a
 * complete message is received by the tokenizer.
 *
 * Do not call GNUNET_SERVER_mst_destroy in callback
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR to stop further processing
 */
static int
stream_mst_callback (void *cls, void *client,
                     const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_MQ_MessageQueue *mq = cls;

  GNUNET_assert (NULL != message);
  dispatch_message (mq, message);
  return GNUNET_OK;
}


/**
 * Functions of this signature are called whenever data is available from the
 * stream.
 *
 * @param cls the closure from GNUNET_STREAM_read
 * @param status the status of the stream at the time this function is called
 * @param data traffic from the other side
 * @param size the number of bytes available in data read; will be 0 on timeout 
 * @return number of bytes of processed from 'data' (any data remaining should be
 *         given to the next time the read processor is called).
 */
static size_t
stream_data_processor (void *cls,
                       enum GNUNET_STREAM_Status status,
                       const void *data,
                       size_t size)
{
  struct GNUNET_MQ_MessageQueue *mq = cls;
  struct MessageStreamState *mss;
  int ret;
  
  mss = (struct MessageStreamState *) mq->impl_state;
  GNUNET_assert (GNUNET_STREAM_OK == status);
  ret = GNUNET_SERVER_mst_receive (mss->mst, NULL, data, size, GNUNET_NO, GNUNET_NO);
  GNUNET_assert (GNUNET_OK == ret);
  /* we always read all data */
    mss->rh = GNUNET_STREAM_read (mss->socket, GNUNET_TIME_UNIT_FOREVER_REL, 
                                  stream_data_processor, mq);
  return size;
}


struct GNUNET_MQ_MessageQueue *
GNUNET_MQ_queue_for_stream_socket (struct GNUNET_STREAM_Socket *socket,
                                   const struct GNUNET_MQ_Handler *handlers,
                                   void *cls)
{
  struct GNUNET_MQ_MessageQueue *mq;
  struct MessageStreamState *mss;

  mq = GNUNET_new (struct GNUNET_MQ_MessageQueue);
  mss = GNUNET_new (struct MessageStreamState);
  mss->socket = socket;
  mq->impl_state = mss;
  mq->send_impl = stream_socket_send_impl;
  mq->handlers = handlers;
  mq->handlers_cls = cls;
  if (NULL != handlers)
  {
    mss->mst = GNUNET_SERVER_mst_create (stream_mst_callback, mq);
    mss->rh = GNUNET_STREAM_read (socket, GNUNET_TIME_UNIT_FOREVER_REL, 
                                  stream_data_processor, mq);
  }
  return mq;
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

  mq->current_msg = NULL;
  GNUNET_assert (NULL != mqm);
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
        GNUNET_SERVER_notify_transmit_ready (state->client, msg_size, 
                                             GNUNET_TIME_UNIT_FOREVER_REL,
                                             &transmit_queued, mq);
  }
  else if (NULL != mq->empty_cb)
    mq->empty_cb (mq->empty_cls);
  return msg_size;
}


static void
server_client_send_impl (struct GNUNET_MQ_MessageQueue *mq, struct GNUNET_MQ_Message *mqm)
{
  struct ServerClientSocketState *state = mq->impl_state;
  int msize;

  GNUNET_assert (NULL != state);

  if (NULL != state->th)
  {
    GNUNET_CONTAINER_DLL_insert_tail (mq->msg_head, mq->msg_tail, mqm);
    return;
  }
  GNUNET_assert (NULL == mq->current_msg);
  msize = ntohs (mq->msg_head->mh->size);
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
  mq->send_impl = server_client_send_impl;
  return mq;
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

  mq->current_msg = NULL;
  GNUNET_assert (NULL != mqm);
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
      GNUNET_CLIENT_notify_transmit_ready (state->connection, htons (mq->current_msg->mh->size), 
                                             GNUNET_TIME_UNIT_FOREVER_REL, GNUNET_NO,
                                             &connection_client_transmit_queued, mq);
  }
  else if (NULL != mq->empty_cb)
    mq->empty_cb (mq->empty_cls);
  return msg_size;
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
  
  if (NULL == msg)
  {
    if (NULL == mq->read_error_cb)
      LOG (GNUNET_ERROR_TYPE_WARNING, "ignoring read error (no handler installed)\n");
    mq->read_error_cb (mq->read_error_cls);
    return;
  }
  dispatch_message (mq, msg);
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

  if (NULL != handlers)
  {
    GNUNET_CLIENT_receive (connection, handle_client_message, mq,
                           GNUNET_TIME_UNIT_FOREVER_REL);
  }

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
    mq->assoc_map = GNUNET_CONTAINER_multihashmap32_create (8);
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
  GNUNET_free (mq);
}


/**
 * Call a callback once all messages queued have been sent,
 * i.e. the message queue is empty.
 *
 * @param mqm the message queue to send the notification for
 * @param cb the callback to call on an empty queue
 * @param cls closure for cb
 */
void
GNUNET_MQ_notify_empty (struct GNUNET_MQ_MessageQueue *mqm,
                        GNUNET_MQ_NotifyCallback cb,
                        void *cls)
{
  mqm->empty_cb = cb;
  mqm->empty_cls = cls;
}
