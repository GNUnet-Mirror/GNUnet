/*
  This file is part of GNUnet.
  (C) 2008--2013 Christian Grothoff (and other contributing authors)

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
 * @file testbed/gnunet-service-testbed_barriers.c
 * @brief barrier handling at the testbed controller
 * @author Sree Harsha Totakura <sreeharsha@totakura.in> 
 */

#include "gnunet-service-testbed.h"

/**
 * timeout for outgoing message transmissions in seconds
 */
#define MESSAGE_SEND_TIMEOUT(s) \
  GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, s)


/**
 * Barrier
 */
struct Barrier;


/**
 * Message queue for transmitting messages
 */
struct MessageQueue
{
  /**
   * next pointer for DLL
   */
  struct MessageQueue *next;

  /**
   * prev pointer for DLL
   */
  struct MessageQueue *prev;

  /**
   * The message to be sent
   */
  struct GNUNET_MessageHeader *msg;
};

/**
 * Context to be associated with each client
 */
struct ClientCtx
{
  /**
   * The barrier this client is waiting for
   */
  struct Barrier *barrier;

  /**
   * DLL next ptr
   */
  struct ClientCtx *next;

  /**
   * DLL prev ptr
   */
  struct ClientCtx *prev;

  /**
   * The client handle
   */
  struct GNUNET_SERVER_Client *client;

  /**
   * the transmission handle
   */
  struct GNUNET_SERVER_TransmitHandle *tx;

  /**
   * message queue head
   */
  struct MessageQueue *mq_head;

  /**
   * message queue tail
   */
  struct MessageQueue *mq_tail;
};


/**
 * Barrier
 */
struct Barrier
{
  /**
   * The hashcode of the barrier name
   */
  struct GNUNET_HashCode hash;

  /**
   * The name of the barrier
   */
  char *name;

  /**
   * DLL head for the list of clients waiting for this barrier
   */
  struct ClientCtx *head;

  /**
   * DLL tail for the list of clients waiting for this barrier
   */
  struct ClientCtx *tail;

  /**
   * Number of peers which have reached this barrier
   */
  unsigned int nreached;

  /**
   * Number of slaves we have initialised this barrier
   */
  unsigned int nslaves;

  /**
   * Quorum percentage to be reached
   */
  uint8_t quorum;
  
  /**
   * Was there a timeout while propagating initialisation
   */
  uint8_t timedout;
};


/**
 * Hashtable handle for storing initialised barriers
 */
static struct GNUNET_CONTAINER_MultiHashMap *barrier_map;

/**
 * Service context
 */
static struct GNUNET_SERVICE_Context *ctx;


/**
 * Function called to notify a client about the connection
 * begin ready to queue more data.  "buf" will be
 * NULL and "size" zero if the connection was closed for
 * writing in the meantime.
 *
 * @param cls client context
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t 
transmit_ready_cb (void *cls, size_t size, void *buf)
{
  struct ClientCtx *ctx = cls;
  struct GNUNET_SERVER_Client *client = ctx->client;
  struct MessageQueue *mq;
  struct GNUNET_MessageHeader *msg;
  size_t wrote;

  ctx->tx = NULL;
  wrote = 0;
  if ((0 == size) || (NULL == buf))
  {
    GNUNET_assert (NULL != ctx->client);
    GNUNET_SERVER_client_drop (ctx->client);
    ctx->client = NULL;    
    return 0;
  }
  mq = ctx->mq_head;
  msg = mq->msg;
  wrote = ntohs (msg->size);
  GNUNET_assert (size >= wrote);
  (void) memcpy (buf, msg, wrote);
  GNUNET_CONTAINER_DLL_remove (ctx->mq_head, ctx->mq_tail, mq);
  GNUNET_free (mq->msg);
  GNUNET_free (mq);
  if (NULL != (mq = ctx->mq_head))
    ctx->tx = GNUNET_SERVER_notify_transmit_ready (client, ntohs (msg->size),
                                                  MESSAGE_SEND_TIMEOUT (30),
                                                  &transmit_ready_cb, ctx);
  return wrote;
}


/**
 * Queue a message into a clients message queue
 *
 * @param ctx the context associated with the client
 * @param msg the message to queue.  Will be consumed
 */
static void
queue_message (struct ClientCtx *ctx, struct GNUNET_MessageHeader *msg)
{
  struct MessageQueue *mq;
  struct GNUNET_SERVER_Client *client = ctx->client;
  
  mq = GNUNET_malloc (sizeof (struct MessageQueue));
  mq->msg = msg;
  GNUNET_CONTAINER_DLL_insert_tail (ctx->mq_head, ctx->mq_tail, mq);
  if (NULL == ctx->tx)
   ctx->tx = GNUNET_SERVER_notify_transmit_ready (client, ntohs (msg->size),
                                                  MESSAGE_SEND_TIMEOUT (30),
                                                  &transmit_ready_cb, ctx);
}


#if 0
/**
 * Function to remove a barrier from the barrier map and cleanup resources
 * occupied by a barrier
 *
 * @param barrier the barrier handle
 */
static void
remove_barrier (struct Barrier *barrier)
{
  GNUNET_assert (GNUNET_YES == GNUNET_CONTAINER_multihashmap_remove (barrier_map,
                                                                    &barrier->hash,
                                                                    barrier));
  GNUNET_free (barrier->name);
  GNUNET_free (barrier);
}


/**
 * Function called upon timeout while waiting for a response from the
 * subcontrollers to barrier init message
 *
 * @param 
 * @return 
 */
static void
fwd_tout_barrier_init (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ForwardedOperationContext *foctx = cls;
  struct Barrier *barrier = foctx->cls;
  
  barrier->nslaves--;
  barrier->timedout = GNUNET_YES;
  if (0 == barrier->nslaves)
  {
    GST_send_operation_fail_msg (foctx->client, foctx->operation_id,
                                 "Timeout while contacting a slave controller");
    remove_barrier (barrier);
  }
}
#endif

/**
 * Task for sending barrier crossed notifications to waiting client
 *
 * @param cls the barrier which is crossed
 * @param tc scheduler task context
 */
static void
notify_task_cb (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Barrier *barrier = cls;
  struct ClientCtx *client_ctx;
  struct GNUNET_TESTBED_BarrierStatus *msg;
  struct GNUNET_MessageHeader *dup_msg;
  uint16_t name_len;
  uint16_t msize;

  name_len = strlen (barrier->name) + 1;
  msize = sizeof (struct GNUNET_TESTBED_BarrierStatus) + name_len;  
  msg = GNUNET_malloc (msize);
  msg->header.size = htons (msize);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_TESTBED_BARRIER_STATUS);
  msg->status = 0;
  msg->name_len = htons (name_len);
  (void) memcpy (msg->data, barrier->name, name_len);
  msg->data[name_len] = '\0';
  while (NULL != (client_ctx = barrier->head))
  {
    dup_msg = GNUNET_copy_message (&msg->header);
    queue_message (client_ctx, dup_msg);
    GNUNET_CONTAINER_DLL_remove (barrier->head, barrier->tail, client_ctx);
    GNUNET_SERVER_client_set_user_context_ (client_ctx->client, NULL, 0);
    GNUNET_free (client_ctx);
  }
}


/**
 * Message handler for GNUNET_MESSAGE_TYPE_TESTBED_BARRIER_WAIT messages.  This
 * message should come from peers or a shared helper service using the
 * testbed-barrier client API (@see gnunet_testbed_barrier_service.h)
 *
 * This handler is queued in the main service and will handle the messages sent
 * either from the testbed driver or from a high level controller
 *
 * @param cls NULL
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_barrier_wait (void *cls, struct GNUNET_SERVER_Client *client,
                     const struct GNUNET_MessageHeader *message)
{
  const struct GNUNET_TESTBED_BarrierWait *msg;
  struct Barrier *barrier;
  char *name;
  struct ClientCtx *client_ctx;
  struct GNUNET_HashCode key;
  size_t name_len;
  uint16_t msize;
  
  msize = ntohs (message->size);
  if (msize <= sizeof (struct GNUNET_TESTBED_BarrierWait))
  {
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  if (NULL == barrier_map)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  msg = (const struct GNUNET_TESTBED_BarrierWait *) message;
  name_len = msize - sizeof (struct GNUNET_TESTBED_BarrierWait);
  name = GNUNET_malloc (name_len + 1);
  name[name_len] = '\0';
  (void) memcpy (name, msg->name, name_len);
  GNUNET_CRYPTO_hash (name, name_len - 1, &key);
  if (NULL == (barrier = GNUNET_CONTAINER_multihashmap_get (barrier_map, &key)))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    GNUNET_free (name);
    return;
  }
  client_ctx = GNUNET_SERVER_client_get_user_context (client, struct ClientCtx);
  if (NULL == client_ctx)
  {
    client_ctx = GNUNET_malloc (sizeof (struct ClientCtx));
    client_ctx->client = client;
    GNUNET_SERVER_client_keep (client);
    client_ctx->barrier = barrier;
    GNUNET_CONTAINER_DLL_insert_tail (barrier->head, barrier->tail, client_ctx);
    barrier->nreached++;
    if ((barrier->quorum * GST_num_local_peers) <= (barrier->nreached * 100))
      notify_task_cb (barrier, NULL);
  }
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Functions with this signature are called whenever a client
 * is disconnected on the network level.
 *
 * @param cls closure
 * @param client identification of the client; NULL
 *        for the last call when the server is destroyed
 */
static void
disconnect_cb (void *cls, struct GNUNET_SERVER_Client *client)
{
  struct ClientCtx *client_ctx;
  struct Barrier *barrier;
  
  client_ctx = GNUNET_SERVER_client_get_user_context (client, struct ClientCtx);
  if (NULL == client_ctx)
    return;
  barrier = client_ctx->barrier;
  GNUNET_CONTAINER_DLL_remove (barrier->head, barrier->tail, client_ctx);
  if (NULL != client_ctx->tx)
    GNUNET_SERVER_notify_transmit_ready_cancel (client_ctx->tx);
  
}


/**
 * Function to initialise barrriers component
 */
void
GST_barriers_init (struct GNUNET_CONFIGURATION_Handle *cfg)
{
  static const struct GNUNET_SERVER_MessageHandler message_handlers[] = {
    {&handle_barrier_wait, NULL, GNUNET_MESSAGE_TYPE_TESTBED_BARRIER_WAIT, 0},
    {NULL, NULL, 0, 0}
  };
  struct GNUNET_SERVER_Handle *srv;

  barrier_map = GNUNET_CONTAINER_multihashmap_create (3, GNUNET_YES);
  ctx = GNUNET_SERVICE_start ("testbed-barrier", cfg,
                              GNUNET_SERVICE_OPTION_MANUAL_SHUTDOWN);
  srv = GNUNET_SERVICE_get_server (ctx);
  GNUNET_SERVER_add_handlers (srv, message_handlers);
  GNUNET_SERVER_disconnect_notify (srv, &disconnect_cb, NULL);  
}


/**
 * Function to stop the barrier service
 */
void
GST_barriers_stop ()
{
  GNUNET_assert (NULL != ctx);
  GNUNET_SERVICE_stop (ctx);
}


/**
 * Message handler for GNUNET_MESSAGE_TYPE_TESTBED_BARRIER_INIT messages.  This
 * message should always come from a parent controller or the testbed API if we
 * are the root controller.
 *
 * This handler is queued in the main service and will handle the messages sent
 * either from the testbed driver or from a high level controller
 *
 * @param cls NULL
 * @param client identification of the client
 * @param message the actual message
 */
void
GST_handle_barrier_init (void *cls, struct GNUNET_SERVER_Client *client,
                         const struct GNUNET_MessageHeader *message)
{
  const struct GNUNET_TESTBED_BarrierInit *msg;
  const char *name;
  struct Barrier *barrier;
  struct Slave *slave;
  struct GNUNET_HashCode hash;
  size_t name_len;
  uint64_t op_id;
  unsigned int cnt;
  uint16_t msize;
  
  if (NULL == GST_context)
  {
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  if (client != GST_context->client)
  {
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  msize = ntohs (message->size);
  if (msize <= sizeof (struct GNUNET_TESTBED_BarrierInit))
  {
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  msg = (const struct GNUNET_TESTBED_BarrierInit *) message;
  op_id = GNUNET_ntohll (msg->op_id);
  name = msg->name;
  name_len = (size_t) msize - sizeof (struct GNUNET_TESTBED_BarrierInit);
  GNUNET_CRYPTO_hash (name, name_len, &hash);
  if (GNUNET_YES == GNUNET_CONTAINER_multihashmap_contains (barrier_map, &hash))
  {
    GST_send_operation_fail_msg (client, op_id, "Barrier already initialised");
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  barrier = GNUNET_malloc (sizeof (struct Barrier));
  (void) memcpy (&barrier->hash, &hash, sizeof (struct GNUNET_HashCode));
  barrier->quorum = msg->quorum;
  barrier->name = GNUNET_malloc (name_len + 1);
  barrier->name[name_len] = '\0';
  (void) memcpy (barrier->name, name, name_len);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multihashmap_put (barrier_map,
                                                    &barrier->hash,
                                                    barrier,
                                                    GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST));
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
  /* Propagate barrier init to subcontrollers */
  for (cnt = 0; cnt < GST_slave_list_size; cnt++)
  {
    if (NULL == (slave = GST_slave_list[cnt]))
      continue;
    if (NULL == slave->controller)
    {
      GNUNET_break (0);/* May happen when we are connecting to the controller */
      continue;
    }    
    GNUNET_break (0);           /* FIXME */
  }
}
