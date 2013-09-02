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
 * Test to see if local peers have reached the required quorum of a barrier
 */
#define LOCAL_QUORUM_REACHED(barrier)           \
  ((barrier->quorum * GST_num_local_peers) <= (barrier->nreached * 100))


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
 * Wrapper around Barrier handle
 */
struct WBarrier
{
  /**
   * DLL next pointer
   */
  struct WBarrier *next;

  /**
   * DLL prev pointer
   */
  struct WBarrier *prev;

  /**
   * The local barrier associated with the creation of this wrapper
   */
  struct Barrier *barrier;

  /**
   * The barrier handle from API
   */
  struct GNUNET_TESTBED_Barrier *hbarrier;

  /**
   * Has this barrier been crossed?
   */
  uint8_t reached;
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
   * The client handle to the master controller
   */
  struct GNUNET_SERVER_Client *client;

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
   * DLL head for the list of barrier handles
   */
  struct WBarrier *whead;

  /**
   * DLL tail for the list of barrier handles
   */
  struct WBarrier *wtail;

  /**
   * Identifier for the timeout task
   */
  GNUNET_SCHEDULER_TaskIdentifier tout_task;
  
  /**
   * The status of this barrier
   */
  enum GNUNET_TESTBED_BarrierStatus status;
  
  /**
   * Number of barriers wrapped in the above DLL
   */
  unsigned int num_wbarriers;

  /**
   * Number of wrapped barriers reached so far
   */
  unsigned int num_wbarriers_reached;

  /**
   * Number of wrapped barrier initialised so far
   */
  unsigned int num_wbarriers_inited;

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
  if (NULL != barrier->client)
    GNUNET_SERVER_client_drop (barrier->client);
  GNUNET_free (barrier);
}


/**
 * Cancels all subcontroller barrier handles
 *
 * @param barrier the local barrier
 */
static void
cancel_wrappers (struct Barrier *barrier)
{
  struct WBarrier *wrapper;

  while (NULL != (wrapper = barrier->whead))
  {
    GNUNET_TESTBED_barrier_cancel (wrapper->hbarrier);
    GNUNET_CONTAINER_DLL_remove (barrier->whead, barrier->wtail, wrapper);
    GNUNET_free (wrapper);
  }
}


/**
 * Sends a barrier failed message
 *
 * @param barrier the corresponding barrier
 * @param status the status of the barrier
 * @param emsg the error message; should be non-NULL for
 *   status=BARRIER_STATUS_ERROR 
 */
static void
send_barrier_status_msg (struct Barrier *barrier, 
                         enum GNUNET_TESTBED_BarrierStatus status,
                         const char *emsg)
{
  struct GNUNET_TESTBED_BarrierStatusMsg *msg;
  size_t name_len;
  uint16_t msize;

  GNUNET_assert ((NULL == emsg) || (BARRIER_STATUS_ERROR == status));
  name_len = strlen (barrier->name) + 1;
  msize = sizeof (struct GNUNET_TESTBED_BarrierStatusMsg)
      + name_len
      + (NULL == emsg) ? 0 : strlen (emsg) + 1;
  msg = GNUNET_malloc (msize);
  msg->status = htons (status);
  msg->name_len = htons (name_len);
  (void) memcpy (msg->data, barrier->name, name_len);
  if (NULL != emsg)
    (void) memcpy (msg->data + name_len, emsg, strlen (emsg) + 1);
  GST_queue_message (barrier->client, &msg->header);
}



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
  struct GNUNET_TESTBED_BarrierStatusMsg *msg;
  struct GNUNET_MessageHeader *dup_msg;
  uint16_t name_len;
  uint16_t msize;

  name_len = strlen (barrier->name) + 1;
  msize = sizeof (struct GNUNET_TESTBED_BarrierStatusMsg) + name_len;  
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
    if (LOCAL_QUORUM_REACHED (barrier))
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
  GNUNET_assert (NULL != barrier_map);
  GNUNET_CONTAINER_multihashmap_destroy (barrier_map);
  GNUNET_assert (NULL != ctx);
  GNUNET_SERVICE_stop (ctx);
}


/**
 * Functions of this type are to be given as callback argument to
 * GNUNET_TESTBED_barrier_init().  The callback will be called when status
 * information is available for the barrier.
 *
 * @param cls the closure given to GNUNET_TESTBED_barrier_init()
 * @param name the name of the barrier
 * @param barrier the barrier handle
 * @param status status of the barrier; GNUNET_OK if the barrier is crossed;
 *   GNUNET_SYSERR upon error
 * @param emsg if the status were to be GNUNET_SYSERR, this parameter has the
 *   error messsage
 */
static void 
wbarrier_status_cb (void *cls, const char *name,
                    struct GNUNET_TESTBED_Barrier *b_,
                    enum GNUNET_TESTBED_BarrierStatus status,
                    const char *emsg)
{
  struct WBarrier *wrapper = cls;
  struct Barrier *barrier = wrapper->barrier;

  GNUNET_assert (b_ == wrapper->hbarrier);
  wrapper->hbarrier = NULL;
  GNUNET_CONTAINER_DLL_remove (barrier->whead, barrier->wtail, wrapper);
  GNUNET_free (wrapper);
  if (BARRIER_STATUS_ERROR == status)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Initialising barrier `%s' failed at a sub-controller: %s\n",
         barrier->name, (NULL != emsg) ? emsg : "NULL");
    cancel_wrappers (barrier);
    if (NULL == emsg)
      emsg = "Initialisation failed at a sub-controller";
    send_barrier_status_msg (barrier, BARRIER_STATUS_ERROR, emsg);
    return;
  }
  switch (status)
  {
  case BARRIER_STATUS_CROSSED:
    barrier->num_wbarriers_reached++;
    if ((barrier->num_wbarriers_reached == barrier->num_wbarriers)
        && (LOCAL_QUORUM_REACHED (barrier)))
      send_barrier_status_msg (barrier, BARRIER_STATUS_CROSSED, NULL);
    break;
  case BARRIER_STATUS_INITIALISED:
    barrier->num_wbarriers_inited++;
    if (barrier->num_wbarriers_inited == barrier->num_wbarriers)
      send_barrier_status_msg (barrier, BARRIER_STATUS_INITIALISED, NULL);
    break;
  case BARRIER_STATUS_ERROR:
    GNUNET_assert (0);
  }
  return;
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
  struct Barrier *barrier = cls;
  
  barrier->nslaves--;
  barrier->timedout = GNUNET_YES;
  cancel_wrappers (barrier);
  send_barrier_status_msg (barrier, BARRIER_STATUS_ERROR,
                           "Timedout while propagating barrier initialisation\n");
  remove_barrier (barrier);
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
  struct WBarrier *wrapper;
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
  barrier->client = client;
  GNUNET_SERVER_client_keep (client);
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
    wrapper = GNUNET_malloc (sizeof (struct WBarrier));
    wrapper->barrier = barrier;
    GNUNET_CONTAINER_DLL_insert_tail (barrier->whead, barrier->wtail, wrapper);
    wrapper->hbarrier = GNUNET_TESTBED_barrier_init (slave->controller,
                                                     barrier->name,
                                                     barrier->quorum,
                                                     &wbarrier_status_cb,
                                                     wrapper);    
  }
  if (NULL == barrier->whead)   /* No further propagation */
    send_barrier_status_msg (barrier, BARRIER_STATUS_INITIALISED, NULL);
  else
    barrier->tout_task = GNUNET_SCHEDULER_add_delayed (MESSAGE_SEND_TIMEOUT (30),
                                                       &fwd_tout_barrier_init,
                                                       barrier);
}

/* end of gnunet-service-testbed_barriers.c */
