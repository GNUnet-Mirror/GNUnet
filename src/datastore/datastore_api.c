/*
     This file is part of GNUnet
     Copyright (C) 2004-2013, 2016 GNUnet e.V.

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
 * @file datastore/datastore_api.c
 * @brief Management for the datastore for files stored on a GNUnet node.  Implements
 *        a priority queue for requests
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_arm_service.h"
#include "gnunet_constants.h"
#include "gnunet_datastore_service.h"
#include "gnunet_statistics_service.h"
#include "datastore.h"

#define LOG(kind,...) GNUNET_log_from (kind, "datastore-api",__VA_ARGS__)

/**
 * Collect an instane number of statistics?  May cause excessive IPC.
 */
#define INSANE_STATISTICS GNUNET_NO

/**
 * If a client stopped asking for more results, how many more do
 * we receive from the DB before killing the connection?  Trade-off
 * between re-doing TCP handshakes and (needlessly) receiving
 * useless results.
 */
#define MAX_EXCESS_RESULTS 8

/**
 * Context for processing status messages.
 */
struct StatusContext
{
  /**
   * Continuation to call with the status.
   */
  GNUNET_DATASTORE_ContinuationWithStatus cont;

  /**
   * Closure for @e cont.
   */
  void *cont_cls;

};


/**
 * Context for processing result messages.
 */
struct ResultContext
{
  /**
   * Function to call with the result.
   */
  GNUNET_DATASTORE_DatumProcessor proc;

  /**
   * Closure for @e proc.
   */
  void *proc_cls;

};


/**
 *  Context for a queue operation.
 */
union QueueContext
{

  struct StatusContext sc;

  struct ResultContext rc;

};


/**
 * Entry in our priority queue.
 */
struct GNUNET_DATASTORE_QueueEntry
{

  /**
   * This is a linked list.
   */
  struct GNUNET_DATASTORE_QueueEntry *next;

  /**
   * This is a linked list.
   */
  struct GNUNET_DATASTORE_QueueEntry *prev;

  /**
   * Handle to the master context.
   */
  struct GNUNET_DATASTORE_Handle *h;

  /**
   * Function to call after transmission of the request.
   */
  GNUNET_DATASTORE_ContinuationWithStatus cont;

  /**
   * Closure for @e cont.
   */
  void *cont_cls;

  /**
   * Context for the operation.
   */
  union QueueContext qc;

  /**
   * Envelope of the request to transmit, NULL after
   * transmission.
   */
  struct GNUNET_MQ_Envelope *env;

  /**
   * Priority in the queue.
   */
  unsigned int priority;

  /**
   * Maximum allowed length of queue (otherwise
   * this request should be discarded).
   */
  unsigned int max_queue;

  /**
   * Expected response type.
   */
  uint16_t response_type;

};


/**
 * Handle to the datastore service.
 */
struct GNUNET_DATASTORE_Handle
{

  /**
   * Our configuration.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Current connection to the datastore service.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Handle for statistics.
   */
  struct GNUNET_STATISTICS_Handle *stats;

  /**
   * Current head of priority queue.
   */
  struct GNUNET_DATASTORE_QueueEntry *queue_head;

  /**
   * Current tail of priority queue.
   */
  struct GNUNET_DATASTORE_QueueEntry *queue_tail;

  /**
   * Task for trying to reconnect.
   */
  struct GNUNET_SCHEDULER_Task *reconnect_task;

  /**
   * How quickly should we retry?  Used for exponential back-off on
   * connect-errors.
   */
  struct GNUNET_TIME_Relative retry_time;

  /**
   * Number of entries in the queue.
   */
  unsigned int queue_size;

  /**
   * Number of results we're receiving for the current query
   * after application stopped to care.  Used to determine when
   * to reset the connection.
   */
  unsigned int result_count;

  /**
   * We should ignore the next message(s) from the service.
   */
  unsigned int skip_next_messages;

};


/**
 * Try reconnecting to the datastore service.
 *
 * @param cls the `struct GNUNET_DATASTORE_Handle`
 */
static void
try_reconnect (void *cls);


/**
 * Disconnect from the service and then try reconnecting to the datastore service
 * after some delay.
 *
 * @param h handle to datastore to disconnect and reconnect
 */
static void
do_disconnect (struct GNUNET_DATASTORE_Handle *h)
{
  if (NULL == h->mq)
  {
    GNUNET_break (0);
    return;
  }
  GNUNET_MQ_destroy (h->mq);
  h->mq = NULL;
  h->skip_next_messages = 0;
  h->reconnect_task
    = GNUNET_SCHEDULER_add_delayed (h->retry_time,
                                    &try_reconnect,
                                    h);
}


/**
 * Free a queue entry.  Removes the given entry from the
 * queue and releases associated resources.  Does NOT
 * call the callback.
 *
 * @param qe entry to free.
 */
static void
free_queue_entry (struct GNUNET_DATASTORE_QueueEntry *qe)
{
  struct GNUNET_DATASTORE_Handle *h = qe->h;

  GNUNET_CONTAINER_DLL_remove (h->queue_head,
                               h->queue_tail,
                               qe);
  h->queue_size--;
  if (NULL != qe->env)
    GNUNET_MQ_discard (qe->env);
  GNUNET_free (qe);
}


/**
 * Handle error in sending drop request to datastore.
 *
 * @param cls closure with the datastore handle
 * @param error error code
 */
static void
mq_error_handler (void *cls,
                  enum GNUNET_MQ_Error error)
{
  struct GNUNET_DATASTORE_Handle *h = cls;
  struct GNUNET_DATASTORE_QueueEntry *qe;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "MQ error, reconnecting to DATASTORE\n");
  do_disconnect (h);
  qe = h->queue_head;
  if ( (NULL != qe) &&
       (NULL == qe->env) )
  {
    union QueueContext qc = qe->qc;
    uint16_t rt = qe->response_type;

    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Failed to receive response from database.\n");
    free_queue_entry (qe);
    switch (rt)
    {
    case GNUNET_MESSAGE_TYPE_DATASTORE_STATUS:
      if (NULL != qc.sc.cont)
        qc.sc.cont (qc.sc.cont_cls,
                    GNUNET_SYSERR,
                    GNUNET_TIME_UNIT_ZERO_ABS,
                    _("DATASTORE disconnected"));
      break;
    case GNUNET_MESSAGE_TYPE_DATASTORE_DATA:
      if (NULL != qc.rc.proc)
        qc.rc.proc (qc.rc.proc_cls,
                    NULL,
                    0,
                    NULL, 0, 0, 0,
                    GNUNET_TIME_UNIT_ZERO_ABS,
                    0);
      break;
    default:
      GNUNET_break (0);
    }
  }
}


/**
 * Connect to the datastore service.
 *
 * @param cfg configuration to use
 * @return handle to use to access the service
 */
struct GNUNET_DATASTORE_Handle *
GNUNET_DATASTORE_connect (const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_DATASTORE_Handle *h;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Establishing DATASTORE connection!\n");
  h = GNUNET_new (struct GNUNET_DATASTORE_Handle);
  h->cfg = cfg;
  try_reconnect (h);
  if (NULL == h->mq)
  {
    GNUNET_free (h);
    return NULL;
  }
  h->stats = GNUNET_STATISTICS_create ("datastore-api",
                                       cfg);
  return h;
}


/**
 * Task used by to disconnect from the datastore after
 * we send the #GNUNET_MESSAGE_TYPE_DATASTORE_DROP message.
 *
 * @param cls the datastore handle
 */
static void
disconnect_after_drop (void *cls)
{
  struct GNUNET_DATASTORE_Handle *h = cls;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Drop sent, disconnecting\n");
  GNUNET_DATASTORE_disconnect (h,
                               GNUNET_NO);
}


/**
 * Handle error in sending drop request to datastore.
 *
 * @param cls closure with the datastore handle
 * @param error error code
 */
static void
disconnect_on_mq_error (void *cls,
                        enum GNUNET_MQ_Error error)
{
  struct GNUNET_DATASTORE_Handle *h = cls;

  LOG (GNUNET_ERROR_TYPE_ERROR,
       "Failed to ask datastore to drop tables\n");
  GNUNET_DATASTORE_disconnect (h,
                               GNUNET_NO);
}


/**
 * Disconnect from the datastore service (and free
 * associated resources).
 *
 * @param h handle to the datastore
 * @param drop set to #GNUNET_YES to delete all data in datastore (!)
 */
void
GNUNET_DATASTORE_disconnect (struct GNUNET_DATASTORE_Handle *h,
                             int drop)
{
  struct GNUNET_DATASTORE_QueueEntry *qe;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Datastore disconnect\n");
  if (NULL != h->mq)
  {
    GNUNET_MQ_destroy (h->mq);
    h->mq = NULL;
  }
  if (NULL != h->reconnect_task)
  {
    GNUNET_SCHEDULER_cancel (h->reconnect_task);
    h->reconnect_task = NULL;
  }
  while (NULL != (qe = h->queue_head))
  {
    switch (qe->response_type)
    {
    case GNUNET_MESSAGE_TYPE_DATASTORE_STATUS:
      if (NULL != qe->qc.sc.cont)
        qe->qc.sc.cont (qe->qc.sc.cont_cls,
                        GNUNET_SYSERR,
                        GNUNET_TIME_UNIT_ZERO_ABS,
                        _("Disconnected from DATASTORE"));
      break;
    case GNUNET_MESSAGE_TYPE_DATASTORE_DATA:
      if (NULL != qe->qc.rc.proc)
        qe->qc.rc.proc (qe->qc.rc.proc_cls,
                        NULL,
                        0,
                        NULL, 0, 0, 0,
                        GNUNET_TIME_UNIT_ZERO_ABS,
                        0);
      break;
    default:
      GNUNET_break (0);
    }
    free_queue_entry (qe);
  }
  if (GNUNET_YES == drop)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Re-connecting to issue DROP!\n");
    GNUNET_assert (NULL == h->mq);
    h->mq = GNUNET_CLIENT_connecT (h->cfg,
                                   "datastore",
                                   NULL,
                                   &disconnect_on_mq_error,
                                   h);
    if (NULL != h->mq)
    {
      struct GNUNET_MessageHeader *hdr;
      struct GNUNET_MQ_Envelope *env;

      env = GNUNET_MQ_msg (hdr,
                           GNUNET_MESSAGE_TYPE_DATASTORE_DROP);
      GNUNET_MQ_notify_sent (env,
                             &disconnect_after_drop,
                             h);
      GNUNET_MQ_send (h->mq,
                      env);
      return;
    }
    GNUNET_break (0);
  }
  GNUNET_STATISTICS_destroy (h->stats,
                             GNUNET_NO);
  h->stats = NULL;
  GNUNET_free (h);
}


/**
 * Create a new entry for our priority queue (and possibly discard other entires if
 * the queue is getting too long).
 *
 * @param h handle to the datastore
 * @param env envelope with the message to queue
 * @param queue_priority priority of the entry
 * @param max_queue_size at what queue size should this request be dropped
 *        (if other requests of higher priority are in the queue)
 * @param expected_type which type of response do we expect,
 *        #GNUNET_MESSAGE_TYPE_DATASTORE_STATUS or
 *        #GNUNET_MESSAGE_TYPE_DATASTORE_DATA
 * @param qc client context (NOT a closure for @a response_proc)
 * @return NULL if the queue is full
 */
static struct GNUNET_DATASTORE_QueueEntry *
make_queue_entry (struct GNUNET_DATASTORE_Handle *h,
                  struct GNUNET_MQ_Envelope *env,
                  unsigned int queue_priority,
                  unsigned int max_queue_size,
                  uint16_t expected_type,
                  const union QueueContext *qc)
{
  struct GNUNET_DATASTORE_QueueEntry *qe;
  struct GNUNET_DATASTORE_QueueEntry *pos;
  unsigned int c;

  c = 0;
  pos = h->queue_head;
  while ( (NULL != pos) &&
          (c < max_queue_size) &&
          (pos->priority >= queue_priority) )
  {
    c++;
    pos = pos->next;
  }
  if (c >= max_queue_size)
  {
    GNUNET_STATISTICS_update (h->stats,
                              gettext_noop ("# queue overflows"),
                              1,
                              GNUNET_NO);
    GNUNET_MQ_discard (env);
    return NULL;
  }
  qe = GNUNET_new (struct GNUNET_DATASTORE_QueueEntry);
  qe->h = h;
  qe->env = env;
  qe->response_type = expected_type;
  qe->qc = *qc;
  qe->priority = queue_priority;
  qe->max_queue = max_queue_size;
  if (NULL == pos)
  {
    /* append at the tail */
    pos = h->queue_tail;
  }
  else
  {
    pos = pos->prev;
    /* do not insert at HEAD if HEAD query was already
     * transmitted and we are still receiving replies! */
    if ( (NULL == pos) &&
         (NULL == h->queue_head->env) )
      pos = h->queue_head;
  }
  c++;
#if INSANE_STATISTICS
  GNUNET_STATISTICS_update (h->stats,
                            gettext_noop ("# queue entries created"),
                            1,
                            GNUNET_NO);
#endif
  GNUNET_CONTAINER_DLL_insert_after (h->queue_head,
                                     h->queue_tail,
                                     pos,
                                     qe);
  h->queue_size++;
  return qe;
}


/**
 * Process entries in the queue (or do nothing if we are already
 * doing so).
 *
 * @param h handle to the datastore
 */
static void
process_queue (struct GNUNET_DATASTORE_Handle *h)
{
  struct GNUNET_DATASTORE_QueueEntry *qe;

  if (NULL == (qe = h->queue_head))
  {
    /* no entry in queue */
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Queue empty\n");
    return;
  }
  if (NULL == qe->env)
  {
    /* waiting for replies */
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Head request already transmitted\n");
    return;
  }
  if (NULL == h->mq)
  {
    /* waiting for reconnect */
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Not connected\n");
    return;
  }
  GNUNET_MQ_send (h->mq,
                  qe->env);
  qe->env = NULL;
}




/**
 * Function called to check status message from the service.
 *
 * @param cls closure
 * @param sm status message received
 * @return #GNUNET_OK if the message is well-formed
 */
static int
check_status (void *cls,
              const struct StatusMessage *sm)
{
  uint16_t msize = ntohs (sm->header.size) - sizeof (*sm);
  int32_t status = ntohl (sm->status);

  if (msize > 0)
  {
    const char *emsg = (const char *) &sm[1];

    if ('\0' != emsg[msize - 1])
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
  }
  else if (GNUNET_SYSERR == status)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Function called to handle status message from the service.
 *
 * @param cls closure
 * @param sm status message received
 */
static void
handle_status (void *cls,
               const struct StatusMessage *sm)
{
  struct GNUNET_DATASTORE_Handle *h = cls;
  struct GNUNET_DATASTORE_QueueEntry *qe;
  struct StatusContext rc;
  const char *emsg;
  int32_t status = ntohl (sm->status);

  if (h->skip_next_messages > 0)
  {
    h->skip_next_messages--;
    process_queue (h);
    return;
  }
  if (NULL == (qe = h->queue_head))
  {
    GNUNET_break (0);
    do_disconnect (h);
    return;
  }
  if (NULL != qe->env)
  {
    GNUNET_break (0);
    do_disconnect (h);
    return;
  }
  if (GNUNET_MESSAGE_TYPE_DATASTORE_STATUS != qe->response_type)
  {
    GNUNET_break (0);
    do_disconnect (h);
    return;
  }
  rc = qe->qc.sc;
  free_queue_entry (qe);
  if (ntohs (sm->header.size) > sizeof (struct StatusMessage))
    emsg = (const char *) &sm[1];
  else
    emsg = NULL;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received status %d/%s\n",
       (int) status,
       emsg);
  GNUNET_STATISTICS_update (h->stats,
                            gettext_noop ("# status messages received"),
                            1,
                            GNUNET_NO);
  h->retry_time = GNUNET_TIME_UNIT_ZERO;
  process_queue (h);
  if (NULL != rc.cont)
    rc.cont (rc.cont_cls,
             status,
	     GNUNET_TIME_absolute_ntoh (sm->min_expiration),
	     emsg);
}


/**
 * Check data message we received from the service.
 *
 * @param cls closure with the `struct GNUNET_DATASTORE_Handle *`
 * @param dm message received
 */
static int
check_data (void *cls,
            const struct DataMessage *dm)
{
  uint16_t msize = ntohs (dm->header.size) - sizeof (*dm);

  if (msize != ntohl (dm->size))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handle data message we got from the service.
 *
 * @param cls closure with the `struct GNUNET_DATASTORE_Handle *`
 * @param dm message received
 */
static void
handle_data (void *cls,
             const struct DataMessage *dm)
{
  struct GNUNET_DATASTORE_Handle *h = cls;
  struct GNUNET_DATASTORE_QueueEntry *qe;
  struct ResultContext rc;

  if (h->skip_next_messages > 0)
  {
    process_queue (h);
    return;
  }
  qe = h->queue_head;
  if (NULL == qe)
  {
    GNUNET_break (0);
    do_disconnect (h);
    return;
  }
  if (NULL != qe->env)
  {
    GNUNET_break (0);
    do_disconnect (h);
    return;
  }
  if (GNUNET_MESSAGE_TYPE_DATASTORE_DATA != qe->response_type)
  {
    GNUNET_break (0);
    do_disconnect (h);
    return;
  }
#if INSANE_STATISTICS
  GNUNET_STATISTICS_update (h->stats,
                            gettext_noop ("# Results received"),
                            1,
                            GNUNET_NO);
#endif
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received result %llu with type %u and size %u with key %s\n",
       (unsigned long long) GNUNET_ntohll (dm->uid),
       ntohl (dm->type),
       ntohl (dm->size),
       GNUNET_h2s (&dm->key));
  rc = qe->qc.rc;
  free_queue_entry (qe);
  h->retry_time = GNUNET_TIME_UNIT_ZERO;
  process_queue (h);
  if (NULL != rc.proc)
    rc.proc (rc.proc_cls,
             &dm->key,
             ntohl (dm->size),
             &dm[1],
             ntohl (dm->type),
             ntohl (dm->priority),
             ntohl (dm->anonymity),
             GNUNET_TIME_absolute_ntoh (dm->expiration),
             GNUNET_ntohll (dm->uid));
}


/**
 * Type of a function to call when we receive a
 * #GNUNET_MESSAGE_TYPE_DATASTORE_DATA_END message from the service.
 *
 * @param cls closure with the `struct GNUNET_DATASTORE_Handle *`
 * @param msg message received
 */
static void
handle_data_end (void *cls,
                 const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_DATASTORE_Handle *h = cls;
  struct GNUNET_DATASTORE_QueueEntry *qe;
  struct ResultContext rc;

  if (h->skip_next_messages > 0)
  {
    h->skip_next_messages--;
    process_queue (h);
    return;
  }
  qe = h->queue_head;
  if (NULL == qe)
  {
    GNUNET_break (0);
    do_disconnect (h);
    return;
  }
  if (NULL != qe->env)
  {
    GNUNET_break (0);
    do_disconnect (h);
    return;
  }
  if (GNUNET_MESSAGE_TYPE_DATASTORE_DATA != qe->response_type)
  {
    GNUNET_break (0);
    do_disconnect (h);
    return;
  }
  rc = qe->qc.rc;
  free_queue_entry (qe);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received end of result set, new queue size is %u\n",
       h->queue_size);
  h->retry_time = GNUNET_TIME_UNIT_ZERO;
  h->result_count = 0;
  process_queue (h);
  /* signal end of iteration */
  if (NULL != rc.proc)
    rc.proc (rc.proc_cls,
             NULL,
             0,
             NULL,
             0,
             0,
             0,
             GNUNET_TIME_UNIT_ZERO_ABS,
             0);
}


/**
 * Try reconnecting to the datastore service.
 *
 * @param cls the `struct GNUNET_DATASTORE_Handle`
 */
static void
try_reconnect (void *cls)
{
  struct GNUNET_DATASTORE_Handle *h = cls;
  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_var_size (status,
                           GNUNET_MESSAGE_TYPE_DATASTORE_STATUS,
                           struct StatusMessage,
                           h),
    GNUNET_MQ_hd_var_size (data,
                           GNUNET_MESSAGE_TYPE_DATASTORE_DATA,
                           struct DataMessage,
                           h),
    GNUNET_MQ_hd_fixed_size (data_end,
                             GNUNET_MESSAGE_TYPE_DATASTORE_DATA_END,
                             struct GNUNET_MessageHeader,
                             h),
    GNUNET_MQ_handler_end ()
  };

  h->retry_time = GNUNET_TIME_STD_BACKOFF (h->retry_time);
  h->reconnect_task = NULL;
  GNUNET_assert (NULL == h->mq);
  h->mq = GNUNET_CLIENT_connecT (h->cfg,
                                 "datastore",
                                 handlers,
                                 &mq_error_handler,
                                 h);
  if (NULL == h->mq)
    return;
  GNUNET_STATISTICS_update (h->stats,
                            gettext_noop ("# datastore connections (re)created"),
                            1,
                            GNUNET_NO);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Reconnected to DATASTORE\n");
  process_queue (h);
}


/**
 * Dummy continuation used to do nothing (but be non-zero).
 *
 * @param cls closure
 * @param result result
 * @param min_expiration expiration time
 * @param emsg error message
 */
static void
drop_status_cont (void *cls,
                  int32_t result,
		  struct GNUNET_TIME_Absolute min_expiration,
		  const char *emsg)
{
  /* do nothing */
}


/**
 * Store an item in the datastore.  If the item is already present,
 * the priorities are summed up and the higher expiration time and
 * lower anonymity level is used.
 *
 * @param h handle to the datastore
 * @param rid reservation ID to use (from "reserve"); use 0 if no
 *            prior reservation was made
 * @param key key for the value
 * @param size number of bytes in data
 * @param data content stored
 * @param type type of the content
 * @param priority priority of the content
 * @param anonymity anonymity-level for the content
 * @param replication how often should the content be replicated to other peers?
 * @param expiration expiration time for the content
 * @param queue_priority ranking of this request in the priority queue
 * @param max_queue_size at what queue size should this request be dropped
 *        (if other requests of higher priority are in the queue)
 * @param cont continuation to call when done
 * @param cont_cls closure for @a cont
 * @return NULL if the entry was not queued, otherwise a handle that can be used to
 *         cancel; note that even if NULL is returned, the callback will be invoked
 *         (or rather, will already have been invoked)
 */
struct GNUNET_DATASTORE_QueueEntry *
GNUNET_DATASTORE_put (struct GNUNET_DATASTORE_Handle *h,
                      uint32_t rid,
                      const struct GNUNET_HashCode *key,
                      size_t size,
                      const void *data,
                      enum GNUNET_BLOCK_Type type,
                      uint32_t priority,
                      uint32_t anonymity,
                      uint32_t replication,
                      struct GNUNET_TIME_Absolute expiration,
                      unsigned int queue_priority,
                      unsigned int max_queue_size,
                      GNUNET_DATASTORE_ContinuationWithStatus cont,
                      void *cont_cls)
{
  struct GNUNET_DATASTORE_QueueEntry *qe;
  struct GNUNET_MQ_Envelope *env;
  struct DataMessage *dm;
  union QueueContext qc;

  if (size + sizeof (*dm) >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    return NULL;
  }

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Asked to put %u bytes of data under key `%s' for %s\n",
       size,
       GNUNET_h2s (key),
       GNUNET_STRINGS_relative_time_to_string (GNUNET_TIME_absolute_get_remaining (expiration),
					       GNUNET_YES));
  env = GNUNET_MQ_msg_extra (dm,
                             size,
                             GNUNET_MESSAGE_TYPE_DATASTORE_PUT);
  dm->rid = htonl (rid);
  dm->size = htonl ((uint32_t) size);
  dm->type = htonl (type);
  dm->priority = htonl (priority);
  dm->anonymity = htonl (anonymity);
  dm->replication = htonl (replication);
  dm->reserved = htonl (0);
  dm->uid = GNUNET_htonll (0);
  dm->expiration = GNUNET_TIME_absolute_hton (expiration);
  dm->key = *key;
  GNUNET_memcpy (&dm[1],
          data,
          size);
  qc.sc.cont = cont;
  qc.sc.cont_cls = cont_cls;
  qe = make_queue_entry (h,
                         env,
                         queue_priority,
                         max_queue_size,
                         GNUNET_MESSAGE_TYPE_DATASTORE_STATUS,
                         &qc);
  if (NULL == qe)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Could not create queue entry for PUT\n");
    return NULL;
  }
  GNUNET_STATISTICS_update (h->stats,
                            gettext_noop ("# PUT requests executed"),
                            1,
                            GNUNET_NO);
  process_queue (h);
  return qe;
}


/**
 * Reserve space in the datastore.  This function should be used
 * to avoid "out of space" failures during a longer sequence of "put"
 * operations (for example, when a file is being inserted).
 *
 * @param h handle to the datastore
 * @param amount how much space (in bytes) should be reserved (for content only)
 * @param entries how many entries will be created (to calculate per-entry overhead)
 * @param cont continuation to call when done; "success" will be set to
 *             a positive reservation value if space could be reserved.
 * @param cont_cls closure for @a cont
 * @return NULL if the entry was not queued, otherwise a handle that can be used to
 *         cancel; note that even if NULL is returned, the callback will be invoked
 *         (or rather, will already have been invoked)
 */
struct GNUNET_DATASTORE_QueueEntry *
GNUNET_DATASTORE_reserve (struct GNUNET_DATASTORE_Handle *h,
                          uint64_t amount,
                          uint32_t entries,
                          GNUNET_DATASTORE_ContinuationWithStatus cont,
                          void *cont_cls)
{
  struct GNUNET_DATASTORE_QueueEntry *qe;
  struct GNUNET_MQ_Envelope *env;
  struct ReserveMessage *rm;
  union QueueContext qc;

  if (NULL == cont)
    cont = &drop_status_cont;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Asked to reserve %llu bytes of data and %u entries\n",
       (unsigned long long) amount,
       (unsigned int) entries);
  env = GNUNET_MQ_msg (rm,
                       GNUNET_MESSAGE_TYPE_DATASTORE_RESERVE);
  rm->entries = htonl (entries);
  rm->amount = GNUNET_htonll (amount);

  qc.sc.cont = cont;
  qc.sc.cont_cls = cont_cls;
  qe = make_queue_entry (h,
                         env,
                         UINT_MAX,
                         UINT_MAX,
                         GNUNET_MESSAGE_TYPE_DATASTORE_STATUS,
                         &qc);
  if (NULL == qe)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Could not create queue entry to reserve\n");
    return NULL;
  }
  GNUNET_STATISTICS_update (h->stats,
                            gettext_noop ("# RESERVE requests executed"),
                            1,
                            GNUNET_NO);
  process_queue (h);
  return qe;
}


/**
 * Signal that all of the data for which a reservation was made has
 * been stored and that whatever excess space might have been reserved
 * can now be released.
 *
 * @param h handle to the datastore
 * @param rid reservation ID (value of "success" in original continuation
 *        from the "reserve" function).
 * @param queue_priority ranking of this request in the priority queue
 * @param max_queue_size at what queue size should this request be dropped
 *        (if other requests of higher priority are in the queue)
 * @param queue_priority ranking of this request in the priority queue
 * @param max_queue_size at what queue size should this request be dropped
 *        (if other requests of higher priority are in the queue)
 * @param cont continuation to call when done
 * @param cont_cls closure for @a cont
 * @return NULL if the entry was not queued, otherwise a handle that can be used to
 *         cancel; note that even if NULL is returned, the callback will be invoked
 *         (or rather, will already have been invoked)
 */
struct GNUNET_DATASTORE_QueueEntry *
GNUNET_DATASTORE_release_reserve (struct GNUNET_DATASTORE_Handle *h,
                                  uint32_t rid,
                                  unsigned int queue_priority,
                                  unsigned int max_queue_size,
                                  GNUNET_DATASTORE_ContinuationWithStatus cont,
                                  void *cont_cls)
{
  struct GNUNET_DATASTORE_QueueEntry *qe;
  struct GNUNET_MQ_Envelope *env;
  struct ReleaseReserveMessage *rrm;
  union QueueContext qc;

  if (NULL == cont)
    cont = &drop_status_cont;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Asked to release reserve %d\n",
       rid);
  env = GNUNET_MQ_msg (rrm,
                       GNUNET_MESSAGE_TYPE_DATASTORE_RELEASE_RESERVE);
  rrm->rid = htonl (rid);
  qc.sc.cont = cont;
  qc.sc.cont_cls = cont_cls;
  qe = make_queue_entry (h,
                         env,
                         queue_priority,
                         max_queue_size,
                         GNUNET_MESSAGE_TYPE_DATASTORE_STATUS,
                         &qc);
  if (NULL == qe)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Could not create queue entry to release reserve\n");
    return NULL;
  }
  GNUNET_STATISTICS_update (h->stats,
                            gettext_noop
                            ("# RELEASE RESERVE requests executed"), 1,
                            GNUNET_NO);
  process_queue (h);
  return qe;
}


/**
 * Update a value in the datastore.
 *
 * @param h handle to the datastore
 * @param uid identifier for the value
 * @param priority how much to increase the priority of the value
 * @param expiration new expiration value should be MAX of existing and this argument
 * @param queue_priority ranking of this request in the priority queue
 * @param max_queue_size at what queue size should this request be dropped
 *        (if other requests of higher priority are in the queue)
 * @param cont continuation to call when done
 * @param cont_cls closure for @a cont
 * @return NULL if the entry was not queued, otherwise a handle that can be used to
 *         cancel; note that even if NULL is returned, the callback will be invoked
 *         (or rather, will already have been invoked)
 */
struct GNUNET_DATASTORE_QueueEntry *
GNUNET_DATASTORE_update (struct GNUNET_DATASTORE_Handle *h,
                         uint64_t uid,
                         uint32_t priority,
                         struct GNUNET_TIME_Absolute expiration,
                         unsigned int queue_priority,
                         unsigned int max_queue_size,
                         GNUNET_DATASTORE_ContinuationWithStatus cont,
                         void *cont_cls)
{
  struct GNUNET_DATASTORE_QueueEntry *qe;
  struct GNUNET_MQ_Envelope *env;
  struct UpdateMessage *um;
  union QueueContext qc;

  if (NULL == cont)
    cont = &drop_status_cont;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Asked to update entry %llu raising priority by %u and expiration to %s\n",
       uid,
       (unsigned int) priority,
       GNUNET_STRINGS_absolute_time_to_string (expiration));
  env = GNUNET_MQ_msg (um,
                       GNUNET_MESSAGE_TYPE_DATASTORE_UPDATE);
  um->priority = htonl (priority);
  um->expiration = GNUNET_TIME_absolute_hton (expiration);
  um->uid = GNUNET_htonll (uid);

  qc.sc.cont = cont;
  qc.sc.cont_cls = cont_cls;
  qe = make_queue_entry (h,
                         env,
                         queue_priority,
                         max_queue_size,
                         GNUNET_MESSAGE_TYPE_DATASTORE_STATUS,
                         &qc);
  if (NULL == qe)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Could not create queue entry for UPDATE\n");
    return NULL;
  }
  GNUNET_STATISTICS_update (h->stats,
                            gettext_noop ("# UPDATE requests executed"), 1,
                            GNUNET_NO);
  process_queue (h);
  return qe;
}


/**
 * Explicitly remove some content from the database.
 * The @a cont continuation will be called with `status`
 * #GNUNET_OK" if content was removed, #GNUNET_NO
 * if no matching entry was found and #GNUNET_SYSERR
 * on all other types of errors.
 *
 * @param h handle to the datastore
 * @param key key for the value
 * @param size number of bytes in data
 * @param data content stored
 * @param queue_priority ranking of this request in the priority queue
 * @param max_queue_size at what queue size should this request be dropped
 *        (if other requests of higher priority are in the queue)
 * @param cont continuation to call when done
 * @param cont_cls closure for @a cont
 * @return NULL if the entry was not queued, otherwise a handle that can be used to
 *         cancel; note that even if NULL is returned, the callback will be invoked
 *         (or rather, will already have been invoked)
 */
struct GNUNET_DATASTORE_QueueEntry *
GNUNET_DATASTORE_remove (struct GNUNET_DATASTORE_Handle *h,
                         const struct GNUNET_HashCode *key,
                         size_t size,
                         const void *data,
                         unsigned int queue_priority,
                         unsigned int max_queue_size,
                         GNUNET_DATASTORE_ContinuationWithStatus cont,
                         void *cont_cls)
{
  struct GNUNET_DATASTORE_QueueEntry *qe;
  struct DataMessage *dm;
  struct GNUNET_MQ_Envelope *env;
  union QueueContext qc;

  if (sizeof (*dm) + size >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    return NULL;
  }
  if (NULL == cont)
    cont = &drop_status_cont;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Asked to remove %u bytes under key `%s'\n",
       size,
       GNUNET_h2s (key));
  env = GNUNET_MQ_msg_extra (dm,
                             size,
                             GNUNET_MESSAGE_TYPE_DATASTORE_REMOVE);
  dm->rid = htonl (0);
  dm->size = htonl (size);
  dm->type = htonl (0);
  dm->priority = htonl (0);
  dm->anonymity = htonl (0);
  dm->uid = GNUNET_htonll (0);
  dm->expiration = GNUNET_TIME_absolute_hton (GNUNET_TIME_UNIT_ZERO_ABS);
  dm->key = *key;
  GNUNET_memcpy (&dm[1],
          data,
          size);

  qc.sc.cont = cont;
  qc.sc.cont_cls = cont_cls;

  qe = make_queue_entry (h,
                         env,
                         queue_priority,
                         max_queue_size,
                         GNUNET_MESSAGE_TYPE_DATASTORE_STATUS,
                         &qc);
  if (NULL == qe)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Could not create queue entry for REMOVE\n");
    return NULL;
  }
  GNUNET_STATISTICS_update (h->stats,
                            gettext_noop ("# REMOVE requests executed"),
                            1,
                            GNUNET_NO);
  process_queue (h);
  return qe;
}



/**
 * Get a random value from the datastore for content replication.
 * Returns a single, random value among those with the highest
 * replication score, lowering positive replication scores by one for
 * the chosen value (if only content with a replication score exists,
 * a random value is returned and replication scores are not changed).
 *
 * @param h handle to the datastore
 * @param queue_priority ranking of this request in the priority queue
 * @param max_queue_size at what queue size should this request be dropped
 *        (if other requests of higher priority are in the queue)
 * @param proc function to call on a random value; it
 *        will be called once with a value (if available)
 *        and always once with a value of NULL.
 * @param proc_cls closure for @a proc
 * @return NULL if the entry was not queued, otherwise a handle that can be used to
 *         cancel
 */
struct GNUNET_DATASTORE_QueueEntry *
GNUNET_DATASTORE_get_for_replication (struct GNUNET_DATASTORE_Handle *h,
                                      unsigned int queue_priority,
                                      unsigned int max_queue_size,
                                      GNUNET_DATASTORE_DatumProcessor proc,
                                      void *proc_cls)
{
  struct GNUNET_DATASTORE_QueueEntry *qe;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_MessageHeader *m;
  union QueueContext qc;

  GNUNET_assert (NULL != proc);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Asked to get replication entry\n");
  env = GNUNET_MQ_msg (m,
                       GNUNET_MESSAGE_TYPE_DATASTORE_GET_REPLICATION);
  qc.rc.proc = proc;
  qc.rc.proc_cls = proc_cls;
  qe = make_queue_entry (h,
                         env,
                         queue_priority,
                         max_queue_size,
                         GNUNET_MESSAGE_TYPE_DATASTORE_DATA,
                         &qc);
  if (NULL == qe)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Could not create queue entry for GET REPLICATION\n");
    return NULL;
  }
  GNUNET_STATISTICS_update (h->stats,
                            gettext_noop
                            ("# GET REPLICATION requests executed"), 1,
                            GNUNET_NO);
  process_queue (h);
  return qe;
}


/**
 * Get a single zero-anonymity value from the datastore.
 *
 * @param h handle to the datastore
 * @param offset offset of the result (modulo num-results); set to
 *               a random 64-bit value initially; then increment by
 *               one each time; detect that all results have been found by uid
 *               being again the first uid ever returned.
 * @param queue_priority ranking of this request in the priority queue
 * @param max_queue_size at what queue size should this request be dropped
 *        (if other requests of higher priority are in the queue)
 * @param type allowed type for the operation (never zero)
 * @param proc function to call on a random value; it
 *        will be called once with a value (if available)
 *        or with NULL if none value exists.
 * @param proc_cls closure for @a proc
 * @return NULL if the entry was not queued, otherwise a handle that can be used to
 *         cancel
 */
struct GNUNET_DATASTORE_QueueEntry *
GNUNET_DATASTORE_get_zero_anonymity (struct GNUNET_DATASTORE_Handle *h,
                                     uint64_t offset,
                                     unsigned int queue_priority,
                                     unsigned int max_queue_size,
                                     enum GNUNET_BLOCK_Type type,
                                     GNUNET_DATASTORE_DatumProcessor proc,
                                     void *proc_cls)
{
  struct GNUNET_DATASTORE_QueueEntry *qe;
  struct GNUNET_MQ_Envelope *env;
  struct GetZeroAnonymityMessage *m;
  union QueueContext qc;

  GNUNET_assert (NULL != proc);
  GNUNET_assert (type != GNUNET_BLOCK_TYPE_ANY);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Asked to get %llu-th zero-anonymity entry of type %d\n",
       (unsigned long long) offset,
       type);
  env = GNUNET_MQ_msg (m,
                       GNUNET_MESSAGE_TYPE_DATASTORE_GET_ZERO_ANONYMITY);
  m->type = htonl ((uint32_t) type);
  m->offset = GNUNET_htonll (offset);
  qc.rc.proc = proc;
  qc.rc.proc_cls = proc_cls;
  qe = make_queue_entry (h,
                         env,
                         queue_priority,
                         max_queue_size,
                         GNUNET_MESSAGE_TYPE_DATASTORE_DATA,
                         &qc);
  if (NULL == qe)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Could not create queue entry for zero-anonymity procation\n");
    return NULL;
  }
  GNUNET_STATISTICS_update (h->stats,
                            gettext_noop
                            ("# GET ZERO ANONYMITY requests executed"), 1,
                            GNUNET_NO);
  process_queue (h);
  return qe;
}


/**
 * Get a result for a particular key from the datastore.  The processor
 * will only be called once.
 *
 * @param h handle to the datastore
 * @param offset offset of the result (modulo num-results); set to
 *               a random 64-bit value initially; then increment by
 *               one each time; detect that all results have been found by uid
 *               being again the first uid ever returned.
 * @param key maybe NULL (to match all entries)
 * @param type desired type, 0 for any
 * @param queue_priority ranking of this request in the priority queue
 * @param max_queue_size at what queue size should this request be dropped
 *        (if other requests of higher priority are in the queue)
 * @param proc function to call on each matching value;
 *        will be called once with a NULL value at the end
 * @param proc_cls closure for @a proc
 * @return NULL if the entry was not queued, otherwise a handle that can be used to
 *         cancel
 */
struct GNUNET_DATASTORE_QueueEntry *
GNUNET_DATASTORE_get_key (struct GNUNET_DATASTORE_Handle *h,
                          uint64_t offset,
                          const struct GNUNET_HashCode *key,
                          enum GNUNET_BLOCK_Type type,
                          unsigned int queue_priority,
                          unsigned int max_queue_size,
                          GNUNET_DATASTORE_DatumProcessor proc,
                          void *proc_cls)
{
  struct GNUNET_DATASTORE_QueueEntry *qe;
  struct GNUNET_MQ_Envelope *env;
  struct GetKeyMessage *gkm;
  struct GetMessage *gm;
  union QueueContext qc;

  GNUNET_assert (NULL != proc);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Asked to look for data of type %u under key `%s'\n",
       (unsigned int) type,
       GNUNET_h2s (key));
  if (NULL == key)
  {
    env = GNUNET_MQ_msg (gm,
                         GNUNET_MESSAGE_TYPE_DATASTORE_GET);
    gm->type = htonl (type);
    gm->offset = GNUNET_htonll (offset);
  }
  else
  {
    env = GNUNET_MQ_msg (gkm,
                         GNUNET_MESSAGE_TYPE_DATASTORE_GET_KEY);
    gkm->type = htonl (type);
    gkm->offset = GNUNET_htonll (offset);
    gkm->key = *key;
  }
  qc.rc.proc = proc;
  qc.rc.proc_cls = proc_cls;
  qe = make_queue_entry (h,
                         env,
                         queue_priority,
                         max_queue_size,
                         GNUNET_MESSAGE_TYPE_DATASTORE_DATA,
                         &qc);
  if (NULL == qe)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Could not queue request for `%s'\n",
         GNUNET_h2s (key));
    return NULL;
  }
#if INSANE_STATISTICS
  GNUNET_STATISTICS_update (h->stats,
                            gettext_noop ("# GET requests executed"),
                            1,
                            GNUNET_NO);
#endif
  process_queue (h);
  return qe;
}


/**
 * Cancel a datastore operation.  The final callback from the
 * operation must not have been done yet.
 *
 * @param qe operation to cancel
 */
void
GNUNET_DATASTORE_cancel (struct GNUNET_DATASTORE_QueueEntry *qe)
{
  struct GNUNET_DATASTORE_Handle *h = qe->h;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Pending DATASTORE request %p cancelled (%d, %d)\n",
       qe,
       NULL == qe->env,
       h->queue_head == qe);
  if (NULL == qe->env)
  {
    free_queue_entry (qe);
    h->skip_next_messages++;
    return;
  }
  free_queue_entry (qe);
  process_queue (h);
}


/* end of datastore_api.c */
