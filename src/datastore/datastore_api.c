/*
     This file is part of GNUnet
     (C) 2004, 2005, 2006, 2007, 2009, 2010, 2011 Christian Grothoff (and other contributing authors)

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
 * @file datastore/datastore_api.c
 * @brief Management for the datastore for files stored on a GNUnet node.  Implements
 *        a priority queue for requests (with timeouts).
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
   * Closure for cont.
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
   * Closure for proc.
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
   * Response processor (NULL if we are not waiting for a response).
   * This struct should be used for the closure, function-specific
   * arguments can be passed via 'qc'.
   */
  GNUNET_CLIENT_MessageHandler response_proc;

  /**
   * Function to call after transmission of the request.
   */
  GNUNET_DATASTORE_ContinuationWithStatus cont;

  /**
   * Closure for 'cont'.
   */
  void *cont_cls;

  /**
   * Context for the operation.
   */
  union QueueContext qc;

  /**
   * Task for timeout signalling.
   */
  GNUNET_SCHEDULER_TaskIdentifier task;

  /**
   * Timeout for the current operation.
   */
  struct GNUNET_TIME_Absolute timeout;

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
   * Number of bytes in the request message following
   * this struct.  32-bit value for nicer memory
   * access (and overall struct alignment).
   */
  uint32_t message_size;

  /**
   * Has this message been transmitted to the service?
   * Only ever GNUNET_YES for the head of the queue.
   * Note that the overall struct should end at a
   * multiple of 64 bits.
   */
  int was_transmitted;

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
  struct GNUNET_CLIENT_Connection *client;

  /**
   * Handle for statistics.
   */
  struct GNUNET_STATISTICS_Handle *stats;

  /**
   * Current transmit handle.
   */
  struct GNUNET_CLIENT_TransmitHandle *th;

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
  GNUNET_SCHEDULER_TaskIdentifier reconnect_task;

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
   * Are we currently trying to receive from the service?
   */
  int in_receive;

  /**
   * We should ignore the next message(s) from the service.
   */
  unsigned int skip_next_messages;

};



/**
 * Connect to the datastore service.
 *
 * @param cfg configuration to use
 * @return handle to use to access the service
 */
struct GNUNET_DATASTORE_Handle *
GNUNET_DATASTORE_connect (const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_CLIENT_Connection *c;
  struct GNUNET_DATASTORE_Handle *h;

  c = GNUNET_CLIENT_connect ("datastore", cfg);
  if (c == NULL)
    return NULL;                /* oops */
  h = GNUNET_malloc (sizeof (struct GNUNET_DATASTORE_Handle) +
                     GNUNET_SERVER_MAX_MESSAGE_SIZE - 1);
  h->client = c;
  h->cfg = cfg;
  h->stats = GNUNET_STATISTICS_create ("datastore-api", cfg);
  return h;
}


/**
 * Task used by 'transmit_drop' to disconnect the datastore.
 *
 * @param cls the datastore handle
 * @param tc scheduler context
 */
static void
disconnect_after_drop (void *cls,
		       const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_DATASTORE_Handle *h = cls;

  GNUNET_DATASTORE_disconnect (h, GNUNET_NO);
}


/**
 * Transmit DROP message to datastore service.
 *
 * @param cls the 'struct GNUNET_DATASTORE_Handle'
 * @param size number of bytes that can be copied to buf
 * @param buf where to copy the drop message
 * @return number of bytes written to buf
 */
static size_t
transmit_drop (void *cls, size_t size, void *buf)
{
  struct GNUNET_DATASTORE_Handle *h = cls;
  struct GNUNET_MessageHeader *hdr;

  if (buf == NULL)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         _("Failed to transmit request to drop database.\n"));
    GNUNET_SCHEDULER_add_continuation (&disconnect_after_drop, h,
				       GNUNET_SCHEDULER_REASON_PREREQ_DONE);
    return 0;
  }
  GNUNET_assert (size >= sizeof (struct GNUNET_MessageHeader));
  hdr = buf;
  hdr->size = htons (sizeof (struct GNUNET_MessageHeader));
  hdr->type = htons (GNUNET_MESSAGE_TYPE_DATASTORE_DROP);
  GNUNET_SCHEDULER_add_continuation (&disconnect_after_drop, h,
				     GNUNET_SCHEDULER_REASON_PREREQ_DONE);
  return sizeof (struct GNUNET_MessageHeader);
}


/**
 * Disconnect from the datastore service (and free
 * associated resources).
 *
 * @param h handle to the datastore
 * @param drop set to GNUNET_YES to delete all data in datastore (!)
 */
void
GNUNET_DATASTORE_disconnect (struct GNUNET_DATASTORE_Handle *h, int drop)
{
  struct GNUNET_DATASTORE_QueueEntry *qe;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Datastore disconnect\n");
  if (NULL != h->th)
  {
    GNUNET_CLIENT_notify_transmit_ready_cancel (h->th);
    h->th = NULL;
  }
  if (h->client != NULL)
  {
    GNUNET_CLIENT_disconnect (h->client);
    h->client = NULL;
  }
  if (h->reconnect_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (h->reconnect_task);
    h->reconnect_task = GNUNET_SCHEDULER_NO_TASK;
  }
  while (NULL != (qe = h->queue_head))
  {
    GNUNET_assert (NULL != qe->response_proc);
    qe->response_proc (h, NULL);
  }
  if (GNUNET_YES == drop)
  {
    h->client = GNUNET_CLIENT_connect ("datastore", h->cfg);
    if (h->client != NULL)
    {
      if (NULL !=
          GNUNET_CLIENT_notify_transmit_ready (h->client,
                                               sizeof (struct
                                                       GNUNET_MessageHeader),
                                               GNUNET_TIME_UNIT_MINUTES,
                                               GNUNET_YES, &transmit_drop, h))
        return;
      GNUNET_CLIENT_disconnect (h->client);
      h->client = NULL;
    }
    GNUNET_break (0);
  }
  GNUNET_STATISTICS_destroy (h->stats, GNUNET_NO);
  h->stats = NULL;
  GNUNET_free (h);
}


/**
 * A request has timed out (before being transmitted to the service).
 *
 * @param cls the 'struct GNUNET_DATASTORE_QueueEntry'
 * @param tc scheduler context
 */
static void
timeout_queue_entry (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_DATASTORE_QueueEntry *qe = cls;

  GNUNET_STATISTICS_update (qe->h->stats,
                            gettext_noop ("# queue entry timeouts"), 1,
                            GNUNET_NO);
  qe->task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_assert (qe->was_transmitted == GNUNET_NO);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Timeout of request in datastore queue\n");
  qe->response_proc (qe->h, NULL);
}


/**
 * Create a new entry for our priority queue (and possibly discard other entires if
 * the queue is getting too long).
 *
 * @param h handle to the datastore
 * @param msize size of the message to queue
 * @param queue_priority priority of the entry
 * @param max_queue_size at what queue size should this request be dropped
 *        (if other requests of higher priority are in the queue)
 * @param timeout timeout for the operation
 * @param response_proc function to call with replies (can be NULL)
 * @param qc client context (NOT a closure for response_proc)
 * @return NULL if the queue is full
 */
static struct GNUNET_DATASTORE_QueueEntry *
make_queue_entry (struct GNUNET_DATASTORE_Handle *h, size_t msize,
                  unsigned int queue_priority, unsigned int max_queue_size,
                  struct GNUNET_TIME_Relative timeout,
                  GNUNET_CLIENT_MessageHandler response_proc,
                  const union QueueContext *qc)
{
  struct GNUNET_DATASTORE_QueueEntry *ret;
  struct GNUNET_DATASTORE_QueueEntry *pos;
  unsigned int c;

  c = 0;
  pos = h->queue_head;
  while ((pos != NULL) && (c < max_queue_size) &&
         (pos->priority >= queue_priority))
  {
    c++;
    pos = pos->next;
  }
  if (c >= max_queue_size)
  {
    GNUNET_STATISTICS_update (h->stats, gettext_noop ("# queue overflows"), 1,
                              GNUNET_NO);
    return NULL;
  }
  ret = GNUNET_malloc (sizeof (struct GNUNET_DATASTORE_QueueEntry) + msize);
  ret->h = h;
  ret->response_proc = response_proc;
  ret->qc = *qc;
  ret->timeout = GNUNET_TIME_relative_to_absolute (timeout);
  ret->priority = queue_priority;
  ret->max_queue = max_queue_size;
  ret->message_size = msize;
  ret->was_transmitted = GNUNET_NO;
  if (pos == NULL)
  {
    /* append at the tail */
    pos = h->queue_tail;
  }
  else
  {
    pos = pos->prev;
    /* do not insert at HEAD if HEAD query was already
     * transmitted and we are still receiving replies! */
    if ((pos == NULL) && (h->queue_head->was_transmitted))
      pos = h->queue_head;
  }
  c++;
  GNUNET_STATISTICS_update (h->stats, gettext_noop ("# queue entries created"),
                            1, GNUNET_NO);
  GNUNET_CONTAINER_DLL_insert_after (h->queue_head, h->queue_tail, pos, ret);
  h->queue_size++;
  ret->task = GNUNET_SCHEDULER_add_delayed (timeout, &timeout_queue_entry, ret);
  pos = ret->next;
  while (pos != NULL)
  {
    if ((pos->max_queue < h->queue_size) && (pos->was_transmitted == GNUNET_NO))
    {
      GNUNET_assert (pos->response_proc != NULL);
      /* move 'pos' element to head so that it will be
       * killed on 'NULL' call below */
      LOG (GNUNET_ERROR_TYPE_DEBUG, "Dropping request from datastore queue\n");
      GNUNET_CONTAINER_DLL_remove (h->queue_head, h->queue_tail, pos);
      GNUNET_CONTAINER_DLL_insert (h->queue_head, h->queue_tail, pos);
      GNUNET_STATISTICS_update (h->stats,
                                gettext_noop
                                ("# Requests dropped from datastore queue"), 1,
                                GNUNET_NO);
      GNUNET_assert (h->queue_head == pos);
      pos->response_proc (h, NULL);
      break;
    }
    pos = pos->next;
  }
  return ret;
}


/**
 * Process entries in the queue (or do nothing if we are already
 * doing so).
 *
 * @param h handle to the datastore
 */
static void
process_queue (struct GNUNET_DATASTORE_Handle *h);


/**
 * Try reconnecting to the datastore service.
 *
 * @param cls the 'struct GNUNET_DATASTORE_Handle'
 * @param tc scheduler context
 */
static void
try_reconnect (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_DATASTORE_Handle *h = cls;

  if (h->retry_time.rel_value < GNUNET_CONSTANTS_SERVICE_RETRY.rel_value)
    h->retry_time = GNUNET_CONSTANTS_SERVICE_RETRY;
  else
    h->retry_time = GNUNET_TIME_relative_multiply (h->retry_time, 2);
  if (h->retry_time.rel_value > GNUNET_CONSTANTS_SERVICE_TIMEOUT.rel_value)
    h->retry_time = GNUNET_CONSTANTS_SERVICE_TIMEOUT;
  h->reconnect_task = GNUNET_SCHEDULER_NO_TASK;
  h->client = GNUNET_CLIENT_connect ("datastore", h->cfg);
  if (h->client == NULL)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR, "DATASTORE reconnect failed (fatally)\n");
    return;
  }
  GNUNET_STATISTICS_update (h->stats,
                            gettext_noop
                            ("# datastore connections (re)created"), 1,
                            GNUNET_NO);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Reconnected to DATASTORE\n");
  process_queue (h);
}


/**
 * Disconnect from the service and then try reconnecting to the datastore service
 * after some delay.
 *
 * @param h handle to datastore to disconnect and reconnect
 */
static void
do_disconnect (struct GNUNET_DATASTORE_Handle *h)
{
  if (h->client == NULL)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "client NULL in disconnect, will not try to reconnect\n");
    return;
  }
#if 0
  GNUNET_STATISTICS_update (stats, gettext_noop ("# reconnected to DATASTORE"),
                            1, GNUNET_NO);
#endif
  GNUNET_CLIENT_disconnect (h->client);
  h->skip_next_messages = 0;
  h->client = NULL;
  h->reconnect_task =
      GNUNET_SCHEDULER_add_delayed (h->retry_time, &try_reconnect, h);
}


/**
 * Function called whenever we receive a message from
 * the service.  Calls the appropriate handler.
 *
 * @param cls the 'struct GNUNET_DATASTORE_Handle'
 * @param msg the received message
 */
static void
receive_cb (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_DATASTORE_Handle *h = cls;
  struct GNUNET_DATASTORE_QueueEntry *qe;

  h->in_receive = GNUNET_NO;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Receiving reply from datastore\n");
  if (h->skip_next_messages > 0)
  {
    h->skip_next_messages--;
    process_queue (h);
    return;
  }
  if (NULL == (qe = h->queue_head))
  {
    GNUNET_break (0);
    process_queue (h);
    return;
  }
  qe->response_proc (h, msg);
}


/**
 * Transmit request from queue to datastore service.
 *
 * @param cls the 'struct GNUNET_DATASTORE_Handle'
 * @param size number of bytes that can be copied to buf
 * @param buf where to copy the drop message
 * @return number of bytes written to buf
 */
static size_t
transmit_request (void *cls, size_t size, void *buf)
{
  struct GNUNET_DATASTORE_Handle *h = cls;
  struct GNUNET_DATASTORE_QueueEntry *qe;
  size_t msize;

  h->th = NULL;
  if (NULL == (qe = h->queue_head))
    return 0;                   /* no entry in queue */
  if (buf == NULL)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Failed to transmit request to DATASTORE.\n");
    GNUNET_STATISTICS_update (h->stats,
                              gettext_noop ("# transmission request failures"),
                              1, GNUNET_NO);
    do_disconnect (h);
    return 0;
  }
  if (size < (msize = qe->message_size))
  {
    process_queue (h);
    return 0;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Transmitting %u byte request to DATASTORE\n",
       msize);
  memcpy (buf, &qe[1], msize);
  qe->was_transmitted = GNUNET_YES;
  GNUNET_SCHEDULER_cancel (qe->task);
  qe->task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_assert (GNUNET_NO == h->in_receive);
  h->in_receive = GNUNET_YES;
  GNUNET_CLIENT_receive (h->client, &receive_cb, h,
                         GNUNET_TIME_absolute_get_remaining (qe->timeout));
  GNUNET_STATISTICS_update (h->stats,
                            gettext_noop ("# bytes sent to datastore"), 1,
                            GNUNET_NO);
  return msize;
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
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Queue empty\n");
    return;                     /* no entry in queue */
  }
  if (qe->was_transmitted == GNUNET_YES)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Head request already transmitted\n");
    return;                     /* waiting for replies */
  }
  if (h->th != NULL)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Pending transmission request\n");
    return;                     /* request pending */
  }
  if (h->client == NULL)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Not connected\n");
    return;                     /* waiting for reconnect */
  }
  if (GNUNET_YES == h->in_receive)
  {
    /* wait for response to previous query */
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Queueing %u byte request to DATASTORE\n",
       qe->message_size);
  h->th =
      GNUNET_CLIENT_notify_transmit_ready (h->client, qe->message_size,
                                           GNUNET_TIME_absolute_get_remaining
                                           (qe->timeout), GNUNET_YES,
                                           &transmit_request, h);
  GNUNET_assert (GNUNET_NO == h->in_receive);
  GNUNET_break (NULL != h->th);
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
drop_status_cont (void *cls, int32_t result, 
		  struct GNUNET_TIME_Absolute min_expiration,
		  const char *emsg)
{
  /* do nothing */
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

  GNUNET_CONTAINER_DLL_remove (h->queue_head, h->queue_tail, qe);
  if (qe->task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (qe->task);
    qe->task = GNUNET_SCHEDULER_NO_TASK;
  }
  h->queue_size--;
  qe->was_transmitted = GNUNET_SYSERR;  /* use-after-free warning */
  GNUNET_free (qe);
}


/**
 * Type of a function to call when we receive a message
 * from the service.
 *
 * @param cls closure
 * @param msg message received, NULL on timeout or fatal error
 */
static void
process_status_message (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_DATASTORE_Handle *h = cls;
  struct GNUNET_DATASTORE_QueueEntry *qe;
  struct StatusContext rc;
  const struct StatusMessage *sm;
  const char *emsg;
  int32_t status;
  int was_transmitted;

  if (NULL == (qe = h->queue_head))
  {
    GNUNET_break (0);
    do_disconnect (h);
    return;
  }
  rc = qe->qc.sc;
  if (msg == NULL)
  {
    was_transmitted = qe->was_transmitted;
    free_queue_entry (qe);
    if (was_transmitted == GNUNET_YES)
      do_disconnect (h);
    else
      process_queue (h);
    if (rc.cont != NULL)
      rc.cont (rc.cont_cls, GNUNET_SYSERR,
	       GNUNET_TIME_UNIT_ZERO_ABS,
               _("Failed to receive status response from database."));
    return;
  }
  GNUNET_assert (GNUNET_YES == qe->was_transmitted);
  free_queue_entry (qe);
  if ((ntohs (msg->size) < sizeof (struct StatusMessage)) ||
      (ntohs (msg->type) != GNUNET_MESSAGE_TYPE_DATASTORE_STATUS))
  {
    GNUNET_break (0);
    h->retry_time = GNUNET_TIME_UNIT_ZERO;
    do_disconnect (h);
    if (rc.cont != NULL)
      rc.cont (rc.cont_cls, GNUNET_SYSERR,
	       GNUNET_TIME_UNIT_ZERO_ABS,
               _("Error reading response from datastore service"));
    return;
  }
  sm = (const struct StatusMessage *) msg;
  status = ntohl (sm->status);
  emsg = NULL;
  if (ntohs (msg->size) > sizeof (struct StatusMessage))
  {
    emsg = (const char *) &sm[1];
    if (emsg[ntohs (msg->size) - sizeof (struct StatusMessage) - 1] != '\0')
    {
      GNUNET_break (0);
      emsg = _("Invalid error message received from datastore service");
    }
  }
  if ((status == GNUNET_SYSERR) && (emsg == NULL))
  {
    GNUNET_break (0);
    emsg = _("Invalid error message received from datastore service");
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Received status %d/%s\n", (int) status, emsg);
  GNUNET_STATISTICS_update (h->stats,
                            gettext_noop ("# status messages received"), 1,
                            GNUNET_NO);
  h->retry_time.rel_value = 0;
  process_queue (h);
  if (rc.cont != NULL)
    rc.cont (rc.cont_cls, status, 
	     GNUNET_TIME_absolute_ntoh (sm->min_expiration),
	     emsg);
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
 * @param timeout timeout for the operation
 * @param cont continuation to call when done
 * @param cont_cls closure for cont
 * @return NULL if the entry was not queued, otherwise a handle that can be used to
 *         cancel; note that even if NULL is returned, the callback will be invoked
 *         (or rather, will already have been invoked)
 */
struct GNUNET_DATASTORE_QueueEntry *
GNUNET_DATASTORE_put (struct GNUNET_DATASTORE_Handle *h, uint32_t rid,
                      const GNUNET_HashCode * key, size_t size,
                      const void *data, enum GNUNET_BLOCK_Type type,
                      uint32_t priority, uint32_t anonymity,
                      uint32_t replication,
                      struct GNUNET_TIME_Absolute expiration,
                      unsigned int queue_priority, unsigned int max_queue_size,
                      struct GNUNET_TIME_Relative timeout,
                      GNUNET_DATASTORE_ContinuationWithStatus cont,
                      void *cont_cls)
{
  struct GNUNET_DATASTORE_QueueEntry *qe;
  struct DataMessage *dm;
  size_t msize;
  union QueueContext qc;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Asked to put %u bytes of data under key `%s' for %llu ms\n", size,
       GNUNET_h2s (key),
       GNUNET_TIME_absolute_get_remaining (expiration).rel_value);
  msize = sizeof (struct DataMessage) + size;
  GNUNET_assert (msize < GNUNET_SERVER_MAX_MESSAGE_SIZE);
  qc.sc.cont = cont;
  qc.sc.cont_cls = cont_cls;
  qe = make_queue_entry (h, msize, queue_priority, max_queue_size, timeout,
                         &process_status_message, &qc);
  if (qe == NULL)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Could not create queue entry for PUT\n");
    return NULL;
  }
  GNUNET_STATISTICS_update (h->stats, gettext_noop ("# PUT requests executed"),
                            1, GNUNET_NO);
  dm = (struct DataMessage *) &qe[1];
  dm->header.type = htons (GNUNET_MESSAGE_TYPE_DATASTORE_PUT);
  dm->header.size = htons (msize);
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
  memcpy (&dm[1], data, size);
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
 * @param queue_priority ranking of this request in the priority queue
 * @param max_queue_size at what queue size should this request be dropped
 *        (if other requests of higher priority are in the queue)
 * @param timeout how long to wait at most for a response (or before dying in queue)
 * @param cont continuation to call when done; "success" will be set to
 *             a positive reservation value if space could be reserved.
 * @param cont_cls closure for cont
 * @return NULL if the entry was not queued, otherwise a handle that can be used to
 *         cancel; note that even if NULL is returned, the callback will be invoked
 *         (or rather, will already have been invoked)
 */
struct GNUNET_DATASTORE_QueueEntry *
GNUNET_DATASTORE_reserve (struct GNUNET_DATASTORE_Handle *h, uint64_t amount,
                          uint32_t entries, unsigned int queue_priority,
                          unsigned int max_queue_size,
                          struct GNUNET_TIME_Relative timeout,
                          GNUNET_DATASTORE_ContinuationWithStatus cont,
                          void *cont_cls)
{
  struct GNUNET_DATASTORE_QueueEntry *qe;
  struct ReserveMessage *rm;
  union QueueContext qc;

  if (cont == NULL)
    cont = &drop_status_cont;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Asked to reserve %llu bytes of data and %u entries\n",
       (unsigned long long) amount, (unsigned int) entries);
  qc.sc.cont = cont;
  qc.sc.cont_cls = cont_cls;
  qe = make_queue_entry (h, sizeof (struct ReserveMessage), queue_priority,
                         max_queue_size, timeout, &process_status_message, &qc);
  if (qe == NULL)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Could not create queue entry to reserve\n");
    return NULL;
  }
  GNUNET_STATISTICS_update (h->stats,
                            gettext_noop ("# RESERVE requests executed"), 1,
                            GNUNET_NO);
  rm = (struct ReserveMessage *) &qe[1];
  rm->header.type = htons (GNUNET_MESSAGE_TYPE_DATASTORE_RESERVE);
  rm->header.size = htons (sizeof (struct ReserveMessage));
  rm->entries = htonl (entries);
  rm->amount = GNUNET_htonll (amount);
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
 * @param timeout how long to wait at most for a response
 * @param cont continuation to call when done
 * @param cont_cls closure for cont
 * @return NULL if the entry was not queued, otherwise a handle that can be used to
 *         cancel; note that even if NULL is returned, the callback will be invoked
 *         (or rather, will already have been invoked)
 */
struct GNUNET_DATASTORE_QueueEntry *
GNUNET_DATASTORE_release_reserve (struct GNUNET_DATASTORE_Handle *h,
                                  uint32_t rid, unsigned int queue_priority,
                                  unsigned int max_queue_size,
                                  struct GNUNET_TIME_Relative timeout,
                                  GNUNET_DATASTORE_ContinuationWithStatus cont,
                                  void *cont_cls)
{
  struct GNUNET_DATASTORE_QueueEntry *qe;
  struct ReleaseReserveMessage *rrm;
  union QueueContext qc;

  if (cont == NULL)
    cont = &drop_status_cont;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Asked to release reserve %d\n", rid);
  qc.sc.cont = cont;
  qc.sc.cont_cls = cont_cls;
  qe = make_queue_entry (h, sizeof (struct ReleaseReserveMessage),
                         queue_priority, max_queue_size, timeout,
                         &process_status_message, &qc);
  if (qe == NULL)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Could not create queue entry to release reserve\n");
    return NULL;
  }
  GNUNET_STATISTICS_update (h->stats,
                            gettext_noop
                            ("# RELEASE RESERVE requests executed"), 1,
                            GNUNET_NO);
  rrm = (struct ReleaseReserveMessage *) &qe[1];
  rrm->header.type = htons (GNUNET_MESSAGE_TYPE_DATASTORE_RELEASE_RESERVE);
  rrm->header.size = htons (sizeof (struct ReleaseReserveMessage));
  rrm->rid = htonl (rid);
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
 * @param timeout how long to wait at most for a response
 * @param cont continuation to call when done
 * @param cont_cls closure for cont
 * @return NULL if the entry was not queued, otherwise a handle that can be used to
 *         cancel; note that even if NULL is returned, the callback will be invoked
 *         (or rather, will already have been invoked)
 */
struct GNUNET_DATASTORE_QueueEntry *
GNUNET_DATASTORE_update (struct GNUNET_DATASTORE_Handle *h, uint64_t uid,
                         uint32_t priority,
                         struct GNUNET_TIME_Absolute expiration,
                         unsigned int queue_priority,
                         unsigned int max_queue_size,
                         struct GNUNET_TIME_Relative timeout,
                         GNUNET_DATASTORE_ContinuationWithStatus cont,
                         void *cont_cls)
{
  struct GNUNET_DATASTORE_QueueEntry *qe;
  struct UpdateMessage *um;
  union QueueContext qc;

  if (cont == NULL)
    cont = &drop_status_cont;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Asked to update entry %llu raising priority by %u and expiration to %llu\n",
       uid, (unsigned int) priority, (unsigned long long) expiration.abs_value);
  qc.sc.cont = cont;
  qc.sc.cont_cls = cont_cls;
  qe = make_queue_entry (h, sizeof (struct UpdateMessage), queue_priority,
                         max_queue_size, timeout, &process_status_message, &qc);
  if (qe == NULL)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Could not create queue entry for UPDATE\n");
    return NULL;
  }
  GNUNET_STATISTICS_update (h->stats,
                            gettext_noop ("# UPDATE requests executed"), 1,
                            GNUNET_NO);
  um = (struct UpdateMessage *) &qe[1];
  um->header.type = htons (GNUNET_MESSAGE_TYPE_DATASTORE_UPDATE);
  um->header.size = htons (sizeof (struct UpdateMessage));
  um->priority = htonl (priority);
  um->expiration = GNUNET_TIME_absolute_hton (expiration);
  um->uid = GNUNET_htonll (uid);
  process_queue (h);
  return qe;
}


/**
 * Explicitly remove some content from the database.
 * The "cont"inuation will be called with status
 * "GNUNET_OK" if content was removed, "GNUNET_NO"
 * if no matching entry was found and "GNUNET_SYSERR"
 * on all other types of errors.
 *
 * @param h handle to the datastore
 * @param key key for the value
 * @param size number of bytes in data
 * @param data content stored
 * @param queue_priority ranking of this request in the priority queue
 * @param max_queue_size at what queue size should this request be dropped
 *        (if other requests of higher priority are in the queue)
 * @param timeout how long to wait at most for a response
 * @param cont continuation to call when done
 * @param cont_cls closure for cont
 * @return NULL if the entry was not queued, otherwise a handle that can be used to
 *         cancel; note that even if NULL is returned, the callback will be invoked
 *         (or rather, will already have been invoked)
 */
struct GNUNET_DATASTORE_QueueEntry *
GNUNET_DATASTORE_remove (struct GNUNET_DATASTORE_Handle *h,
                         const GNUNET_HashCode * key, size_t size,
                         const void *data, unsigned int queue_priority,
                         unsigned int max_queue_size,
                         struct GNUNET_TIME_Relative timeout,
                         GNUNET_DATASTORE_ContinuationWithStatus cont,
                         void *cont_cls)
{
  struct GNUNET_DATASTORE_QueueEntry *qe;
  struct DataMessage *dm;
  size_t msize;
  union QueueContext qc;

  if (cont == NULL)
    cont = &drop_status_cont;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Asked to remove %u bytes under key `%s'\n",
       size, GNUNET_h2s (key));
  qc.sc.cont = cont;
  qc.sc.cont_cls = cont_cls;
  msize = sizeof (struct DataMessage) + size;
  GNUNET_assert (msize < GNUNET_SERVER_MAX_MESSAGE_SIZE);
  qe = make_queue_entry (h, msize, queue_priority, max_queue_size, timeout,
                         &process_status_message, &qc);
  if (qe == NULL)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Could not create queue entry for REMOVE\n");
    return NULL;
  }
  GNUNET_STATISTICS_update (h->stats,
                            gettext_noop ("# REMOVE requests executed"), 1,
                            GNUNET_NO);
  dm = (struct DataMessage *) &qe[1];
  dm->header.type = htons (GNUNET_MESSAGE_TYPE_DATASTORE_REMOVE);
  dm->header.size = htons (msize);
  dm->rid = htonl (0);
  dm->size = htonl (size);
  dm->type = htonl (0);
  dm->priority = htonl (0);
  dm->anonymity = htonl (0);
  dm->uid = GNUNET_htonll (0);
  dm->expiration = GNUNET_TIME_absolute_hton (GNUNET_TIME_UNIT_ZERO_ABS);
  dm->key = *key;
  memcpy (&dm[1], data, size);
  process_queue (h);
  return qe;
}


/**
 * Type of a function to call when we receive a message
 * from the service.
 *
 * @param cls closure
 * @param msg message received, NULL on timeout or fatal error
 */
static void
process_result_message (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_DATASTORE_Handle *h = cls;
  struct GNUNET_DATASTORE_QueueEntry *qe;
  struct ResultContext rc;
  const struct DataMessage *dm;
  int was_transmitted;

  if (msg == NULL)
  {
    qe = h->queue_head;
    GNUNET_assert (NULL != qe);
    rc = qe->qc.rc;
    was_transmitted = qe->was_transmitted;
    free_queue_entry (qe);
    if (was_transmitted == GNUNET_YES)
    {
      LOG (GNUNET_ERROR_TYPE_WARNING,
           _("Failed to receive response from database.\n"));
      do_disconnect (h);
    }
    else
    {
      process_queue (h);
    }
    if (rc.proc != NULL)
      rc.proc (rc.proc_cls, NULL, 0, NULL, 0, 0, 0, GNUNET_TIME_UNIT_ZERO_ABS,
               0);
    return;
  }
  if (ntohs (msg->type) == GNUNET_MESSAGE_TYPE_DATASTORE_DATA_END)
  {
    GNUNET_break (ntohs (msg->size) == sizeof (struct GNUNET_MessageHeader));
    qe = h->queue_head;
    rc = qe->qc.rc;
    GNUNET_assert (GNUNET_YES == qe->was_transmitted);
    free_queue_entry (qe);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Received end of result set, new queue size is %u\n", h->queue_size);
    h->retry_time.rel_value = 0;
    h->result_count = 0;
    process_queue (h);
    if (rc.proc != NULL)
      rc.proc (rc.proc_cls, NULL, 0, NULL, 0, 0, 0, GNUNET_TIME_UNIT_ZERO_ABS,
               0);
    return;
  }
  qe = h->queue_head;
  GNUNET_assert (NULL != qe);
  rc = qe->qc.rc;
  if (GNUNET_YES != qe->was_transmitted)
  {
    GNUNET_break (0);
    free_queue_entry (qe);
    h->retry_time = GNUNET_TIME_UNIT_ZERO;
    do_disconnect (h);
    if (rc.proc != NULL)
      rc.proc (rc.proc_cls, NULL, 0, NULL, 0, 0, 0, GNUNET_TIME_UNIT_ZERO_ABS,
               0);
    return;
  }
  if ((ntohs (msg->size) < sizeof (struct DataMessage)) ||
      (ntohs (msg->type) != GNUNET_MESSAGE_TYPE_DATASTORE_DATA) ||
      (ntohs (msg->size) !=
       sizeof (struct DataMessage) +
       ntohl (((const struct DataMessage *) msg)->size)))
  {
    GNUNET_break (0);
    free_queue_entry (qe);
    h->retry_time = GNUNET_TIME_UNIT_ZERO;
    do_disconnect (h);
    if (rc.proc != NULL)
      rc.proc (rc.proc_cls, NULL, 0, NULL, 0, 0, 0, GNUNET_TIME_UNIT_ZERO_ABS,
               0);
    return;
  }
  GNUNET_STATISTICS_update (h->stats, gettext_noop ("# Results received"), 1,
                            GNUNET_NO);
  dm = (const struct DataMessage *) msg;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received result %llu with type %u and size %u with key %s\n",
       (unsigned long long) GNUNET_ntohll (dm->uid), ntohl (dm->type),
       ntohl (dm->size), GNUNET_h2s (&dm->key));
  free_queue_entry (qe);
  h->retry_time.rel_value = 0;
  process_queue (h);
  if (rc.proc != NULL)
    rc.proc (rc.proc_cls, &dm->key, ntohl (dm->size), &dm[1], ntohl (dm->type),
             ntohl (dm->priority), ntohl (dm->anonymity),
             GNUNET_TIME_absolute_ntoh (dm->expiration),
             GNUNET_ntohll (dm->uid));
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
 * @param timeout how long to wait at most for a response
 * @param proc function to call on a random value; it
 *        will be called once with a value (if available)
 *        and always once with a value of NULL.
 * @param proc_cls closure for proc
 * @return NULL if the entry was not queued, otherwise a handle that can be used to
 *         cancel
 */
struct GNUNET_DATASTORE_QueueEntry *
GNUNET_DATASTORE_get_for_replication (struct GNUNET_DATASTORE_Handle *h,
                                      unsigned int queue_priority,
                                      unsigned int max_queue_size,
                                      struct GNUNET_TIME_Relative timeout,
                                      GNUNET_DATASTORE_DatumProcessor proc,
                                      void *proc_cls)
{
  struct GNUNET_DATASTORE_QueueEntry *qe;
  struct GNUNET_MessageHeader *m;
  union QueueContext qc;

  GNUNET_assert (NULL != proc);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Asked to get replication entry in %llu ms\n",
       (unsigned long long) timeout.rel_value);
  qc.rc.proc = proc;
  qc.rc.proc_cls = proc_cls;
  qe = make_queue_entry (h, sizeof (struct GNUNET_MessageHeader),
                         queue_priority, max_queue_size, timeout,
                         &process_result_message, &qc);
  if (qe == NULL)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Could not create queue entry for GET REPLICATION\n");
    return NULL;
  }
  GNUNET_STATISTICS_update (h->stats,
                            gettext_noop
                            ("# GET REPLICATION requests executed"), 1,
                            GNUNET_NO);
  m = (struct GNUNET_MessageHeader *) &qe[1];
  m->type = htons (GNUNET_MESSAGE_TYPE_DATASTORE_GET_REPLICATION);
  m->size = htons (sizeof (struct GNUNET_MessageHeader));
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
 * @param timeout how long to wait at most for a response
 * @param type allowed type for the operation (never zero)
 * @param proc function to call on a random value; it
 *        will be called once with a value (if available)
 *        or with NULL if none value exists.
 * @param proc_cls closure for proc
 * @return NULL if the entry was not queued, otherwise a handle that can be used to
 *         cancel
 */
struct GNUNET_DATASTORE_QueueEntry *
GNUNET_DATASTORE_get_zero_anonymity (struct GNUNET_DATASTORE_Handle *h,
                                     uint64_t offset,
                                     unsigned int queue_priority,
                                     unsigned int max_queue_size,
                                     struct GNUNET_TIME_Relative timeout,
                                     enum GNUNET_BLOCK_Type type,
                                     GNUNET_DATASTORE_DatumProcessor proc,
                                     void *proc_cls)
{
  struct GNUNET_DATASTORE_QueueEntry *qe;
  struct GetZeroAnonymityMessage *m;
  union QueueContext qc;

  GNUNET_assert (NULL != proc);
  GNUNET_assert (type != GNUNET_BLOCK_TYPE_ANY);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Asked to get %llu-th zero-anonymity entry of type %d in %llu ms\n",
       (unsigned long long) offset, type,
       (unsigned long long) timeout.rel_value);
  qc.rc.proc = proc;
  qc.rc.proc_cls = proc_cls;
  qe = make_queue_entry (h, sizeof (struct GetZeroAnonymityMessage),
                         queue_priority, max_queue_size, timeout,
                         &process_result_message, &qc);
  if (qe == NULL)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Could not create queue entry for zero-anonymity procation\n");
    return NULL;
  }
  GNUNET_STATISTICS_update (h->stats,
                            gettext_noop
                            ("# GET ZERO ANONYMITY requests executed"), 1,
                            GNUNET_NO);
  m = (struct GetZeroAnonymityMessage *) &qe[1];
  m->header.type = htons (GNUNET_MESSAGE_TYPE_DATASTORE_GET_ZERO_ANONYMITY);
  m->header.size = htons (sizeof (struct GetZeroAnonymityMessage));
  m->type = htonl ((uint32_t) type);
  m->offset = GNUNET_htonll (offset);
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
 * @param timeout how long to wait at most for a response
 * @param proc function to call on each matching value;
 *        will be called once with a NULL value at the end
 * @param proc_cls closure for proc
 * @return NULL if the entry was not queued, otherwise a handle that can be used to
 *         cancel
 */
struct GNUNET_DATASTORE_QueueEntry *
GNUNET_DATASTORE_get_key (struct GNUNET_DATASTORE_Handle *h, uint64_t offset,
                          const GNUNET_HashCode * key,
                          enum GNUNET_BLOCK_Type type,
                          unsigned int queue_priority,
                          unsigned int max_queue_size,
                          struct GNUNET_TIME_Relative timeout,
                          GNUNET_DATASTORE_DatumProcessor proc, void *proc_cls)
{
  struct GNUNET_DATASTORE_QueueEntry *qe;
  struct GetMessage *gm;
  union QueueContext qc;

  GNUNET_assert (NULL != proc);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Asked to look for data of type %u under key `%s'\n",
       (unsigned int) type, GNUNET_h2s (key));
  qc.rc.proc = proc;
  qc.rc.proc_cls = proc_cls;
  qe = make_queue_entry (h, sizeof (struct GetMessage), queue_priority,
                         max_queue_size, timeout, &process_result_message, &qc);
  if (qe == NULL)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Could not queue request for `%s'\n",
         GNUNET_h2s (key));
    return NULL;
  }
  GNUNET_STATISTICS_update (h->stats, gettext_noop ("# GET requests executed"),
                            1, GNUNET_NO);
  gm = (struct GetMessage *) &qe[1];
  gm->header.type = htons (GNUNET_MESSAGE_TYPE_DATASTORE_GET);
  gm->type = htonl (type);
  gm->offset = GNUNET_htonll (offset);
  if (key != NULL)
  {
    gm->header.size = htons (sizeof (struct GetMessage));
    gm->key = *key;
  }
  else
  {
    gm->header.size =
        htons (sizeof (struct GetMessage) - sizeof (GNUNET_HashCode));
  }
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
  struct GNUNET_DATASTORE_Handle *h;

  GNUNET_assert (GNUNET_SYSERR != qe->was_transmitted);
  h = qe->h;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Pending DATASTORE request %p cancelled (%d, %d)\n", qe,
       qe->was_transmitted, h->queue_head == qe);
  if (GNUNET_YES == qe->was_transmitted)
  {
    free_queue_entry (qe);
    h->skip_next_messages++;
    return;
  }
  free_queue_entry (qe);
  process_queue (h);
}


/* end of datastore_api.c */
