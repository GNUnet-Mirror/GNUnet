/*
     This file is part of GNUnet
     (C) 2004, 2005, 2006, 2007, 2009, 2010 Christian Grothoff (and other contributing authors)

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
 * @file datastore/datastore_api.c
 * @brief Management for the datastore for files stored on a GNUnet node.  Implements
 *        a priority queue for requests (with timeouts).
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_arm_service.h"
#include "gnunet_constants.h"
#include "gnunet_datastore_service.h"
#include "datastore.h"

/**
 * Entry in our priority queue.
 */
struct QueueEntry
{

  /**
   * This is a linked list.
   */
  struct QueueEntry *next;

  /**
   * This is a linked list.
   */
  struct QueueEntry *prev;

  /**
   * Handle to the master context.
   */
  struct GNUNET_DATASTORE_Handle *h;

  /**
   * Response processor (NULL if we are not waiting for a response).
   * This struct should be used for the closure, function-specific
   * arguments can be passed via 'client_ctx'.
   */
  GNUNET_CLIENT_MessageHandler response_proc;
  
  /**
   * Specific context (variable argument that
   * can be used by the response processor).
   */
  void *client_ctx;

  /**
   * Function to call after transmission of the request.
   */
  GNUNET_DATASTORE_ContinuationWithStatus contX;
   
  /**
   * Closure for 'cont'.
   */
  void *cont_clsX;

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
  int32_t was_transmitted;

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
   * Our scheduler.
   */
  struct GNUNET_SCHEDULER_Handle *sched;

  /**
   * Current connection to the datastore service.
   */
  struct GNUNET_CLIENT_Connection *client;

  /**
   * Current transmit handle.
   */
  struct GNUNET_CLIENT_TransmitHandle *th;

  /**
   * Current head of priority queue.
   */
  struct QueueEntry *queue_head;

  /**
   * Current tail of priority queue.
   */
  struct QueueEntry *queue_tail;

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

};



/**
 * Connect to the datastore service.
 *
 * @param cfg configuration to use
 * @param sched scheduler to use
 * @return handle to use to access the service
 */
struct GNUNET_DATASTORE_Handle *
GNUNET_DATASTORE_connect (const struct
			  GNUNET_CONFIGURATION_Handle
			  *cfg,
			  struct
			  GNUNET_SCHEDULER_Handle
			  *sched)
{
  struct GNUNET_CLIENT_Connection *c;
  struct GNUNET_DATASTORE_Handle *h;
  
  c = GNUNET_CLIENT_connect (sched, "datastore", cfg);
  if (c == NULL)
    return NULL; /* oops */
  h = GNUNET_malloc (sizeof(struct GNUNET_DATASTORE_Handle) + 
		     GNUNET_SERVER_MAX_MESSAGE_SIZE);
  h->client = c;
  h->cfg = cfg;
  h->sched = sched;
  return h;
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
transmit_drop (void *cls,
	       size_t size, 
	       void *buf)
{
  struct GNUNET_DATASTORE_Handle *h = cls;
  struct GNUNET_MessageHeader *hdr;
  
  if (buf == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  _("Failed to transmit request to drop database.\n"));
      GNUNET_DATASTORE_disconnect (h, GNUNET_NO);
      return 0;
    }
  GNUNET_assert (size >= sizeof(struct GNUNET_MessageHeader));
  hdr = buf;
  hdr->size = htons(sizeof(struct GNUNET_MessageHeader));
  hdr->type = htons(GNUNET_MESSAGE_TYPE_DATASTORE_DROP);
  GNUNET_DATASTORE_disconnect (h, GNUNET_NO);
  return sizeof(struct GNUNET_MessageHeader);
}


/**
 * Disconnect from the datastore service (and free
 * associated resources).
 *
 * @param h handle to the datastore
 * @param drop set to GNUNET_YES to delete all data in datastore (!)
 */
void GNUNET_DATASTORE_disconnect (struct GNUNET_DATASTORE_Handle *h,
				  int drop)
{
  struct QueueEntry *qe;

  if (h->client != NULL)
    GNUNET_CLIENT_disconnect (h->client, GNUNET_NO);
  if (h->reconnect_task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (h->sched,
			     h->reconnect_task);
  h->client = NULL;
  while (NULL != (qe = h->queue_head))
    {
      GNUNET_CONTAINER_DLL_remove (h->queue_head,
				   h->queue_tail,
				   qe);
      if (NULL != qe->response_proc)
	qe->response_proc (qe, NULL);
      GNUNET_free (qe);
    }
  if (GNUNET_YES == drop) 
    {
      h->client = GNUNET_CLIENT_connect (h->sched, "datastore", h->cfg);
      if (h->client != NULL)
	{
	  if (NULL != 
	      GNUNET_CLIENT_notify_transmit_ready (h->client,
						   sizeof(struct GNUNET_MessageHeader),
						   GNUNET_TIME_UNIT_MINUTES,
						   GNUNET_YES,
						   &transmit_drop,
						   h))
	    return;
	  GNUNET_CLIENT_disconnect (h->client, GNUNET_NO);
	}
      GNUNET_break (0);
    }
  GNUNET_free (h);
}


/**
 * A request has timed out (before being transmitted to the service).
 *
 * @param cls the 'struct QueueEntry'
 * @param tc scheduler context
 */
static void
timeout_queue_entry (void *cls,
		     const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct QueueEntry *qe = cls;
  struct GNUNET_DATASTORE_Handle *h = qe->h;

  qe->task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_assert (qe->was_transmitted == GNUNET_NO);
  GNUNET_CONTAINER_DLL_remove (h->queue_head,
			       h->queue_tail,
			       qe);
  if (qe->response_proc != NULL)
    qe->response_proc (qe, NULL);
  GNUNET_free (qe);
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
 * @param client_ctx client context (NOT a closure for response_proc)
 * @return NULL if the queue is full (and this entry was dropped)
 */
static struct QueueEntry *
make_queue_entry (struct GNUNET_DATASTORE_Handle *h,
		  size_t msize,
		  unsigned int queue_priority,
		  unsigned int max_queue_size,
		  struct GNUNET_TIME_Relative timeout,
		  GNUNET_CLIENT_MessageHandler response_proc,		 
		  void *client_ctx)
{
  struct QueueEntry *ret;
  struct QueueEntry *pos;
  unsigned int c;

  c = 0;
  pos = h->queue_head;
  while ( (pos != NULL) &&
	  (c < max_queue_size) &&
	  (pos->priority >= queue_priority) )
    {
      c++;
      pos = pos->next;
    }
  if (c >= max_queue_size)
    return NULL;
  if (pos == NULL)
    {
      /* append at the tail */
      pos = h->queue_tail;
    }
  else
    {
      pos = pos->prev; 
      /* do not insert at HEAD if HEAD query was already
	 transmitted and we are still receiving replies! */
      if ( (pos == NULL) &&
	   (h->queue_head->was_transmitted) )
	pos = h->queue_head;
    }
  ret = GNUNET_malloc (sizeof (struct QueueEntry) + msize);
  GNUNET_CONTAINER_DLL_insert_after (h->queue_head,
				     h->queue_tail,
				     pos,
				     ret);
  ret->h = h;
  ret->response_proc = response_proc;
  ret->client_ctx = client_ctx;
  ret->task = GNUNET_SCHEDULER_add_delayed (h->sched,
					    timeout,
					    &timeout_queue_entry,
					    ret);
  ret->timeout = GNUNET_TIME_relative_to_absolute (timeout);
  ret->priority = queue_priority;
  ret->max_queue = max_queue_size;
  ret->message_size = msize;
  ret->was_transmitted = GNUNET_NO;
  h->queue_size++;
  c++;
  pos = ret->next;
  while (pos != NULL) 
    {
      if (pos->max_queue < h->queue_size)
	{
	  GNUNET_CONTAINER_DLL_remove (h->queue_head,
				       h->queue_tail,
				       pos);
	  GNUNET_SCHEDULER_cancel (h->sched,
				   pos->task);
	  if (pos->response_proc != NULL)
	    pos->response_proc (pos, NULL);
	  GNUNET_free (pos);
	  h->queue_size--;
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
try_reconnect (void *cls,
	       const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_DATASTORE_Handle *h = cls;

  if (h->retry_time.value < GNUNET_CONSTANTS_SERVICE_RETRY.value)
    h->retry_time = GNUNET_CONSTANTS_SERVICE_RETRY;
  else
    h->retry_time = GNUNET_TIME_relative_multiply (h->retry_time, 2);
  if (h->retry_time.value > GNUNET_CONSTANTS_SERVICE_TIMEOUT.value)
    h->retry_time = GNUNET_CONSTANTS_SERVICE_TIMEOUT;
  h->reconnect_task = GNUNET_SCHEDULER_NO_TASK;
  h->client = GNUNET_CLIENT_connect (h->sched, "datastore", h->cfg);
  if (h->client == NULL)
    return;
  process_queue (h);
}


/**
 * Disconnect from the service and then try reconnecting to the datastore service
 * after some delay.
 *
 * @param cls the 'struct GNUNET_DATASTORE_Handle'
 * @param tc scheduler context
 */
static void
do_disconnect (struct GNUNET_DATASTORE_Handle *h)
{
  GNUNET_CLIENT_disconnect (h->client, GNUNET_NO);
  h->client = NULL;
  h->reconnect_task = GNUNET_SCHEDULER_add_delayed (h->sched,
						    h->retry_time,
						    &try_reconnect,
						    h);      
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
transmit_request (void *cls,
		  size_t size, 
		  void *buf)
{
  struct GNUNET_DATASTORE_Handle *h = cls;
  struct QueueEntry *qe;
  size_t msize;

  h->th = NULL;
  if (NULL == (qe = h->queue_head))
    return 0; /* no entry in queue */
  if (buf == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  _("Failed to transmit request to database.\n"));
      do_disconnect (h);
      return 0;
    }
  if (size < (msize = qe->message_size))
    {
      process_queue (h);
      return 0;
    }
  memcpy (buf, &qe[1], msize);
  qe->was_transmitted = GNUNET_YES;
  GNUNET_SCHEDULER_cancel (h->sched,
			   qe->task);
  qe->task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_CLIENT_receive (h->client,
			 qe->response_proc,
			 qe,
			 GNUNET_TIME_absolute_get_remaining (qe->timeout));
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
  struct QueueEntry *qe;

  if (NULL == (qe = h->queue_head))
    return; /* no entry in queue */
  if (qe->was_transmitted == GNUNET_YES)
    return; /* waiting for replies */
  if (h->th != NULL)
    return; /* request pending */
  if (h->client == NULL)
    return; /* waiting for reconnect */
  h->th = GNUNET_CLIENT_notify_transmit_ready (h->client,
					       qe->message_size,
					       GNUNET_TIME_absolute_get_remaining (qe->timeout),
					       GNUNET_YES,
					       &transmit_request,
					       h);
}




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
 * Dummy continuation used to do nothing (but be non-zero).
 *
 * @param cls closure
 * @param result result 
 * @param emsg error message
 */
static void
drop_status_cont (void *cls, int result, const char *emsg)
{
  /* do nothing */
}


/**
 * Type of a function to call when we receive a message
 * from the service.
 *
 * @param cls closure
 * @param msg message received, NULL on timeout or fatal error
 */
static void 
process_status_message (void *cls,
			const struct
			GNUNET_MessageHeader * msg)
{
  struct QueueEntry *qe = cls;
  struct GNUNET_DATASTORE_Handle *h = qe->h;
  struct StatusContext *rc = qe->client_ctx;
  const struct StatusMessage *sm;
  const char *emsg;
  int32_t status;

  GNUNET_CONTAINER_DLL_remove (h->queue_head,
			       h->queue_tail,
			       qe);
  GNUNET_free (qe);
  if (msg == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  _("Failed to receive response from database.\n"));
      do_disconnect (h);
      return;
    }

  if ( (ntohs(msg->size) < sizeof(struct StatusMessage)) ||
       (ntohs(msg->type) != GNUNET_MESSAGE_TYPE_DATASTORE_STATUS) ) 
    {
      GNUNET_break (0);
      h->retry_time = GNUNET_TIME_UNIT_ZERO;
      do_disconnect (h);
      rc->cont (rc->cont_cls, 
		GNUNET_SYSERR,
		_("Error reading response from datastore service"));
      GNUNET_free (rc);
      return;
    }
  sm = (const struct StatusMessage*) msg;
  status = ntohl(sm->status);
  emsg = NULL;
  if (ntohs(msg->size) > sizeof(struct StatusMessage))
    {
      emsg = (const char*) &sm[1];
      if (emsg[ntohs(msg->size) - sizeof(struct StatusMessage) - 1] != '\0')
	{
	  GNUNET_break (0);
	  emsg = _("Invalid error message received from datastore service");
	}
    }  
  if ( (status == GNUNET_SYSERR) &&
       (emsg == NULL) )
    {
      GNUNET_break (0);
      emsg = _("Invalid error message received from datastore service");
    }
#if DEBUG_DATASTORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Received status %d/%s\n",
	      (int) status,
	      emsg);
#endif
  rc->cont (rc->cont_cls, 
	    status,
	    emsg);
  GNUNET_free (rc);  
  process_queue (h);
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
 * @param expiration expiration time for the content
 * @param queue_priority ranking of this request in the priority queue
 * @param max_queue_size at what queue size should this request be dropped
 *        (if other requests of higher priority are in the queue)
 * @param timeout timeout for the operation
 * @param cont continuation to call when done
 * @param cont_cls closure for cont
 */
void
GNUNET_DATASTORE_put (struct GNUNET_DATASTORE_Handle *h,
		      int rid,
                      const GNUNET_HashCode * key,
                      uint32_t size,
                      const void *data,
                      enum GNUNET_BLOCK_Type type,
                      uint32_t priority,
                      uint32_t anonymity,
                      struct GNUNET_TIME_Absolute expiration,
		      unsigned int queue_priority,
		      unsigned int max_queue_size,
                      struct GNUNET_TIME_Relative timeout,
		      GNUNET_DATASTORE_ContinuationWithStatus cont,
		      void *cont_cls)
{
  struct StatusContext *scont;
  struct QueueEntry *qe;
  struct DataMessage *dm;
  size_t msize;

#if DEBUG_DATASTORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Asked to put %u bytes of data under key `%s'\n",
	      size,
	      GNUNET_h2s (key));
#endif
  msize = sizeof(struct DataMessage) + size;
  GNUNET_assert (msize <= GNUNET_SERVER_MAX_MESSAGE_SIZE);
  scont = GNUNET_malloc (sizeof (struct StatusContext));
  scont->cont = cont;
  scont->cont_cls = cont_cls;
  qe = make_queue_entry (h, msize,
			 queue_priority, max_queue_size, timeout,
			 &process_status_message, scont);
  if (qe == NULL)
    return;
  dm = (struct DataMessage* ) &qe[1];
  dm->header.type = htons(GNUNET_MESSAGE_TYPE_DATASTORE_PUT);
  dm->header.size = htons(msize);
  dm->rid = htonl(rid);
  dm->size = htonl(size);
  dm->type = htonl(type);
  dm->priority = htonl(priority);
  dm->anonymity = htonl(anonymity);
  dm->uid = GNUNET_htonll(0);
  dm->expiration = GNUNET_TIME_absolute_hton(expiration);
  dm->key = *key;
  memcpy (&dm[1], data, size);
  process_queue (h);
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
 */
void
GNUNET_DATASTORE_reserve (struct GNUNET_DATASTORE_Handle *h,
			  uint64_t amount,
			  uint32_t entries,
			  unsigned int queue_priority,
			  unsigned int max_queue_size,
			  struct GNUNET_TIME_Relative timeout,
			  GNUNET_DATASTORE_ContinuationWithStatus cont,
			  void *cont_cls)
{
  struct QueueEntry *qe;
  struct ReserveMessage *rm;
  struct StatusContext *scont;

  if (cont == NULL)
    cont = &drop_status_cont;
#if DEBUG_DATASTORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Asked to reserve %llu bytes of data and %u entries'\n",
	      (unsigned long long) amount,
	      (unsigned int) entries);
#endif
  scont = GNUNET_malloc (sizeof (struct StatusContext));
  scont->cont = cont;
  scont->cont_cls = cont_cls;
  qe = make_queue_entry (h, sizeof(struct ReserveMessage),
			 queue_priority, max_queue_size, timeout,
			 &process_status_message, scont);
  if (qe == NULL)
    return;
  rm = (struct ReserveMessage*) &qe[1];
  rm->header.type = htons(GNUNET_MESSAGE_TYPE_DATASTORE_RESERVE);
  rm->header.size = htons(sizeof (struct ReserveMessage));
  rm->entries = htonl(entries);
  rm->amount = GNUNET_htonll(amount);
  process_queue (h);
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
 */
void
GNUNET_DATASTORE_release_reserve (struct GNUNET_DATASTORE_Handle *h,
				  int rid,
				  unsigned int queue_priority,
				  unsigned int max_queue_size,
				  struct GNUNET_TIME_Relative timeout,
				  GNUNET_DATASTORE_ContinuationWithStatus cont,
				  void *cont_cls)
{
  struct QueueEntry *qe;
  struct ReleaseReserveMessage *rrm;
  struct StatusContext *scont;

  if (cont == NULL)
    cont = &drop_status_cont;
#if DEBUG_DATASTORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Asked to release reserve %d\n",
	      rid);
#endif
  scont = GNUNET_malloc (sizeof (struct StatusContext));
  scont->cont = cont;
  scont->cont_cls = cont_cls;
  qe = make_queue_entry (h, sizeof(struct ReleaseReserveMessage),
			 queue_priority, max_queue_size, timeout,
			 &process_status_message, scont);
  if (qe == NULL)
    return;
  rrm = (struct ReleaseReserveMessage*) &qe[1];
  rrm->header.type = htons(GNUNET_MESSAGE_TYPE_DATASTORE_RELEASE_RESERVE);
  rrm->header.size = htons(sizeof (struct ReleaseReserveMessage));
  rrm->rid = htonl(rid);
  process_queue (h);
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
 */
void
GNUNET_DATASTORE_update (struct GNUNET_DATASTORE_Handle *h,
			 unsigned long long uid,
			 uint32_t priority,
			 struct GNUNET_TIME_Absolute expiration,
			 unsigned int queue_priority,
			 unsigned int max_queue_size,
			 struct GNUNET_TIME_Relative timeout,
			 GNUNET_DATASTORE_ContinuationWithStatus cont,
			 void *cont_cls)
{
  struct QueueEntry *qe;
  struct UpdateMessage *um;
  struct StatusContext *scont;

  if (cont == NULL)
    cont = &drop_status_cont;
#if DEBUG_DATASTORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Asked to update entry %llu raising priority by %u and expiration to %llu\n",
	      uid,
	      (unsigned int) priority,
	      (unsigned long long) expiration.value);
#endif
  scont = GNUNET_malloc (sizeof (struct StatusContext));
  scont->cont = cont;
  scont->cont_cls = cont_cls;
  qe = make_queue_entry (h, sizeof(struct UpdateMessage),
			 queue_priority, max_queue_size, timeout,
			 &process_status_message, scont);
  if (qe == NULL)
    return;
  um = (struct UpdateMessage*) &qe[1];
  um->header.type = htons(GNUNET_MESSAGE_TYPE_DATASTORE_UPDATE);
  um->header.size = htons(sizeof (struct UpdateMessage));
  um->priority = htonl(priority);
  um->expiration = GNUNET_TIME_absolute_hton(expiration);
  um->uid = GNUNET_htonll(uid);
  process_queue (h);
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
 */
void
GNUNET_DATASTORE_remove (struct GNUNET_DATASTORE_Handle *h,
                         const GNUNET_HashCode *key,
                         uint32_t size, 
			 const void *data,
			 unsigned int queue_priority,
			 unsigned int max_queue_size,
			 struct GNUNET_TIME_Relative timeout,
			 GNUNET_DATASTORE_ContinuationWithStatus cont,
			 void *cont_cls)
{
  struct QueueEntry *qe;
  struct DataMessage *dm;
  size_t msize;
  struct StatusContext *scont;

  if (cont == NULL)
    cont = &drop_status_cont;
#if DEBUG_DATASTORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Asked to remove %u bytes under key `%s'\n",
	      size,
	      GNUNET_h2s (key));
#endif
  scont = GNUNET_malloc (sizeof (struct StatusContext));
  scont->cont = cont;
  scont->cont_cls = cont_cls;
  msize = sizeof(struct DataMessage) + size;
  GNUNET_assert (msize <= GNUNET_SERVER_MAX_MESSAGE_SIZE);
  qe = make_queue_entry (h, msize,
			 queue_priority, max_queue_size, timeout,
			 &process_status_message, scont);
  if (qe == NULL)
    return;
  dm = (struct DataMessage*) &qe[1];
  dm->header.type = htons(GNUNET_MESSAGE_TYPE_DATASTORE_REMOVE);
  dm->header.size = htons(msize);
  dm->rid = htonl(0);
  dm->size = htonl(size);
  dm->type = htonl(0);
  dm->priority = htonl(0);
  dm->anonymity = htonl(0);
  dm->uid = GNUNET_htonll(0);
  dm->expiration = GNUNET_TIME_absolute_hton(GNUNET_TIME_UNIT_ZERO_ABS);
  dm->key = *key;
  memcpy (&dm[1], data, size);
  process_queue (h);
}



/**
 * Context for processing result messages.
 */
struct ResultContext
{
  /**
   * Iterator to call with the result.
   */
  GNUNET_DATASTORE_Iterator iter;

  /**
   * Closure for iter.
   */
  void *iter_cls;

};


/**
 * Type of a function to call when we receive a message
 * from the service.
 *
 * @param cls closure
 * @param msg message received, NULL on timeout or fatal error
 */
static void 
process_result_message (void *cls,
			const struct GNUNET_MessageHeader * msg)
{
  struct QueueEntry *qe = cls;
  struct GNUNET_DATASTORE_Handle *h = qe->h;
  struct ResultContext *rc = qe->client_ctx;
  const struct DataMessage *dm;

  if (msg == NULL)
    {
#if DEBUG_DATASTORE
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  _("Failed to receive response from datastore\n"));
#endif
      GNUNET_CONTAINER_DLL_remove (h->queue_head,
				   h->queue_tail,
				   qe);
      GNUNET_free (qe);
      do_disconnect (h);
      rc->iter (rc->iter_cls,
		NULL, 0, NULL, 0, 0, 0, 
		GNUNET_TIME_UNIT_ZERO_ABS, 0);	
      GNUNET_free (rc);
      return;
    }
  if (ntohs(msg->type) == GNUNET_MESSAGE_TYPE_DATASTORE_DATA_END) 
    {
      GNUNET_break (ntohs(msg->size) == sizeof(struct GNUNET_MessageHeader));
#if DEBUG_DATASTORE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Received end of result set\n");
#endif
      GNUNET_CONTAINER_DLL_remove (h->queue_head,
				   h->queue_tail,
				   qe);
      GNUNET_free (qe);
      rc->iter (rc->iter_cls,
		NULL, 0, NULL, 0, 0, 0, 
		GNUNET_TIME_UNIT_ZERO_ABS, 0);	
      GNUNET_free (rc);
      process_queue (h);
      return;
    }
  if ( (ntohs(msg->size) < sizeof(struct DataMessage)) ||
       (ntohs(msg->type) != GNUNET_MESSAGE_TYPE_DATASTORE_DATA) ||
       (ntohs(msg->size) != sizeof(struct DataMessage) + ntohl (((const struct DataMessage*)msg)->size)) )
    {
      GNUNET_break (0);
      GNUNET_CONTAINER_DLL_remove (h->queue_head,
				   h->queue_tail,
				   qe);
      GNUNET_free (qe);
      h->retry_time = GNUNET_TIME_UNIT_ZERO;
      do_disconnect (h);
      rc->iter (rc->iter_cls,
		NULL, 0, NULL, 0, 0, 0, 
		GNUNET_TIME_UNIT_ZERO_ABS, 0);	
      GNUNET_free (rc);
      return;
    }
  dm = (const struct DataMessage*) msg;
#if DEBUG_DATASTORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Received result %llu with type %u and size %u with key %s\n",
	      (unsigned long long) GNUNET_ntohll(dm->uid),
	      ntohl(dm->type),
	      ntohl(dm->size),
	      GNUNET_h2s(&dm->key));
#endif
  rc->iter (rc->iter_cls,
	    &dm->key,
	    ntohl(dm->size),
	    &dm[1],
	    ntohl(dm->type),
	    ntohl(dm->priority),
	    ntohl(dm->anonymity),
	    GNUNET_TIME_absolute_ntoh(dm->expiration),	
	    GNUNET_ntohll(dm->uid));
}


/**
 * Get a random value from the datastore.
 *
 * @param h handle to the datastore
 * @param queue_priority ranking of this request in the priority queue
 * @param max_queue_size at what queue size should this request be dropped
 *        (if other requests of higher priority are in the queue)
 * @param timeout how long to wait at most for a response
 * @param iter function to call on a random value; it
 *        will be called once with a value (if available)
 *        and always once with a value of NULL.
 * @param iter_cls closure for iter
 */
void
GNUNET_DATASTORE_get_random (struct GNUNET_DATASTORE_Handle *h,
			     unsigned int queue_priority,
			     unsigned int max_queue_size,
			     struct GNUNET_TIME_Relative timeout,
                             GNUNET_DATASTORE_Iterator iter, 
			     void *iter_cls)
{
  struct QueueEntry *qe;
  struct GNUNET_MessageHeader *m;
  struct ResultContext *rcont;

#if DEBUG_DATASTORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Asked to get random entry in %llu ms\n",
	      (unsigned long long) timeout.value);
#endif
  rcont = GNUNET_malloc (sizeof (struct ResultContext));
  rcont->iter = iter;
  rcont->iter_cls = iter_cls;
  qe = make_queue_entry (h, sizeof(struct GNUNET_MessageHeader),
			 queue_priority, max_queue_size, timeout,
			 &process_result_message, rcont);
  if (qe == NULL)
    return;
  m = (struct GNUNET_MessageHeader*) &qe[1];
  m->type = htons(GNUNET_MESSAGE_TYPE_DATASTORE_GET_RANDOM);
  m->size = htons(sizeof (struct GNUNET_MessageHeader));
  process_queue (h);
}



/**
 * Iterate over the results for a particular key
 * in the datastore.  The iterator will only be called
 * once initially; if the first call did contain a
 * result, further results can be obtained by calling
 * "GNUNET_DATASTORE_get_next" with the given argument.
 *
 * @param h handle to the datastore
 * @param key maybe NULL (to match all entries)
 * @param type desired type, 0 for any
 * @param queue_priority ranking of this request in the priority queue
 * @param max_queue_size at what queue size should this request be dropped
 *        (if other requests of higher priority are in the queue)
 * @param timeout how long to wait at most for a response
 * @param iter function to call on each matching value;
 *        will be called once with a NULL value at the end
 * @param iter_cls closure for iter
 */
void
GNUNET_DATASTORE_get (struct GNUNET_DATASTORE_Handle *h,
                      const GNUNET_HashCode * key,
		      enum GNUNET_BLOCK_Type type,
		      unsigned int queue_priority,
		      unsigned int max_queue_size,
		      struct GNUNET_TIME_Relative timeout,
                      GNUNET_DATASTORE_Iterator iter, 
		      void *iter_cls)
{
  struct QueueEntry *qe;
  struct GetMessage *gm;
  struct ResultContext *rcont;

#if DEBUG_DATASTORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Asked to look for data of type %u under key `%s'\n",
	      (unsigned int) type,
	      GNUNET_h2s (key));
#endif
  rcont = GNUNET_malloc (sizeof (struct ResultContext));
  rcont->iter = iter;
  rcont->iter_cls = iter_cls;
  qe = make_queue_entry (h, sizeof(struct GetMessage),
			 queue_priority, max_queue_size, timeout,
			 &process_result_message, rcont);
  if (qe == NULL)
    return;
  gm = (struct GetMessage*) &qe[1];
  gm->header.type = htons(GNUNET_MESSAGE_TYPE_DATASTORE_GET);
  gm->type = htonl(type);
  if (key != NULL)
    {
      gm->header.size = htons(sizeof (struct GetMessage));
      gm->key = *key;
    }
  else
    {
      gm->header.size = htons(sizeof (struct GetMessage) - sizeof(GNUNET_HashCode));
    }
  process_queue (h);
}


/**
 * Function called to trigger obtaining the next result
 * from the datastore.
 * 
 * @param h handle to the datastore
 * @param more GNUNET_YES to get moxre results, GNUNET_NO to abort
 *        iteration (with a final call to "iter" with key/data == NULL).
 */
void 
GNUNET_DATASTORE_get_next (struct GNUNET_DATASTORE_Handle *h,
			   int more)
{
  struct QueueEntry *qe = h->queue_head;
  struct ResultContext *rc = qe->client_ctx;

  GNUNET_assert (NULL != qe);
  GNUNET_assert (&process_result_message == qe->response_proc);
  if (GNUNET_YES == more)
    {     
      GNUNET_CLIENT_receive (h->client,
			     qe->response_proc,
			     qe,
			     GNUNET_TIME_absolute_get_remaining (qe->timeout));
      return;
    }
  GNUNET_CONTAINER_DLL_remove (h->queue_head,
			       h->queue_tail,
			       qe);
  GNUNET_free (qe);
  h->retry_time = GNUNET_TIME_UNIT_ZERO;
  do_disconnect (h);
  rc->iter (rc->iter_cls,
	    NULL, 0, NULL, 0, 0, 0, 
	    GNUNET_TIME_UNIT_ZERO_ABS, 0);	
  GNUNET_free (rc);
}


/* end of datastore_api.c */
