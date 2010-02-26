/*
     This file is part of GNUnet.
     (C) 2009, 2010 Christian Grothoff (and other contributing authors)

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
 * @file fs/gnunet-service-fs_drq.c
 * @brief queueing of requests to the datastore service
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet-service-fs_drq.h"


/**
 * Signature of a function that is called whenever a datastore
 * request can be processed (or an entry put on the queue times out).
 *
 * @param cls closure
 * @param ok GNUNET_OK if DS is ready, GNUNET_SYSERR on timeout
 */
typedef void (*RequestFunction)(void *cls,
				int ok);


/**
 * Doubly-linked list of our requests for the datastore.
 */
struct DatastoreRequestQueue
{

  /**
   * This is a doubly-linked list.
   */
  struct DatastoreRequestQueue *next;

  /**
   * This is a doubly-linked list.
   */
  struct DatastoreRequestQueue *prev;

  /**
   * Function to call (will issue the request).
   */
  RequestFunction req;

  /**
   * Closure for req.
   */
  void *req_cls;

  /**
   * When should this request time-out because we don't care anymore?
   */
  struct GNUNET_TIME_Absolute timeout;
    
  /**
   * ID of task used for signaling timeout.
   */
  GNUNET_SCHEDULER_TaskIdentifier task;

  /**
   * Is this request at the head of the queue irrespective of its
   * timeout value?
   */
  int forced_head;

};

/**
 * Our scheduler.
 */
static struct GNUNET_SCHEDULER_Handle *sched;

/**
 * Our configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Head of request queue for the datastore, sorted by timeout.
 */
static struct DatastoreRequestQueue *drq_head;

/**
 * Tail of request queue for the datastore.
 */
static struct DatastoreRequestQueue *drq_tail;

/**
 * Our connection to the datastore.
 */
static struct GNUNET_DATASTORE_Handle *dsh;

/**
 * Pointer to the currently actively running request,
 * NULL if none is running.
 */
static struct DatastoreRequestQueue *drq_running;


/**
 * A datastore request had to be timed out. 
 *
 * @param cls closure (unused)
 * @param tc task context, unused
 */
static void
timeout_ds_request (void *cls,
		    const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct DatastoreRequestQueue *e = cls;

  e->task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_CONTAINER_DLL_remove (drq_head, drq_tail, e);
  e->req (e->req_cls, GNUNET_NO);
  GNUNET_free (e);  
}


/**
 * A datastore request can be run right now.  Run it.
 *
 * @param cls closure (of type "struct DatastoreRequestQueue*")
 * @param tc task context, unused
 */
static void
run_next_request (void *cls,
		  const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct DatastoreRequestQueue *e = cls;
  
  e->req (e->req_cls, GNUNET_YES);
}


/**
 * Run the next DS request in our queue, we're done with the current
 * one.
 */
static void
next_ds_request ()
{
  struct DatastoreRequestQueue *e;

  GNUNET_free_non_null (drq_running);
  drq_running = NULL;
  e = drq_head;
  if (e == NULL)
    return;
  GNUNET_CONTAINER_DLL_remove (drq_head, drq_tail, e);
  drq_running = e;
  GNUNET_SCHEDULER_cancel (sched, e->task);
  e->task = GNUNET_SCHEDULER_add_now (sched,
				      &run_next_request,
				      e);
}


/**
 * Remove a pending request from the request queue.
 *
 * @param req request to remove
 */
static void
dequeue_ds_request (struct DatastoreRequestQueue *req)  
{
  GNUNET_CONTAINER_DLL_remove (drq_head, drq_tail, req);
  GNUNET_SCHEDULER_cancel (sched, req->task);
  GNUNET_free (req);
}


/**
 * Queue a request for the datastore.
 *
 * @param deadline by when the request should run
 * @param fun function to call once the request can be run
 * @param fun_cls closure for fun
 * @param immediate should this be queued immediately at
 *        the head of the queue (irrespecitive of the deadline)?
 * @return handle that can be used to dequeue the request
 */
static struct DatastoreRequestQueue *
queue_ds_request (struct GNUNET_TIME_Relative deadline,
		  RequestFunction fun,
		  void *fun_cls,
		  int immediate)
{
  struct DatastoreRequestQueue *e;
  struct DatastoreRequestQueue *bef;

  e = GNUNET_malloc (sizeof (struct DatastoreRequestQueue));
  e->timeout = GNUNET_TIME_relative_to_absolute (deadline);
  e->req = fun;
  e->req_cls = fun_cls;
  e->forced_head = immediate;
  if (GNUNET_YES == immediate)
    {
      /* local request, highest prio, put at head of queue
	 regardless of deadline */
      bef = NULL;
    }
  else
    {
      bef = drq_tail;
      while ( (NULL != bef) &&
	      (e->timeout.value < bef->timeout.value) &&
	      (GNUNET_YES != e->forced_head) )
	bef = bef->prev;
    }
  GNUNET_CONTAINER_DLL_insert_after (drq_head, drq_tail, bef, e);
  e->task = GNUNET_SCHEDULER_add_delayed (sched,
					  deadline,
					  &timeout_ds_request,
					  e);
  if (drq_running == NULL)
    next_ds_request ();
  return e;				       
}


/**
 * Task run during shutdown.
 *
 * @param cls unused
 * @param tc unused
 */
static void
shutdown_task (void *cls,
	       const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct DatastoreRequestQueue *drq;

  GNUNET_assert (NULL != dsh);
  GNUNET_DATASTORE_disconnect (dsh,
			       GNUNET_NO);
  dsh = NULL;
  while (NULL != (drq = drq_head))
    {
      drq_head = drq->next;
      GNUNET_SCHEDULER_cancel (sched, drq->task);
      drq->req (drq->req_cls, GNUNET_NO);
      GNUNET_free (drq);
    }
  drq_tail = NULL;
}


/**
 * Closure for 'do_get' and 'get_iterator'.
 */
struct GetClosure
{
  /**
   * Key we are doing the 'get' for.
   */
  GNUNET_HashCode key;

  /**
   * Datastore entry type we are doing the 'get' for.
   */
  uint32_t type;

  /**
   * Function to call for each entry.
   */
  GNUNET_DATASTORE_Iterator iter;

  /**
   * Closure for iter.
   */
  void *iter_cls;

  /**
   * Timeout for this operation.
   */
  struct GNUNET_TIME_Absolute timeout;
};


/**
 * Wrapper for the datastore get operation.  Makes sure to trigger the
 * next datastore operation in the queue once the operation is
 * complete.
 *
 * @param cls our 'struct GetClosure*'
 * @param key key for the content
 * @param size number of bytes in data
 * @param data content stored
 * @param type type of the content
 * @param priority priority of the content
 * @param anonymity anonymity-level for the content
 * @param expiration expiration time for the content
 * @param uid unique identifier for the datum;
 *        maybe 0 if no unique identifier is available
 */
static void
get_iterator (void *cls,
	      const GNUNET_HashCode * key,
	      uint32_t size,
	      const void *data,
	      uint32_t type,
	      uint32_t priority,
	      uint32_t anonymity,
	      struct GNUNET_TIME_Absolute
	      expiration, 
	      uint64_t uid)
{
  struct GetClosure *gc = cls;

  if (gc->iter == NULL) 
    {
      /* stop the iteration */
      if (key != NULL)
	GNUNET_DATASTORE_get_next (dsh, GNUNET_NO);
    }
  else
    {
      gc->iter (gc->iter_cls,
		key, size, data, type,
		priority, anonymity, expiration, uid);
    }
  if (key == NULL)
    {
      next_ds_request ();
      GNUNET_free (gc);
    }
}


/**
 * We're at the head of the reqeust queue, execute the
 * get operation (or signal error).
 *
 * @param cls the 'struct GetClosure'
 * @param ok GNUNET_OK if we can run the GET, otherwise
 *        we need to time out
 */
static void
do_get (void *cls,
	int ok)
{
  struct GetClosure *gc = cls;

  if (ok != GNUNET_OK)
    {
      if (gc->iter != NULL)
	gc->iter (gc->iter_cls,
		  NULL, 0, NULL, 0, 0, 0, 
		  GNUNET_TIME_UNIT_ZERO_ABS, 0);
      GNUNET_free (gc);
      next_ds_request ();
      return;
    }
  GNUNET_DATASTORE_get (dsh, &gc->key, gc->type, 
			&get_iterator,
			gc,
			GNUNET_TIME_absolute_get_remaining(gc->timeout));
}


/**
 * Iterate over the results for a particular key
 * in the datastore.  The iterator will only be called
 * once initially; if the first call did contain a
 * result, further results can be obtained by calling
 * "GNUNET_DATASTORE_get_next" with the given argument.
 *
 * @param key maybe NULL (to match all entries)
 * @param type desired type, 0 for any
 * @param iter function to call on each matching value;
 *        will be called once with a NULL value at the end
 * @param iter_cls closure for iter
 * @param timeout how long to wait at most for a response
 * @param immediate should this be queued immediately at
 *        the head of the queue (irrespecitive of the timeout)?
 */
struct DatastoreRequestQueue *
GNUNET_FS_drq_get (const GNUNET_HashCode * key,
		   uint32_t type,
		   GNUNET_DATASTORE_Iterator iter, 
		   void *iter_cls,
		   struct GNUNET_TIME_Relative timeout,
		   int immediate)
{
  struct GetClosure *gc;

  gc = GNUNET_malloc (sizeof (struct GetClosure));
  gc->key = *key;
  gc->type = type;
  gc->iter = iter;
  gc->iter_cls = iter_cls;
  gc->timeout = GNUNET_TIME_relative_to_absolute (timeout);
  return queue_ds_request (timeout,
			   &do_get,
			   gc,
			   immediate);
}


/**
 * Cancel the given operation.
 *
 * @param drq the queued operation (must not have been
 *        triggered so far)
 */
void
GNUNET_FS_drq_get_cancel (struct DatastoreRequestQueue *drq)
{
  struct GetClosure *gc;
  if (drq == drq_running)
    {
      /* 'DATASTORE_get' has already been started (and this call might
	 actually be be legal since it is possible that the client has
	 not yet received any calls to its the iterator; so we need
	 to cancel somehow; we do this by getting to the 'GetClosure'
	 and zeroing the 'iter' field, which stops the iteration */
      gc = drq_running->req_cls;
      gc->iter = NULL;
    }
  else
    {
      dequeue_ds_request (drq);  
    }
}


/**
 * Function called to trigger obtaining the next result
 * from the datastore.
 * 
 * @param more GNUNET_YES to get more results, GNUNET_NO to abort
 *        iteration (with a final call to "iter" with key/data == NULL).
 */
void
GNUNET_FS_drq_get_next (int more)
{
  GNUNET_DATASTORE_get_next (dsh, more);
}


/**
 * Explicitly remove some content from the database.
 * The "cont"inuation will be called with status
 * "GNUNET_OK" if content was removed, "GNUNET_NO"
 * if no matching entry was found and "GNUNET_SYSERR"
 * on all other types of errors.
 *
 * @param key key for the value
 * @param size number of bytes in data
 * @param data content stored
 * @param cont continuation to call when done
 * @param cont_cls closure for cont
 * @param timeout how long to wait at most for a response
 */
void
GNUNET_FS_drq_remove (const GNUNET_HashCode *key,
		      uint32_t size, const void *data,
		      GNUNET_DATASTORE_ContinuationWithStatus cont,
		      void *cont_cls,
		      struct GNUNET_TIME_Relative timeout)
{
  if (dsh == NULL)
    {
      GNUNET_break (0);
      return;
    }
  GNUNET_DATASTORE_remove (dsh, key, size, data,
			   cont, cont_cls, timeout);
}


/**
 * Setup datastore request queues.
 * 
 * @param s scheduler to use
 * @param c configuration to use
 * @return GNUNET_OK on success
 */
int 
GNUNET_FS_drq_init (struct GNUNET_SCHEDULER_Handle *s,
		    const struct GNUNET_CONFIGURATION_Handle *c)
{
  sched = s;
  cfg = c;
  dsh = GNUNET_DATASTORE_connect (cfg,
				  sched);
  if (NULL == dsh)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Failed to connect to `%s' service.\n"),
		  "datastore");
      return GNUNET_SYSERR;
    }
  GNUNET_SCHEDULER_add_delayed (sched,
				GNUNET_TIME_UNIT_FOREVER_REL,
				&shutdown_task,
				NULL);
  return GNUNET_OK;
}


/* end of gnunet-service-fs_drq.c */
