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

#define DEBUG_DRQ GNUNET_NO

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
   * Function to call for each entry.
   */
  GNUNET_DATASTORE_Iterator iter;

  /**
   * Closure for iter.
   */
  void *iter_cls;

  /**
   * Key we are doing the 'get' for.
   */
  GNUNET_HashCode key;

  /**
   * Timeout for this operation.
   */
  struct GNUNET_TIME_Absolute timeout;
    
  /**
   * ID of task used for signaling timeout.
   */
  GNUNET_SCHEDULER_TaskIdentifier task;

  /**
   * Datastore entry type we are doing the 'get' for.
   */
  enum GNUNET_BLOCK_Type type;

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
 * Run the next DS request in our queue, we're done with the current
 * one.
 */
static void
next_ds_request ();


/**
 * Wrapper for the datastore get operation.  Makes sure to trigger the
 * next datastore operation in the queue once the operation is
 * complete.
 *
 * @param cls our 'struct DatastoreRequestQueue*'
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
	      enum GNUNET_BLOCK_Type type,
	      uint32_t priority,
	      uint32_t anonymity,
	      struct GNUNET_TIME_Absolute
	      expiration, 
	      uint64_t uid)
{
  struct DatastoreRequestQueue *gc = cls;

  if (gc->iter == NULL) 
    {
      /* stop the iteration */
#if DEBUG_DRQ
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Iteration terminated\n");
#endif
      if (key != NULL)
	GNUNET_DATASTORE_get_next (dsh, GNUNET_NO);
    }
  else
    {
#if DEBUG_DRQ
      if (key != NULL)
	GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		    "Iteration produced %u-byte result for `%s'\n",
		    size,
		    GNUNET_h2s (key));
#endif
      gc->iter (gc->iter_cls,
		key, size, data, type,
		priority, anonymity, expiration, uid);
    }
  if (key == NULL)
    {
#if DEBUG_DRQ
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Iteration completed\n");
#endif
      GNUNET_assert (gc == drq_running);
      GNUNET_free (gc);
      drq_running = NULL;
      next_ds_request ();
    }
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
  struct DatastoreRequestQueue *gc = cls;

  gc->task = GNUNET_SCHEDULER_NO_TASK;
#if DEBUG_DRQ
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Running datastore request for `%s' of type %u\n",
	      GNUNET_h2s (&gc->key),
	      gc->type);
#endif
  GNUNET_DATASTORE_get (dsh, 
			&gc->key,
			gc->type, 
			42 /* FIXME */, 64 /* FIXME */,
			GNUNET_TIME_absolute_get_remaining(gc->timeout),
			&get_iterator,
			gc);
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

#if DEBUG_DRQ
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Datastore request timed out in queue before transmission\n");
#endif
  e->task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_CONTAINER_DLL_remove (drq_head, drq_tail, e);
  if (e->iter != NULL)
    e->iter (e->iter_cls,
	     NULL, 0, NULL, 0, 0, 0, 
	     GNUNET_TIME_UNIT_ZERO_ABS, 0);
  GNUNET_free (e);  
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

#if DEBUG_DRQ
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "DRQ shutdown initiated\n");
#endif
  GNUNET_assert (NULL != dsh);
  GNUNET_DATASTORE_disconnect (dsh,
			       GNUNET_NO);
  dsh = NULL;
  while (NULL != (drq = drq_head))
    {
      drq_head = drq->next;
      GNUNET_SCHEDULER_cancel (sched, drq->task);
      if (drq->iter != NULL)
	drq->iter (drq->iter_cls,
		   NULL, 0, NULL, 0, 0, 0, 
		   GNUNET_TIME_UNIT_ZERO_ABS, 0);
      GNUNET_free (drq);
    }
  drq_tail = NULL;
  if (drq_running != NULL)
    {
      if (drq_running->task != GNUNET_SCHEDULER_NO_TASK)
	{
	  GNUNET_SCHEDULER_cancel (sched,
				   drq_running->task);
	}
      if (drq_running->iter != NULL)
	{
	  drq_running->iter (drq_running->iter_cls,
			     NULL, 0, NULL, 0, 0, 0, 
			     GNUNET_TIME_UNIT_ZERO_ABS, 0);
	}
      GNUNET_free (drq_running);
      drq_running = NULL;
    }
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
		   enum GNUNET_BLOCK_Type type,
		   GNUNET_DATASTORE_Iterator iter, 
		   void *iter_cls,
		   struct GNUNET_TIME_Relative timeout,
		   int immediate)
{
  struct DatastoreRequestQueue *e;
  struct DatastoreRequestQueue *bef;

#if DEBUG_DRQ
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "DRQ receives request for `%s' of type %u\n",
	      GNUNET_h2s (key),
	      type);
#endif
  e = GNUNET_malloc (sizeof (struct DatastoreRequestQueue));
  e->timeout = GNUNET_TIME_relative_to_absolute (timeout);
  e->forced_head = immediate;
  e->key = *key;
  e->type = type;
  e->iter = iter;
  e->iter_cls = iter_cls;
  e->timeout = GNUNET_TIME_relative_to_absolute (timeout);
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
					  timeout,
					  &timeout_ds_request,
					  e);
  if (drq_running == NULL)
    next_ds_request ();
  return e;				       
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
#if DEBUG_DRQ
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "DRQ receives request cancellation request\n");
#endif
  if (drq == drq_running)
    {
      /* 'DATASTORE_get' has already been started (and this call might
	 actually be be legal since it is possible that the client has
	 not yet received any calls to its the iterator; so we need to
	 cancel somehow; we do this by zeroing the 'iter' field, which
	 stops the iteration */
      drq_running->iter = NULL;
    }
  else
    {
      GNUNET_CONTAINER_DLL_remove (drq_head, drq_tail, drq);
      GNUNET_SCHEDULER_cancel (sched, drq->task);
      GNUNET_free (drq);
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
#if DEBUG_DRQ
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "DRQ receives request for next result (more is %d)\n",
	      more);
#endif
  GNUNET_DATASTORE_get_next (dsh, more);
}


/**
 * Closure for 'drq_remove_cont'.
 */
struct RemoveContext
{
  struct GNUNET_DATASTORE_Handle *rmdsh; 
  GNUNET_DATASTORE_ContinuationWithStatus cont;
  void *cont_cls;
};


static void 
drq_remove_cont (void *cls,
		 int success,
		 const char *msg)
{
  struct RemoveContext *rc = cls;

  rc->cont (rc->cont_cls,
	    success,
	    msg);
  GNUNET_DATASTORE_disconnect (rc->rmdsh, GNUNET_NO);
  GNUNET_free (rc);
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
  struct GNUNET_DATASTORE_Handle *rmdsh; 
  struct RemoveContext *rc;

  rmdsh = GNUNET_DATASTORE_connect (cfg,
				    sched);
  if (rmdsh == NULL)
    {
      GNUNET_break (0);
      cont (cont_cls,
	    GNUNET_SYSERR,
	    _("Failed to connect to datastore"));
      return;
    }
  rc = GNUNET_malloc (sizeof (struct RemoveContext));
  rc->cont = cont;
  rc->cont_cls = cont_cls;
  rc->rmdsh = rmdsh;
  GNUNET_DATASTORE_remove (rmdsh, key, size, data,
			   -3, 128,
			   timeout,
			   &drq_remove_cont, 
			   rc);
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
