/*
     This file is part of GNUnet.
     (C) 2001, 2002, 2003, 2004, 2005, 2006, 2008, 2009 Christian Grothoff (and other contributing authors)

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
 * @file fs/fs.c
 * @brief main FS functions
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_fs_service.h"
#include "fs.h"


/**
 * Start the given job (send signal, remove from pending queue, update
 * counters and state).
 *
 * @param qe job to start
 */
static void
start_job (struct GNUNET_FS_QueueEntry *qe)
{
  qe->client = GNUNET_CLIENT_connect (qe->h->sched, "fs", qe->h->cfg);
  if (qe->client == NULL)
    {
      GNUNET_break (0);
      return;
    }
  qe->start (qe->cls, qe->client);
  switch (qe->category)
    {
    case GNUNET_FS_QC_DOWNLOAD:
      qe->h->active_downloads++;
      break;
    case GNUNET_FS_QC_PROBE:
      qe->h->active_probes++;
      break;
    }
  qe->start_time = GNUNET_TIME_absolute_get ();
  GNUNET_CONTAINER_DLL_remove (qe->h->pending_head,
			       qe->h->pending_tail,
			       qe);
  GNUNET_CONTAINER_DLL_insert_after (qe->h->pending_head,
				     qe->h->running_tail,
				     qe->h->running_tail,
				     qe);
}


/**
 * Stop the given job (send signal, remove from active queue, update
 * counters and state).
 *
 * @param qe job to stop
 */
static void
stop_job (struct GNUNET_FS_QueueEntry *qe)
{
  qe->client = NULL;
  qe->stop (qe->cls);
  switch (qe->category)
    {
    case GNUNET_FS_QC_DOWNLOAD:
      qe->h->active_downloads--;
      break;
    case GNUNET_FS_QC_PROBE:
      qe->h->active_probes--;
      break;
    }
  qe->run_time = GNUNET_TIME_relative_add (qe->run_time,
					   GNUNET_TIME_absolute_get_duration (qe->start_time));
  GNUNET_CONTAINER_DLL_remove (qe->h->running_head,
			       qe->h->running_tail,
			       qe);
  GNUNET_CONTAINER_DLL_insert_after (qe->h->pending_head,
				     qe->h->pending_tail,
				     qe->h->pending_tail,
				     qe);
}


/**
 * Process the jobs in the job queue, possibly starting some
 * and stopping others.
 *
 * @param cls the 'struct GNUNET_FS_Handle'
 * @param tc scheduler context
 */
static void
process_job_queue (void *cls,
		   const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_FS_Handle *h = cls;

  h->queue_job = GNUNET_SCHEDULER_NO_TASK;
  /* FIXME: stupid implementation that just starts everything follows... */
  while (NULL != h->pending_head)
    start_job (h->pending_head);
  
  /* FIXME: possibly re-schedule queue-job! */
}

/**
 * Add a job to the queue.
 *
 * @param h handle to the overall FS state
 * @param start function to call to begin the job
 * @param stop function to call to pause the job, or on dequeue (if the job was running)
 * @param cls closure for start and stop
 * @param cat category of the job
 * @return queue handle
 */
struct GNUNET_FS_QueueEntry *
GNUNET_FS_queue_ (struct GNUNET_FS_Handle *h,
		  GNUNET_FS_QueueStart start,
		  GNUNET_FS_QueueStop stop,
		  void *cls,
		  enum GNUNET_FS_QueueCategory cat)
{
  struct GNUNET_FS_QueueEntry *qe;

  qe = GNUNET_malloc (sizeof (struct GNUNET_FS_QueueEntry));
  qe->h = h;
  qe->start = start;
  qe->stop = stop;
  qe->cls = cls;
  qe->queue_time = GNUNET_TIME_absolute_get ();
  qe->category = cat;
  GNUNET_CONTAINER_DLL_insert_after (h->pending_head,
				     h->pending_tail,
				     h->pending_tail,
				     qe);
  if (h->queue_job != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (h->sched,
			     h->queue_job);
  h->queue_job 
    = GNUNET_SCHEDULER_add_now (h->sched,
				&process_job_queue,
				h);
  return qe;
}


/**
 * Dequeue a job from the queue.
 * @param qh handle for the job
 */
void
GNUNET_FS_dequeue_ (struct GNUNET_FS_QueueEntry *qh)
{
  if (qh->client != NULL)    
    {
      if (qh->h->queue_job != GNUNET_SCHEDULER_NO_TASK)
	GNUNET_SCHEDULER_cancel (qh->h->sched,
				 qh->h->queue_job);
      qh->h->queue_job 
	= GNUNET_SCHEDULER_add_now (qh->h->sched,
				    &process_job_queue,
				    qh->h);
      stop_job (qh);
    }
  GNUNET_CONTAINER_DLL_remove (qh->h->pending_head,
			       qh->h->pending_tail,
			       qh);
  GNUNET_free (qh);
}


/**
 * Setup a connection to the file-sharing service.
 *
 * @param sched scheduler to use
 * @param cfg configuration to use
 * @param client_name unique identifier for this client 
 * @param upcb function to call to notify about FS actions
 * @param upcb_cls closure for upcb
 * @param flags specific attributes for fs-operations
 * @param ... list of optional options, terminated with GNUNET_FS_OPTIONS_END
 * @return NULL on error
 */
struct GNUNET_FS_Handle *
GNUNET_FS_start (struct GNUNET_SCHEDULER_Handle *sched,
		 const struct GNUNET_CONFIGURATION_Handle *cfg,
		 const char *client_name,
		 GNUNET_FS_ProgressCallback upcb,
		 void *upcb_cls,
		 enum GNUNET_FS_Flags flags,
		 ...)
{
  struct GNUNET_FS_Handle *ret;
  struct GNUNET_CLIENT_Connection *client;
  
  client = GNUNET_CLIENT_connect (sched,
				  "fs",
				  cfg);
  if (NULL == client)
    return NULL;
  ret = GNUNET_malloc (sizeof (struct GNUNET_FS_Handle));
  ret->sched = sched;
  ret->cfg = cfg;
  ret->client_name = GNUNET_strdup (client_name);
  ret->upcb = upcb;
  ret->upcb_cls = upcb_cls;
  ret->client = client;
  ret->flags = flags;
  // FIXME: process varargs!
  // FIXME: setup receive-loop with client

  // FIXME: deserialize state; use client-name to find master-directory!
  // Deserialize-Upload:
  // * read FNs for upload FIs, deserialize each
  // Deserialize Search:
  // * read search queries
  // * for each query, read file with search results
  // * for each search result with active download, deserialize download
  // * for each directory search result, check for active downloads of contents
  // Deserialize Download:
  // * always part of search???
  // Deserialize Unindex:
  // * read FNs for unindex with progress offset
  return ret;
}


/**
 * Close our connection with the file-sharing service.
 * The callback given to GNUNET_FS_start will no longer be
 * called after this function returns.
 *
 * @param h handle that was returned from GNUNET_FS_start
 */                    
void 
GNUNET_FS_stop (struct GNUNET_FS_Handle *h)
{
  // FIXME: serialize state!? (or is it always serialized???)
  // FIXME: terminate receive-loop with client  
  if (h->queue_job != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (h->sched,
			     h->queue_job);
  GNUNET_CLIENT_disconnect (h->client, GNUNET_NO);
  GNUNET_free (h->client_name);
  GNUNET_free (h);
}


/* end of fs.c */
