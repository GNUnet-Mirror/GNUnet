/*
     This file is part of GNUnet.
     (C) 2011, 2012 Christian Grothoff

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
 * @file util/helper.c
 * @brief API for dealing with (SUID) helper processes that communicate via GNUNET_MessageHeaders on stdin/stdout
 * @author Philipp Toelke
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"


/**
 * Entry in the queue of messages we need to transmit to the helper.
 */
struct HelperMessageQueueEntry
{

  /**
   * This is an entry in a DLL.
   */
  struct HelperMessageQueueEntry *next;

  /**
   * This is an entry in a DLL.
   */
  struct HelperMessageQueueEntry *prev;

  /**
   * Message to transmit (allocated at the end of this struct)
   */
  const struct GNUNET_MessageHeader *msg;
  
  /**
   * Function to call upon completion.
   */
  GNUNET_HELPER_Continuation cont;

  /**
   * Closure to 'cont'.
   */
  void *cont_cls;

  /**
   * Current write position.
   */
  unsigned int wpos;

};


/**
 * The handle to a helper process.
 */
struct GNUNET_HELPER_Handle
{

  /**
   * PipeHandle to receive data from the helper
   */
  struct GNUNET_DISK_PipeHandle *helper_in;
  
  /**
   * PipeHandle to send data to the helper
   */
  struct GNUNET_DISK_PipeHandle *helper_out;
  
  /**
   * FileHandle to receive data from the helper
   */
  const struct GNUNET_DISK_FileHandle *fh_from_helper;
  
  /**
   * FileHandle to send data to the helper
   */
  const struct GNUNET_DISK_FileHandle *fh_to_helper;
  
  /**
   * The process id of the helper
   */
  struct GNUNET_OS_Process *helper_proc;

  /**
   * The Message-Tokenizer that tokenizes the messages comming from the helper
   */
  struct GNUNET_SERVER_MessageStreamTokenizer *mst;

  /**
   * First message queued for transmission to helper.
   */
  struct HelperMessageQueueEntry *mq_head;

  /**
   * Last message queued for transmission to helper.
   */
  struct HelperMessageQueueEntry *mq_tail;

  /**
   * Binary to run.
   */
  const char *binary_name;

  /**
   * NULL-terminated list of command-line arguments.
   */
  char *const *binary_argv;
		    
  /**
   * Task to read from the helper.
   */
  GNUNET_SCHEDULER_TaskIdentifier read_task;

  /**
   * Task to read from the helper.
   */
  GNUNET_SCHEDULER_TaskIdentifier write_task;

  /**
   * Restart task.
   */
  GNUNET_SCHEDULER_TaskIdentifier restart_task;
};


/**
 * Stop the helper process, we're closing down or had an error.
 *
 * @param h handle to the helper process
 */
static void
stop_helper (struct GNUNET_HELPER_Handle *h)
{
  struct HelperMessageQueueEntry *qe;

  if (NULL != h->helper_proc)
  {
    GNUNET_OS_process_kill (h->helper_proc, SIGKILL);
    GNUNET_OS_process_wait (h->helper_proc);
    GNUNET_OS_process_close (h->helper_proc);
    h->helper_proc = NULL;
  }
  if (GNUNET_SCHEDULER_NO_TASK != h->restart_task)
  {
    GNUNET_SCHEDULER_cancel (h->restart_task);
    h->restart_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (GNUNET_SCHEDULER_NO_TASK != h->read_task)
  {
    GNUNET_SCHEDULER_cancel (h->read_task);
    h->read_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (GNUNET_SCHEDULER_NO_TASK != h->write_task)
  {
    GNUNET_SCHEDULER_cancel (h->write_task);
    h->write_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (NULL != h->helper_in)
  {
    GNUNET_DISK_pipe_close (h->helper_in);
    h->helper_in = NULL;
    h->fh_to_helper = NULL;
  }
  if (NULL != h->helper_out)
  {
    GNUNET_DISK_pipe_close (h->helper_out);
    h->helper_out = NULL;
    h->fh_from_helper = NULL;
  }
  while (NULL != (qe = h->mq_head))
  {
    GNUNET_CONTAINER_DLL_remove (h->mq_head,
				 h->mq_tail,
				 qe);
    qe->cont (qe->cont_cls, GNUNET_NO);
    GNUNET_free (qe);
  }
  /* purge MST buffer */
  GNUNET_SERVER_mst_receive (h->mst, NULL, NULL, 0, GNUNET_YES, GNUNET_NO);
}


/**
 * Restart the helper process.
 *
 * @param cls handle to the helper process
 * @param tc scheduler context
 */
static void
restart_task (void *cls,
	      const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Read from the helper-process
 *
 * @param cls handle to the helper process
 * @param tc scheduler context
 */
static void
helper_read (void *cls,
	     const struct GNUNET_SCHEDULER_TaskContext *tsdkctx)
{
  struct GNUNET_HELPER_Handle *h = cls;
  char buf[GNUNET_SERVER_MAX_MESSAGE_SIZE];
  ssize_t t;

  h->read_task = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tsdkctx->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
  {
    /* try again */
    h->read_task = GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL,
						   h->fh_from_helper, &helper_read, h);
    return;
  }
  t = GNUNET_DISK_file_read (h->fh_from_helper, &buf, sizeof (buf));
  if (t < 0)
  {
    /* On read-error, restart the helper */
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("Error reading from `%s': %s\n"),
		h->binary_name,
		STRERROR (errno));
    stop_helper (h);
    /* Restart the helper */
    h->restart_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
				    &restart_task, h);
    return;
  }
  if (0 == t)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, 
		_("Got 0 bytes from helper `%s' (EOF)\n"),
		h->binary_name);
#if 0
    stop_helper (h);
    /* Restart the helper */
    h->restart_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
				    &restart_task, h);
#endif
    return;
  }
  if (GNUNET_SYSERR ==
      GNUNET_SERVER_mst_receive (h->mst, NULL, buf, t, GNUNET_NO, GNUNET_NO))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, 
		_("Failed to parse inbound message from helper `%s'\n"),
		h->binary_name);
    stop_helper (h);
    /* Restart the helper */
    h->restart_task =
        GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
                                      &restart_task, h);
    return;

  }
  h->read_task = GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL,
						 h->fh_from_helper, &helper_read, h);
}


/**
 * Start the helper process.
 *
 * @param h handle to the helper process
 */
static void
start_helper (struct GNUNET_HELPER_Handle *h)
{
  h->helper_in = GNUNET_DISK_pipe (GNUNET_YES, GNUNET_YES, GNUNET_NO);
  h->helper_out = GNUNET_DISK_pipe (GNUNET_YES, GNUNET_NO, GNUNET_YES);
  if ( (h->helper_in == NULL) || (h->helper_out == NULL))
  {
    /* out of file descriptors? try again later... */
    stop_helper (h);
    h->restart_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
				    &restart_task, h);    
    return;
  }
  h->fh_from_helper =
      GNUNET_DISK_pipe_handle (h->helper_out, GNUNET_DISK_PIPE_END_READ);
  h->fh_to_helper =
      GNUNET_DISK_pipe_handle (h->helper_in, GNUNET_DISK_PIPE_END_WRITE);
  h->helper_proc =
      GNUNET_OS_start_process_vap (h->helper_in, h->helper_out,
				   h->binary_name,
				   h->binary_argv);
  if (NULL == h->helper_proc)
  {
    /* failed to start process? try again later... */
    stop_helper (h);
    h->restart_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
				    &restart_task, h);    
    return;
  }
  GNUNET_DISK_pipe_close_end (h->helper_out, GNUNET_DISK_PIPE_END_WRITE);
  GNUNET_DISK_pipe_close_end (h->helper_in, GNUNET_DISK_PIPE_END_READ);
  h->read_task = GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL,
						 h->fh_from_helper, 
						 &helper_read, 
						 h);
}


/**
 * Restart the helper process.
 *
 * @param cls handle to the helper process
 * @param tc scheduler context
 */
static void
restart_task (void *cls,
	      const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_HELPER_Handle*h = cls;

  h->restart_task = GNUNET_SCHEDULER_NO_TASK;
  start_helper (h);
}


/**
 * @brief Starts a helper and begins reading from it
 *
 * @param binary_name name of the binary to run
 * @param binary_argv NULL-terminated list of arguments to give when starting the binary (this
 *                    argument must not be modified by the client for
 *                     the lifetime of the helper h)
 * @param cb function to call if we get messages from the helper
 * @param cb_cls Closure for the callback
 * @return the new H, NULL on error
 */
struct GNUNET_HELPER_Handle*
GNUNET_HELPER_start (const char *binary_name,
		     char *const binary_argv[],
		     GNUNET_SERVER_MessageTokenizerCallback cb, void *cb_cls)
{
  struct GNUNET_HELPER_Handle*h;

  h =  GNUNET_malloc (sizeof (struct GNUNET_HELPER_Handle));
  h->binary_name = binary_name;
  h->binary_argv = binary_argv;
  h->mst = GNUNET_SERVER_mst_create (cb, cb_cls);
  start_helper (h);
  return h;
}


/**
 * @brief Kills the helper, closes the pipe and frees the h
 *
 * @param h h to helper to stop
 */
void
GNUNET_HELPER_stop (struct GNUNET_HELPER_Handle *h)
{
  struct HelperMessageQueueEntry *qe;

  /* signal pending writes that we were stopped */
  while (NULL != (qe = h->mq_head))
  {
    GNUNET_CONTAINER_DLL_remove (h->mq_head,
				 h->mq_tail,
				 qe);
    qe->cont (qe->cont_cls, GNUNET_SYSERR);
    GNUNET_free (qe);
  }
  stop_helper (h);
  GNUNET_SERVER_mst_destroy (h->mst);
  GNUNET_free (h);
}


/**
 * Write to the helper-process
 *
 * @param cls handle to the helper process
 * @param tc scheduler context
 */
static void
helper_write (void *cls,
	     const struct GNUNET_SCHEDULER_TaskContext *tsdkctx)
{
  struct GNUNET_HELPER_Handle *h = cls;
  struct HelperMessageQueueEntry *qe;
  const char *buf;
  ssize_t t;

  h->write_task = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tsdkctx->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
  {
    /* try again */
    h->write_task = GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL,
						    h->fh_to_helper, &helper_write, h);
    return;
  }  
  if (NULL == (qe = h->mq_head))
    return; /* how did this happen? */
  buf = (const char*) qe->msg;
  t = GNUNET_DISK_file_write (h->fh_to_helper, &buf[qe->wpos], ntohs (qe->msg->size) - qe->wpos);
  if (t <= 0)
  {
    /* On write-error, restart the helper */
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("Error writing to `%s': %s\n"),
		h->binary_name,
		STRERROR (errno));
    stop_helper (h);
    /* Restart the helper */
    h->restart_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
				    &restart_task, h);
    return;
  }
  qe->wpos += t;
  if (qe->wpos == ntohs (qe->msg->size))
  {
    GNUNET_CONTAINER_DLL_remove (h->mq_head,
				 h->mq_tail,
				 qe);
    if (NULL != qe->cont)
      qe->cont (qe->cont_cls, GNUNET_YES);
    GNUNET_free (qe);
  }
  if (NULL != h->mq_head)
    h->write_task = GNUNET_SCHEDULER_add_write_file (GNUNET_TIME_UNIT_FOREVER_REL,
						     h->fh_to_helper, 
						     &helper_write, 
						     h);
}


/**
 * Send an message to the helper.
 *
 * @param h helper to send message to
 * @param msg message to send
 * @param can_drop can the message be dropped if there is already one in the queue?
 * @param cont continuation to run once the message is out (PREREQ_DONE on succees, CANCEL
 *             if the helper process died, NULL during GNUNET_HELPER_stop).
 * @param cont_cls closure for 'cont'
 * @return GNUNET_YES if the message will be sent
 *         GNUNET_NO if the message was dropped
 */
int
GNUNET_HELPER_send (struct GNUNET_HELPER_Handle *h, 
		    const struct GNUNET_MessageHeader *msg,
		    int can_drop,
		    GNUNET_HELPER_Continuation cont,
		    void *cont_cls)
{
  struct HelperMessageQueueEntry *qe;
  uint16_t mlen;

  if ( (GNUNET_YES == can_drop) &&
       (h->mq_head != NULL) )
    return GNUNET_NO;
  mlen = ntohs (msg->size);
  qe = GNUNET_malloc (sizeof (struct HelperMessageQueueEntry) + mlen);
  qe->msg = (const struct GNUNET_MessageHeader*) &qe[1];
  memcpy (&qe[1], msg, mlen);
  qe->cont = cont;
  qe->cont_cls = cont_cls;
  GNUNET_CONTAINER_DLL_insert_tail (h->mq_head,
				    h->mq_tail,
				    qe);
  if (GNUNET_SCHEDULER_NO_TASK == h->write_task)
    h->write_task = GNUNET_SCHEDULER_add_write_file (GNUNET_TIME_UNIT_FOREVER_REL,
						     h->fh_to_helper, 
						     &helper_write, 
						     h);
    
  return GNUNET_YES;
}


/* end of helper.c */
