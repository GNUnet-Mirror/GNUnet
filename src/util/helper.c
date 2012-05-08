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
struct GNUNET_HELPER_SendHandle
{

  /**
   * This is an entry in a DLL.
   */
  struct GNUNET_HELPER_SendHandle *next;

  /**
   * This is an entry in a DLL.
   */
  struct GNUNET_HELPER_SendHandle *prev;

  /**
   * Message to transmit (allocated at the end of this struct)
   */
  const struct GNUNET_MessageHeader *msg;
 
  /**
   * The handle to a helper process.
   */
  struct GNUNET_HELPER_Handle *h;
 
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
  struct GNUNET_HELPER_SendHandle *sh_head;

  /**
   * Last message queued for transmission to helper.
   */
  struct GNUNET_HELPER_SendHandle *sh_tail;

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
  struct GNUNET_HELPER_SendHandle *sh;

  if (NULL != h->helper_proc)
  {
    GNUNET_break (0 == GNUNET_OS_process_kill (h->helper_proc, SIGTERM));
    GNUNET_break (GNUNET_OK == GNUNET_OS_process_wait (h->helper_proc));
    GNUNET_OS_process_destroy (h->helper_proc);
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
  while (NULL != (sh = h->sh_head))
  {
    GNUNET_CONTAINER_DLL_remove (h->sh_head,
				 h->sh_tail,
				 sh);
    if (NULL != sh->cont)
      sh->cont (sh->cont_cls, GNUNET_NO);
    GNUNET_free (sh);
  }
  /* purge MST buffer */
  (void) GNUNET_SERVER_mst_receive (h->mst, NULL, NULL, 0, GNUNET_YES, GNUNET_NO);
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
	     const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_HELPER_Handle *h = cls;
  char buf[GNUNET_SERVER_MAX_MESSAGE_SIZE] GNUNET_ALIGN;
  ssize_t t;

  h->read_task = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
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
    /* this happens if the helper is shut down via a 
       signal, so it is not a "hard" error */
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, 
		_("Got 0 bytes from helper `%s' (EOF)\n"),
		h->binary_name);
    stop_helper (h);
    /* Restart the helper */
    h->restart_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
				    &restart_task, h);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, 
	      _("Got %u bytes from helper `%s'\n"),
	      (unsigned int) t,
	      h->binary_name);
  h->read_task = GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL,
						 h->fh_from_helper, &helper_read, h);
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
}


/**
 * Start the helper process.
 *
 * @param h handle to the helper process
 */
static void
start_helper (struct GNUNET_HELPER_Handle *h)
{
  h->helper_in = GNUNET_DISK_pipe (GNUNET_YES, GNUNET_YES, GNUNET_YES, GNUNET_NO);
  h->helper_out = GNUNET_DISK_pipe (GNUNET_YES, GNUNET_YES, GNUNET_NO, GNUNET_YES);
  if ( (h->helper_in == NULL) || (h->helper_out == NULL))
  {
    /* out of file descriptors? try again later... */
    stop_helper (h);
    h->restart_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
				    &restart_task, h);    
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
	      _("Starting HELPER process `%s'\n"),
	      h->binary_name);
  h->fh_from_helper =
      GNUNET_DISK_pipe_handle (h->helper_out, GNUNET_DISK_PIPE_END_READ);
  h->fh_to_helper =
      GNUNET_DISK_pipe_handle (h->helper_in, GNUNET_DISK_PIPE_END_WRITE);
  h->helper_proc =
      GNUNET_OS_start_process_vap (GNUNET_NO,
				   h->helper_in, h->helper_out,
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
  struct GNUNET_HELPER_SendHandle *sh;

  /* signal pending writes that we were stopped */
  while (NULL != (sh = h->sh_head))
  {
    GNUNET_CONTAINER_DLL_remove (h->sh_head,
				 h->sh_tail,
				 sh);
    if (NULL != sh->cont)
      sh->cont (sh->cont_cls, GNUNET_SYSERR);
    GNUNET_free (sh);
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
	     const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_HELPER_Handle *h = cls;
  struct GNUNET_HELPER_SendHandle *sh;
  const char *buf;
  ssize_t t;

  h->write_task = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
  {
    /* try again */
    h->write_task = GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL,
						    h->fh_to_helper, &helper_write, h);
    return;
  }  
  if (NULL == (sh = h->sh_head))
    return; /* how did this happen? */
  buf = (const char*) sh->msg;
  t = GNUNET_DISK_file_write (h->fh_to_helper, &buf[sh->wpos], ntohs (sh->msg->size) - sh->wpos);
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
  sh->wpos += t;
  if (sh->wpos == ntohs (sh->msg->size))
  {
    GNUNET_CONTAINER_DLL_remove (h->sh_head,
				 h->sh_tail,
				 sh);
    if (NULL != sh->cont)
      sh->cont (sh->cont_cls, GNUNET_YES);
    GNUNET_free (sh);
  }
  if (NULL != h->sh_head)
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
 * @return NULL if the message was dropped, 
 *         otherwise handle to cancel *cont* (actual transmission may
 *         not be abortable)
 */
struct GNUNET_HELPER_SendHandle *
GNUNET_HELPER_send (struct GNUNET_HELPER_Handle *h, 
		    const struct GNUNET_MessageHeader *msg,
		    int can_drop,
		    GNUNET_HELPER_Continuation cont,
		    void *cont_cls)
{
  struct GNUNET_HELPER_SendHandle *sh;
  uint16_t mlen;

  if (NULL == h->fh_to_helper)
    return NULL;
  if ( (GNUNET_YES == can_drop) &&
       (NULL != h->sh_head) )
    return NULL;
  mlen = ntohs (msg->size);
  sh = GNUNET_malloc (sizeof (struct GNUNET_HELPER_SendHandle) + mlen);
  sh->msg = (const struct GNUNET_MessageHeader*) &sh[1];
  memcpy (&sh[1], msg, mlen);
  sh->h = h;
  sh->cont = cont;
  sh->cont_cls = cont_cls;
  GNUNET_CONTAINER_DLL_insert_tail (h->sh_head,
				    h->sh_tail,
				    sh);
  if (GNUNET_SCHEDULER_NO_TASK == h->write_task)
    h->write_task = GNUNET_SCHEDULER_add_write_file (GNUNET_TIME_UNIT_FOREVER_REL,
						     h->fh_to_helper, 
						     &helper_write, 
						     h);
    
  return sh;
}

/**
 * Cancel a 'send' operation.  If possible, transmitting the
 * message is also aborted, but at least 'cont' won't be
 * called.
 *
 * @param sh operation to cancel
 */
void
GNUNET_HELPER_send_cancel (struct GNUNET_HELPER_SendHandle *sh)
{
  struct GNUNET_HELPER_Handle *h = sh->h;

  sh->cont = NULL;
  sh->cont_cls = NULL;
  if (0 == sh->wpos)
  {
    GNUNET_CONTAINER_DLL_remove (h->sh_head, h->sh_tail, sh);
    if (NULL == h->sh_head)
    {
      GNUNET_SCHEDULER_cancel (h->write_task);
      h->write_task = GNUNET_SCHEDULER_NO_TASK;
    }
    GNUNET_free (sh);
  }
}


/* end of helper.c */
