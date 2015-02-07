/*
     This file is part of GNUnet.
     Copyright (C) 2011, 2012 Christian Grothoff

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
 * @brief API for dealing with (SUID) helper processes that communicate via
 *          GNUNET_MessageHeaders on stdin/stdout
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
   * The exception callback
   */
  GNUNET_HELPER_ExceptionCallback exp_cb;

  /**
   * The closure for callbacks
   */
  void *cb_cls;

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
  char *binary_name;

  /**
   * NULL-terminated list of command-line arguments.
   */
  char **binary_argv;
		
  /**
   * Task to read from the helper.
   */
  struct GNUNET_SCHEDULER_Task * read_task;

  /**
   * Task to read from the helper.
   */
  struct GNUNET_SCHEDULER_Task * write_task;

  /**
   * Restart task.
   */
  struct GNUNET_SCHEDULER_Task * restart_task;

  /**
   * Does the helper support the use of a control pipe for signalling?
   */
  int with_control_pipe;

};


/**
 * Sends termination signal to the helper process.  The helper process is not
 * reaped; call GNUNET_HELPER_wait() for reaping the dead helper process.
 *
 * @param h the helper handle
 * @param soft_kill if GNUNET_YES, signals termination by closing the helper's
 *          stdin; GNUNET_NO to signal termination by sending SIGTERM to helper
 * @return #GNUNET_OK on success; #GNUNET_SYSERR on error
 */
int
GNUNET_HELPER_kill (struct GNUNET_HELPER_Handle *h,
		    int soft_kill)
{
  struct GNUNET_HELPER_SendHandle *sh;
  int ret;

  while (NULL != (sh = h->sh_head))
  {
    GNUNET_CONTAINER_DLL_remove (h->sh_head,
				 h->sh_tail,
				 sh);
    if (NULL != sh->cont)
      sh->cont (sh->cont_cls, GNUNET_NO);
    GNUNET_free (sh);
  }
  if (NULL != h->restart_task)
  {
    GNUNET_SCHEDULER_cancel (h->restart_task);
    h->restart_task = NULL;
  }
  if (NULL != h->read_task)
  {
    GNUNET_SCHEDULER_cancel (h->read_task);
    h->read_task = NULL;
  }
  if (NULL == h->helper_proc)
    return GNUNET_SYSERR;
  if (GNUNET_YES == soft_kill)
  {
    /* soft-kill only possible with pipes */
    GNUNET_assert (NULL != h->helper_in);
    ret = GNUNET_DISK_pipe_close (h->helper_in);
    h->helper_in = NULL;
    h->fh_to_helper = NULL;
    return ret;
  }
  if (0 != GNUNET_OS_process_kill (h->helper_proc, GNUNET_TERM_SIG))
    return GNUNET_SYSERR;
  return GNUNET_OK;
}


/**
 * Reap the helper process.  This call is blocking(!).  The helper process
 * should either be sent a termination signal before or should be dead before
 * calling this function
 *
 * @param h the helper handle
 * @return #GNUNET_OK on success; #GNUNET_SYSERR on error
 */
int
GNUNET_HELPER_wait (struct GNUNET_HELPER_Handle *h)
{
  struct GNUNET_HELPER_SendHandle *sh;
  int ret;

  ret = GNUNET_SYSERR;
  if (NULL != h->helper_proc)
  {
    ret = GNUNET_OS_process_wait (h->helper_proc);
    GNUNET_OS_process_destroy (h->helper_proc);
    h->helper_proc = NULL;
  }
  if (NULL != h->read_task)
  {
    GNUNET_SCHEDULER_cancel (h->read_task);
    h->read_task = NULL;
  }
  if (NULL != h->write_task)
  {
    GNUNET_SCHEDULER_cancel (h->write_task);
    h->write_task = NULL;
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
  if (NULL != h->mst)
    (void) GNUNET_SERVER_mst_receive (h->mst, NULL, NULL, 0, GNUNET_YES, GNUNET_NO);
  return ret;
}


/**
 * Stop the helper process, we're closing down or had an error.
 *
 * @param h handle to the helper process
 * @param soft_kill if #GNUNET_YES, signals termination by closing the helper's
 *          stdin; #GNUNET_NO to signal termination by sending SIGTERM to helper
 */
static void
stop_helper (struct GNUNET_HELPER_Handle *h,
	     int soft_kill)
{
  if (NULL != h->restart_task)
  {
    GNUNET_SCHEDULER_cancel (h->restart_task);
    h->restart_task = NULL;
  }
  else
  {
    GNUNET_break (GNUNET_OK == GNUNET_HELPER_kill (h, soft_kill));
    GNUNET_break (GNUNET_OK == GNUNET_HELPER_wait (h));
  }
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

  h->read_task = NULL;
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
    if (NULL != h->exp_cb)
    {
      h->exp_cb (h->cb_cls);
      GNUNET_HELPER_stop (h, GNUNET_NO);
      return;
    }
    stop_helper (h, GNUNET_NO);
    /* Restart the helper */
    h->restart_task =
	GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS, &restart_task, h);
    return;
  }
  if (0 == t)
  {
    /* this happens if the helper is shut down via a
       signal, so it is not a "hard" error */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Got 0 bytes from helper `%s' (EOF)\n",
		h->binary_name);
    if (NULL != h->exp_cb)
    {
      h->exp_cb (h->cb_cls);
      GNUNET_HELPER_stop (h, GNUNET_NO);
      return;
    }
    stop_helper (h, GNUNET_NO);
    /* Restart the helper */
    h->restart_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
				    &restart_task, h);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Got %u bytes from helper `%s'\n",
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
    if (NULL != h->exp_cb)
    {
      h->exp_cb (h->cb_cls);
      GNUNET_HELPER_stop (h, GNUNET_NO);
      return;
    }
    stop_helper (h, GNUNET_NO);
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
    stop_helper (h, GNUNET_NO);
    h->restart_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
				    &restart_task, h);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Starting HELPER process `%s'\n",
	      h->binary_name);
  h->fh_from_helper =
      GNUNET_DISK_pipe_handle (h->helper_out, GNUNET_DISK_PIPE_END_READ);
  h->fh_to_helper =
      GNUNET_DISK_pipe_handle (h->helper_in, GNUNET_DISK_PIPE_END_WRITE);
  h->helper_proc =
    GNUNET_OS_start_process_vap (h->with_control_pipe, GNUNET_OS_INHERIT_STD_ERR,
				 h->helper_in, h->helper_out, NULL,
				 h->binary_name,
				 h->binary_argv);
  if (NULL == h->helper_proc)
  {
    /* failed to start process? try again later... */
    stop_helper (h, GNUNET_NO);
    h->restart_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
				    &restart_task, h);
    return;
  }
  GNUNET_DISK_pipe_close_end (h->helper_out, GNUNET_DISK_PIPE_END_WRITE);
  GNUNET_DISK_pipe_close_end (h->helper_in, GNUNET_DISK_PIPE_END_READ);
  if (NULL != h->mst)
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

  h->restart_task = NULL;
  start_helper (h);
}


/**
 * Starts a helper and begins reading from it. The helper process is
 * restarted when it dies except when it is stopped using GNUNET_HELPER_stop()
 * or when the exp_cb callback is not NULL.
 *
 * @param with_control_pipe does the helper support the use of a control pipe for signalling?
 * @param binary_name name of the binary to run
 * @param binary_argv NULL-terminated list of arguments to give when starting the binary (this
 *                    argument must not be modified by the client for
 *                     the lifetime of the helper handle)
 * @param cb function to call if we get messages from the helper
 * @param exp_cb the exception callback to call. Set this to NULL if the helper
 *          process has to be restarted automatically when it dies/crashes
 * @param cb_cls closure for the above callback
 * @return the new Handle, NULL on error
 */
struct GNUNET_HELPER_Handle *
GNUNET_HELPER_start (int with_control_pipe,
		     const char *binary_name,
		     char *const binary_argv[],
		     GNUNET_SERVER_MessageTokenizerCallback cb,
		     GNUNET_HELPER_ExceptionCallback exp_cb,
		     void *cb_cls)
{
  struct GNUNET_HELPER_Handle *h;
  unsigned int c;

  h = GNUNET_new (struct GNUNET_HELPER_Handle);
  h->with_control_pipe = with_control_pipe;
  /* Lookup in libexec path only if we are starting gnunet helpers */
  if (NULL != strstr (binary_name, "gnunet"))
    h->binary_name = GNUNET_OS_get_libexec_binary_path (binary_name);
  else
    h->binary_name = GNUNET_strdup (binary_name);
  for (c = 0; NULL != binary_argv[c]; c++);
  h->binary_argv = GNUNET_malloc (sizeof (char *) * (c + 1));
  for (c = 0; NULL != binary_argv[c]; c++)
    h->binary_argv[c] = GNUNET_strdup (binary_argv[c]);
  h->binary_argv[c] = NULL;
  h->cb_cls = cb_cls;
  if (NULL != cb)
    h->mst = GNUNET_SERVER_mst_create (cb, h->cb_cls);
  h->exp_cb = exp_cb;
  start_helper (h);
  return h;
}


/**
 * Free's the resources occupied by the helper handle
 *
 * @param h the helper handle to free
 */
void
GNUNET_HELPER_destroy (struct GNUNET_HELPER_Handle *h)
{
  unsigned int c;
  struct GNUNET_HELPER_SendHandle *sh;

  if (NULL != h->write_task)
  {
    GNUNET_SCHEDULER_cancel (h->write_task);
    h->write_task = NULL;
  }
  GNUNET_assert (NULL == h->read_task);
  GNUNET_assert (NULL == h->restart_task);
  while (NULL != (sh = h->sh_head))
  {
    GNUNET_CONTAINER_DLL_remove (h->sh_head,
				 h->sh_tail,
				 sh);
    if (NULL != sh->cont)
      sh->cont (sh->cont_cls, GNUNET_SYSERR);
    GNUNET_free (sh);
  }
  if (NULL != h->mst)
    GNUNET_SERVER_mst_destroy (h->mst);
  GNUNET_free (h->binary_name);
  for (c = 0; h->binary_argv[c] != NULL; c++)
    GNUNET_free (h->binary_argv[c]);
  GNUNET_free (h->binary_argv);
  GNUNET_free (h);
}


/**
 * Kills the helper, closes the pipe and frees the handle
 *
 * @param h handle to helper to stop
 * @param soft_kill if #GNUNET_YES, signals termination by closing the helper's
 *          stdin; #GNUNET_NO to signal termination by sending SIGTERM to helper
 */
void
GNUNET_HELPER_stop (struct GNUNET_HELPER_Handle *h,
		    int soft_kill)
{
  h->exp_cb = NULL;
  stop_helper (h, soft_kill);
  GNUNET_HELPER_destroy (h);
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

  h->write_task = NULL;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
  {
    /* try again */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Helper write triggered during shutdown, retrying\n");
    h->write_task = GNUNET_SCHEDULER_add_write_file (GNUNET_TIME_UNIT_FOREVER_REL,
						     h->fh_to_helper, &helper_write, h);
    return;
  }
  if (NULL == (sh = h->sh_head))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Helper write had no work!\n");
    return; /* how did this happen? */
  }
  buf = (const char*) sh->msg;
  t = GNUNET_DISK_file_write (h->fh_to_helper,
			      &buf[sh->wpos],
			      ntohs (sh->msg->size) - sh->wpos);
  if (-1 == t)
  {
    /* On write-error, restart the helper */
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		_("Error writing to `%s': %s\n"),
		h->binary_name,
		STRERROR (errno));
    if (NULL != h->exp_cb)
    {
      h->exp_cb (h->cb_cls);
      GNUNET_HELPER_stop (h, GNUNET_NO);
      return;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Stopping and restarting helper task!\n");
    stop_helper (h, GNUNET_NO);
    /* Restart the helper */
    h->restart_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
				    &restart_task, h);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Transmitted %u bytes to %s\n",
	      (unsigned int) t,
	      h->binary_name);
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
 * @param cont continuation to run once the message is out (#GNUNET_OK on succees, #GNUNET_NO
 *             if the helper process died, #GNUNET_SYSERR during #GNUNET_HELPER_destroy).
 * @param cont_cls closure for @a cont
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
  if (NULL == h->write_task)
    h->write_task = GNUNET_SCHEDULER_add_write_file (GNUNET_TIME_UNIT_FOREVER_REL,
						     h->fh_to_helper,
						     &helper_write,
						     h);

  return sh;
}

/**
 * Cancel a #GNUNET_HELPER_send operation.  If possible, transmitting the
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
    GNUNET_free (sh);
    if (NULL == h->sh_head)
    {
      GNUNET_SCHEDULER_cancel (h->write_task);
      h->write_task = NULL;
    }
  }
}


/* end of helper.c */
