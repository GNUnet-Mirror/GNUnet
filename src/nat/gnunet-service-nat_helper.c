/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2010, 2011, 2016 GNUnet e.V.

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
 * @file nat/gnunet-service-nat_helper.c
 * @brief runs the gnunet-helper-nat-server
 * @author Milan Bouchet-Valat
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet-service-nat_helper.h"


/**
 * Information we keep per NAT helper process.
 */
struct HelperContext
{

  /**
   * IP address we pass to the NAT helper.
   */
  struct in_addr internal_address;

  /**
   * Function to call if we receive a reversal request.
   */
  GN_ReversalCallback cb;

  /**
   * Closure for @e cb.
   */
  void *cb_cls;

  /**
   * How long do we wait for restarting a crashed gnunet-helper-nat-server?
   */
  struct GNUNET_TIME_Relative server_retry_delay;

  /**
   * ID of select gnunet-helper-nat-server stdout read task
   */
  struct GNUNET_SCHEDULER_Task *server_read_task;

  /**
   * The process id of the server process (if behind NAT)
   */
  struct GNUNET_OS_Process *server_proc;

  /**
   * stdout pipe handle for the gnunet-helper-nat-server process
   */
  struct GNUNET_DISK_PipeHandle *server_stdout;

  /**
   * stdout file handle (for reading) for the gnunet-helper-nat-server process
   */
  const struct GNUNET_DISK_FileHandle *server_stdout_handle;
};


/**
 * Task that restarts the gnunet-helper-nat-server process after a crash
 * after a certain delay.
 *
 * @param cls a `struct HelperContext`
 */
static void
restart_nat_server (void *cls);


/**
 * Try again starting the helper later
 *
 * @param h context of the helper
 */
static void
try_again (struct HelperContext *h)
{
  GNUNET_assert (NULL == h->server_read_task);
  h->server_retry_delay
    = GNUNET_TIME_STD_BACKOFF (h->server_retry_delay);
  h->server_read_task
    = GNUNET_SCHEDULER_add_delayed (h->server_retry_delay,
				    &restart_nat_server,
				    h);
}


/**
 * We have been notified that gnunet-helper-nat-server has written
 * something to stdout.  Handle the output, then reschedule this
 * function to be called again once more is available.
 *
 * @param cls the `struct HelperContext`
 */
static void
nat_server_read (void *cls)
{
  struct HelperContext *h = cls;
  char mybuf[40];
  ssize_t bytes;
  int port;
  const char *port_start;
  struct sockaddr_in sin_addr;

  h->server_read_task = NULL;
  memset (mybuf,
	  0,
	  sizeof (mybuf));
  bytes
    = GNUNET_DISK_file_read (h->server_stdout_handle,
			     mybuf,
			     sizeof (mybuf));
  if (bytes < 1)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Finished reading from server stdout with code: %d\n",
		(int) bytes);
    if (0 != GNUNET_OS_process_kill (h->server_proc,
				     GNUNET_TERM_SIG))
      GNUNET_log_from_strerror (GNUNET_ERROR_TYPE_WARNING,
				"nat",
				"kill");
    GNUNET_OS_process_wait (h->server_proc);
    GNUNET_OS_process_destroy (h->server_proc);
    h->server_proc = NULL;
    GNUNET_DISK_pipe_close (h->server_stdout);
    h->server_stdout = NULL;
    h->server_stdout_handle = NULL;
    try_again (h);
    return;
  }

  port_start = NULL;
  for (size_t i = 0; i < sizeof (mybuf); i++)
  {
    if (mybuf[i] == '\n')
    {
      mybuf[i] = '\0';
      break;
    }
    if ((mybuf[i] == ':') && (i + 1 < sizeof (mybuf)))
    {
      mybuf[i] = '\0';
      port_start = &mybuf[i + 1];
    }
  }

  /* construct socket address of sender */
  memset (&sin_addr,
	  0,
	  sizeof (sin_addr));
  sin_addr.sin_family = AF_INET;
#if HAVE_SOCKADDR_IN_SIN_LEN
  sin_addr.sin_len = sizeof (sin_addr);
#endif
  if ( (NULL == port_start) ||
       (1 != SSCANF (port_start,
		     "%d",
		     &port)) ||
       (-1 == inet_pton (AF_INET,
			 mybuf,
			 &sin_addr.sin_addr)))
  {
    /* should we restart gnunet-helper-nat-server? */
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		_("gnunet-helper-nat-server generated malformed address `%s'\n"),
		mybuf);
    h->server_read_task
      = GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL,
                                        h->server_stdout_handle,
                                        &nat_server_read,
					h);
    return;
  }
  sin_addr.sin_port = htons ((uint16_t) port);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "gnunet-helper-nat-server read: %s:%d\n",
	      mybuf,
	      port);
  h->cb (h->cb_cls,
	 &sin_addr);
  h->server_read_task
    = GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL,
                                      h->server_stdout_handle,
				      &nat_server_read,
                                      h);
}


/**
 * Task that restarts the gnunet-helper-nat-server process after a crash
 * after a certain delay.
 *
 * @param cls a `struct HelperContext`
 */
static void
restart_nat_server (void *cls)
{
  struct HelperContext *h = cls;
  char *binary;
  char ia[INET_ADDRSTRLEN];

  h->server_read_task = NULL;
  GNUNET_assert (NULL !=
		 inet_ntop (AF_INET,
			    &h->internal_address,
			    ia,
			    sizeof (ia)));
  /* Start the server process */
  binary
    = GNUNET_OS_get_libexec_binary_path ("gnunet-helper-nat-server");
  if (GNUNET_YES !=
      GNUNET_OS_check_helper_binary (binary,
                                     GNUNET_YES,
                                     ia))
  {
    /* move instantly to max delay, as this is unlikely to be fixed */
    h->server_retry_delay
      = GNUNET_TIME_STD_EXPONENTIAL_BACKOFF_THRESHOLD;
    GNUNET_free (binary);
    try_again (h);
    return;
  }
  h->server_stdout
    = GNUNET_DISK_pipe (GNUNET_YES, GNUNET_YES,
			GNUNET_NO, GNUNET_YES);
  if (NULL == h->server_stdout)
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR,
			 "pipe");
    GNUNET_free (binary);
    try_again (h);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Starting `%s' at `%s'\n",
	      "gnunet-helper-nat-server",
	      ia);
  h->server_proc
    = GNUNET_OS_start_process (GNUNET_NO,
			       0,
			       NULL,
			       h->server_stdout,
			       NULL,
			       binary,
			       "gnunet-helper-nat-server",
			       ia,
			       NULL);
  GNUNET_free (binary);
  if (NULL == h->server_proc)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		_("Failed to start %s\n"),
		"gnunet-helper-nat-server");
    GNUNET_DISK_pipe_close (h->server_stdout);
    h->server_stdout = NULL;
    try_again (h);
    return;
  }
  /* Close the write end of the read pipe */
  GNUNET_DISK_pipe_close_end (h->server_stdout,
			      GNUNET_DISK_PIPE_END_WRITE);
  h->server_stdout_handle
    = GNUNET_DISK_pipe_handle (h->server_stdout,
			       GNUNET_DISK_PIPE_END_READ);
  h->server_read_task
    = GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL,
				      h->server_stdout_handle,
				      &nat_server_read,
				      h);
}


/**
 * Start the gnunet-helper-nat-server and process incoming
 * requests.
 *
 * @param internal_address
 * @param cb function to call if we receive a request
 * @param cb_cls closure for @a cb
 * @return NULL on error
 */
struct HelperContext *
GN_start_gnunet_nat_server_ (const struct in_addr *internal_address,
			     GN_ReversalCallback cb,
			     void *cb_cls)
{
  struct HelperContext *h;

  h = GNUNET_new (struct HelperContext);
  h->cb = cb;
  h->cb_cls = cb_cls;
  h->internal_address = *internal_address;
  restart_nat_server (h);
  if (NULL == h->server_stdout)
  {
    GN_stop_gnunet_nat_server_ (h);
    return NULL;
  }
  return h;
}


/**
 * Start the gnunet-helper-nat-server and process incoming
 * requests.
 *
 * @param h helper context to stop
 */
void
GN_stop_gnunet_nat_server_ (struct HelperContext *h)
{
  if (NULL != h->server_read_task)
  {
    GNUNET_SCHEDULER_cancel (h->server_read_task);
    h->server_read_task = NULL;
  }
  if (NULL != h->server_proc)
  {
    if (0 != GNUNET_OS_process_kill (h->server_proc,
                                     GNUNET_TERM_SIG))
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING,
			   "kill");
    GNUNET_OS_process_wait (h->server_proc);
    GNUNET_OS_process_destroy (h->server_proc);
    h->server_proc = NULL;
    GNUNET_DISK_pipe_close (h->server_stdout);
    h->server_stdout = NULL;
    h->server_stdout_handle = NULL;
  }
  if (NULL != h->server_stdout)
  {
    GNUNET_DISK_pipe_close (h->server_stdout);
    h->server_stdout = NULL;
    h->server_stdout_handle = NULL;
  }
  GNUNET_free (h);
}


/**
 * We want to connect to a peer that is behind NAT.  Run the
 * gnunet-helper-nat-client to send dummy ICMP responses to cause
 * that peer to connect to us (connection reversal).
 *
 * @param internal_address out internal address to use
 * @param internal_port port to use
 * @param remote_v4 the address of the peer (IPv4-only)
 * @return #GNUNET_SYSERR on error,
 *         #GNUNET_OK otherwise
 */
int
GN_request_connection_reversal (const struct in_addr *internal_address,
				uint16_t internal_port,
				const struct in_addr *remote_v4)
{
  char intv4[INET_ADDRSTRLEN];
  char remv4[INET_ADDRSTRLEN];
  char port_as_string[6];
  struct GNUNET_OS_Process *proc;
  char *binary;

  if (NULL == inet_ntop (AF_INET,
			 internal_address,
			 intv4,
			 INET_ADDRSTRLEN))
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING,
			 "inet_ntop");
    return GNUNET_SYSERR;
  }
  if (NULL == inet_ntop (AF_INET,
			 remote_v4,
			 remv4,
			 INET_ADDRSTRLEN))
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING,
			 "inet_ntop");
    return GNUNET_SYSERR;
  }
  GNUNET_snprintf (port_as_string,
                   sizeof (port_as_string),
                   "%d",
                   internal_port);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Running gnunet-helper-nat-client %s %s %u\n",
	      intv4,
	      remv4,
	      internal_port);
  binary
    = GNUNET_OS_get_libexec_binary_path ("gnunet-helper-nat-client");
  proc
    = GNUNET_OS_start_process (GNUNET_NO,
			       0,
			       NULL,
			       NULL,
			       NULL,
                               binary,
                               "gnunet-helper-nat-client",
                               intv4,
                               remv4,
			       port_as_string,
			       NULL);
  GNUNET_free (binary);
  if (NULL == proc)
    return GNUNET_SYSERR;
  /* we know that the gnunet-helper-nat-client will terminate virtually
   * instantly */
  GNUNET_OS_process_wait (proc);
  GNUNET_OS_process_destroy (proc);
  return GNUNET_OK;
}


/* end of gnunet-service-nat_helper.c */
