/*
     This file is part of GNUnet.
     (C) 2009, 2010, 2011 Christian Grothoff (and other contributing authors)

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
 * @file arm/gnunet-service-arm.c
 * @brief the automated restart manager service
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_arm_service.h"
#include "gnunet_protocols.h"
#include "arm.h"

/**
 * Threshold after which exponential backoff shouldn't increase (in ms); 30m
 */
#define EXPONENTIAL_BACKOFF_THRESHOLD GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 30)


/**
 * List of our services.
 */
struct ServiceList;


/**
 * Record with information about a listen socket we have open.
 */
struct ServiceListeningInfo
{
  /**
   * This is a linked list.
   */
  struct ServiceListeningInfo *next;

  /**
   * This is a linked list.
   */
  struct ServiceListeningInfo *prev;

  /**
   * Address this socket is listening on.
   */
  struct sockaddr *service_addr;

  /**
   * Service this listen socket is for.
   */
  struct ServiceList *sl;

  /**
   * Number of bytes in 'service_addr'
   */
  socklen_t service_addr_len;

  /**
   * Our listening socket.
   */
  struct GNUNET_NETWORK_Handle *listen_socket;

  /**
   * Task doing the accepting.
   */
  GNUNET_SCHEDULER_TaskIdentifier accept_task;

};


/**
 * List of our services.
 */
struct ServiceList
{
  /**
   * This is a doubly-linked list.
   */
  struct ServiceList *next;

  /**
   * This is a doubly-linked list.
   */
  struct ServiceList *prev;

  /**
   * Linked list of listen sockets associated with this service.
   */
  struct ServiceListeningInfo *listen_head;

  /**
   * Linked list of listen sockets associated with this service.
   */
  struct ServiceListeningInfo *listen_tail;

  /**
   * Name of the service.
   */
  char *name;

  /**
   * Name of the binary used.
   */
  char *binary;

  /**
   * Name of the configuration file used.
   */
  char *config;

  /**
   * Client to notify upon kill completion (waitpid), NULL
   * if we should simply restart the process.
   */
  struct GNUNET_SERVER_Client *killing_client;

  /**
   * Process structure pointer of the child.
   */
  struct GNUNET_OS_Process *proc;

  /**
   * Process exponential backoff time
   */
  struct GNUNET_TIME_Relative backoff;

  /**
   * Absolute time at which the process is scheduled to restart in case of death
   */
  struct GNUNET_TIME_Absolute restart_at;

  /**
   * Is this service to be started by default (or did a client tell us explicitly
   * to start it)?  GNUNET_NO if the service is started only upon 'accept' on a
   * listen socket or possibly explicitly by a client changing the value.
   */
  int is_default;

  /**
   * Should we use pipes to signal this process? (YES for Java binaries and if we
   * are on Windoze).
   */
  int pipe_control;
};

/**
 * List of running services.
 */
static struct ServiceList *running_head;

/**
 * List of running services.
 */
static struct ServiceList *running_tail;

/**
 * Our configuration
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Command to prepend to each actual command.
 */
static char *prefix_command;

/**
 * Option to append to each actual command.
 */
static char *final_option;

/**
 * ID of task called whenever we get a SIGCHILD.
 */
static GNUNET_SCHEDULER_TaskIdentifier child_death_task;

/**
 * ID of task called whenever the timeout for restarting a child
 * expires.
 */
static GNUNET_SCHEDULER_TaskIdentifier child_restart_task;

/**
 * Pipe used to communicate shutdown via signal.
 */
static struct GNUNET_DISK_PipeHandle *sigpipe;

/**
 * Are we in shutdown mode?
 */
static int in_shutdown;

/**
 * Handle to our server instance.  Our server is a bit special in that
 * its service is not immediately stopped once we get a shutdown
 * request (since we need to continue service until all of our child
 * processes are dead).  This handle is used to shut down the server
 * (and thus trigger process termination) once all child processes are
 * also dead.  A special option in the ARM configuration modifies the
 * behaviour of the service implementation to not do the shutdown
 * immediately.
 */
static struct GNUNET_SERVER_Handle *server;


#include "do_start_process.c"


/**
 * Actually start the process for the given service.
 *
 * @param sl identifies service to start
 */
static void
start_process (struct ServiceList *sl)
{
  char *loprefix;
  char *options;
  char *optpos;
  char *optend;
  const char *next;
  int use_debug;
  char b;
  char *val;
  struct ServiceListeningInfo *sli;
  SOCKTYPE *lsocks;
  unsigned int ls;

  /* calculate listen socket list */
  lsocks = NULL;
  ls = 0;
  for (sli = sl->listen_head; NULL != sli; sli = sli->next)
    {
      GNUNET_array_append (lsocks, ls,
			   GNUNET_NETWORK_get_fd (sli->listen_socket));
      if (sli->accept_task != GNUNET_SCHEDULER_NO_TASK)
	{
	  GNUNET_SCHEDULER_cancel (sli->accept_task);
	  sli->accept_task = GNUNET_SCHEDULER_NO_TASK;
	}
    }
#if WINDOWS
  GNUNET_array_append (lsocks, ls, INVALID_SOCKET);
#else
  GNUNET_array_append (lsocks, ls, -1);
#endif

  /* obtain configuration */
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg, sl->name, "PREFIX",
					     &loprefix))
    loprefix = GNUNET_strdup (prefix_command);
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg, sl->name, "OPTIONS",
					     &options))
    {
      options = GNUNET_strdup (final_option);
      if (NULL == strstr (options, "%"))
	{
	  /* replace '{}' with service name */
	  while (NULL != (optpos = strstr (options, "{}")))
	    {
	      optpos[0] = '%';
	      optpos[1] = 's';
	      GNUNET_asprintf (&optpos, options, sl->name);
	      GNUNET_free (options);
	      options = optpos;
	    }
	  /* replace '$PATH' with value associated with "PATH" */
	  while (NULL != (optpos = strstr (options, "$")))
	    {
	      optend = optpos + 1;
	      while (isupper ((unsigned char) *optend))
		optend++;
	      b = *optend;
	      if ('\0' == b)
		next = "";
	      else
		next = optend + 1;
	      *optend = '\0';
	      if (GNUNET_OK !=
		  GNUNET_CONFIGURATION_get_value_string (cfg, "PATHS",
							 optpos + 1, &val))
		val = GNUNET_strdup ("");
	      *optpos = '\0';
	      GNUNET_asprintf (&optpos, "%s%s%c%s", options, val, b, next);
	      GNUNET_free (options);
	      GNUNET_free (val);
	      options = optpos;
	    }
	}
    }
  use_debug = GNUNET_CONFIGURATION_get_value_yesno (cfg, sl->name, "DEBUG");

  /* actually start process */
#if DEBUG_ARM
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Starting service `%s' using binary `%s' and configuration `%s'\n",
	      sl->name, sl->binary, sl->config);
#endif
  GNUNET_assert (NULL == sl->proc);
  if (GNUNET_YES == use_debug)
    sl->proc =
      do_start_process (sl->pipe_control,
			lsocks, loprefix, sl->binary, "-c", sl->config, "-L",
			"DEBUG", options, NULL);
  else
    sl->proc =
      do_start_process (sl->pipe_control,
			lsocks, loprefix, sl->binary, "-c", sl->config,
			options, NULL);
  if (sl->proc == NULL)
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("Failed to start service `%s'\n"),
		sl->name);
  else
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Starting service `%s'\n"),
		sl->name);
  /* clean up */
  GNUNET_free (loprefix);
  GNUNET_free (options);
  GNUNET_array_grow (lsocks, ls, 0);
}


/**
 * Transmit a status result message.
 *
 * @param cls pointer to "unit16_t*" with message type
 * @param size number of bytes available in buf
 * @param buf where to copy the message, NULL on error
 * @return number of bytes copied to buf
 */
static size_t
write_result (void *cls, size_t size, void *buf)
{
  enum GNUNET_ARM_ProcessStatus *res = cls;
  struct GNUNET_ARM_ResultMessage *msg;

  if (buf == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		_("Could not send status result to client\n"));
    return 0;			/* error, not much we can do */
  }
#if DEBUG_ARM
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Sending status response %u to client\n", (unsigned int) *res);
#endif
  GNUNET_assert (size >= sizeof (struct GNUNET_ARM_ResultMessage));
  msg = buf;
  msg->header.size = htons (sizeof (struct GNUNET_ARM_ResultMessage));
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_ARM_RESULT);
  msg->status = htonl ((uint32_t) (*res));
  GNUNET_free (res);
  return sizeof (struct GNUNET_ARM_ResultMessage);
}


/**
 * Signal our client that we will start or stop the
 * service.
 *
 * @param client who is being signalled
 * @param name name of the service
 * @param result message type to send
 * @return NULL if it was not found
 */
static void
signal_result (struct GNUNET_SERVER_Client *client, const char *name,
	       enum GNUNET_ARM_ProcessStatus result)
{
  enum GNUNET_ARM_ProcessStatus *res;

  if (NULL == client)
    return;
  /* FIXME: this is not super-clean yet... */
  res = GNUNET_malloc (sizeof (enum GNUNET_ARM_ProcessStatus));
  *res = result;
  GNUNET_SERVER_notify_transmit_ready (client,
				       sizeof (struct
					       GNUNET_ARM_ResultMessage),
				       GNUNET_TIME_UNIT_FOREVER_REL,
				       &write_result, res);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Find the process with the given service
 * name in the given list and return it.
 *
 * @param name which service entry to look up
 * @return NULL if it was not found
 */
static struct ServiceList *
find_service (const char *name)
{
  struct ServiceList *sl;

  sl = running_head;
  while (sl != NULL)
    {
      if (0 == strcasecmp (sl->name, name))
	return sl;
      sl = sl->next;
    }
  return NULL;
}


/**
 * First connection has come to the listening socket associated with the service,
 * create the service in order to relay the incoming connection to it
 *
 * @param cls callback data, struct ServiceListeningInfo describing a listen socket
 * @param tc context
 */
static void
accept_connection (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ServiceListeningInfo *sli = cls;
  struct ServiceList *sl = sli->sl;

  sli->accept_task = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (GNUNET_SCHEDULER_REASON_SHUTDOWN & tc->reason))
    return;
  start_process (sl);
}


/**
 * Creating a listening socket for each of the service's addresses and
 * wait for the first incoming connection to it
 *
 * @param sa address associated with the service
 * @param addr_len length of sa
 * @param sl service entry for the service in question
 */
static void
create_listen_socket (struct sockaddr *sa, socklen_t addr_len,
		      struct ServiceList *sl)
{
  const static int on = 1;
  struct GNUNET_NETWORK_Handle *sock;
  struct ServiceListeningInfo *sli;

  switch (sa->sa_family)
    {
    case AF_INET:
      sock = GNUNET_NETWORK_socket_create (PF_INET, SOCK_STREAM, 0);
      break;
    case AF_INET6:
      sock = GNUNET_NETWORK_socket_create (PF_INET6, SOCK_STREAM, 0);
      break;
    case AF_UNIX:
      if (strcmp (GNUNET_a2s (sa, addr_len), "@") == 0)	/* Do not bind to blank UNIX path! */
	return;
      sock = GNUNET_NETWORK_socket_create (PF_UNIX, SOCK_STREAM, 0);
      break;
    default:
      GNUNET_break (0);
      sock = NULL;
      errno = EAFNOSUPPORT;
      break;
    }
  if (NULL == sock)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Unable to create socket for service `%s': %s\n"),
		  sl->name, STRERROR (errno));
      GNUNET_free (sa);
      return;
    }
  if (GNUNET_NETWORK_socket_setsockopt
      (sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof (on)) != GNUNET_OK)
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
			 "setsockopt");
#ifdef IPV6_V6ONLY
  if ((sa->sa_family == AF_INET6) &&
      (GNUNET_NETWORK_socket_setsockopt
       (sock, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof (on)) != GNUNET_OK))
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
			 "setsockopt");
#endif

  if (GNUNET_NETWORK_socket_bind
      (sock, (const struct sockaddr *) sa, addr_len) != GNUNET_OK)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  _
		  ("Unable to bind listening socket for service `%s' to address `%s': %s\n"),
		  sl->name, GNUNET_a2s (sa, addr_len), STRERROR (errno));
      GNUNET_break (GNUNET_OK == GNUNET_NETWORK_socket_close (sock));
      GNUNET_free (sa);
      return;
    }
  if (GNUNET_NETWORK_socket_listen (sock, 5) != GNUNET_OK)
    {
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "listen");
      GNUNET_break (GNUNET_OK == GNUNET_NETWORK_socket_close (sock));
      GNUNET_free (sa);
      return;
    }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
	      _("ARM now monitors connections to service `%s' at `%s'\n"),
	      sl->name, GNUNET_a2s (sa, addr_len));
  sli = GNUNET_malloc (sizeof (struct ServiceListeningInfo));
  sli->service_addr = sa;
  sli->service_addr_len = addr_len;
  sli->listen_socket = sock;
  sli->sl = sl;
  sli->accept_task =
    GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL, sock,
				   &accept_connection, sli);
  GNUNET_CONTAINER_DLL_insert (sl->listen_head, sl->listen_tail, sli);
}


/**
 * Remove and free an entry in the service list.  Listen sockets
 * must have already been cleaned up.  Only to be called during shutdown.
 *
 * @param sl entry to free
 */
static void
free_service (struct ServiceList *sl)
{
  GNUNET_assert (GNUNET_YES == in_shutdown);
  GNUNET_CONTAINER_DLL_remove (running_head, running_tail, sl);
  GNUNET_assert (NULL == sl->listen_head);
  GNUNET_free_non_null (sl->config);
  GNUNET_free_non_null (sl->binary);
  GNUNET_free (sl->name);
  GNUNET_free (sl);
}


/**
 * Handle START-message.
 *
 * @param cls closure (always NULL)
 * @param client identification of the client
 * @param message the actual message
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static void
handle_start (void *cls, struct GNUNET_SERVER_Client *client,
	      const struct GNUNET_MessageHeader *message)
{
  const char *servicename;
  struct ServiceList *sl;
  uint16_t size;

  size = ntohs (message->size);
  size -= sizeof (struct GNUNET_MessageHeader);
  servicename = (const char *) &message[1];
  if ((size == 0) || (servicename[size - 1] != '\0'))
    {
      GNUNET_break (0);
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }
  if (GNUNET_YES == in_shutdown)
    {
      signal_result (client, servicename, GNUNET_ARM_PROCESS_SHUTDOWN);
      return;
    }
  sl = find_service (servicename);
  if (NULL == sl)
    {
      signal_result (client, servicename, GNUNET_ARM_PROCESS_UNKNOWN);
      return;
    }
  sl->is_default = GNUNET_YES;
  if (sl->proc != NULL)
    {
      signal_result (client, servicename, GNUNET_ARM_PROCESS_ALREADY_RUNNING);
      return;
    }
  start_process (sl);
  signal_result (client, servicename, GNUNET_ARM_PROCESS_STARTING);
}


/**
 * Handle STOP-message.
 *
 * @param cls closure (always NULL)
 * @param client identification of the client
 * @param message the actual message
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static void
handle_stop (void *cls, struct GNUNET_SERVER_Client *client,
	     const struct GNUNET_MessageHeader *message)
{
  struct ServiceList *sl;
  const char *servicename;
  uint16_t size;

  size = ntohs (message->size);
  size -= sizeof (struct GNUNET_MessageHeader);
  servicename = (const char *) &message[1];
  if ((size == 0) || (servicename[size - 1] != '\0'))
    {
      GNUNET_break (0);
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
	      _("Preparing to stop `%s'\n"), servicename);
  sl = find_service (servicename);
  if (sl == NULL)
    {
      signal_result (client, servicename, GNUNET_ARM_PROCESS_UNKNOWN);
      return;
    }
  sl->is_default = GNUNET_NO;
  if (GNUNET_YES == in_shutdown)
    {
      /* shutdown in progress */
      signal_result (client, servicename, GNUNET_ARM_PROCESS_SHUTDOWN);
      return;
    }
  if (sl->killing_client != NULL)
    {
      /* killing already in progress */
      signal_result (client, servicename,
		     GNUNET_ARM_PROCESS_ALREADY_STOPPING);
      return;
    }
  if (sl->proc == NULL)
    {
      /* process is down */
      signal_result (client, servicename, GNUNET_ARM_PROCESS_ALREADY_DOWN);
      return;
    }
#if DEBUG_ARM
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Sending kill signal to service `%s', waiting for process to die.\n",
	      servicename);
#endif
  if (0 != GNUNET_OS_process_kill (sl->proc, SIGTERM))
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "kill");
  sl->killing_client = client;
  GNUNET_SERVER_client_keep (client);
}


/**
 * We are done with everything.  Stop remaining
 * tasks, signal handler and the server.
 */
static void
do_shutdown ()
{
  if (NULL != server)
    {
      GNUNET_SERVER_destroy (server);
      server = NULL;
    }
  if (GNUNET_SCHEDULER_NO_TASK != child_death_task)
    {
      GNUNET_SCHEDULER_cancel (child_death_task);
      child_death_task = GNUNET_SCHEDULER_NO_TASK;
    }
}


/**
 * Task run for shutdown.
 *
 * @param cls closure, NULL if we need to self-restart
 * @param tc context
 */
static void
shutdown_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ServiceList *pos;
  struct ServiceList *nxt;
  struct ServiceListeningInfo *sli;

  if (GNUNET_SCHEDULER_NO_TASK != child_restart_task)
    {
      GNUNET_SCHEDULER_cancel (child_restart_task);
      child_restart_task = GNUNET_SCHEDULER_NO_TASK;
    }
  in_shutdown = GNUNET_YES;
  /* first, stop listening */
  for (pos = running_head; NULL != pos; pos = pos->next)
    {
      while (NULL != (sli = pos->listen_head))
	{
	  GNUNET_CONTAINER_DLL_remove (pos->listen_head,
				       pos->listen_tail, sli);
	  if (sli->accept_task != GNUNET_SCHEDULER_NO_TASK)
	    {
	      GNUNET_SCHEDULER_cancel (sli->accept_task);
	      sli->accept_task = GNUNET_SCHEDULER_NO_TASK;
	    }
	  GNUNET_break (GNUNET_OK ==
			GNUNET_NETWORK_socket_close (sli->listen_socket));
	  GNUNET_free (sli->service_addr);
	  GNUNET_free (sli);
	}
    }
  /* then, shutdown all existing service processes */
  nxt = running_head;
  while (NULL != (pos = nxt))
    {
      nxt = pos->next;
      if (pos->proc != NULL)
	{
	  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Stopping service `%s'\n",
		      pos->name);
	  if (0 != GNUNET_OS_process_kill (pos->proc, SIGTERM))
	    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "kill");
	}
      else
	{
	  free_service (pos);
	}
    }
  /* finally, should all service processes be already gone, terminate for real */
  if (running_head == NULL)
    do_shutdown ();
}


/**
 * Task run whenever it is time to restart a child that died.
 *
 * @param cls closure, always NULL
 * @param tc context
 */
static void
delayed_restart_task (void *cls,
		      const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ServiceList *sl;
  struct GNUNET_TIME_Relative lowestRestartDelay;
  struct ServiceListeningInfo *sli;

  child_restart_task = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;
  GNUNET_assert (GNUNET_NO == in_shutdown);
  lowestRestartDelay = GNUNET_TIME_UNIT_FOREVER_REL;

  /* check for services that need to be restarted due to
   * configuration changes or because the last restart failed */
  for (sl = running_head; NULL != sl; sl = sl->next)
    {
      if (sl->proc == NULL)
	{
	  /* service is currently not running */
	  if (GNUNET_TIME_absolute_get_remaining (sl->restart_at).rel_value ==
	      0)
	    {
	      /* restart is now allowed */
	      if (sl->is_default)
		{
		  /* process should run by default, start immediately */
		  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
			      _("Restarting service `%s'.\n"), sl->name);
		  start_process (sl);
		}
	      else
		{
		  /* process is run on-demand, ensure it is re-started if there is demand */
		  for (sli = sl->listen_head; NULL != sli; sli = sli->next)
		    if (GNUNET_SCHEDULER_NO_TASK == sli->accept_task)
		      {
			/* accept was actually paused, so start it again */
			sli->accept_task =
			  GNUNET_SCHEDULER_add_read_net
			  (GNUNET_TIME_UNIT_FOREVER_REL, sli->listen_socket,
			   &accept_connection, sli);
		      }
		}
	    }
	  else
	    {
	      /* update calculation for earliest time to reactivate a service */
	      lowestRestartDelay =
		GNUNET_TIME_relative_min (lowestRestartDelay,
					  GNUNET_TIME_absolute_get_remaining
					  (sl->restart_at));
	    }
	}
    }
  if (lowestRestartDelay.rel_value != GNUNET_TIME_UNIT_FOREVER_REL.rel_value)
    {
#if DEBUG_ARM
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Will restart process in %llums\n",
		  (unsigned long long) lowestRestartDelay.rel_value);
#endif
      child_restart_task =
	GNUNET_SCHEDULER_add_delayed_with_priority (lowestRestartDelay,
						    GNUNET_SCHEDULER_PRIORITY_IDLE, 
						    &delayed_restart_task, NULL);
    }
}


/**
 * Task triggered whenever we receive a SIGCHLD (child
 * process died).
 *
 * @param cls closure, NULL if we need to self-restart
 * @param tc context
 */
static void
maint_child_death (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ServiceList *pos;
  struct ServiceList *next;
  struct ServiceListeningInfo *sli;
  const char *statstr;
  int statcode;
  int ret;
  char c[16];
  enum GNUNET_OS_ProcessStatusType statusType;
  unsigned long statusCode;
  const struct GNUNET_DISK_FileHandle *pr;

  pr = GNUNET_DISK_pipe_handle (sigpipe, GNUNET_DISK_PIPE_END_READ);
  child_death_task = GNUNET_SCHEDULER_NO_TASK;
  if (0 == (tc->reason & GNUNET_SCHEDULER_REASON_READ_READY))
    {
      /* shutdown scheduled us, ignore! */
      child_death_task =
	GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL,
					pr, &maint_child_death, NULL);
      return;
    }
  /* consume the signal */
  GNUNET_break (0 < GNUNET_DISK_file_read (pr, &c, sizeof (c)));

  /* check for services that died (WAITPID) */
  next = running_head;
  while (NULL != (pos = next))
    {
      next = pos->next;

      if (pos->proc == NULL)
	{
	  if (GNUNET_YES == in_shutdown)
	    free_service (pos);
	  continue;
	}
      if ((GNUNET_SYSERR ==
	   (ret =
	    GNUNET_OS_process_status (pos->proc, &statusType, &statusCode)))
	  || ((ret == GNUNET_NO) || (statusType == GNUNET_OS_PROCESS_STOPPED)
	      || (statusType == GNUNET_OS_PROCESS_RUNNING)))
	continue;
      if (statusType == GNUNET_OS_PROCESS_EXITED)
	{
	  statstr = _( /* process termination method */ "exit");
	  statcode = statusCode;
	}
      else if (statusType == GNUNET_OS_PROCESS_SIGNALED)
	{
	  statstr = _( /* process termination method */ "signal");
	  statcode = statusCode;
	}
      else
	{
	  statstr = _( /* process termination method */ "unknown");
	  statcode = 0;
	}
      GNUNET_OS_process_close (pos->proc);
      pos->proc = NULL;
      if (NULL != pos->killing_client)
	{
	  signal_result (pos->killing_client, pos->name,
			 GNUNET_ARM_PROCESS_DOWN);
	  GNUNET_SERVER_client_drop (pos->killing_client);
	  pos->killing_client = NULL;
	  /* process can still be re-started on-demand, ensure it is re-started if there is demand */
	  for (sli = pos->listen_head; NULL != sli; sli = sli->next)
	    {
	      GNUNET_break (GNUNET_SCHEDULER_NO_TASK == sli->accept_task);
	      sli->accept_task =
		GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
					       sli->listen_socket,
					       &accept_connection, sli);
	    }
	  continue;
	}
      if (GNUNET_YES != in_shutdown)
	{
	  if ((statusType == GNUNET_OS_PROCESS_EXITED) && (statcode == 0))
	    {
	      /* process terminated normally, allow restart at any time */
	      pos->restart_at.abs_value = 0;
	    }
          else
            {
	      if (0 == (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
	        GNUNET_log (GNUNET_ERROR_TYPE_INFO,
			    _
			    ("Service `%s' terminated with status %s/%d, will restart in %llu ms\n"),
			    pos->name, statstr, statcode, pos->backoff.rel_value);
	      /* schedule restart */
	      pos->restart_at = GNUNET_TIME_relative_to_absolute (pos->backoff);
	      pos->backoff =
	        GNUNET_TIME_relative_min (EXPONENTIAL_BACKOFF_THRESHOLD,
				          GNUNET_TIME_relative_multiply
				          (pos->backoff, 2));
            }
	  if (GNUNET_SCHEDULER_NO_TASK != child_restart_task)
	    GNUNET_SCHEDULER_cancel (child_restart_task);
	  child_restart_task =
	    GNUNET_SCHEDULER_add_with_priority
	    (GNUNET_SCHEDULER_PRIORITY_IDLE, 
	     &delayed_restart_task, NULL);
	}
      else
	{
	  free_service (pos);
	}
    }
  child_death_task =
    GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL,
				    pr, &maint_child_death, NULL);
  if ((NULL == running_head) && (GNUNET_YES == in_shutdown))
    do_shutdown ();
}


/**
 * Transmit our shutdown acknowledgement to the client.
 *
 * @param cls the 'struct GNUNET_SERVER_Client'
 * @param size number of bytes available in buf
 * @param buf where to write the message
 * @return number of bytes written
 */
static size_t
transmit_shutdown_ack (void *cls, size_t size, void *buf)
{
  struct GNUNET_SERVER_Client *client = cls;
  struct GNUNET_ARM_ResultMessage *msg;

  if (size < sizeof (struct GNUNET_ARM_ResultMessage))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		  _("Failed to transmit shutdown ACK.\n"));
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return 0;			/* client disconnected */
    }
  /* Make the connection flushing for the purpose of ACK transmitting,
   * needed on W32 to ensure that the message is even received, harmless
   * on other platforms... */
  GNUNET_break (GNUNET_OK == GNUNET_SERVER_client_disable_corking (client));
  msg = (struct GNUNET_ARM_ResultMessage *) buf;
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_ARM_RESULT);
  msg->header.size = htons (sizeof (struct GNUNET_ARM_ResultMessage));
  msg->status = htonl ((uint32_t) GNUNET_ARM_PROCESS_SHUTDOWN);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
  GNUNET_SERVER_client_drop (client);
  return sizeof (struct GNUNET_ARM_ResultMessage);
}


/**
 * Handler for SHUTDOWN message.
 *
 * @param cls closure (refers to service)
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_shutdown (void *cls, struct GNUNET_SERVER_Client *client,
		 const struct GNUNET_MessageHeader *message)
{
  GNUNET_SCHEDULER_shutdown ();
  GNUNET_SERVER_client_keep (client);
  GNUNET_SERVER_notify_transmit_ready (client,
				       sizeof (struct GNUNET_ARM_ResultMessage),
				       GNUNET_TIME_UNIT_FOREVER_REL,
				       &transmit_shutdown_ack, client);
  GNUNET_SERVER_client_persist_ (client);
}


/**
 * Signal handler called for SIGCHLD.  Triggers the
 * respective handler by writing to the trigger pipe.
 */
static void
sighandler_child_death ()
{
  static char c;
  int old_errno = errno;	/* back-up errno */

  GNUNET_break (1 ==
		GNUNET_DISK_file_write (GNUNET_DISK_pipe_handle
					(sigpipe, GNUNET_DISK_PIPE_END_WRITE),
					&c, sizeof (c)));
  errno = old_errno;		/* restore errno */
}


/**
 * Setup our service record for the given section in the configuration file
 * (assuming the section is for a service).
 *
 * @param cls unused
 * @param section a section in the configuration file
 * @return GNUNET_OK (continue)
 */
static void
setup_service (void *cls, const char *section)
{
  struct ServiceList *sl;
  char *binary;
  char *config;
  struct stat sbuf;
  struct sockaddr **addrs;
  socklen_t *addr_lens;
  int ret;
  unsigned int i;

  if (strcasecmp (section, "arm") == 0)
    return;
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg, section, "BINARY", &binary))
    {
      /* not a service section */
      return;
    }
  sl = find_service (section);
  if (NULL != sl)
  {
    /* got the same section twice!? */
    GNUNET_break (0);
    return;
  }
  config = NULL;
  if ((GNUNET_OK !=
       GNUNET_CONFIGURATION_get_value_filename (cfg, section, "CONFIG",
						&config)) ||
      (0 != STAT (config, &sbuf)))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  _
		  ("Configuration file `%s' for service `%s' not valid: %s\n"),
		  config, section,
		  (config == NULL) ? _("option missing") : STRERROR (errno));
      GNUNET_free (binary);
      GNUNET_free_non_null (config);
      return;
    }
  sl = GNUNET_malloc (sizeof (struct ServiceList));
  sl->name = GNUNET_strdup (section);
  sl->binary = binary;
  sl->config = config;
  sl->backoff = GNUNET_TIME_UNIT_MILLISECONDS;
  sl->restart_at = GNUNET_TIME_UNIT_FOREVER_ABS;
#if WINDOWS
  sl->pipe_control = GNUNET_YES;
#else
  if (GNUNET_CONFIGURATION_have_value (cfg, section, "PIPECONTROL"))
    sl->pipe_control = GNUNET_CONFIGURATION_get_value_yesno (cfg, section, "PIPECONTROL");
#endif  
  GNUNET_CONTAINER_DLL_insert (running_head, running_tail, sl);
  if (GNUNET_YES !=
      GNUNET_CONFIGURATION_get_value_yesno (cfg, section, "AUTOSTART"))
    return;
  if (0 >= (ret = GNUNET_SERVICE_get_server_addresses (section, cfg,
						       &addrs, &addr_lens)))
    return;
  /* this will free (or capture) addrs[i] */
  for (i = 0; i < ret; i++)
    create_listen_socket (addrs[i], addr_lens[i], sl);
  GNUNET_free (addrs);
  GNUNET_free (addr_lens);
}


/**
 * Process arm requests.
 *
 * @param cls closure
 * @param serv the initialized server
 * @param c configuration to use
 */
static void
run (void *cls, struct GNUNET_SERVER_Handle *serv,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  static const struct GNUNET_SERVER_MessageHandler handlers[] = {
    {&handle_start, NULL, GNUNET_MESSAGE_TYPE_ARM_START, 0},
    {&handle_stop, NULL, GNUNET_MESSAGE_TYPE_ARM_STOP, 0},
    {&handle_shutdown, NULL, GNUNET_MESSAGE_TYPE_ARM_SHUTDOWN,
     sizeof (struct GNUNET_MessageHeader)},
    {NULL, NULL, 0, 0}
  };
  char *defaultservices;
  const char *pos;
  struct ServiceList *sl;

  cfg = c;
  server = serv;
  GNUNET_assert (serv != NULL);
  GNUNET_SERVER_ignore_shutdown (serv, GNUNET_YES);
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &shutdown_task,
				NULL);
  child_death_task =
    GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL,
				    GNUNET_DISK_pipe_handle (sigpipe,
							     GNUNET_DISK_PIPE_END_READ),
				    &maint_child_death, NULL);

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg, "ARM", "GLOBAL_PREFIX",
					     &prefix_command))
    prefix_command = GNUNET_strdup ("");
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg, "ARM", "GLOBAL_POSTFIX",
					     &final_option))
    final_option = GNUNET_strdup ("");

  GNUNET_CONFIGURATION_iterate_sections (cfg, &setup_service, NULL);

  /* start default services... */
  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_get_value_string (cfg, "ARM", "DEFAULTSERVICES",
					     &defaultservices))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		  _("Starting default services `%s'\n"), defaultservices);
      if (0 < strlen (defaultservices))
	{
	  for (pos = strtok (defaultservices, " "); NULL != pos;
	       pos = strtok (NULL, " "))
	    {
	      sl = find_service (pos);
	      if (NULL == sl)
		{
		  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
			      _
			      ("Default service `%s' not configured correctly!\n"),
			      pos);
		  continue;
		}
	      sl->is_default = GNUNET_YES;
	      start_process (sl);
	    }
	}
      GNUNET_free (defaultservices);
    }
  else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		  _
		  ("No default services configured, GNUnet will not really start right now.\n"));
    }

  /* process client requests */
  GNUNET_SERVER_add_handlers (server, handlers);
}


/**
 * The main function for the arm service.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  int ret;
  struct GNUNET_SIGNAL_Context *shc_chld;

  sigpipe = GNUNET_DISK_pipe (GNUNET_NO, GNUNET_NO, GNUNET_NO, GNUNET_NO);
  GNUNET_assert (sigpipe != NULL);
  shc_chld =
    GNUNET_SIGNAL_handler_install (GNUNET_SIGCHLD, &sighandler_child_death);
  ret =
    (GNUNET_OK ==
     GNUNET_SERVICE_run (argc, argv, "arm", GNUNET_YES, &run, NULL)) ? 0 : 1;
  GNUNET_SIGNAL_handler_uninstall (shc_chld);
  shc_chld = NULL;
  GNUNET_DISK_pipe_close (sigpipe);
  sigpipe = NULL;
  return ret;
}


#ifdef LINUX
#include <malloc.h>

/**
 * MINIMIZE heap size (way below 128k) since this process doesn't need much.
 */
void __attribute__ ((constructor)) GNUNET_ARM_memory_init ()
{
  mallopt (M_TRIM_THRESHOLD, 4 * 1024);
  mallopt (M_TOP_PAD, 1 * 1024);
  malloc_trim (0);
}
#endif


/* end of gnunet-service-arm.c */
