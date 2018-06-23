/*
     This file is part of GNUnet.
     Copyright (C) 2009-2011, 2015, 2016 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.
    
     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.
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

#define LOG(kind,...) GNUNET_log_from (kind, "util", __VA_ARGS__)

#define LOG_STRERROR(kind,syscall) GNUNET_log_from_strerror (kind, "util", syscall)


#if HAVE_WAIT4
/**
 * Name of the file for writing resource utilization summaries to.
 */
static char *wait_filename;

/**
 * Handle for the file for writing resource summaries.
 */
static FILE *wait_file;
#endif


/**
 * How many messages do we queue up at most for optional
 * notifications to a client?  (this can cause notifications
 * about outgoing messages to be dropped).
 */
#define MAX_NOTIFY_QUEUE 1024


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
   * Number of bytes in @e service_addr
   */
  socklen_t service_addr_len;

  /**
   * Our listening socket.
   */
  struct GNUNET_NETWORK_Handle *listen_socket;

  /**
   * Task doing the accepting.
   */
  struct GNUNET_SCHEDULER_Task *accept_task;

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
  struct GNUNET_SERVICE_Client *killing_client;

  /**
   * ID of the request that killed the service (for reporting back).
   */
  uint64_t killing_client_request_id;

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
   * Time we asked the service to shut down (used to calculate time it took
   * the service to terminate).
   */
  struct GNUNET_TIME_Absolute killed_at;

  /**
   * Is this service to be started by default (or did a client tell us explicitly
   * to start it)?  #GNUNET_NO if the service is started only upon 'accept' on a
   * listen socket or possibly explicitly by a client changing the value.
   */
  int force_start;

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
static struct GNUNET_SCHEDULER_Task *child_death_task;

/**
 * ID of task called whenever the timeout for restarting a child
 * expires.
 */
static struct GNUNET_SCHEDULER_Task *child_restart_task;

/**
 * Pipe used to communicate shutdown via signal.
 */
static struct GNUNET_DISK_PipeHandle *sigpipe;

/**
 * Are we in shutdown mode?
 */
static int in_shutdown;

/**
 * Return value from main
 */
static int global_ret;

/**
 * Are we starting user services?
 */
static int start_user = GNUNET_YES;

/**
 * Are we starting system services?
 */
static int start_system = GNUNET_YES;

/**
 * Handle to our service instance.  Our service is a bit special in that
 * its service is not immediately stopped once we get a shutdown
 * request (since we need to continue service until all of our child
 * processes are dead).  This handle is used to shut down the service
 * (and thus trigger process termination) once all child processes are
 * also dead.  A special option in the ARM configuration modifies the
 * behaviour of the service implementation to not do the shutdown
 * immediately.
 */
static struct GNUNET_SERVICE_Handle *service;

/**
 * Context for notifications we need to send to our clients.
 */
static struct GNUNET_NotificationContext *notifier;


/**
 * Add the given UNIX domain path as an address to the
 * list (as the first entry).
 *
 * @param saddrs array to update
 * @param saddrlens where to store the address length
 * @param unixpath path to add
 * @param abstract #GNUNET_YES to add an abstract UNIX domain socket.  This
 *          parameter is ignore on systems other than LINUX
 */
static void
add_unixpath (struct sockaddr **saddrs,
              socklen_t *saddrlens,
              const char *unixpath,
              int abstract)
{
#ifdef AF_UNIX
  struct sockaddr_un *un;

  un = GNUNET_new (struct sockaddr_un);
  un->sun_family = AF_UNIX;
  strncpy (un->sun_path, unixpath, sizeof (un->sun_path) - 1);
#ifdef LINUX
  if (GNUNET_YES == abstract)
    un->sun_path[0] = '\0';
#endif
#if HAVE_SOCKADDR_UN_SUN_LEN
  un->sun_len = (u_char) sizeof (struct sockaddr_un);
#endif
  *saddrs = (struct sockaddr *) un;
  *saddrlens = sizeof (struct sockaddr_un);
#else
  /* this function should never be called
   * unless AF_UNIX is defined! */
  GNUNET_assert (0);
#endif
}


/**
 * Get the list of addresses that a server for the given service
 * should bind to.
 *
 * @param service_name name of the service
 * @param cfg configuration (which specifies the addresses)
 * @param addrs set (call by reference) to an array of pointers to the
 *              addresses the server should bind to and listen on; the
 *              array will be NULL-terminated (on success)
 * @param addr_lens set (call by reference) to an array of the lengths
 *              of the respective `struct sockaddr` struct in the @a addrs
 *              array (on success)
 * @return number of addresses found on success,
 *              #GNUNET_SYSERR if the configuration
 *              did not specify reasonable finding information or
 *              if it specified a hostname that could not be resolved;
 *              #GNUNET_NO if the number of addresses configured is
 *              zero (in this case, `*addrs` and `*addr_lens` will be
 *              set to NULL).
 */
static int
get_server_addresses (const char *service_name,
		      const struct GNUNET_CONFIGURATION_Handle *cfg,
		      struct sockaddr ***addrs,
		      socklen_t ** addr_lens)
{
  int disablev6;
  struct GNUNET_NETWORK_Handle *desc;
  unsigned long long port;
  char *unixpath;
  struct addrinfo hints;
  struct addrinfo *res;
  struct addrinfo *pos;
  struct addrinfo *next;
  unsigned int i;
  int resi;
  int ret;
  int abstract;
  struct sockaddr **saddrs;
  socklen_t *saddrlens;
  char *hostname;

  *addrs = NULL;
  *addr_lens = NULL;
  desc = NULL;
  if (GNUNET_CONFIGURATION_have_value (cfg,
				       service_name,
				       "DISABLEV6"))
  {
    if (GNUNET_SYSERR ==
        (disablev6 =
         GNUNET_CONFIGURATION_get_value_yesno (cfg,
					       service_name,
					       "DISABLEV6")))
      return GNUNET_SYSERR;
  }
  else
    disablev6 = GNUNET_NO;

  if (! disablev6)
  {
    /* probe IPv6 support */
    desc = GNUNET_NETWORK_socket_create (PF_INET6,
					 SOCK_STREAM,
					 0);
    if (NULL == desc)
    {
      if ( (ENOBUFS == errno) ||
	   (ENOMEM == errno) ||
	   (ENFILE == errno) ||
	   (EACCES == errno) )
      {
        LOG_STRERROR (GNUNET_ERROR_TYPE_ERROR,
		      "socket");
        return GNUNET_SYSERR;
      }
      LOG (GNUNET_ERROR_TYPE_INFO,
           _("Disabling IPv6 support for service `%s', failed to create IPv6 socket: %s\n"),
           service_name,
	   STRERROR (errno));
      disablev6 = GNUNET_YES;
    }
    else
    {
      GNUNET_break (GNUNET_OK == GNUNET_NETWORK_socket_close (desc));
      desc = NULL;
    }
  }

  port = 0;
  if (GNUNET_CONFIGURATION_have_value (cfg,
				       service_name,
				       "PORT"))
  {
    if (GNUNET_OK !=
	GNUNET_CONFIGURATION_get_value_number (cfg,
					       service_name,
					       "PORT",
					       &port))
    {
      LOG (GNUNET_ERROR_TYPE_ERROR,
           _("Require valid port number for service `%s' in configuration!\n"),
           service_name);
    }
    if (port > 65535)
    {
      LOG (GNUNET_ERROR_TYPE_ERROR,
           _("Require valid port number for service `%s' in configuration!\n"),
           service_name);
      return GNUNET_SYSERR;
    }
  }

  if (GNUNET_CONFIGURATION_have_value (cfg,
				       service_name,
				       "BINDTO"))
  {
    GNUNET_break (GNUNET_OK ==
                  GNUNET_CONFIGURATION_get_value_string (cfg,
							 service_name,
                                                         "BINDTO",
							 &hostname));
  }
  else
    hostname = NULL;

  unixpath = NULL;
  abstract = GNUNET_NO;
#ifdef AF_UNIX
  if ((GNUNET_YES ==
       GNUNET_CONFIGURATION_have_value (cfg,
					service_name,
					"UNIXPATH")) &&
      (GNUNET_OK ==
       GNUNET_CONFIGURATION_get_value_filename (cfg,
						service_name,
						"UNIXPATH",
						&unixpath)) &&
      (0 < strlen (unixpath)))
  {
    /* probe UNIX support */
    struct sockaddr_un s_un;

    if (strlen (unixpath) >= sizeof (s_un.sun_path))
    {
      LOG (GNUNET_ERROR_TYPE_WARNING,
           _("UNIXPATH `%s' too long, maximum length is %llu\n"),
	   unixpath,
           (unsigned long long) sizeof (s_un.sun_path));
      unixpath = GNUNET_NETWORK_shorten_unixpath (unixpath);
      LOG (GNUNET_ERROR_TYPE_INFO,
	   _("Using `%s' instead\n"),
           unixpath);
    }
#ifdef LINUX
    abstract = GNUNET_CONFIGURATION_get_value_yesno (cfg,
                                                     "TESTING",
                                                     "USE_ABSTRACT_SOCKETS");
    if (GNUNET_SYSERR == abstract)
      abstract = GNUNET_NO;
#endif
    if ( (GNUNET_YES != abstract) &&
	 (GNUNET_OK !=
	  GNUNET_DISK_directory_create_for_file (unixpath)) ) 
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR,
				"mkdir",
				unixpath);
  }
  if (NULL != unixpath)
  {
    desc = GNUNET_NETWORK_socket_create (AF_UNIX, SOCK_STREAM, 0);
    if (NULL == desc)
    {
      if ( (ENOBUFS == errno) ||
	   (ENOMEM == errno) ||
	   (ENFILE == errno) ||
	   (EACCES == errno) )
      {
        LOG_STRERROR (GNUNET_ERROR_TYPE_ERROR, "socket");
        GNUNET_free_non_null (hostname);
        GNUNET_free (unixpath);
        return GNUNET_SYSERR;
      }
      LOG (GNUNET_ERROR_TYPE_INFO,
           _("Disabling UNIX domain socket support for service `%s', failed to create UNIX domain socket: %s\n"),
           service_name,
           STRERROR (errno));
      GNUNET_free (unixpath);
      unixpath = NULL;
    }
    else
    {
      GNUNET_break (GNUNET_OK == GNUNET_NETWORK_socket_close (desc));
      desc = NULL;
    }
  }
#endif

  if ( (0 == port) &&
       (NULL == unixpath) )
  {
    if (GNUNET_YES ==
	GNUNET_CONFIGURATION_get_value_yesno (cfg,
					      service_name,
					      "START_ON_DEMAND"))
      LOG (GNUNET_ERROR_TYPE_ERROR,
	   _("Have neither PORT nor UNIXPATH for service `%s', but one is required\n"),
	   service_name);
    GNUNET_free_non_null (hostname);
    return GNUNET_SYSERR;
  }
  if (0 == port)
  {
    saddrs = GNUNET_new_array (2,
			       struct sockaddr *);
    saddrlens = GNUNET_new_array (2,
				  socklen_t);
    add_unixpath (saddrs,
		  saddrlens,
		  unixpath,
		  abstract);
    GNUNET_free_non_null (unixpath);
    GNUNET_free_non_null (hostname);
    *addrs = saddrs;
    *addr_lens = saddrlens;
    return 1;
  }

  if (NULL != hostname)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Resolving `%s' since that is where `%s' will bind to.\n",
         hostname,
         service_name);
    memset (&hints, 0, sizeof (struct addrinfo));
    if (disablev6)
      hints.ai_family = AF_INET;
    hints.ai_protocol = IPPROTO_TCP;
    if ((0 != (ret = getaddrinfo (hostname,
				  NULL,
				  &hints,
				  &res))) ||
        (NULL == res))
    {
      LOG (GNUNET_ERROR_TYPE_ERROR,
           _("Failed to resolve `%s': %s\n"),
           hostname,
           gai_strerror (ret));
      GNUNET_free (hostname);
      GNUNET_free_non_null (unixpath);
      return GNUNET_SYSERR;
    }
    next = res;
    i = 0;
    while (NULL != (pos = next))
    {
      next = pos->ai_next;
      if ((disablev6) && (pos->ai_family == AF_INET6))
        continue;
      i++;
    }
    if (0 == i)
    {
      LOG (GNUNET_ERROR_TYPE_ERROR,
           _("Failed to find %saddress for `%s'.\n"),
           disablev6 ? "IPv4 " : "",
           hostname);
      freeaddrinfo (res);
      GNUNET_free (hostname);
      GNUNET_free_non_null (unixpath);
      return GNUNET_SYSERR;
    }
    resi = i;
    if (NULL != unixpath)
      resi++;
    saddrs = GNUNET_new_array (resi + 1,
			       struct sockaddr *);
    saddrlens = GNUNET_new_array (resi + 1,
				  socklen_t);
    i = 0;
    if (NULL != unixpath)
    {
      add_unixpath (saddrs, saddrlens, unixpath, abstract);
      i++;
    }
    next = res;
    while (NULL != (pos = next))
    {
      next = pos->ai_next;
      if ((disablev6) && (AF_INET6 == pos->ai_family))
        continue;
      if ((IPPROTO_TCP != pos->ai_protocol) && (0 != pos->ai_protocol))
        continue;               /* not TCP */
      if ((SOCK_STREAM != pos->ai_socktype) && (0 != pos->ai_socktype))
        continue;               /* huh? */
      LOG (GNUNET_ERROR_TYPE_DEBUG, "Service `%s' will bind to `%s'\n",
           service_name, GNUNET_a2s (pos->ai_addr, pos->ai_addrlen));
      if (AF_INET == pos->ai_family)
      {
        GNUNET_assert (sizeof (struct sockaddr_in) == pos->ai_addrlen);
        saddrlens[i] = pos->ai_addrlen;
        saddrs[i] = GNUNET_malloc (saddrlens[i]);
        GNUNET_memcpy (saddrs[i], pos->ai_addr, saddrlens[i]);
        ((struct sockaddr_in *) saddrs[i])->sin_port = htons (port);
      }
      else
      {
        GNUNET_assert (AF_INET6 == pos->ai_family);
        GNUNET_assert (sizeof (struct sockaddr_in6) == pos->ai_addrlen);
        saddrlens[i] = pos->ai_addrlen;
        saddrs[i] = GNUNET_malloc (saddrlens[i]);
        GNUNET_memcpy (saddrs[i], pos->ai_addr, saddrlens[i]);
        ((struct sockaddr_in6 *) saddrs[i])->sin6_port = htons (port);
      }
      i++;
    }
    GNUNET_free (hostname);
    freeaddrinfo (res);
    resi = i;
  }
  else
  {
    /* will bind against everything, just set port */
    if (disablev6)
    {
      /* V4-only */
      resi = 1;
      if (NULL != unixpath)
        resi++;
      i = 0;
      saddrs = GNUNET_new_array (resi + 1,
				 struct sockaddr *);
      saddrlens = GNUNET_new_array (resi + 1,
				    socklen_t);
      if (NULL != unixpath)
      {
        add_unixpath (saddrs, saddrlens, unixpath, abstract);
        i++;
      }
      saddrlens[i] = sizeof (struct sockaddr_in);
      saddrs[i] = GNUNET_malloc (saddrlens[i]);
#if HAVE_SOCKADDR_IN_SIN_LEN
      ((struct sockaddr_in *) saddrs[i])->sin_len = saddrlens[i];
#endif
      ((struct sockaddr_in *) saddrs[i])->sin_family = AF_INET;
      ((struct sockaddr_in *) saddrs[i])->sin_port = htons (port);
    }
    else
    {
      /* dual stack */
      resi = 2;
      if (NULL != unixpath)
        resi++;
      saddrs = GNUNET_new_array (resi + 1,
				 struct sockaddr *);
      saddrlens = GNUNET_new_array (resi + 1,
				    socklen_t);
      i = 0;
      if (NULL != unixpath)
      {
        add_unixpath (saddrs,
		      saddrlens,
		      unixpath,
		      abstract);
        i++;
      }
      saddrlens[i] = sizeof (struct sockaddr_in6);
      saddrs[i] = GNUNET_malloc (saddrlens[i]);
#if HAVE_SOCKADDR_IN_SIN_LEN
      ((struct sockaddr_in6 *) saddrs[i])->sin6_len = saddrlens[0];
#endif
      ((struct sockaddr_in6 *) saddrs[i])->sin6_family = AF_INET6;
      ((struct sockaddr_in6 *) saddrs[i])->sin6_port = htons (port);
      i++;
      saddrlens[i] = sizeof (struct sockaddr_in);
      saddrs[i] = GNUNET_malloc (saddrlens[i]);
#if HAVE_SOCKADDR_IN_SIN_LEN
      ((struct sockaddr_in *) saddrs[i])->sin_len = saddrlens[1];
#endif
      ((struct sockaddr_in *) saddrs[i])->sin_family = AF_INET;
      ((struct sockaddr_in *) saddrs[i])->sin_port = htons (port);
    }
  }
  GNUNET_free_non_null (unixpath);
  *addrs = saddrs;
  *addr_lens = saddrlens;
  return resi;
}


/**
 * Signal our client that we will start or stop the
 * service.
 *
 * @param client who is being signalled
 * @param name name of the service
 * @param request_id id of the request that is being responded to.
 * @param result message type to send
 * @return NULL if it was not found
 */
static void
signal_result (struct GNUNET_SERVICE_Client *client,
	       const char *name,
	       uint64_t request_id,
	       enum GNUNET_ARM_Result result)
{
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_ARM_ResultMessage *msg;

  (void) name;
  env = GNUNET_MQ_msg (msg,
                       GNUNET_MESSAGE_TYPE_ARM_RESULT);
  msg->result = htonl (result);
  msg->arm_msg.request_id = GNUNET_htonll (request_id);
  GNUNET_MQ_send (GNUNET_SERVICE_client_get_mq (client),
                  env);
}


/**
 * Tell all clients about status change of a service.
 *
 * @param name name of the service
 * @param status message type to send
 * @param unicast if not NULL, send to this client only.
 *                otherwise, send to all clients in the notifier
 */
static void
broadcast_status (const char *name,
		  enum GNUNET_ARM_ServiceStatus status,
		  struct GNUNET_SERVICE_Client *unicast)
{
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_ARM_StatusMessage *msg;
  size_t namelen;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending status %u of service `%s' to client\n",
              (unsigned int) status,
              name);
  namelen = strlen (name) + 1;
  env = GNUNET_MQ_msg_extra (msg,
                             namelen,
                             GNUNET_MESSAGE_TYPE_ARM_STATUS);
  msg->status = htonl ((uint32_t) (status));
  GNUNET_memcpy ((char *) &msg[1],
                 name,
                 namelen);
  if (NULL == unicast)
  {
    if (NULL != notifier)
      GNUNET_notification_context_broadcast (notifier,
                                             &msg->header,
                                             GNUNET_YES);
    GNUNET_MQ_discard (env);
  }
  else
  {
    GNUNET_MQ_send (GNUNET_SERVICE_client_get_mq (unicast),
                    env);
  }
}


/**
 * Actually start the process for the given service.
 *
 * @param sl identifies service to start
 * @param client that asked to start the service (may be NULL)
 * @param request_id id of the request in response to which the process is
 *                   being started. 0 if starting was not requested.
 */
static void
start_process (struct ServiceList *sl,
               struct GNUNET_SERVICE_Client *client,
               uint64_t request_id)
{
  char *loprefix;
  char *options;
  int use_debug;
  int is_simple_service;
  struct ServiceListeningInfo *sli;
  SOCKTYPE *lsocks;
  unsigned int ls;
  char *binary;
  char *quotedbinary;

  /* calculate listen socket list */
  lsocks = NULL;
  ls = 0;
  for (sli = sl->listen_head; NULL != sli; sli = sli->next)
    {
      GNUNET_array_append (lsocks, ls,
			   GNUNET_NETWORK_get_fd (sli->listen_socket));
      if (NULL != sli->accept_task)
	{
	  GNUNET_SCHEDULER_cancel (sli->accept_task);
	  sli->accept_task = NULL;
	}
    }
#if WINDOWS
  GNUNET_array_append (lsocks,
                       ls,
                       INVALID_SOCKET);
#else
  GNUNET_array_append (lsocks,
                       ls,
                       -1);
#endif

  /* obtain configuration */
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg,
                                             sl->name,
                                             "PREFIX",
                                             &loprefix))
    loprefix = GNUNET_strdup (prefix_command);
  else
    loprefix = GNUNET_CONFIGURATION_expand_dollar (cfg,
                                                   loprefix);
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg,
                                             sl->name,
                                             "OPTIONS",
                                             &options))
    options = NULL;
  else
    options = GNUNET_CONFIGURATION_expand_dollar (cfg,
                                                  options);
  {
    char *new_options;
    char *optpos;
    char *fin_options;

    fin_options = GNUNET_strdup (final_option);
    /* replace '{}' with service name */
    while (NULL != (optpos = strstr (fin_options,
                                     "{}")))
    {
      /* terminate string at opening parenthesis */
      *optpos = 0;
      GNUNET_asprintf (&new_options,
                       "%s%s%s",
                       fin_options,
                       sl->name,
                       optpos + 2);
      GNUNET_free (fin_options);
      fin_options = new_options;
    }
    if (NULL != options)
    {
      /* combine "fin_options" with "options" */
      optpos = options;
      GNUNET_asprintf (&options,
                       "%s %s",
                       fin_options,
                       optpos);
      GNUNET_free (fin_options);
      GNUNET_free (optpos);
    }
    else
    {
      /* only have "fin_options", use that */
      options = fin_options;
    }
  }
  options = GNUNET_CONFIGURATION_expand_dollar (cfg,
                                                options);
  use_debug = GNUNET_CONFIGURATION_get_value_yesno (cfg,
                                                    sl->name,
                                                    "DEBUG");
  {
    const char *service_type = NULL;
    const char *choices[] = { "GNUNET", "SIMPLE", NULL };

    is_simple_service = GNUNET_NO;
    if ( (GNUNET_OK ==
          GNUNET_CONFIGURATION_get_value_choice (cfg,
                                                 sl->name,
                                                 "TYPE",
                                                 choices,
                                                 &service_type)) &&
         (0 == strcasecmp (service_type, "SIMPLE")) )
      is_simple_service = GNUNET_YES;
  }

  GNUNET_assert (NULL == sl->proc);
  if (GNUNET_YES == is_simple_service)
  {
    /* A simple service will receive no GNUnet specific
       command line options. */
    binary = GNUNET_strdup (sl->binary);
    binary = GNUNET_CONFIGURATION_expand_dollar (cfg, binary);
    GNUNET_asprintf (&quotedbinary,
                     "\"%s\"",
                     sl->binary);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Starting simple service `%s' using binary `%s'\n",
                sl->name, sl->binary);
    /* FIXME: dollar expansion should only be done outside
     * of ''-quoted strings, escaping should be considered. */
    if (NULL != options)
      options = GNUNET_CONFIGURATION_expand_dollar (cfg, options);
    sl->proc =
      GNUNET_OS_start_process_s (sl->pipe_control,
                                 GNUNET_OS_INHERIT_STD_OUT_AND_ERR,
                                 lsocks,
                                 loprefix,
                                 quotedbinary,
                                 options,
                                 NULL);
  }
  else
  {
    /* actually start process */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Starting service `%s' using binary `%s' and configuration `%s'\n",
                sl->name, sl->binary, sl->config);
    binary = GNUNET_OS_get_libexec_binary_path (sl->binary);
    GNUNET_asprintf (&quotedbinary,
                     "\"%s\"",
                     binary);

    if (GNUNET_YES == use_debug)
    {
      if (NULL == sl->config)
        sl->proc =
          GNUNET_OS_start_process_s (sl->pipe_control,
                                     GNUNET_OS_INHERIT_STD_OUT_AND_ERR,
                                     lsocks,
                                     loprefix,
                                     quotedbinary,
                                     "-L", "DEBUG",
                                     options,
                                     NULL);
      else
        sl->proc =
            GNUNET_OS_start_process_s (sl->pipe_control,
                                       GNUNET_OS_INHERIT_STD_OUT_AND_ERR,
                                       lsocks,
                                       loprefix,
                                       quotedbinary,
                                       "-c", sl->config,
                                       "-L", "DEBUG",
                                       options,
                                       NULL);
    }
    else
    {
      if (NULL == sl->config)
        sl->proc =
            GNUNET_OS_start_process_s (sl->pipe_control,
                                       GNUNET_OS_INHERIT_STD_OUT_AND_ERR,
                                       lsocks,
                                       loprefix,
                                       quotedbinary,
                                       options,
                                       NULL);
      else
        sl->proc =
            GNUNET_OS_start_process_s (sl->pipe_control,
                                       GNUNET_OS_INHERIT_STD_OUT_AND_ERR,
                                       lsocks,
                                       loprefix,
                                       quotedbinary,
                                       "-c", sl->config,
                                       options,
                                       NULL);
    }
  }
  GNUNET_free (binary);
  GNUNET_free (quotedbinary);
  if (NULL == sl->proc)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Failed to start service `%s'\n"),
		sl->name);
    if (client)
      signal_result (client,
                     sl->name,
                     request_id,
                     GNUNET_ARM_RESULT_START_FAILED);
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                _("Starting service `%s'\n"),
		sl->name);
    broadcast_status (sl->name,
                      GNUNET_ARM_SERVICE_STARTING,
                      NULL);
    if (client)
      signal_result (client,
                     sl->name,
                     request_id,
                     GNUNET_ARM_RESULT_STARTING);
  }
  /* clean up */
  GNUNET_free (loprefix);
  GNUNET_free (options);
  GNUNET_array_grow (lsocks,
                     ls,
                     0);
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
 * @param cls callback data, `struct ServiceListeningInfo` describing a listen socket
 */
static void
accept_connection (void *cls)
{
  struct ServiceListeningInfo *sli = cls;
  struct ServiceList *sl = sli->sl;

  sli->accept_task = NULL;
  GNUNET_assert (GNUNET_NO == in_shutdown);
  start_process (sl, NULL, 0);
}


/**
 * Creating a listening socket for each of the service's addresses and
 * wait for the first incoming connection to it
 *
 * @param sa address associated with the service
 * @param addr_len length of @a sa
 * @param sl service entry for the service in question
 */
static void
create_listen_socket (struct sockaddr *sa,
                      socklen_t addr_len,
		      struct ServiceList *sl)
{
  static int on = 1;
  struct GNUNET_NETWORK_Handle *sock;
  struct ServiceListeningInfo *sli;
#ifndef WINDOWS
  int match_uid;
  int match_gid;
#endif

  switch (sa->sa_family)
  {
  case AF_INET:
    sock = GNUNET_NETWORK_socket_create (PF_INET,
                                         SOCK_STREAM,
                                         0);
    break;
  case AF_INET6:
    sock = GNUNET_NETWORK_socket_create (PF_INET6,
                                         SOCK_STREAM,
                                         0);
    break;
  case AF_UNIX:
    if (0 == strcmp (GNUNET_a2s (sa,
                                 addr_len),
                     "@"))	/* Do not bind to blank UNIX path! */
      return;
    sock = GNUNET_NETWORK_socket_create (PF_UNIX,
                                         SOCK_STREAM,
                                         0);
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
                sl->name,
                STRERROR (errno));
    GNUNET_free (sa);
    return;
  }
  if (GNUNET_OK !=
      GNUNET_NETWORK_socket_setsockopt (sock,
                                        SOL_SOCKET,
                                        SO_REUSEADDR,
                                        &on,
                                        sizeof (on)))
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
			 "setsockopt");
#ifdef IPV6_V6ONLY
  if ( (sa->sa_family == AF_INET6) &&
       (GNUNET_OK !=
        GNUNET_NETWORK_socket_setsockopt (sock,
                                          IPPROTO_IPV6,
                                          IPV6_V6ONLY,
                                          &on,
                                          sizeof (on))) )
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR | GNUNET_ERROR_TYPE_BULK,
			 "setsockopt");
#endif
#ifndef WINDOWS
  if (AF_UNIX == sa->sa_family)
    GNUNET_NETWORK_unix_precheck ((struct sockaddr_un *) sa);
#endif
  if (GNUNET_OK !=
      GNUNET_NETWORK_socket_bind (sock,
                                  (const struct sockaddr *) sa,
                                  addr_len))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("Unable to bind listening socket for service `%s' to address `%s': %s\n"),
                sl->name,
                GNUNET_a2s (sa,
                            addr_len),
                STRERROR (errno));
    GNUNET_break (GNUNET_OK ==
                  GNUNET_NETWORK_socket_close (sock));
    GNUNET_free (sa);
    return;
  }
#ifndef WINDOWS
  if ((AF_UNIX == sa->sa_family)
#ifdef LINUX
      /* Permission settings are not required when abstract sockets are used */
      && ('\0' != ((const struct sockaddr_un *)sa)->sun_path[0])
#endif
      )
  {
    match_uid =
      GNUNET_CONFIGURATION_get_value_yesno (cfg,
                                            sl->name,
                                            "UNIX_MATCH_UID");
    match_gid =
      GNUNET_CONFIGURATION_get_value_yesno (cfg,
                                            sl->name,
                                            "UNIX_MATCH_GID");
    GNUNET_DISK_fix_permissions (((const struct sockaddr_un *)sa)->sun_path,
                                 match_uid,
                                 match_gid);

  }
#endif
  if (GNUNET_OK !=
      GNUNET_NETWORK_socket_listen (sock, 5))
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR,
                         "listen");
    GNUNET_break (GNUNET_OK ==
                  GNUNET_NETWORK_socket_close (sock));
    GNUNET_free (sa);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
	      _("ARM now monitors connections to service `%s' at `%s'\n"),
	      sl->name,
              GNUNET_a2s (sa,
                          addr_len));
  sli = GNUNET_new (struct ServiceListeningInfo);
  sli->service_addr = sa;
  sli->service_addr_len = addr_len;
  sli->listen_socket = sock;
  sli->sl = sl;
  sli->accept_task
    = GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                     sock,
                                     &accept_connection, sli);
  GNUNET_CONTAINER_DLL_insert (sl->listen_head,
			       sl->listen_tail,
			       sli);
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
  GNUNET_CONTAINER_DLL_remove (running_head,
                               running_tail,
                               sl);
  GNUNET_assert (NULL == sl->listen_head);
  GNUNET_free_non_null (sl->config);
  GNUNET_free_non_null (sl->binary);
  GNUNET_free (sl->name);
  GNUNET_free (sl);
}


/**
 * Check START-message.
 *
 * @param cls identification of the client
 * @param amsg the actual message
 * @return #GNUNET_OK to keep the connection open,
 *         #GNUNET_SYSERR to close it (signal serious error)
 */
static int
check_start (void *cls,
             const struct GNUNET_ARM_Message *amsg)
{
  uint16_t size;
  const char *servicename;

  (void) cls;
  size = ntohs (amsg->header.size) - sizeof (struct GNUNET_ARM_Message);
  servicename = (const char *) &amsg[1];
  if ( (0 == size) ||
       (servicename[size - 1] != '\0') )
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handle START-message.
 *
 * @param cls identification of the client
 * @param amsg the actual message
 */
static void
handle_start (void *cls,
	      const struct GNUNET_ARM_Message *amsg)
{
  struct GNUNET_SERVICE_Client *client = cls;
  const char *servicename;
  struct ServiceList *sl;
  uint64_t request_id;

  request_id = GNUNET_ntohll (amsg->request_id);
  servicename = (const char *) &amsg[1];
  GNUNET_SERVICE_client_continue (client);
  if (GNUNET_YES == in_shutdown)
  {
    signal_result (client,
                   servicename,
                   request_id,
		   GNUNET_ARM_RESULT_IN_SHUTDOWN);
    return;
  }
  sl = find_service (servicename);
  if (NULL == sl)
  {
    signal_result (client,
                   servicename,
                   request_id,
		   GNUNET_ARM_RESULT_IS_NOT_KNOWN);
    return;
  }
  sl->force_start = GNUNET_YES;
  if (NULL != sl->proc)
  {
    signal_result (client,
                   servicename,
                   request_id,
		   GNUNET_ARM_RESULT_IS_STARTED_ALREADY);
    return;
  }
  start_process (sl,
                 client,
                 request_id);
}


/**
 * Start a shutdown sequence.
 *
 * @param cls closure (refers to service)
 */
static void
trigger_shutdown (void *cls)
{
  (void) cls;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Triggering shutdown\n");
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Check STOP-message.
 *
 * @param cls identification of the client
 * @param amsg the actual message
 * @return #GNUNET_OK to keep the connection open,
 *         #GNUNET_SYSERR to close it (signal serious error)
 */
static int
check_stop (void *cls,
            const struct GNUNET_ARM_Message *amsg)
{
  uint16_t size;
  const char *servicename;

  (void) cls;
  size = ntohs (amsg->header.size) - sizeof (struct GNUNET_ARM_Message);
  servicename = (const char *) &amsg[1];
  if ( (0 == size) ||
       (servicename[size - 1] != '\0') )
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handle STOP-message.
 *
 * @param cls identification of the client
 * @param amsg the actual message
 */
static void
handle_stop (void *cls,
	     const struct GNUNET_ARM_Message *amsg)
{
  struct GNUNET_SERVICE_Client *client = cls;
  struct ServiceList *sl;
  const char *servicename;
  uint64_t request_id;

  request_id = GNUNET_ntohll (amsg->request_id);
  servicename = (const char *) &amsg[1];
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
	      _("Preparing to stop `%s'\n"),
	      servicename);
  GNUNET_SERVICE_client_continue (client);
  if (0 == strcasecmp (servicename,
                       "arm"))
  {
    broadcast_status (servicename,
		      GNUNET_ARM_SERVICE_STOPPING,
                      NULL);
    signal_result (client,
		   servicename,
		   request_id,
		   GNUNET_ARM_RESULT_STOPPING);
    GNUNET_SERVICE_client_persist (client);
    GNUNET_SCHEDULER_add_now (&trigger_shutdown,
                              NULL);
    return;
  }
  sl = find_service (servicename);
  if (NULL == sl)
  {
    signal_result (client,
                   servicename,
                   request_id,
                   GNUNET_ARM_RESULT_IS_NOT_KNOWN);
    return;
  }
  sl->force_start = GNUNET_NO;
  if (GNUNET_YES == in_shutdown)
  {
    /* shutdown in progress */
    signal_result (client,
                   servicename,
                   request_id,
                   GNUNET_ARM_RESULT_IN_SHUTDOWN);
    return;
  }
  if (NULL != sl->killing_client)
  {
    /* killing already in progress */
    signal_result (client,
		   servicename,
		   request_id,
		   GNUNET_ARM_RESULT_IS_STOPPING_ALREADY);
    return;
  }
  if (NULL == sl->proc)
  {
    /* process is down */
    signal_result (client,
		   servicename,
		   request_id,
		   GNUNET_ARM_RESULT_IS_STOPPED_ALREADY);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Sending kill signal to service `%s', waiting for process to die.\n",
	      servicename);
  broadcast_status (servicename,
		    GNUNET_ARM_SERVICE_STOPPING,
		    NULL);
  /* no signal_start - only when it's STOPPED */
  sl->killed_at = GNUNET_TIME_absolute_get ();
  if (0 != GNUNET_OS_process_kill (sl->proc,
                                   GNUNET_TERM_SIG))
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING,
                         "kill");
  sl->killing_client = client;
  sl->killing_client_request_id = request_id;
}


/**
 * Handle LIST-message.
 *
 * @param cls identification of the client
 * @param message the actual message
 */
static void
handle_list (void *cls,
             const struct GNUNET_ARM_Message *request)
{
  struct GNUNET_SERVICE_Client *client = cls;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_ARM_ListResultMessage *msg;
  size_t string_list_size;
  struct ServiceList *sl;
  uint16_t count;
  char *pos;

  GNUNET_break (0 == ntohl (request->reserved));
  count = 0;
  string_list_size = 0;

  /* first count the running processes get their name's size */
  for (sl = running_head; NULL != sl; sl = sl->next)
  {
    if (NULL != sl->proc)
    {
      string_list_size += strlen (sl->name);
      string_list_size += strlen (sl->binary);
      string_list_size += 4;
      count++;
    }
  }

  env = GNUNET_MQ_msg_extra (msg,
                             string_list_size,
                             GNUNET_MESSAGE_TYPE_ARM_LIST_RESULT);
  msg->arm_msg.request_id = request->request_id;
  msg->count = htons (count);

  pos = (char *) &msg[1];
  for (sl = running_head; NULL != sl; sl = sl->next)
  {
    if (NULL != sl->proc)
    {
      size_t s = strlen (sl->name) + strlen (sl->binary) + 4;
      GNUNET_snprintf (pos,
                       s,
                       "%s (%s)",
                       sl->name,
                       sl->binary);
      pos += s;
    }
  }
  GNUNET_MQ_send (GNUNET_SERVICE_client_get_mq (client),
                  env);
  GNUNET_SERVICE_client_continue (client);
}


/**
 * Handle TEST-message by sending back TEST.
 *
 * @param cls identification of the client
 * @param message the actual message
 */
static void
handle_test (void *cls,
             const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_SERVICE_Client *client = cls;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_MessageHeader *msg;

  (void) message;
  env = GNUNET_MQ_msg (msg,
                       GNUNET_MESSAGE_TYPE_ARM_TEST);
  GNUNET_MQ_send (GNUNET_SERVICE_client_get_mq (client),
                  env);
  GNUNET_SERVICE_client_continue (client);
}


/**
 * We are done with everything.  Stop remaining
 * tasks, signal handler and the server.
 */
static void
do_shutdown ()
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Last shutdown phase\n");
  if (NULL != notifier)
  {
    GNUNET_notification_context_destroy (notifier);
    notifier = NULL;
  }
  if (NULL != service)
  {
    GNUNET_SERVICE_shutdown (service);
    service = NULL;
  }
  if (NULL != child_death_task)
  {
    GNUNET_SCHEDULER_cancel (child_death_task);
    child_death_task = NULL;
  }
}


/**
 * Count how many services are still active.
 *
 * @param running_head list of services
 * @return number of active services found
 */
static unsigned int
list_count (struct ServiceList *running_head)
{
  struct ServiceList *i;
  unsigned int res;

  for (res = 0, i = running_head; NULL != i; i = i->next, res++)
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"%s\n",
		i->name);
  return res;
}


/**
 * Task run for shutdown.
 *
 * @param cls closure, NULL if we need to self-restart
 */
static void
shutdown_task (void *cls)
{
  struct ServiceList *pos;
  struct ServiceList *nxt;
  struct ServiceListeningInfo *sli;

  (void) cls;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "First shutdown phase\n");
  if (NULL != child_restart_task)
  {
    GNUNET_SCHEDULER_cancel (child_restart_task);
    child_restart_task = NULL;
  }
  in_shutdown = GNUNET_YES;
  /* first, stop listening */
  for (pos = running_head; NULL != pos; pos = pos->next)
  {
    while (NULL != (sli = pos->listen_head))
    {
      GNUNET_CONTAINER_DLL_remove (pos->listen_head,
                                   pos->listen_tail,
                                   sli);
      if (NULL != sli->accept_task)
      {
        GNUNET_SCHEDULER_cancel (sli->accept_task);
        sli->accept_task = NULL;
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
    if (NULL != pos->proc)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		  "Stopping service `%s'\n",
		  pos->name);
      pos->killed_at = GNUNET_TIME_absolute_get ();
      if (0 != GNUNET_OS_process_kill (pos->proc,
                                       GNUNET_TERM_SIG))
	GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING,
                             "kill");
    }
    else
    {
      free_service (pos);
    }
  }
  /* finally, should all service processes be already gone, terminate for real */
  if (NULL == running_head)
    do_shutdown ();
  else
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Delaying shutdown, have %u childs still running\n",
		list_count (running_head));
}


/**
 * Task run whenever it is time to restart a child that died.
 *
 * @param cls closure, always NULL
 */
static void
delayed_restart_task (void *cls)

{
  struct ServiceList *sl;
  struct GNUNET_TIME_Relative lowestRestartDelay;
  struct ServiceListeningInfo *sli;

  (void) cls;
  child_restart_task = NULL;
  GNUNET_assert (GNUNET_NO == in_shutdown);
  lowestRestartDelay = GNUNET_TIME_UNIT_FOREVER_REL;

  /* check for services that need to be restarted due to
   * configuration changes or because the last restart failed */
  for (sl = running_head; NULL != sl; sl = sl->next)
  {
    if (NULL != sl->proc)
      continue;
    /* service is currently not running */
    if (0 == GNUNET_TIME_absolute_get_remaining (sl->restart_at).rel_value_us)
    {
      /* restart is now allowed */
      if (sl->force_start)
      {
	/* process should run by default, start immediately */
	GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		    _("Restarting service `%s'.\n"),
                    sl->name);
	start_process (sl,
                       NULL,
                       0);
      }
      else
      {
	/* process is run on-demand, ensure it is re-started if there is demand */
	for (sli = sl->listen_head; NULL != sli; sli = sli->next)
	  if (NULL == sli->accept_task)
	  {
	    /* accept was actually paused, so start it again */
	    sli->accept_task
	      = GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                               sli->listen_socket,
                                               &accept_connection,
                                               sli);
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
  if (lowestRestartDelay.rel_value_us != GNUNET_TIME_UNIT_FOREVER_REL.rel_value_us)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Will restart process in %s\n",
		GNUNET_STRINGS_relative_time_to_string (lowestRestartDelay,
                                                        GNUNET_YES));
    child_restart_task =
      GNUNET_SCHEDULER_add_delayed_with_priority (lowestRestartDelay,
						  GNUNET_SCHEDULER_PRIORITY_IDLE,
						  &delayed_restart_task,
                                                  NULL);
  }
}


/**
 * Task triggered whenever we receive a SIGCHLD (child
 * process died).
 *
 * @param cls closure, NULL 
 */
static void
maint_child_death (void *cls)
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

  (void) cls;
  pr = GNUNET_DISK_pipe_handle (sigpipe,
				GNUNET_DISK_PIPE_END_READ);
  child_death_task = NULL;
  /* consume the signal */
  GNUNET_break (0 < GNUNET_DISK_file_read (pr,
                                           &c,
                                           sizeof (c)));

  /* check for services that died (WAITPID) */
  next = running_head;
  while (NULL != (pos = next))
  {
    next = pos->next;

    if (NULL == pos->proc)
    {
      if (GNUNET_YES == in_shutdown)
        free_service (pos);
      continue;
    }
#if HAVE_WAIT4
    if (NULL != wait_file)
    {
      /* need to use 'wait4()' to obtain and log performance data */
      struct rusage ru;
      int status;
      pid_t pid;

      pid = GNUNET_OS_process_get_pid (pos->proc);
      ret = wait4 (pid,
                   &status,
                   WNOHANG,
                   &ru);
      if (ret <= 0)
        continue; /* no process done */
      if (WIFEXITED (status))
      {
        statusType = GNUNET_OS_PROCESS_EXITED;
        statusCode = WEXITSTATUS (status);
      }
      else if (WIFSIGNALED (status))
      {
        statusType = GNUNET_OS_PROCESS_SIGNALED;
        statusCode = WTERMSIG (status);
      }
      else if (WIFSTOPPED (status))
      {
        statusType = GNUNET_OS_PROCESS_SIGNALED;
        statusCode = WSTOPSIG (status);
      }
#ifdef WIFCONTINUED
      else if (WIFCONTINUED (status))
      {
        statusType = GNUNET_OS_PROCESS_RUNNING;
        statusCode = 0;
      }
#endif
      else
      {
        statusType = GNUNET_OS_PROCESS_UNKNOWN;
        statusCode = 0;
      }
      if ( (GNUNET_OS_PROCESS_EXITED == statusType) ||
           (GNUNET_OS_PROCESS_SIGNALED == statusType) )
      {
        double utime = ru.ru_utime.tv_sec + (ru.ru_utime.tv_usec / 10e6);
        double stime = ru.ru_stime.tv_sec + (ru.ru_stime.tv_usec / 10e6);
        fprintf (wait_file,
                 "%s(%u) %.3f %.3f %llu %llu %llu %llu %llu\n",
                 pos->binary,
                 (unsigned int) pid,
                 utime,
                 stime,
                 (unsigned long long) ru.ru_maxrss,
                 (unsigned long long) ru.ru_inblock,
                 (unsigned long long) ru.ru_oublock,
                 (unsigned long long) ru.ru_nvcsw,
                 (unsigned long long) ru.ru_nivcsw);
      }
    }
    else /* continue with JUST this "if" as "else" (intentionally no brackets!) */
#endif
    if ( (GNUNET_SYSERR ==
          (ret =
           GNUNET_OS_process_status (pos->proc,
                                     &statusType,
                                     &statusCode))) ||
         (ret == GNUNET_NO) ||
         (statusType == GNUNET_OS_PROCESS_STOPPED) ||
         (statusType == GNUNET_OS_PROCESS_UNKNOWN) ||
         (statusType == GNUNET_OS_PROCESS_RUNNING) )
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
    if (0 != pos->killed_at.abs_value_us)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  _("Service `%s' took %s to terminate\n"),
                  pos->name,
                  GNUNET_STRINGS_relative_time_to_string (GNUNET_TIME_absolute_get_duration (pos->killed_at),
                                                          GNUNET_YES));
    }
    GNUNET_OS_process_destroy (pos->proc);
    pos->proc = NULL;
    broadcast_status (pos->name,
                      GNUNET_ARM_SERVICE_STOPPED,
                      NULL);
    if (NULL != pos->killing_client)
    {
      signal_result (pos->killing_client, pos->name,
                     pos->killing_client_request_id,
                     GNUNET_ARM_RESULT_STOPPED);
      pos->killing_client = NULL;
      pos->killing_client_request_id = 0;
    }
    if (GNUNET_YES != in_shutdown)
    {
      if ( (statusType == GNUNET_OS_PROCESS_EXITED) &&
           (statcode == 0) )
      {
        /* process terminated normally, allow restart at any time */
        pos->restart_at.abs_value_us = 0;
        GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                    _("Service `%s' terminated normally, will restart at any time\n"),
                    pos->name);
        /* process can still be re-started on-demand, ensure it is re-started if there is demand */
        for (sli = pos->listen_head; NULL != sli; sli = sli->next)
        {
          GNUNET_break (NULL == sli->accept_task);
          sli->accept_task =
            GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                           sli->listen_socket,
                                           &accept_connection,
                                           sli);
        }
      }
      else
      {
	GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		    _("Service `%s' terminated with status %s/%d, will restart in %s\n"),
		    pos->name,
		    statstr,
		    statcode,
		    GNUNET_STRINGS_relative_time_to_string (pos->backoff,
							    GNUNET_YES));
	{
	  /* Reduce backoff based on runtime of the process,
	     so that there is a cool-down if a process actually
	     runs for a while. */
	  struct GNUNET_TIME_Relative runtime;
	  unsigned int minutes;

	  runtime = GNUNET_TIME_absolute_get_duration (pos->restart_at);
	  minutes = runtime.rel_value_us / GNUNET_TIME_UNIT_MINUTES.rel_value_us;
	  if (minutes > 31)
	    pos->backoff = GNUNET_TIME_UNIT_ZERO;
	  else
	    pos->backoff.rel_value_us <<= minutes;
	}
	/* schedule restart */
        pos->restart_at = GNUNET_TIME_relative_to_absolute (pos->backoff);
        pos->backoff = GNUNET_TIME_STD_BACKOFF (pos->backoff);
        if (NULL != child_restart_task)
          GNUNET_SCHEDULER_cancel (child_restart_task);
        child_restart_task
          = GNUNET_SCHEDULER_add_with_priority (GNUNET_SCHEDULER_PRIORITY_IDLE,
                                                &delayed_restart_task,
                                                NULL);
      }
    }
    else
    {
      free_service (pos);
    }
  }
  child_death_task = GNUNET_SCHEDULER_add_read_file (
      GNUNET_TIME_UNIT_FOREVER_REL,
      pr,
      &maint_child_death, NULL);
  if ((NULL == running_head) && (GNUNET_YES == in_shutdown))
    do_shutdown ();
  else if (GNUNET_YES == in_shutdown)
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
        "Delaying shutdown after child's death, still have %u children\n",
        list_count (running_head));

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
		GNUNET_DISK_file_write (GNUNET_DISK_pipe_handle (sigpipe,
                                                                 GNUNET_DISK_PIPE_END_WRITE),
					&c,
                                        sizeof (c)));
  errno = old_errno;		/* restore errno */
}


/**
 * Setup our service record for the given section in the configuration file
 * (assuming the section is for a service).
 *
 * @param cls unused
 * @param section a section in the configuration file
 * @return #GNUNET_OK (continue)
 */
static void
setup_service (void *cls,
               const char *section)
{
  struct ServiceList *sl;
  char *binary;
  char *config;
  struct stat sbuf;
  struct sockaddr **addrs;
  socklen_t *addr_lens;
  int ret;

  (void) cls;
  if (0 == strcasecmp (section,
                       "arm"))
    return;
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg,
                                             section,
                                             "BINARY",
                                             &binary))
  {
    /* not a service section */
    return;
  }
  if ((GNUNET_YES ==
       GNUNET_CONFIGURATION_have_value (cfg,
                                        section,
                                        "RUN_PER_USER")) &&
      (GNUNET_YES ==
       GNUNET_CONFIGURATION_get_value_yesno (cfg,
                                             section,
                                             "RUN_PER_USER")))
  {
    if (GNUNET_NO == start_user)
    {
      GNUNET_free (binary);
      return; /* user service, and we don't deal with those */
    }
  }
  else
  {
    if (GNUNET_NO == start_system)
    {
      GNUNET_free (binary);
      return; /* system service, and we don't deal with those */
    }
  }
  sl = find_service (section);
  if (NULL != sl)
  {
    /* got the same section twice!? */
    GNUNET_break (0);
    GNUNET_free (binary);
    return;
  }
  config = NULL;
  if (( (GNUNET_OK !=
	 GNUNET_CONFIGURATION_get_value_filename (cfg,
                                                  section,
                                                  "CONFIG",
                                                  &config)) &&
	(GNUNET_OK !=
	 GNUNET_CONFIGURATION_get_value_filename (cfg,
                                                  "PATHS",
                                                  "DEFAULTCONFIG",
						  &config)) ) ||
      (0 != STAT (config, &sbuf)))
  {
    if (NULL != config)
    {
      GNUNET_log_config_invalid (GNUNET_ERROR_TYPE_WARNING,
				 section, "CONFIG",
				 STRERROR (errno));
      GNUNET_free (config);
      config = NULL;
    }
  }
  sl = GNUNET_new (struct ServiceList);
  sl->name = GNUNET_strdup (section);
  sl->binary = binary;
  sl->config = config;
  sl->backoff = GNUNET_TIME_UNIT_MILLISECONDS;
  sl->restart_at = GNUNET_TIME_UNIT_FOREVER_ABS;
#if WINDOWS
  sl->pipe_control = GNUNET_YES;
#else
  if (GNUNET_CONFIGURATION_have_value (cfg,
                                       section,
                                       "PIPECONTROL"))
    sl->pipe_control = GNUNET_CONFIGURATION_get_value_yesno (cfg,
                                                             section,
                                                             "PIPECONTROL");
#endif
  GNUNET_CONTAINER_DLL_insert (running_head,
                               running_tail,
                               sl);
  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_get_value_yesno (cfg,
                                            section,
                                            "FORCESTART"))
  {
    sl->force_start = GNUNET_YES;
    if (GNUNET_YES ==
        GNUNET_CONFIGURATION_get_value_yesno (cfg,
                                              section,
                                              "NOARMBIND"))
      return;
  }
  else
  {
    if (GNUNET_YES !=
        GNUNET_CONFIGURATION_get_value_yesno (cfg,
                                              section,
                                              "START_ON_DEMAND"))
      return;
  }
  if (0 >= (ret = get_server_addresses (section,
					cfg,
					&addrs,
					&addr_lens)))
    return;
  /* this will free (or capture) addrs[i] */
  for (unsigned int i = 0; i < (unsigned int) ret; i++)
    create_listen_socket (addrs[i],
                          addr_lens[i],
                          sl);
  GNUNET_free (addrs);
  GNUNET_free (addr_lens);
}


/**
 * A client connected, mark as a monitoring client.
 *
 * @param cls closure
 * @param client identification of the client
 * @param mq queue to talk to @a client
 * @return @a client
 */
static void *
client_connect_cb (void *cls,
                   struct GNUNET_SERVICE_Client *client,
                   struct GNUNET_MQ_Handle *mq)
{
  /* All clients are considered to be of the "monitor" kind
   * (that is, they don't affect ARM shutdown).
   */
  (void) cls;
  (void) mq;
  GNUNET_SERVICE_client_mark_monitor (client);
  return client;
}


/**
 * A client disconnected, clean up associated state.
 *
 * @param cls closure
 * @param client identification of the client
 * @param app_ctx must match @a client
 */
static void
client_disconnect_cb (void *cls,
                      struct GNUNET_SERVICE_Client *client,
                      void *app_ctx)
{
  (void) cls;
  GNUNET_assert (client == app_ctx);
  for (struct ServiceList *sl = running_head; NULL != sl; sl = sl->next)
    if (sl->killing_client == client)
      sl->killing_client = NULL;
}


/**
 * Handle MONITOR-message.
 *
 * @param cls identification of the client
 * @param message the actual message
 * @return #GNUNET_OK to keep the connection open,
 *         #GNUNET_SYSERR to close it (signal serious error)
 */
static void
handle_monitor (void *cls,
                const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_SERVICE_Client *client = cls;

  (void) message;
  /* FIXME: might want to start by letting monitor know about
     services that are already running */
  /* Removal is handled by the server implementation, internally. */
  GNUNET_notification_context_add (notifier,
                                   GNUNET_SERVICE_client_get_mq (client));
  broadcast_status ("arm",
                    GNUNET_ARM_SERVICE_MONITORING_STARTED,
                    client);
  GNUNET_SERVICE_client_continue (client);
}


/**
 * Process arm requests.
 *
 * @param cls closure, NULL
 * @param serv the initialized service
 * @param c configuration to use
 */
static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *c,
     struct GNUNET_SERVICE_Handle *serv)
{
  struct ServiceList *sl;

  (void) cls;
  cfg = c;
  service = serv;
  GNUNET_SCHEDULER_add_shutdown (&shutdown_task,
				 NULL);
  child_death_task =
    GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL,
				    GNUNET_DISK_pipe_handle (sigpipe,
							     GNUNET_DISK_PIPE_END_READ),
				    &maint_child_death,
                                    NULL);
#if HAVE_WAIT4
  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_get_value_filename (cfg,
                                               "ARM",
                                               "RESOURCE_DIAGNOSTICS",
                                               &wait_filename))
  {
    wait_file = fopen (wait_filename,
                       "w");
    if (NULL == wait_file)
    {
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR,
                                "fopen",
                                wait_filename);
    }
  }
#endif
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg,
                                             "ARM",
                                             "GLOBAL_PREFIX",
                                             &prefix_command))
    prefix_command = GNUNET_strdup ("");
  else
    prefix_command = GNUNET_CONFIGURATION_expand_dollar (cfg,
                                                         prefix_command);
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg,
                                             "ARM",
                                             "GLOBAL_POSTFIX",
                                             &final_option))
    final_option = GNUNET_strdup ("");
  else
    final_option = GNUNET_CONFIGURATION_expand_dollar (cfg,
                                                       final_option);
  start_user = GNUNET_CONFIGURATION_get_value_yesno (cfg,
                                            "ARM",
                                            "START_USER_SERVICES");
  start_system = GNUNET_CONFIGURATION_get_value_yesno (cfg,
                                            "ARM",
                                            "START_SYSTEM_SERVICES");
  if ( (GNUNET_NO == start_user) && 
       (GNUNET_NO == start_system) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
	"Please configure either START_USER_SERVICES or START_SYSTEM_SERVICES or both.\n");
    GNUNET_SCHEDULER_shutdown ();
    global_ret = 1;
    return;
  }
  GNUNET_CONFIGURATION_iterate_sections (cfg,
                                         &setup_service,
                                         NULL);

  /* start default services... */
  for (sl = running_head; NULL != sl; sl = sl->next)
    if (GNUNET_YES == sl->force_start)
      start_process (sl,
                     NULL,
                     0);
  notifier = GNUNET_notification_context_create (MAX_NOTIFY_QUEUE);
}


/**
 * The main function for the arm service.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc,
      char *const *argv)
{
  struct GNUNET_SIGNAL_Context *shc_chld;
  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_var_size (start,
                           GNUNET_MESSAGE_TYPE_ARM_START,
                           struct GNUNET_ARM_Message,
                           NULL),
    GNUNET_MQ_hd_var_size (stop,
                           GNUNET_MESSAGE_TYPE_ARM_STOP,
                           struct GNUNET_ARM_Message,
                           NULL),
    GNUNET_MQ_hd_fixed_size (monitor,
                             GNUNET_MESSAGE_TYPE_ARM_MONITOR,
                             struct GNUNET_MessageHeader,
                             NULL),
    GNUNET_MQ_hd_fixed_size (list,
                             GNUNET_MESSAGE_TYPE_ARM_LIST,
                             struct GNUNET_ARM_Message,
                             NULL),
    GNUNET_MQ_hd_fixed_size (test,
                             GNUNET_MESSAGE_TYPE_ARM_TEST,
                             struct GNUNET_MessageHeader,
                             NULL),
    GNUNET_MQ_handler_end ()
  };

  sigpipe = GNUNET_DISK_pipe (GNUNET_NO,
                              GNUNET_NO,
                              GNUNET_NO,
                              GNUNET_NO);
  GNUNET_assert (NULL != sigpipe);
  shc_chld =
    GNUNET_SIGNAL_handler_install (GNUNET_SIGCHLD,
                                   &sighandler_child_death);
  if ( GNUNET_OK != GNUNET_SERVICE_run_ (argc,
                             argv,
                             "arm",
                             GNUNET_SERVICE_OPTION_MANUAL_SHUTDOWN,
                             &run,
                             &client_connect_cb,
                             &client_disconnect_cb,
                             NULL,
                             handlers))
    global_ret = 2;
#if HAVE_WAIT4
  if (NULL != wait_file)
  {
    fclose (wait_file);
    wait_file = NULL;
  }
  if (NULL != wait_filename)
  {
    GNUNET_free (wait_filename);
    wait_filename = NULL;
  }
#endif
  GNUNET_SIGNAL_handler_uninstall (shc_chld);
  shc_chld = NULL;
  GNUNET_DISK_pipe_close (sigpipe);
  sigpipe = NULL;
  return global_ret;
}


#if defined(LINUX) && defined(__GLIBC__)
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
