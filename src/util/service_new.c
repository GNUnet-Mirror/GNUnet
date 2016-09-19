/*
     This file is part of GNUnet.
     Copyright (C) 2016 GNUnet e.V.

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
 * @file util/service_new.c
 * @brief functions related to starting services (redesign)
 * @author Christian Grothoff
 * @author Florian Dold
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_constants.h"
#include "gnunet_resolver_service.h"
#include "speedup.h"

#if HAVE_MALLINFO
#include <malloc.h>
#include "gauger.h"
#endif


#define LOG(kind,...) GNUNET_log_from (kind, "util", __VA_ARGS__)

#define LOG_STRERROR(kind,syscall) GNUNET_log_from_strerror (kind, "util", syscall)

#define LOG_STRERROR_FILE(kind,syscall,filename) GNUNET_log_from_strerror_file (kind, "util", syscall, filename)


/**
 * Information the service tracks per listen operation.
 */
struct ServiceListenContext
{

  /**
   * Kept in a DLL.
   */
  struct ServiceListenContext *next;

  /**
   * Kept in a DLL.
   */
  struct ServiceListenContext *prev;

  /**
   * Service this listen context belongs to.
   */
  struct GNUNET_SERVICE_Handle *sh;

  /**
   * Socket we are listening on.
   */
  struct GNUNET_NETWORK_Handle *listen_socket;

  /**
   * Task scheduled to do the listening.
   */
  struct GNUNET_SCHEDULER_Task *listen_task;

};


/**
 * Handle to a service.
 */
struct GNUNET_SERVICE_Handle
{
  /**
   * Our configuration.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Name of our service.
   */
  const char *service_name;

  /**
   * Main service-specific task to run.
   */
  GNUNET_SERVICE_InitCallback service_init_cb;

  /**
   * Function to call when clients connect.
   */
  GNUNET_SERVICE_ConnectHandler connect_cb;

  /**
   * Function to call when clients disconnect / are disconnected.
   */
  GNUNET_SERVICE_DisconnectHandler disconnect_cb;

  /**
   * Closure for @e service_init_cb, @e connect_cb, @e disconnect_cb.
   */
  void *cb_cls;

  /**
   * DLL of listen sockets used to accept new connections.
   */
  struct ServiceListenContext *slc_head;

  /**
   * DLL of listen sockets used to accept new connections.
   */
  struct ServiceListenContext *slc_tail;

  /**
   * Our clients, kept in a DLL.
   */
  struct GNUNET_SERVICE_Client *clients_head;

  /**
   * Our clients, kept in a DLL.
   */
  struct GNUNET_SERVICE_Client *clients_tail;

  /**
   * Message handlers to use for all clients.
   */
  const struct GNUNET_MQ_MessageHandler *handlers;

  /**
   * Closure for @e task.
   */
  void *task_cls;

  /**
   * IPv4 addresses that are not allowed to connect.
   */
  struct GNUNET_STRINGS_IPv4NetworkPolicy *v4_denied;

  /**
   * IPv6 addresses that are not allowed to connect.
   */
  struct GNUNET_STRINGS_IPv6NetworkPolicy *v6_denied;

  /**
   * IPv4 addresses that are allowed to connect (if not
   * set, all are allowed).
   */
  struct GNUNET_STRINGS_IPv4NetworkPolicy *v4_allowed;

  /**
   * IPv6 addresses that are allowed to connect (if not
   * set, all are allowed).
   */
  struct GNUNET_STRINGS_IPv6NetworkPolicy *v6_allowed;

  /**
   * Do we require a matching UID for UNIX domain socket connections?
   * #GNUNET_NO means that the UID does not have to match (however,
   * @e match_gid may still impose other access control checks).
   */
  int match_uid;

  /**
   * Do we require a matching GID for UNIX domain socket connections?
   * Ignored if @e match_uid is #GNUNET_YES.  Note that this is about
   * checking that the client's UID is in our group OR that the
   * client's GID is our GID.  If both "match_gid" and @e match_uid are
   * #GNUNET_NO, all users on the local system have access.
   */
  int match_gid;

  /**
   * Set to #GNUNET_YES if we got a shutdown signal and terminate
   * the service if #have_non_monitor_clients() returns #GNUNET_YES.
   */
  int got_shutdown;

  /**
   * Our options.
   */
  enum GNUNET_SERVICE_Options options;

  /**
   * If we are daemonizing, this FD is set to the
   * pipe to the parent.  Send '.' if we started
   * ok, '!' if not.  -1 if we are not daemonizing.
   */
  int ready_confirm_fd;

  /**
   * Overall success/failure of the service start.
   */
  int ret;

  /**
   * If #GNUNET_YES, consider unknown message types an error where the
   * client is disconnected.
   */
  int require_found;
};


/**
 * Handle to a client that is connected to a service.
 */
struct GNUNET_SERVICE_Client
{

  /**
   * Kept in a DLL.
   */
  struct GNUNET_SERVICE_Client *next;

  /**
   * Kept in a DLL.
   */
  struct GNUNET_SERVICE_Client *prev;

  /**
   * Service that this client belongs to.
   */
  struct GNUNET_SERVICE_Handle *sh;

  /**
   * Socket of this client.
   */
  struct GNUNET_NETWORK_Handle *sock;

  /**
   * Message queue for the client.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Tokenizer we use for processing incoming data.
   */
  struct GNUNET_MessageStreamTokenizer *mst;

  /**
   * Task that warns about missing calls to
   * #GNUNET_SERVICE_client_continue().
   */
  struct GNUNET_SCHEDULER_Task *warn_task;

  /**
   * Task that receives data from the client to
   * pass it to the handlers.
   */
  struct GNUNET_SCHEDULER_Task *recv_task;

  /**
   * Task that transmit data to the client.
   */
  struct GNUNET_SCHEDULER_Task *send_task;

  /**
   * Pointer to the message to be transmitted by @e send_task.
   */
  const struct GNUNET_MessageHeader *msg;
  
  /**
   * User context value, value returned from
   * the connect callback.
   */
  void *user_context;

  /**
   * Time when we last gave a message from this client
   * to the application.
   */
  struct GNUNET_TIME_Absolute warn_start;

  /**
   * Current position in @e msg at which we are transmitting.
   */
  size_t msg_pos;
  
  /**
   * Persist the file handle for this client no matter what happens,
   * force the OS to close once the process actually dies.  Should only
   * be used in special cases!
   */
  int persist;

  /**
   * Is this client a 'monitor' client that should not be counted
   * when deciding on destroying the server during soft shutdown?
   * (see also #GNUNET_SERVICE_start)
   */
  int is_monitor;

  /**
   * Are we waiting for the application to call #GNUNET_SERVICE_client_continue()?
   */
  int needs_continue;

  /**
   * Type of last message processed (for warn_no_receive_done).
   */
  uint16_t warn_type;
};


/**
 * Check if any of the clients we have left are unrelated to
 * monitoring.
 *
 * @param sh service to check clients for
 * @return #GNUNET_YES if we have non-monitoring clients left
 */
static int
have_non_monitor_clients (struct GNUNET_SERVICE_Handle *sh)
{
  struct GNUNET_SERVICE_Client *client;

  for (client = sh->clients_head;NULL != client; client = client->next)
  {
    if (client->is_monitor)
      continue;
    return GNUNET_YES;
  }
  return GNUNET_NO;
}


/**
 * Shutdown task triggered when a service should be terminated.
 * This considers active clients and the service options to see
 * how this specific service is to be terminated, and depending
 * on this proceeds with the shutdown logic.
 *
 * @param cls our `struct GNUNET_SERVICE_Handle`
 */
static void
service_shutdown (void *cls)
{
  struct GNUNET_SERVICE_Handle *sh = cls;

  switch (sh->options)
  {
  case GNUNET_SERVICE_OPTION_NONE:
    GNUNET_SERVICE_shutdown (sh);
    break;
  case GNUNET_SERVICE_OPTION_MANUAL_SHUTDOWN:
    /* This task should never be run if we are using
       the manual shutdown. */
    GNUNET_assert (0);
    break;
  case GNUNET_SERVICE_OPTION_SOFT_SHUTDOWN:
    sh->got_shutdown = GNUNET_YES;
    GNUNET_SERVICE_suspend (sh);
    if (GNUNET_NO == have_non_monitor_clients (sh))
      GNUNET_SERVICE_shutdown (sh);
    break;
  }
}


/**
 * First task run by any service.  Initializes our shutdown task,
 * starts the listening operation on our listen sockets and launches
 * the custom logic of the application service.
 *
 * @param cls our `struct GNUNET_SERVICE_Handle`
 */
static void
service_main (void *cls)
{
  struct GNUNET_SERVICE_Handle *sh = cls;

  if (GNUNET_SERVICE_OPTION_MANUAL_SHUTDOWN != sh->options)
    GNUNET_SCHEDULER_add_shutdown (&service_shutdown,
                                   sh);
  GNUNET_SERVICE_resume (sh);
  sh->service_init_cb (sh->cb_cls,
                       sh->cfg,
                       sh);
}


/**
 * Parse an IPv4 access control list.
 *
 * @param ret location where to write the ACL (set)
 * @param sh service context to use to get the configuration
 * @param option name of the ACL option to parse
 * @return #GNUNET_SYSERR on parse error, #GNUNET_OK on success (including
 *         no ACL configured)
 */
static int
process_acl4 (struct GNUNET_STRINGS_IPv4NetworkPolicy **ret,
              struct GNUNET_SERVICE_Handle *sh,
              const char *option)
{
  char *opt;

  if (! GNUNET_CONFIGURATION_have_value (sh->cfg,
					 sh->service_name,
					 option))
  {
    *ret = NULL;
    return GNUNET_OK;
  }
  GNUNET_break (GNUNET_OK ==
                GNUNET_CONFIGURATION_get_value_string (sh->cfg,
                                                       sh->service_name,
                                                       option,
						       &opt));
  if (NULL == (*ret = GNUNET_STRINGS_parse_ipv4_policy (opt)))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         _("Could not parse IPv4 network specification `%s' for `%s:%s'\n"),
         opt,
	 sh->service_name,
	 option);
    GNUNET_free (opt);
    return GNUNET_SYSERR;
  }
  GNUNET_free (opt);
  return GNUNET_OK;
}


/**
 * Parse an IPv6 access control list.
 *
 * @param ret location where to write the ACL (set)
 * @param sh service context to use to get the configuration
 * @param option name of the ACL option to parse
 * @return #GNUNET_SYSERR on parse error, #GNUNET_OK on success (including
 *         no ACL configured)
 */
static int
process_acl6 (struct GNUNET_STRINGS_IPv6NetworkPolicy **ret,
              struct GNUNET_SERVICE_Handle *sh,
              const char *option)
{
  char *opt;

  if (! GNUNET_CONFIGURATION_have_value (sh->cfg,
					 sh->service_name,
					 option))
  {
    *ret = NULL;
    return GNUNET_OK;
  }
  GNUNET_break (GNUNET_OK ==
                GNUNET_CONFIGURATION_get_value_string (sh->cfg,
                                                       sh->service_name,
                                                       option,
						       &opt));
  if (NULL == (*ret = GNUNET_STRINGS_parse_ipv6_policy (opt)))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         _("Could not parse IPv6 network specification `%s' for `%s:%s'\n"),
         opt,
	 sh->service_name,
	 option);
    GNUNET_free (opt);
    return GNUNET_SYSERR;
  }
  GNUNET_free (opt);
  return GNUNET_OK;
}


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
  strncpy (un->sun_path,
	   unixpath,
	   sizeof (un->sun_path) - 1);
#ifdef LINUX
  if (GNUNET_YES == abstract)
    un->sun_path[0] = '\0';
#endif
#if HAVE_SOCKADDR_IN_SIN_LEN
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
		      socklen_t **addr_lens)
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
      GNUNET_break (GNUNET_OK ==
		    GNUNET_NETWORK_socket_close (desc));
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
    desc = GNUNET_NETWORK_socket_create (AF_UNIX,
					 SOCK_STREAM,
					 0);
    if (NULL == desc)
    {
      if ((ENOBUFS == errno) ||
	  (ENOMEM == errno) ||
	  (ENFILE == errno) ||
          (EACCES == errno))
      {
        LOG_STRERROR (GNUNET_ERROR_TYPE_ERROR,
		      "socket");
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
      GNUNET_break (GNUNET_OK ==
		    GNUNET_NETWORK_socket_close (desc));
      desc = NULL;
    }
  }
#endif

  if ((0 == port) && (NULL == unixpath))
  {
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
    memset (&hints,
	    0,
	    sizeof (struct addrinfo));
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
      if ( (disablev6) &&
	   (pos->ai_family == AF_INET6) )
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
      add_unixpath (saddrs,
		    saddrlens,
		    unixpath,
		    abstract);
      i++;
    }
    next = res;
    while (NULL != (pos = next))
    {
      next = pos->ai_next;
      if ( (disablev6) &&
	   (AF_INET6 == pos->ai_family) )
        continue;
      if ( (IPPROTO_TCP != pos->ai_protocol) &&
	   (0 != pos->ai_protocol) )
        continue;               /* not TCP */
      if ( (SOCK_STREAM != pos->ai_socktype) &&
	   (0 != pos->ai_socktype) )
        continue;               /* huh? */
      LOG (GNUNET_ERROR_TYPE_DEBUG,
	   "Service `%s' will bind to `%s'\n",
           service_name,
	   GNUNET_a2s (pos->ai_addr,
		       pos->ai_addrlen));
      if (AF_INET == pos->ai_family)
      {
        GNUNET_assert (sizeof (struct sockaddr_in) == pos->ai_addrlen);
        saddrlens[i] = pos->ai_addrlen;
        saddrs[i] = GNUNET_malloc (saddrlens[i]);
        GNUNET_memcpy (saddrs[i],
		       pos->ai_addr,
		       saddrlens[i]);
        ((struct sockaddr_in *) saddrs[i])->sin_port = htons (port);
      }
      else
      {
        GNUNET_assert (AF_INET6 == pos->ai_family);
        GNUNET_assert (sizeof (struct sockaddr_in6) == pos->ai_addrlen);
        saddrlens[i] = pos->ai_addrlen;
        saddrs[i] = GNUNET_malloc (saddrlens[i]);
        GNUNET_memcpy (saddrs[i],
		       pos->ai_addr,
		       saddrlens[i]);
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
        add_unixpath (saddrs,
		      saddrlens,
		      unixpath,
		      abstract);
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


#ifdef MINGW
/**
 * Read listen sockets from the parent process (ARM).
 *
 * @param sh service context to initialize
 * @return NULL-terminated array of sockets on success,
 *         NULL if not ok (must bind yourself)
 */
static struct GNUNET_NETWORK_Handle **
receive_sockets_from_parent (struct GNUNET_SERVICE_Handle *sh)
{
  static struct GNUNET_NETWORK_Handle **lsocks;
  const char *env_buf;
  int fail;
  uint64_t count;
  uint64_t i;
  HANDLE lsocks_pipe;

  env_buf = getenv ("GNUNET_OS_READ_LSOCKS");
  if ( (NULL == env_buf) ||
       (strlen (env_buf) <= 0) )
    return NULL;
  /* Using W32 API directly here, because this pipe will
   * never be used outside of this function, and it's just too much of a bother
   * to create a GNUnet API that boxes a HANDLE (the way it is done with socks)
   */
  lsocks_pipe = (HANDLE) strtoul (env_buf,
				  NULL,
				  10);
  if ( (0 == lsocks_pipe) ||
       (INVALID_HANDLE_VALUE == lsocks_pipe))
    return NULL;
  fail = 1;
  do
  {
    int ret;
    int fail2;
    DWORD rd;

    ret = ReadFile (lsocks_pipe,
		    &count,
		    sizeof (count),
		    &rd,
		    NULL);
    if ( (0 == ret) ||
	 (sizeof (count) != rd) ||
	 (0 == count) )
      break;
    lsocks = GNUNET_new_array (count + 1,
			       struct GNUNET_NETWORK_Handle *);

    fail2 = 1;
    for (i = 0; i < count; i++)
    {
      WSAPROTOCOL_INFOA pi;
      uint64_t size;
      SOCKET s;

      ret = ReadFile (lsocks_pipe,
		      &size,
		      sizeof (size),
		      &rd,
		      NULL);
      if ( (0 == ret) ||
	   (sizeof (size) != rd) ||
	   (sizeof (pi) != size) )
        break;
      ret = ReadFile (lsocks_pipe,
		      &pi,
		      sizeof (pi),
		      &rd,
		      NULL);
      if ( (0 == ret) ||
	   (sizeof (pi) != rd))
        break;
      s = WSASocketA (pi.iAddressFamily,
		      pi.iSocketType,
		      pi.iProtocol,
		      &pi,
		      0,
		      WSA_FLAG_OVERLAPPED);
      lsocks[i] = GNUNET_NETWORK_socket_box_native (s);
      if (NULL == lsocks[i])
        break;
      else if (i == count - 1)
        fail2 = 0;
    }
    if (fail2)
      break;
    lsocks[count] = NULL;
    fail = 0;
  }
  while (fail);
  CloseHandle (lsocks_pipe);

  if (fail)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _("Could not access a pre-bound socket, will try to bind myself\n"));
    for (i = 0; (i < count) && (NULL != lsocks[i]); i++)
      GNUNET_break (GNUNET_OK ==
		    GNUNET_NETWORK_socket_close (lsocks[i]));
    GNUNET_free (lsocks);
    return NULL;
  }
  return lsocks;
}
#endif


/**
 * Create and initialize a listen socket for the server.
 *
 * @param server_addr address to listen on
 * @param socklen length of @a server_addr
 * @return NULL on error, otherwise the listen socket
 */
static struct GNUNET_NETWORK_Handle *
open_listen_socket (const struct sockaddr *server_addr,
		    socklen_t socklen)
{
  struct GNUNET_NETWORK_Handle *sock;
  uint16_t port;
  int eno;

  switch (server_addr->sa_family)
  {
  case AF_INET:
    port = ntohs (((const struct sockaddr_in *) server_addr)->sin_port);
    break;
  case AF_INET6:
    port = ntohs (((const struct sockaddr_in6 *) server_addr)->sin6_port);
    break;
  case AF_UNIX:
    port = 0;
    break;
  default:
    GNUNET_break (0);
    port = 0;
    break;
  }
  sock = GNUNET_NETWORK_socket_create (server_addr->sa_family,
				       SOCK_STREAM,
				       0);
  if (NULL == sock)
  {
    LOG_STRERROR (GNUNET_ERROR_TYPE_ERROR,
		  "socket");
    errno = 0;
    return NULL;
  }
  /* bind the socket */
  if (GNUNET_OK != GNUNET_NETWORK_socket_bind (sock,
					       server_addr,
					       socklen))
  {
    eno = errno;
    if (EADDRINUSE != errno)
    {
      /* we don't log 'EADDRINUSE' here since an IPv4 bind may
       * fail if we already took the port on IPv6; if both IPv4 and
       * IPv6 binds fail, then our caller will log using the
       * errno preserved in 'eno' */
      LOG_STRERROR (GNUNET_ERROR_TYPE_ERROR,
                    "bind");
      if (0 != port)
        LOG (GNUNET_ERROR_TYPE_ERROR,
             _("`%s' failed for port %d (%s).\n"),
             "bind",
             port,
             (AF_INET == server_addr->sa_family) ? "IPv4" : "IPv6");
      eno = 0;
    }
    else
    {
      if (0 != port)
        LOG (GNUNET_ERROR_TYPE_WARNING,
             _("`%s' failed for port %d (%s): address already in use\n"),
             "bind", port,
             (AF_INET == server_addr->sa_family) ? "IPv4" : "IPv6");
      else if (AF_UNIX == server_addr->sa_family)
      {
        LOG (GNUNET_ERROR_TYPE_WARNING,
             _("`%s' failed for `%s': address already in use\n"),
             "bind",
             GNUNET_a2s (server_addr, socklen));
      }
    }
    GNUNET_break (GNUNET_OK ==
		  GNUNET_NETWORK_socket_close (sock));
    errno = eno;
    return NULL;
  }
  if (GNUNET_OK != GNUNET_NETWORK_socket_listen (sock,
						 5))
  {
    LOG_STRERROR (GNUNET_ERROR_TYPE_ERROR,
                  "listen");
    GNUNET_break (GNUNET_OK ==
		  GNUNET_NETWORK_socket_close (sock));
    errno = 0;
    return NULL;
  }
  if (0 != port)
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Server starts to listen on port %u.\n",
         port);
  return sock;
}


/**
 * Setup service handle
 *
 * Configuration may specify:
 * - PORT (where to bind to for TCP)
 * - UNIXPATH (where to bind to for UNIX domain sockets)
 * - DISABLEV6 (disable support for IPv6, otherwise we use dual-stack)
 * - BINDTO (hostname or IP address to bind to, otherwise we take everything)
 * - ACCEPT_FROM  (only allow connections from specified IPv4 subnets)
 * - ACCEPT_FROM6 (only allow connections from specified IPv6 subnets)
 * - REJECT_FROM  (disallow allow connections from specified IPv4 subnets)
 * - REJECT_FROM6 (disallow allow connections from specified IPv6 subnets)
 *
 * @param sh service context to initialize
 * @return #GNUNET_OK if configuration succeeded
 */
static int
setup_service (struct GNUNET_SERVICE_Handle *sh)
{
  int tolerant;
  struct GNUNET_NETWORK_Handle **lsocks;
#ifndef MINGW
  const char *nfds;
  unsigned int cnt;
  int flags;
#endif

  if (GNUNET_CONFIGURATION_have_value
      (sh->cfg,
       sh->service_name,
       "TOLERANT"))
  {
    if (GNUNET_SYSERR ==
        (tolerant =
         GNUNET_CONFIGURATION_get_value_yesno (sh->cfg,
					       sh->service_name,
                                               "TOLERANT")))
    {
      LOG (GNUNET_ERROR_TYPE_ERROR,
           _("Specified value for `%s' of service `%s' is invalid\n"),
           "TOLERANT",
	   sh->service_name);
      return GNUNET_SYSERR;
    }
  }
  else
    tolerant = GNUNET_NO;

  lsocks = NULL;
#ifndef MINGW
  errno = 0;
  if ( (NULL != (nfds = getenv ("LISTEN_FDS"))) &&
       (1 == SSCANF (nfds,
		     "%u",
		     &cnt)) &&
       (cnt > 0) &&
       (cnt < FD_SETSIZE) &&
       (cnt + 4 < FD_SETSIZE) )
  {
    lsocks = GNUNET_new_array (cnt + 1,
			       struct GNUNET_NETWORK_Handle *);
    while (0 < cnt--)
    {
      flags = fcntl (3 + cnt,
		     F_GETFD);
      if ( (flags < 0) ||
	   (0 != (flags & FD_CLOEXEC)) ||
	   (NULL ==
	    (lsocks[cnt] = GNUNET_NETWORK_socket_box_native (3 + cnt))))
      {
        LOG (GNUNET_ERROR_TYPE_ERROR,
             _("Could not access pre-bound socket %u, will try to bind myself\n"),
             (unsigned int) 3 + cnt);
        cnt++;
        while (NULL != lsocks[cnt])
          GNUNET_break (GNUNET_OK ==
			GNUNET_NETWORK_socket_close (lsocks[cnt++]));
        GNUNET_free (lsocks);
        lsocks = NULL;
        break;
      }
    }
    unsetenv ("LISTEN_FDS");
  }
#else
  if (NULL != getenv ("GNUNET_OS_READ_LSOCKS"))
  {
    lsocks = receive_sockets_from_parent (sh);
    putenv ("GNUNET_OS_READ_LSOCKS=");
  }
#endif

  if (NULL != lsocks)
  {
    /* listen only on inherited sockets if we have any */
    struct GNUNET_NETWORK_Handle **ls;
    
    for (ls = lsocks; NULL != *ls; ls++)
    {
      struct ServiceListenContext *slc;

      slc = GNUNET_new (struct ServiceListenContext);
      slc->sh = sh;
      slc->listen_socket = *ls;
      GNUNET_CONTAINER_DLL_insert (sh->slc_head,
				   sh->slc_tail,
				   slc);
    }
    GNUNET_free (lsocks);
  }
  else
  {
    struct sockaddr **addrs;
    socklen_t *addrlens;
    int num;

    num = get_server_addresses (sh->service_name,
				sh->cfg,
				&addrs,
				&addrlens);
    if (GNUNET_SYSERR == num)
      return GNUNET_SYSERR;

    for (int i = 0; i < num; i++)
    {
      struct ServiceListenContext *slc;

      slc = GNUNET_new (struct ServiceListenContext);
      slc->sh = sh;
      slc->listen_socket = open_listen_socket (addrs[i],
					       addrlens[i]);
      GNUNET_break (NULL != slc->listen_socket);
      GNUNET_CONTAINER_DLL_insert (sh->slc_head,
				   sh->slc_tail,
				   slc);
    }
  }

  sh->require_found = tolerant ? GNUNET_NO : GNUNET_YES;
  sh->match_uid =
      GNUNET_CONFIGURATION_get_value_yesno (sh->cfg,
					    sh->service_name,
                                            "UNIX_MATCH_UID");
  sh->match_gid =
      GNUNET_CONFIGURATION_get_value_yesno (sh->cfg,
					    sh->service_name,
                                            "UNIX_MATCH_GID");
  process_acl4 (&sh->v4_denied,
		sh,
		"REJECT_FROM");
  process_acl4 (&sh->v4_allowed,
		sh,
		"ACCEPT_FROM");
  process_acl6 (&sh->v6_denied,
		sh,
		"REJECT_FROM6");
  process_acl6 (&sh->v6_allowed,
		sh,
		"ACCEPT_FROM6");
  return GNUNET_OK;
}


/**
 * Get the name of the user that'll be used
 * to provide the service.
 *
 * @param sh service context
 * @return value of the 'USERNAME' option
 */
static char *
get_user_name (struct GNUNET_SERVICE_Handle *sh)
{
  char *un;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (sh->cfg,
					       sh->service_name,
                                               "USERNAME",
					       &un))
    return NULL;
  return un;
}


/**
 * Set user ID.
 *
 * @param sh service context
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static int
set_user_id (struct GNUNET_SERVICE_Handle *sh)
{
  char *user;

  if (NULL == (user = get_user_name (sh)))
    return GNUNET_OK;           /* keep */
#ifndef MINGW
  struct passwd *pws;

  errno = 0;
  pws = getpwnam (user);
  if (NULL == pws)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _("Cannot obtain information about user `%s': %s\n"),
	 user,
         errno == 0 ? _("No such user") : STRERROR (errno));
    GNUNET_free (user);
    return GNUNET_SYSERR;
  }
  if ( (0 != setgid (pws->pw_gid)) ||
       (0 != setegid (pws->pw_gid)) ||
#if HAVE_INITGROUPS
       (0 != initgroups (user,
			 pws->pw_gid)) ||
#endif
       (0 != setuid (pws->pw_uid)) ||
       (0 != seteuid (pws->pw_uid)))
  {
    if ((0 != setregid (pws->pw_gid,
			pws->pw_gid)) ||
        (0 != setreuid (pws->pw_uid,
			pws->pw_uid)))
    {
      LOG (GNUNET_ERROR_TYPE_ERROR,
	   _("Cannot change user/group to `%s': %s\n"),
           user,
	   STRERROR (errno));
      GNUNET_free (user);
      return GNUNET_SYSERR;
    }
  }
#endif
  GNUNET_free (user);
  return GNUNET_OK;
}


/**
 * Get the name of the file where we will
 * write the PID of the service.
 *
 * @param sh service context
 * @return name of the file for the process ID
 */
static char *
get_pid_file_name (struct GNUNET_SERVICE_Handle *sh)
{
  char *pif;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (sh->cfg,
					       sh->service_name,
                                               "PIDFILE",
					       &pif))
    return NULL;
  return pif;
}


/**
 * Delete the PID file that was created by our parent.
 *
 * @param sh service context
 */
static void
pid_file_delete (struct GNUNET_SERVICE_Handle *sh)
{
  char *pif = get_pid_file_name (sh);

  if (NULL == pif)
    return;                     /* no PID file */
  if (0 != UNLINK (pif))
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING,
		       "unlink",
		       pif);
  GNUNET_free (pif);
}


/**
 * Detach from terminal.
 *
 * @param sh service context
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static int
detach_terminal (struct GNUNET_SERVICE_Handle *sh)
{
#ifndef MINGW
  pid_t pid;
  int nullfd;
  int filedes[2];

  if (0 != PIPE (filedes))
  {
    LOG_STRERROR (GNUNET_ERROR_TYPE_ERROR,
		  "pipe");
    return GNUNET_SYSERR;
  }
  pid = fork ();
  if (pid < 0)
  {
    LOG_STRERROR (GNUNET_ERROR_TYPE_ERROR,
		  "fork");
    return GNUNET_SYSERR;
  }
  if (0 != pid)
  {
    /* Parent */
    char c;

    GNUNET_break (0 == CLOSE (filedes[1]));
    c = 'X';
    if (1 != READ (filedes[0],
		   &c,
		   sizeof (char)))
      LOG_STRERROR (GNUNET_ERROR_TYPE_WARNING,
		    "read");
    fflush (stdout);
    switch (c)
    {
    case '.':
      exit (0);
    case 'I':
      LOG (GNUNET_ERROR_TYPE_INFO,
	   _("Service process failed to initialize\n"));
      break;
    case 'S':
      LOG (GNUNET_ERROR_TYPE_INFO,
           _("Service process could not initialize server function\n"));
      break;
    case 'X':
      LOG (GNUNET_ERROR_TYPE_INFO,
           _("Service process failed to report status\n"));
      break;
    }
    exit (1);                   /* child reported error */
  }
  GNUNET_break (0 == CLOSE (0));
  GNUNET_break (0 == CLOSE (1));
  GNUNET_break (0 == CLOSE (filedes[0]));
  nullfd = OPEN ("/dev/null",
		 O_RDWR | O_APPEND);
  if (nullfd < 0)
    return GNUNET_SYSERR;
  /* set stdin/stdout to /dev/null */
  if ( (dup2 (nullfd, 0) < 0) ||
       (dup2 (nullfd, 1) < 0) )
  {
    LOG_STRERROR (GNUNET_ERROR_TYPE_ERROR,
		  "dup2");
    (void) CLOSE (nullfd);
    return GNUNET_SYSERR;
  }
  (void) CLOSE (nullfd);
  /* Detach from controlling terminal */
  pid = setsid ();
  if (-1 == pid)
    LOG_STRERROR (GNUNET_ERROR_TYPE_ERROR,
		  "setsid");
  sh->ready_confirm_fd = filedes[1];
#else
  /* FIXME: we probably need to do something else
   * elsewhere in order to fork the process itself... */
  FreeConsole ();
#endif
  return GNUNET_OK;
}


/**
 * Creates the "main" function for a GNUnet service.  You
 * should almost always use the #GNUNET_SERVICE_MAIN macro
 * instead of calling this function directly (except
 * for ARM, which should call this function directly).
 *
 * The function will launch the service with the name @a service_name
 * using the @a service_options to configure its shutdown
 * behavior. Once the service is ready, the @a init_cb will be called
 * for service-specific initialization.  @a init_cb will be given the
 * service handler which can be used to control the service's
 * availability.  When clients connect or disconnect, the respective
 * @a connect_cb or @a disconnect_cb functions will be called. For
 * messages received from the clients, the respective @a handlers will
 * be invoked; for the closure of the handlers we use the return value
 * from the @a connect_cb invocation of the respective client.
 *
 * Each handler MUST call #GNUNET_SERVICE_client_continue() after each
 * message to receive further messages from this client.  If
 * #GNUNET_SERVICE_client_continue() is not called within a short
 * time, a warning will be logged. If delays are expected, services
 * should call #GNUNET_SERVICE_client_disable_continue_warning() to
 * disable the warning.
 *
 * Clients sending invalid messages (based on @a handlers) will be
 * dropped. Additionally, clients can be dropped at any time using
 * #GNUNET_SERVICE_client_drop().
 *
 * @param argc number of command-line arguments in @a argv
 * @param argv array of command-line arguments
 * @param service_name name of the service to run
 * @param options options controlling shutdown of the service
 * @param service_init_cb function to call once the service is ready
 * @param connect_cb function to call whenever a client connects
 * @param disconnect_cb function to call whenever a client disconnects
 * @param cls closure argument for @a service_init_cb, @a connect_cb and @a disconnect_cb
 * @param handlers NULL-terminated array of message handlers for the service,
 *                 the closure will be set to the value returned by
 *                 the @a connect_cb for the respective connection
 * @return 0 on success, non-zero on error
 */
int
GNUNET_SERVICE_ruN_ (int argc,
                     char *const *argv,
                     const char *service_name,
                     enum GNUNET_SERVICE_Options options,
                     GNUNET_SERVICE_InitCallback service_init_cb,
                     GNUNET_SERVICE_ConnectHandler connect_cb,
                     GNUNET_SERVICE_DisconnectHandler disconnect_cb,
                     void *cls,
                     const struct GNUNET_MQ_MessageHandler *handlers)
{
  struct GNUNET_SERVICE_Handle sh;
  char *cfg_filename;
  char *opt_cfg_filename;
  char *loglev;
  const char *xdg;
  char *logfile;
  int do_daemonize;
  unsigned long long skew_offset;
  unsigned long long skew_variance;
  long long clock_offset;
  struct GNUNET_CONFIGURATION_Handle *cfg;
  int ret;
  int err;

  struct GNUNET_GETOPT_CommandLineOption service_options[] = {
    GNUNET_GETOPT_OPTION_CFG_FILE (&opt_cfg_filename),
    {'d', "daemonize", NULL,
     gettext_noop ("do daemonize (detach from terminal)"), 0,
     GNUNET_GETOPT_set_one, &do_daemonize},
    GNUNET_GETOPT_OPTION_HELP (NULL),
    GNUNET_GETOPT_OPTION_LOGLEVEL (&loglev),
    GNUNET_GETOPT_OPTION_LOGFILE (&logfile),
    GNUNET_GETOPT_OPTION_VERSION (PACKAGE_VERSION " " VCS_VERSION),
    GNUNET_GETOPT_OPTION_END
  };

  memset (&sh,
	  0,
	  sizeof (sh));
  xdg = getenv ("XDG_CONFIG_HOME");
  if (NULL != xdg)
    GNUNET_asprintf (&cfg_filename,
                     "%s%s%s",
                     xdg,
                     DIR_SEPARATOR_STR,
                     GNUNET_OS_project_data_get ()->config_file);
  else
    cfg_filename = GNUNET_strdup (GNUNET_OS_project_data_get ()->user_config_file);
  sh.ready_confirm_fd = -1;
  sh.options = options;
  sh.cfg = cfg = GNUNET_CONFIGURATION_create ();
  sh.service_init_cb = service_init_cb;
  sh.connect_cb = connect_cb;
  sh.disconnect_cb = disconnect_cb;
  sh.cb_cls = cls;
  sh.handlers = handlers;
  sh.service_name = service_name;

  /* setup subsystems */
  loglev = NULL;
  logfile = NULL;
  opt_cfg_filename = NULL;
  do_daemonize = 0;
  ret = GNUNET_GETOPT_run (service_name,
			   service_options,
			   argc,
			   argv);
  if (GNUNET_SYSERR == ret)
    goto shutdown;
  if (GNUNET_NO == ret)
  {
    err = 0;
    goto shutdown;
  }
  if (GNUNET_OK != GNUNET_log_setup (service_name,
				     loglev,
				     logfile))
  {
    GNUNET_break (0);
    goto shutdown;
  }
  if (NULL == opt_cfg_filename)
    opt_cfg_filename = GNUNET_strdup (cfg_filename);
  if (GNUNET_YES == GNUNET_DISK_file_test (opt_cfg_filename))
  {
    if (GNUNET_SYSERR == GNUNET_CONFIGURATION_load (cfg,
						    opt_cfg_filename))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("Malformed configuration file `%s', exit ...\n"),
                  opt_cfg_filename);
      goto shutdown;
    }
  }
  else
  {
    if (GNUNET_SYSERR == GNUNET_CONFIGURATION_load (cfg,
						    NULL))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("Malformed configuration, exit ...\n"));
      goto shutdown;
    }
    if (0 != strcmp (opt_cfg_filename,
		     cfg_filename))
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Could not access configuration file `%s'\n"),
		  opt_cfg_filename);
  }
  if (GNUNET_OK != setup_service (&sh))
    goto shutdown;
  if ( (1 == do_daemonize) &&
       (GNUNET_OK != detach_terminal (&sh)) )
  {
    GNUNET_break (0);
    goto shutdown;
  }
  if (GNUNET_OK != set_user_id (&sh))
    goto shutdown;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Service `%s' runs with configuration from `%s'\n",
       service_name,
       opt_cfg_filename);
  if ((GNUNET_OK ==
       GNUNET_CONFIGURATION_get_value_number (sh.cfg,
					      "TESTING",
                                              "SKEW_OFFSET",
					      &skew_offset)) &&
      (GNUNET_OK ==
       GNUNET_CONFIGURATION_get_value_number (sh.cfg,
					      "TESTING",
                                              "SKEW_VARIANCE",
					      &skew_variance)))
  {
    clock_offset = skew_offset - skew_variance;
    GNUNET_TIME_set_offset (clock_offset);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
	 "Skewing clock by %dll ms\n",
	 clock_offset);
  }
  /* actually run service */
  err = 0;
  GNUNET_SCHEDULER_run (&service_main,
			&sh);
  /* shutdown */
  if (1 == do_daemonize)
    pid_file_delete (&sh);

shutdown:
  if (-1 != sh.ready_confirm_fd)
  {
    if (1 != WRITE (sh.ready_confirm_fd,
		    err ? "I" : "S",
		    1))
      LOG_STRERROR (GNUNET_ERROR_TYPE_WARNING,
		    "write");
    GNUNET_break (0 == CLOSE (sh.ready_confirm_fd));
  }
#if HAVE_MALLINFO
  {
    char *counter;

    if ( (GNUNET_YES ==
	  GNUNET_CONFIGURATION_have_value (sh.cfg,
					   service_name,
					   "GAUGER_HEAP")) &&
	 (GNUNET_OK ==
	  GNUNET_CONFIGURATION_get_value_string (sh.cfg,
						 service_name,
						 "GAUGER_HEAP",
						 &counter)) )
    {
      struct mallinfo mi;

      mi = mallinfo ();
      GAUGER (service_name,
	      counter,
	      mi.usmblks,
	      "blocks");
      GNUNET_free (counter);
    }
  }
#endif
  GNUNET_SPEEDUP_stop_ ();
  GNUNET_CONFIGURATION_destroy (cfg);

  while (NULL != sh.slc_head)
  {
    struct ServiceListenContext *slc = sh.slc_head;

    sh.slc_head = slc->next;
    if (NULL != slc->listen_task)
      GNUNET_SCHEDULER_cancel (slc->listen_task);
    GNUNET_break (GNUNET_OK ==
		  GNUNET_NETWORK_socket_close (slc->listen_socket));
    GNUNET_free (slc);
  }

  GNUNET_free_non_null (logfile);
  GNUNET_free_non_null (loglev);
  GNUNET_free (cfg_filename);
  GNUNET_free_non_null (opt_cfg_filename);
  GNUNET_free_non_null (sh.v4_denied);
  GNUNET_free_non_null (sh.v6_denied);
  GNUNET_free_non_null (sh.v4_allowed);
  GNUNET_free_non_null (sh.v6_allowed);

  return err ? GNUNET_SYSERR : sh.ret;
}


/**
 * Suspend accepting connections from the listen socket temporarily.
 * Resume activity using #GNUNET_SERVICE_resume.
 *
 * @param sh service to stop accepting connections.
 */
void
GNUNET_SERVICE_suspend (struct GNUNET_SERVICE_Handle *sh)
{
  struct ServiceListenContext *slc;

  for (slc = sh->slc_head; NULL != slc; slc = slc->next)
  {
    if (NULL != slc->listen_task)
    {
      GNUNET_SCHEDULER_cancel (slc->listen_task);
      slc->listen_task = NULL;
    }
  }
}


/**
 * Task run when we are ready to transmit data to the
 * client.
 *
 * @param cls the `struct GNUNET_SERVICE_Client *` to send to
 */
static void
do_send (void *cls)
{
  struct GNUNET_SERVICE_Client *client = cls;
  ssize_t ret;
  size_t left;
  const char *buf;

  client->send_task = NULL;
  buf = (const char *) client->msg;
  left = ntohs (client->msg->size) - client->msg_pos;
  ret = GNUNET_NETWORK_socket_send (client->sock,
				    &buf[client->msg_pos],
				    left);
  GNUNET_assert (ret <= (ssize_t) left);
  if (0 == ret)
  {
    GNUNET_MQ_inject_error (client->mq,
			    GNUNET_MQ_ERROR_WRITE);
    return;
  }
  if (-1 == ret)
  {
    if ( (EAGAIN == errno) ||
	 (EINTR == errno) )
    {
      /* ignore */
      ret = 0;
    }
    else
    {
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING,
			   "send");
      GNUNET_MQ_inject_error (client->mq,
			      GNUNET_MQ_ERROR_WRITE);
      return;
    }
  }
  client->msg_pos += ret;
  if (left > ret)
  {
    client->send_task
      = GNUNET_SCHEDULER_add_write_net (GNUNET_TIME_UNIT_FOREVER_REL,
					client->sock,
					&do_send,
					client);
    return;
  }
  GNUNET_MQ_impl_send_continue (client->mq);
}


/**
 * Signature of functions implementing the sending functionality of a
 * message queue.
 *
 * @param mq the message queue
 * @param msg the message to send
 * @param impl_state our `struct GNUNET_SERVICE_Client *`
 */
static void
service_mq_send (struct GNUNET_MQ_Handle *mq,
                 const struct GNUNET_MessageHeader *msg,
                 void *impl_state)
{
  struct GNUNET_SERVICE_Client *client = impl_state;

  GNUNET_assert (NULL == client->send_task);
  client->msg = msg;
  client->msg_pos = 0;
  client->send_task
    = GNUNET_SCHEDULER_add_write_net (GNUNET_TIME_UNIT_FOREVER_REL,
				      client->sock,
				      &do_send,
				      client);
}


/**
 * Implementation function that cancels the currently sent message.
 *
 * @param mq message queue
 * @param impl_state state specific to the implementation
 */
static void
service_mq_cancel (struct GNUNET_MQ_Handle *mq,
                   void *impl_state)
{
  struct GNUNET_SERVICE_Client *client = impl_state;

  GNUNET_assert (0); // not implemented
  // FIXME: stop transmission! (must be possible, otherwise
  // we must have told MQ that the message was sent!)
}


/**
 * Generic error handler, called with the appropriate
 * error code and the same closure specified at the creation of
 * the message queue.
 * Not every message queue implementation supports an error handler.
 *
 * @param cls closure with our `struct GNUNET_SERVICE_Client`
 * @param error error code
 */
static void
service_mq_error_handler (void *cls,
                          enum GNUNET_MQ_Error error)
{
  struct GNUNET_SERVICE_Client *client = cls;
  struct GNUNET_SERVICE_Handle *sh = client->sh;

  if ( (GNUNET_MQ_ERROR_NO_MATCH == error) &&
       (GNUNET_NO == sh->require_found) )
    return; /* ignore error */
  GNUNET_SERVICE_client_drop (client);
}


/**
 * Task run to warn about missing calls to #GNUNET_SERVICE_client_continue().
 *
 * @param cls our `struct GNUNET_SERVICE_Client *` to process more requests from
 */
static void
warn_no_client_continue (void *cls)
{
  struct GNUNET_SERVICE_Client *client = cls;

  GNUNET_break (0 != client->warn_type); /* type should never be 0 here, as we don't use 0 */
  client->warn_task 
    = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_MINUTES,
                                    &warn_no_client_continue,
				    client);
  LOG (GNUNET_ERROR_TYPE_WARNING,
       _("Processing code for message of type %u did not call `GNUNET_SERVICE_client_continue' after %s\n"),
       (unsigned int) client->warn_type,
       GNUNET_STRINGS_relative_time_to_string (GNUNET_TIME_absolute_get_duration (client->warn_start),
					       GNUNET_YES));
}


/**
 * Functions with this signature are called whenever a
 * complete message is received by the tokenizer for a client.
 *
 * Do not call #GNUNET_MST_destroy() from within
 * the scope of this callback.
 *
 * @param cls closure with the `struct GNUNET_SERVICE_Client *`
 * @param message the actual message
 * @return #GNUNET_OK on success (always)
 */
static int
service_client_mst_cb (void *cls,
                       const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_SERVICE_Client *client = cls;

  GNUNET_assert (GNUNET_NO == client->needs_continue);
  client->needs_continue = GNUNET_YES;
  client->warn_type = ntohs (message->type);
  client->warn_start = GNUNET_TIME_absolute_get ();
  client->warn_task
    = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_MINUTES,
				    &warn_no_client_continue,
				    client);
  GNUNET_MQ_inject_message (client->mq,
                            message);
  return GNUNET_OK;
}


/**
 * A client sent us data. Receive and process it.  If we are done,
 * reschedule this task.
 *
 * @param cls the `struct GNUNET_SERVICE_Client` that sent us data.
 */
static void
service_client_recv (void *cls)
{
  struct GNUNET_SERVICE_Client *client = cls;
  int ret;

  client->recv_task = NULL;
  ret = GNUNET_MST_read (client->mst,
			 client->sock,
			 GNUNET_NO,
			 GNUNET_YES);
  if (GNUNET_SYSERR == ret)
  {
    /* client closed connection (or IO error) */
    GNUNET_assert (GNUNET_NO == client->needs_continue);
    GNUNET_SERVICE_client_drop (client);
    return;
  }
  if (GNUNET_NO == ret)
    return; /* more messages in buffer, wait for application
	       to be done processing */
  GNUNET_assert (GNUNET_OK == ret);
  if (GNUNET_YES == client->needs_continue)
    return;
  if (NULL != client->recv_task)
    return;
  /* MST needs more data, re-schedule read job */
  client->recv_task
    = GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
				     client->sock,
				     &service_client_recv,
				     client);
}


/**
 * We have successfully accepted a connection from a client.  Now
 * setup the client (with the scheduler) and tell the application.
 *
 * @param sh service that accepted the client
 * @param sock socket associated with the client
 */
static void
start_client (struct GNUNET_SERVICE_Handle *sh,
              struct GNUNET_NETWORK_Handle *csock)
{
  struct GNUNET_SERVICE_Client *client;

  client = GNUNET_new (struct GNUNET_SERVICE_Client);
  GNUNET_CONTAINER_DLL_insert (sh->clients_head,
                               sh->clients_tail,
                               client);
  client->sh = sh;
  client->sock = csock;
  client->mq = GNUNET_MQ_queue_for_callbacks (&service_mq_send,
                                              NULL,
                                              &service_mq_cancel,
                                              client,
                                              sh->handlers,
                                              &service_mq_error_handler,
                                              client);
  client->mst = GNUNET_MST_create (&service_client_mst_cb,
				   client);
  client->user_context = sh->connect_cb (sh->cb_cls,
                                         client,
                                         client->mq);
  GNUNET_MQ_set_handlers_closure (client->mq,
                                  client->user_context);
  client->recv_task
    = GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
				     client->sock,
				     &service_client_recv,
				     client);
}


/**
 * Check if the given IP address is in the list of IP addresses.
 *
 * @param list a list of networks
 * @param add the IP to check (in network byte order)
 * @return #GNUNET_NO if the IP is not in the list, #GNUNET_YES if it it is
 */
static int
check_ipv4_listed (const struct GNUNET_STRINGS_IPv4NetworkPolicy *list,
                   const struct in_addr *add)
{
  unsigned int i;

  if (NULL == list)
    return GNUNET_NO;
  i = 0;
  while ( (0 != list[i].network.s_addr) ||
	  (0 != list[i].netmask.s_addr) )
  {
    if ((add->s_addr & list[i].netmask.s_addr) ==
        (list[i].network.s_addr & list[i].netmask.s_addr))
      return GNUNET_YES;
    i++;
  }
  return GNUNET_NO;
}


/**
 * Check if the given IP address is in the list of IP addresses.
 *
 * @param list a list of networks
 * @param ip the IP to check (in network byte order)
 * @return #GNUNET_NO if the IP is not in the list, #GNUNET_YES if it it is
 */
static int
check_ipv6_listed (const struct GNUNET_STRINGS_IPv6NetworkPolicy *list,
                   const struct in6_addr *ip)
{
  unsigned int i;
  unsigned int j;
  struct in6_addr zero;

  if (NULL == list)
    return GNUNET_NO;
  memset (&zero,
	  0,
	  sizeof (struct in6_addr));
  i = 0;
NEXT:
  while (0 != memcmp (&zero,
		      &list[i].network,
		      sizeof (struct in6_addr)))
  {
    for (j = 0; j < sizeof (struct in6_addr) / sizeof (int); j++)
      if (((((int *) ip)[j] & ((int *) &list[i].netmask)[j])) !=
          (((int *) &list[i].network)[j] & ((int *) &list[i].netmask)[j]))
      {
        i++;
        goto NEXT;
      }
    return GNUNET_YES;
  }
  return GNUNET_NO;
}


/**
 * We have a client. Accept the incoming socket(s) (and reschedule
 * the listen task).
 *
 * @param cls the `struct ServiceListenContext` of the ready listen socket
 */
static void
accept_client (void *cls)
{
  struct ServiceListenContext *slc = cls;
  struct GNUNET_SERVICE_Handle *sh = slc->sh;

  slc->listen_task = NULL;
  while (1)
  {
    struct GNUNET_NETWORK_Handle *sock;
    const struct sockaddr_in *v4;
    const struct sockaddr_in6 *v6;
    struct sockaddr_storage sa;
    socklen_t addrlen;
    int ok;
    
    addrlen = sizeof (sa);
    sock = GNUNET_NETWORK_socket_accept (slc->listen_socket,
					 (struct sockaddr *) &sa,
					 &addrlen);
    if (NULL == sock)
      break;
    switch (sa.ss_family)
    {
    case AF_INET:
      GNUNET_assert (addrlen == sizeof (struct sockaddr_in));
      v4 = (const struct sockaddr_in *) &sa;
      ok = ( ( (NULL == sh->v4_allowed) ||
	       (check_ipv4_listed (sh->v4_allowed,
				   &v4->sin_addr))) &&
	     ( (NULL == sh->v4_denied) ||
	       (! check_ipv4_listed (sh->v4_denied,
				     &v4->sin_addr)) ) );
      break;
    case AF_INET6:
      GNUNET_assert (addrlen == sizeof (struct sockaddr_in6));
      v6 = (const struct sockaddr_in6 *) &sa;
      ok = ( ( (NULL == sh->v6_allowed) ||
	       (check_ipv6_listed (sh->v6_allowed,
				   &v6->sin6_addr))) &&
	     ( (NULL == sh->v6_denied) ||
	       (! check_ipv6_listed (sh->v6_denied,
				     &v6->sin6_addr)) ) );
      break;
#ifndef WINDOWS
    case AF_UNIX:
      ok = GNUNET_OK;            /* controlled using file-system ACL now */
      break;
#endif
    default:
      LOG (GNUNET_ERROR_TYPE_WARNING,
	   _("Unknown address family %d\n"),
	   sa.ss_family);
      return;
    }
    if (! ok)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
	   "Service rejected incoming connection from %s due to policy.\n",
	   GNUNET_a2s ((const struct sockaddr *) &sa,
		       addrlen));
      GNUNET_break (GNUNET_OK ==
		    GNUNET_NETWORK_socket_close (sock));
      continue;
    }
    LOG (GNUNET_ERROR_TYPE_DEBUG,
	 "Service accepted incoming connection from %s.\n",
	 GNUNET_a2s ((const struct sockaddr *) &sa,
		     addrlen));
    start_client (slc->sh,
		  sock);
  }
  slc->listen_task
    = GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
				     slc->listen_socket,
				     &accept_client,
				     slc);
}


/**
 * Resume accepting connections from the listen socket.
 *
 * @param sh service to resume accepting connections.
 */
void
GNUNET_SERVICE_resume (struct GNUNET_SERVICE_Handle *sh)
{
  struct ServiceListenContext *slc;

  for (slc = sh->slc_head; NULL != slc; slc = slc->next)
  {
    GNUNET_assert (NULL == slc->listen_task);
    slc->listen_task
      = GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
				       slc->listen_socket,
				       &accept_client,
				       slc);
  }
}


/**
 * Task run to resume receiving data from the client after
 * the client called #GNUNET_SERVICE_client_continue().
 *
 * @param cls our `struct GNUNET_SERVICE_Client`
 */
static void
resume_client_receive (void *cls)
{
  struct GNUNET_SERVICE_Client *c = cls;
  int ret;

  c->recv_task = NULL;
  /* first, check if there is still something in the buffer */
  ret = GNUNET_MST_next (c->mst,
			 GNUNET_YES);
  if (GNUNET_SYSERR == ret)
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (c);
    return;
  }
  if (GNUNET_NO == ret)
    return; /* done processing, wait for more later */
  GNUNET_assert (GNUNET_OK == ret);
  if (GNUNET_YES == c->needs_continue)
    return; /* #GNUNET_MST_next() did give a message to the client */
  /* need to receive more data from the network first */
  c->recv_task
    = GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
				     c->sock,
				     &service_client_recv,
				     c);  
}


/**
 * Continue receiving further messages from the given client.
 * Must be called after each message received.
 *
 * @param c the client to continue receiving from
 */
void
GNUNET_SERVICE_client_continue (struct GNUNET_SERVICE_Client *c)
{
  GNUNET_assert (GNUNET_YES == c->needs_continue);
  GNUNET_assert (NULL == c->recv_task);
  c->needs_continue = GNUNET_NO;
  if (NULL != c->warn_task)
  {
    GNUNET_SCHEDULER_cancel (c->warn_task);
    c->warn_task = NULL;
  }
  c->recv_task
    = GNUNET_SCHEDULER_add_now (&resume_client_receive,
				c);
}


/**
 * Disable the warning the server issues if a message is not
 * acknowledged in a timely fashion.  Use this call if a client is
 * intentionally delayed for a while.  Only applies to the current
 * message.
 *
 * @param c client for which to disable the warning
 */
void
GNUNET_SERVICE_client_disable_continue_warning (struct GNUNET_SERVICE_Client *c)
{
  GNUNET_break (NULL != c->warn_task);
  if (NULL != c->warn_task)
  {
    GNUNET_SCHEDULER_cancel (c->warn_task);
    c->warn_task = NULL;
  }
}


/**
 * Ask the server to disconnect from the given client.  This is the
 * same as returning #GNUNET_SYSERR within the check procedure when
 * handling a message, wexcept that it allows dropping of a client even
 * when not handling a message from that client.  The `disconnect_cb`
 * will be called on @a c even if the application closes the connection
 * using this function.
 *
 * @param c client to disconnect now
 */
void
GNUNET_SERVICE_client_drop (struct GNUNET_SERVICE_Client *c)
{
  struct GNUNET_SERVICE_Handle *sh = c->sh;

  GNUNET_CONTAINER_DLL_remove (sh->clients_head,
                               sh->clients_tail,
                               c);
  sh->disconnect_cb (sh->cb_cls,
                     c,
                     c->user_context);
  if (NULL != c->warn_task)
  {
    GNUNET_SCHEDULER_cancel (c->warn_task);
    c->warn_task = NULL;
  }
  if (NULL != c->recv_task)
  {
    GNUNET_SCHEDULER_cancel (c->recv_task);
    c->recv_task = NULL;
  }
  if (NULL != c->send_task)
  {
    GNUNET_SCHEDULER_cancel (c->send_task);
    c->send_task = NULL;
  }
  GNUNET_MST_destroy (c->mst);
  GNUNET_MQ_destroy (c->mq);
  if (GNUNET_NO == c->persist)
  {
    GNUNET_break (GNUNET_OK ==
		  GNUNET_NETWORK_socket_close (c->sock));
  }
  else
  {
    GNUNET_NETWORK_socket_free_memory_only_ (c->sock);
  }
  GNUNET_free (c);
  if ( (GNUNET_YES == sh->got_shutdown) &&
       (GNUNET_NO == have_non_monitor_clients (sh)) )
    GNUNET_SERVICE_shutdown (sh);
}


/**
 * Explicitly stops the service.
 *
 * @param sh server to shutdown
 */
void
GNUNET_SERVICE_shutdown (struct GNUNET_SERVICE_Handle *sh)
{
  struct GNUNET_SERVICE_Client *client;

  GNUNET_SERVICE_suspend (sh);
  sh->got_shutdown = GNUNET_NO;
  while (NULL != (client = sh->clients_head))
    GNUNET_SERVICE_client_drop (client);
}


/**
 * Set the 'monitor' flag on this client.  Clients which have been
 * marked as 'monitors' won't prevent the server from shutting down
 * once #GNUNET_SERVICE_stop_listening() has been invoked.  The idea is
 * that for "normal" clients we likely want to allow them to process
 * their requests; however, monitor-clients are likely to 'never'
 * disconnect during shutdown and thus will not be considered when
 * determining if the server should continue to exist after
 * shutdown has been triggered.
 *
 * @param c client to mark as a monitor
 */
void
GNUNET_SERVICE_client_mark_monitor (struct GNUNET_SERVICE_Client *c)
{
  c->is_monitor = GNUNET_YES;
  if ( (GNUNET_YES == c->sh->got_shutdown) &&
       (GNUNET_NO == have_non_monitor_clients (c->sh)) )
    GNUNET_SERVICE_shutdown (c->sh);
}


/**
 * Set the persist option on this client.  Indicates that the
 * underlying socket or fd should never really be closed.  Used for
 * indicating process death.
 *
 * @param c client to persist the socket (never to be closed)
 */
void
GNUNET_SERVICE_client_persist (struct GNUNET_SERVICE_Client *c)
{
  c->persist = GNUNET_YES;
}


/**
 * Obtain the message queue of @a c.  Convenience function.
 *
 * @param c the client to continue receiving from
 * @return the message queue of @a c
 */
struct GNUNET_MQ_Handle *
GNUNET_SERVICE_client_get_mq (struct GNUNET_SERVICE_Client *c)
{
  return c->mq;
}


/* end of service_new.c */
