/*
     This file is part of GNUnet.
     (C) 2009, 2012 Christian Grothoff (and other contributing authors)

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
 * @file util/service.c
 * @brief functions related to starting services
 * @author Christian Grothoff
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


/* ******************* access control ******************** */

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
  while ((list[i].network.s_addr != 0) || (list[i].netmask.s_addr != 0))
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
  memset (&zero, 0, sizeof (struct in6_addr));
  i = 0;
NEXT:
  while (0 != memcmp (&zero, &list[i].network, sizeof (struct in6_addr)))
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


/* ****************** service struct ****************** */


/**
 * Context for "service_task".
 */
struct GNUNET_SERVICE_Context
{
  /**
   * Our configuration.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Handle for the server.
   */
  struct GNUNET_SERVER_Handle *server;

  /**
   * NULL-terminated array of addresses to bind to, NULL if we got pre-bound
   * listen sockets.
   */
  struct sockaddr **addrs;

  /**
   * Name of our service.
   */
  const char *service_name;

  /**
   * Main service-specific task to run.
   */
  GNUNET_SERVICE_Main task;

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
   * My (default) message handlers.  Adjusted copy
   * of "defhandlers".
   */
  struct GNUNET_SERVER_MessageHandler *my_handlers;

  /**
   * Array of the lengths of the entries in addrs.
   */
  socklen_t *addrlens;

  /**
   * NULL-terminated array of listen sockets we should take over.
   */
  struct GNUNET_NETWORK_Handle **lsocks;

  /**
   * Task ID of the shutdown task.
   */
  struct GNUNET_SCHEDULER_Task * shutdown_task;

  /**
   * Idle timeout for server.
   */
  struct GNUNET_TIME_Relative timeout;

  /**
   * Overall success/failure of the service start.
   */
  int ret;

  /**
   * If we are daemonizing, this FD is set to the
   * pipe to the parent.  Send '.' if we started
   * ok, '!' if not.  -1 if we are not daemonizing.
   */
  int ready_confirm_fd;

  /**
   * Do we close connections if we receive messages
   * for which we have no handler?
   */
  int require_found;

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
   * Our options.
   */
  enum GNUNET_SERVICE_Options options;

};


/* ****************** message handlers ****************** */

/**
 * Send a 'TEST' message back to the client.
 *
 * @param cls the 'struct GNUNET_SERVER_Client' to send TEST to
 * @param size number of bytes available in 'buf'
 * @param buf where to copy the message
 * @return number of bytes written to 'buf'
 */
static size_t
write_test (void *cls, size_t size, void *buf)
{
  struct GNUNET_SERVER_Client *client = cls;
  struct GNUNET_MessageHeader *msg;

  if (size < sizeof (struct GNUNET_MessageHeader))
  {
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return 0;                   /* client disconnected */
  }
  msg = (struct GNUNET_MessageHeader *) buf;
  msg->type = htons (GNUNET_MESSAGE_TYPE_TEST);
  msg->size = htons (sizeof (struct GNUNET_MessageHeader));
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
  return sizeof (struct GNUNET_MessageHeader);
}


/**
 * Handler for TEST message.
 *
 * @param cls closure (refers to service)
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_test (void *cls, struct GNUNET_SERVER_Client *client,
             const struct GNUNET_MessageHeader *message)
{
  /* simply bounce message back to acknowledge */
  if (NULL ==
      GNUNET_SERVER_notify_transmit_ready (client,
                                           sizeof (struct GNUNET_MessageHeader),
                                           GNUNET_TIME_UNIT_FOREVER_REL,
                                           &write_test, client))
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
}


/**
 * Default handlers for all services.  Will be copied and the
 * "callback_cls" fields will be replaced with the specific service
 * struct.
 */
static const struct GNUNET_SERVER_MessageHandler defhandlers[] = {
  {&handle_test, NULL, GNUNET_MESSAGE_TYPE_TEST,
   sizeof (struct GNUNET_MessageHeader)},
  {NULL, NULL, 0, 0}
};


/* ****************** service core routines ************** */


/**
 * Check if access to the service is allowed from the given address.
 *
 * @param cls closure
 * @param uc credentials, if available, otherwise NULL
 * @param addr address
 * @param addrlen length of address
 * @return #GNUNET_YES to allow, #GNUNET_NO to deny, #GNUNET_SYSERR
 *   for unknown address family (will be denied).
 */
static int
check_access (void *cls, const struct GNUNET_CONNECTION_Credentials *uc,
              const struct sockaddr *addr, socklen_t addrlen)
{
  struct GNUNET_SERVICE_Context *sctx = cls;
  const struct sockaddr_in *i4;
  const struct sockaddr_in6 *i6;
  int ret;

  switch (addr->sa_family)
  {
  case AF_INET:
    GNUNET_assert (addrlen == sizeof (struct sockaddr_in));
    i4 = (const struct sockaddr_in *) addr;
    ret = ((NULL == sctx->v4_allowed) ||
           (check_ipv4_listed (sctx->v4_allowed, &i4->sin_addr))) &&
        ((NULL == sctx->v4_denied) ||
         (!check_ipv4_listed (sctx->v4_denied, &i4->sin_addr)));
    break;
  case AF_INET6:
    GNUNET_assert (addrlen == sizeof (struct sockaddr_in6));
    i6 = (const struct sockaddr_in6 *) addr;
    ret = ((NULL == sctx->v6_allowed) ||
           (check_ipv6_listed (sctx->v6_allowed, &i6->sin6_addr))) &&
        ((NULL == sctx->v6_denied) ||
         (!check_ipv6_listed (sctx->v6_denied, &i6->sin6_addr)));
    break;
#ifndef WINDOWS
  case AF_UNIX:
    ret = GNUNET_OK;            /* controlled using file-system ACL now */
    break;
#endif
  default:
    LOG (GNUNET_ERROR_TYPE_WARNING, _("Unknown address family %d\n"),
         addr->sa_family);
    return GNUNET_SYSERR;
  }
  if (GNUNET_OK != ret)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         _("Access from `%s' denied to service `%s'\n"),
	 GNUNET_a2s (addr, addrlen),
         sctx->service_name);
  }
  return ret;
}


/**
 * Get the name of the file where we will
 * write the PID of the service.
 *
 * @param sctx service context
 * @return name of the file for the process ID
 */
static char *
get_pid_file_name (struct GNUNET_SERVICE_Context *sctx)
{
  char *pif;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (sctx->cfg, sctx->service_name,
                                               "PIDFILE", &pif))
    return NULL;
  return pif;
}


/**
 * Parse an IPv4 access control list.
 *
 * @param ret location where to write the ACL (set)
 * @param sctx service context to use to get the configuration
 * @param option name of the ACL option to parse
 * @return #GNUNET_SYSERR on parse error, #GNUNET_OK on success (including
 *         no ACL configured)
 */
static int
process_acl4 (struct GNUNET_STRINGS_IPv4NetworkPolicy **ret,
              struct GNUNET_SERVICE_Context *sctx,
              const char *option)
{
  char *opt;

  if (!GNUNET_CONFIGURATION_have_value (sctx->cfg, sctx->service_name, option))
  {
    *ret = NULL;
    return GNUNET_OK;
  }
  GNUNET_break (GNUNET_OK ==
                GNUNET_CONFIGURATION_get_value_string (sctx->cfg,
                                                       sctx->service_name,
                                                       option, &opt));
  if (NULL == (*ret = GNUNET_STRINGS_parse_ipv4_policy (opt)))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         _("Could not parse IPv4 network specification `%s' for `%s:%s'\n"),
         opt, sctx->service_name, option);
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
 * @param sctx service context to use to get the configuration
 * @param option name of the ACL option to parse
 * @return #GNUNET_SYSERR on parse error, #GNUNET_OK on success (including
 *         no ACL configured)
 */
static int
process_acl6 (struct GNUNET_STRINGS_IPv6NetworkPolicy **ret,
              struct GNUNET_SERVICE_Context *sctx,
              const char *option)
{
  char *opt;

  if (!GNUNET_CONFIGURATION_have_value (sctx->cfg, sctx->service_name, option))
  {
    *ret = NULL;
    return GNUNET_OK;
  }
  GNUNET_break (GNUNET_OK ==
                GNUNET_CONFIGURATION_get_value_string (sctx->cfg,
                                                       sctx->service_name,
                                                       option, &opt));
  if (NULL == (*ret = GNUNET_STRINGS_parse_ipv6_policy (opt)))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         _("Could not parse IPv6 network specification `%s' for `%s:%s'\n"),
         opt, sctx->service_name, option);
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
  strncpy (un->sun_path, unixpath, sizeof (un->sun_path) - 1);
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
int
GNUNET_SERVICE_get_server_addresses (const char *service_name,
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
  if (GNUNET_CONFIGURATION_have_value (cfg, service_name, "DISABLEV6"))
  {
    if (GNUNET_SYSERR ==
        (disablev6 =
         GNUNET_CONFIGURATION_get_value_yesno (cfg, service_name, "DISABLEV6")))
      return GNUNET_SYSERR;
  }
  else
    disablev6 = GNUNET_NO;

  if (!disablev6)
  {
    /* probe IPv6 support */
    desc = GNUNET_NETWORK_socket_create (PF_INET6, SOCK_STREAM, 0);
    if (NULL == desc)
    {
      if ((ENOBUFS == errno) || (ENOMEM == errno) || (ENFILE == errno) ||
          (EACCES == errno))
      {
        LOG_STRERROR (GNUNET_ERROR_TYPE_ERROR, "socket");
        return GNUNET_SYSERR;
      }
      LOG (GNUNET_ERROR_TYPE_INFO,
           _
           ("Disabling IPv6 support for service `%s', failed to create IPv6 socket: %s\n"),
           service_name, STRERROR (errno));
      disablev6 = GNUNET_YES;
    }
    else
    {
      GNUNET_break (GNUNET_OK == GNUNET_NETWORK_socket_close (desc));
      desc = NULL;
    }
  }

  port = 0;
  if (GNUNET_CONFIGURATION_have_value (cfg, service_name, "PORT"))
  {
    if (GNUNET_OK !=
	GNUNET_CONFIGURATION_get_value_number (cfg, service_name,
					       "PORT", &port))
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

  if (GNUNET_CONFIGURATION_have_value (cfg, service_name, "BINDTO"))
  {
    GNUNET_break (GNUNET_OK ==
                  GNUNET_CONFIGURATION_get_value_string (cfg, service_name,
                                                         "BINDTO", &hostname));
  }
  else
    hostname = NULL;

  unixpath = NULL;
  abstract = GNUNET_NO;
#ifdef AF_UNIX
  if ((GNUNET_YES ==
       GNUNET_CONFIGURATION_have_value (cfg, service_name, "UNIXPATH")) &&
      (GNUNET_OK ==
       GNUNET_CONFIGURATION_get_value_filename (cfg, service_name, "UNIXPATH",
                                              &unixpath)) &&
      (0 < strlen (unixpath)))
  {
    /* probe UNIX support */
    struct sockaddr_un s_un;

    if (strlen (unixpath) >= sizeof (s_un.sun_path))
    {
      LOG (GNUNET_ERROR_TYPE_WARNING,
           _("UNIXPATH `%s' too long, maximum length is %llu\n"), unixpath,
           (unsigned long long) sizeof (s_un.sun_path));
      unixpath = GNUNET_NETWORK_shorten_unixpath (unixpath);
      LOG (GNUNET_ERROR_TYPE_INFO,
	   _("Using `%s' instead\n"), unixpath);
    }
#ifdef LINUX
    abstract = GNUNET_CONFIGURATION_get_value_yesno (cfg,
                                                     "TESTING",
                                                     "USE_ABSTRACT_SOCKETS");
    if (GNUNET_SYSERR == abstract)
      abstract = GNUNET_NO;
#endif
    if ((GNUNET_YES != abstract)
        && (GNUNET_OK !=
            GNUNET_DISK_directory_create_for_file (unixpath)))
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR,
				"mkdir",
				unixpath);
  }
  if (NULL != unixpath)
  {
    desc = GNUNET_NETWORK_socket_create (AF_UNIX, SOCK_STREAM, 0);
    if (NULL == desc)
    {
      if ((ENOBUFS == errno) || (ENOMEM == errno) || (ENFILE == errno) ||
          (EACCES == errno))
      {
        LOG_STRERROR (GNUNET_ERROR_TYPE_ERROR, "socket");
        GNUNET_free_non_null (hostname);
        GNUNET_free (unixpath);
        return GNUNET_SYSERR;
      }
      LOG (GNUNET_ERROR_TYPE_INFO,
           _("Disabling UNIX domain socket support for service `%s', failed to create UNIX domain socket: %s\n"),
           service_name, STRERROR (errno));
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
    saddrs = GNUNET_malloc (2 * sizeof (struct sockaddr *));
    saddrlens = GNUNET_malloc (2 * sizeof (socklen_t));
    add_unixpath (saddrs, saddrlens, unixpath, abstract);
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
    if ((0 != (ret = getaddrinfo (hostname, NULL, &hints, &res))) ||
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
    saddrs = GNUNET_malloc ((resi + 1) * sizeof (struct sockaddr *));
    saddrlens = GNUNET_malloc ((resi + 1) * sizeof (socklen_t));
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
        memcpy (saddrs[i], pos->ai_addr, saddrlens[i]);
        ((struct sockaddr_in *) saddrs[i])->sin_port = htons (port);
      }
      else
      {
        GNUNET_assert (AF_INET6 == pos->ai_family);
        GNUNET_assert (sizeof (struct sockaddr_in6) == pos->ai_addrlen);
        saddrlens[i] = pos->ai_addrlen;
        saddrs[i] = GNUNET_malloc (saddrlens[i]);
        memcpy (saddrs[i], pos->ai_addr, saddrlens[i]);
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
      saddrs = GNUNET_malloc ((resi + 1) * sizeof (struct sockaddr *));
      saddrlens = GNUNET_malloc ((resi + 1) * sizeof (socklen_t));
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
      saddrs = GNUNET_malloc ((resi + 1) * sizeof (struct sockaddr *));
      saddrlens = GNUNET_malloc ((resi + 1) * sizeof (socklen_t));
      i = 0;
      if (NULL != unixpath)
      {
        add_unixpath (saddrs, saddrlens, unixpath, abstract);
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
 * @param sctx service context to initialize
 * @return #GNUNET_YES if ok, #GNUNET_NO if not ok (must bind yourself),
 * and #GNUNET_SYSERR on error.
 */
static int
receive_sockets_from_parent (struct GNUNET_SERVICE_Context *sctx)
{
  const char *env_buf;
  int fail;
  uint64_t count;
  uint64_t i;
  HANDLE lsocks_pipe;

  env_buf = getenv ("GNUNET_OS_READ_LSOCKS");
  if ((NULL == env_buf) || (strlen (env_buf) <= 0))
    return GNUNET_NO;
  /* Using W32 API directly here, because this pipe will
   * never be used outside of this function, and it's just too much of a bother
   * to create a GNUnet API that boxes a HANDLE (the way it is done with socks)
   */
  lsocks_pipe = (HANDLE) strtoul (env_buf, NULL, 10);
  if ( (0 == lsocks_pipe) || (INVALID_HANDLE_VALUE == lsocks_pipe))
    return GNUNET_NO;
  fail = 1;
  do
  {
    int ret;
    int fail2;
    DWORD rd;

    ret = ReadFile (lsocks_pipe, &count, sizeof (count), &rd, NULL);
    if ((0 == ret) || (sizeof (count) != rd) || (0 == count))
      break;
    sctx->lsocks =
        GNUNET_malloc (sizeof (struct GNUNET_NETWORK_Handle *) * (count + 1));

    fail2 = 1;
    for (i = 0; i < count; i++)
    {
      WSAPROTOCOL_INFOA pi;
      uint64_t size;
      SOCKET s;

      ret = ReadFile (lsocks_pipe, &size, sizeof (size), &rd, NULL);
      if ( (0 == ret) || (sizeof (size) != rd) || (sizeof (pi) != size) )
        break;
      ret = ReadFile (lsocks_pipe, &pi, sizeof (pi), &rd, NULL);
      if ( (0 == ret) || (sizeof (pi) != rd))
        break;
      s = WSASocketA (pi.iAddressFamily, pi.iSocketType, pi.iProtocol, &pi, 0, WSA_FLAG_OVERLAPPED);
      sctx->lsocks[i] = GNUNET_NETWORK_socket_box_native (s);
      if (NULL == sctx->lsocks[i])
        break;
      else if (i == count - 1)
        fail2 = 0;
    }
    if (fail2)
      break;
    sctx->lsocks[count] = NULL;
    fail = 0;
  }
  while (fail);

  CloseHandle (lsocks_pipe);

  if (fail)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _("Could not access a pre-bound socket, will try to bind myself\n"));
    for (i = 0; (i < count) && (NULL != sctx->lsocks[i]); i++)
      GNUNET_break (0 == GNUNET_NETWORK_socket_close (sctx->lsocks[i]));
    GNUNET_free_non_null (sctx->lsocks);
    sctx->lsocks = NULL;
    return GNUNET_NO;
  }
  return GNUNET_YES;
}
#endif


/**
 * Setup addr, addrlen, idle_timeout
 * based on configuration!
 *
 * Configuration may specify:
 * - PORT (where to bind to for TCP)
 * - UNIXPATH (where to bind to for UNIX domain sockets)
 * - TIMEOUT (after how many ms does an inactive service timeout);
 * - DISABLEV6 (disable support for IPv6, otherwise we use dual-stack)
 * - BINDTO (hostname or IP address to bind to, otherwise we take everything)
 * - ACCEPT_FROM  (only allow connections from specified IPv4 subnets)
 * - ACCEPT_FROM6 (only allow connections from specified IPv6 subnets)
 * - REJECT_FROM  (disallow allow connections from specified IPv4 subnets)
 * - REJECT_FROM6 (disallow allow connections from specified IPv6 subnets)
 *
 * @param sctx service context to initialize
 * @return #GNUNET_OK if configuration succeeded
 */
static int
setup_service (struct GNUNET_SERVICE_Context *sctx)
{
  struct GNUNET_TIME_Relative idleout;
  int tolerant;

#ifndef MINGW
  const char *nfds;
  unsigned int cnt;
  int flags;
#endif

  if (GNUNET_CONFIGURATION_have_value (sctx->cfg, sctx->service_name, "TIMEOUT"))
  {
    if (GNUNET_OK !=
        GNUNET_CONFIGURATION_get_value_time (sctx->cfg, sctx->service_name,
                                             "TIMEOUT", &idleout))
    {
      LOG (GNUNET_ERROR_TYPE_ERROR,
           _("Specified value for `%s' of service `%s' is invalid\n"),
           "TIMEOUT", sctx->service_name);
      return GNUNET_SYSERR;
    }
    sctx->timeout = idleout;
  }
  else
    sctx->timeout = GNUNET_TIME_UNIT_FOREVER_REL;

  if (GNUNET_CONFIGURATION_have_value
      (sctx->cfg, sctx->service_name, "TOLERANT"))
  {
    if (GNUNET_SYSERR ==
        (tolerant =
         GNUNET_CONFIGURATION_get_value_yesno (sctx->cfg, sctx->service_name,
                                               "TOLERANT")))
    {
      LOG (GNUNET_ERROR_TYPE_ERROR,
           _("Specified value for `%s' of service `%s' is invalid\n"),
           "TOLERANT", sctx->service_name);
      return GNUNET_SYSERR;
    }
  }
  else
    tolerant = GNUNET_NO;

#ifndef MINGW
  errno = 0;
  if ((NULL != (nfds = getenv ("LISTEN_FDS"))) &&
      (1 == SSCANF (nfds, "%u", &cnt)) && (cnt > 0) && (cnt < FD_SETSIZE) &&
      (cnt + 4 < FD_SETSIZE))
  {
    sctx->lsocks =
        GNUNET_malloc (sizeof (struct GNUNET_NETWORK_Handle *) * (cnt + 1));
    while (0 < cnt--)
    {
      flags = fcntl (3 + cnt, F_GETFD);
      if ((flags < 0) || (0 != (flags & FD_CLOEXEC)) ||
          (NULL ==
           (sctx->lsocks[cnt] = GNUNET_NETWORK_socket_box_native (3 + cnt))))
      {
        LOG (GNUNET_ERROR_TYPE_ERROR,
             _
             ("Could not access pre-bound socket %u, will try to bind myself\n"),
             (unsigned int) 3 + cnt);
        cnt++;
        while (sctx->lsocks[cnt] != NULL)
          GNUNET_break (0 == GNUNET_NETWORK_socket_close (sctx->lsocks[cnt++]));
        GNUNET_free (sctx->lsocks);
        sctx->lsocks = NULL;
        break;
      }
    }
    unsetenv ("LISTEN_FDS");
  }
#else
  if (getenv ("GNUNET_OS_READ_LSOCKS") != NULL)
  {
    receive_sockets_from_parent (sctx);
    putenv ("GNUNET_OS_READ_LSOCKS=");
  }
#endif

  if ((NULL == sctx->lsocks) &&
      (GNUNET_SYSERR ==
       GNUNET_SERVICE_get_server_addresses (sctx->service_name, sctx->cfg,
                                            &sctx->addrs, &sctx->addrlens)))
    return GNUNET_SYSERR;
  sctx->require_found = tolerant ? GNUNET_NO : GNUNET_YES;
  sctx->match_uid =
      GNUNET_CONFIGURATION_get_value_yesno (sctx->cfg, sctx->service_name,
                                            "UNIX_MATCH_UID");
  sctx->match_gid =
      GNUNET_CONFIGURATION_get_value_yesno (sctx->cfg, sctx->service_name,
                                            "UNIX_MATCH_GID");
  process_acl4 (&sctx->v4_denied, sctx, "REJECT_FROM");
  process_acl4 (&sctx->v4_allowed, sctx, "ACCEPT_FROM");
  process_acl6 (&sctx->v6_denied, sctx, "REJECT_FROM6");
  process_acl6 (&sctx->v6_allowed, sctx, "ACCEPT_FROM6");

  return GNUNET_OK;
}


/**
 * Get the name of the user that'll be used
 * to provide the service.
 *
 * @param sctx service context
 * @return value of the 'USERNAME' option
 */
static char *
get_user_name (struct GNUNET_SERVICE_Context *sctx)
{
  char *un;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (sctx->cfg, sctx->service_name,
                                               "USERNAME", &un))
    return NULL;
  return un;
}


/**
 * Write PID file.
 *
 * @param sctx service context
 * @param pid PID to write (should be equal to 'getpid()'
 * @return  #GNUNET_OK on success (including no work to be done)
 */
static int
write_pid_file (struct GNUNET_SERVICE_Context *sctx, pid_t pid)
{
  FILE *pidfd;
  char *pif;
  char *user;
  char *rdir;
  int len;

  if (NULL == (pif = get_pid_file_name (sctx)))
    return GNUNET_OK;           /* no file desired */
  user = get_user_name (sctx);
  rdir = GNUNET_strdup (pif);
  len = strlen (rdir);
  while ((len > 0) && (rdir[len] != DIR_SEPARATOR))
    len--;
  rdir[len] = '\0';
  if (0 != ACCESS (rdir, F_OK))
  {
    /* we get to create a directory -- and claim it
     * as ours! */
    (void) GNUNET_DISK_directory_create (rdir);
    if ((NULL != user) && (0 < strlen (user)))
      GNUNET_DISK_file_change_owner (rdir, user);
  }
  if (0 != ACCESS (rdir, W_OK | X_OK))
  {
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_ERROR, "access", rdir);
    GNUNET_free (rdir);
    GNUNET_free_non_null (user);
    GNUNET_free (pif);
    return GNUNET_SYSERR;
  }
  GNUNET_free (rdir);
  pidfd = FOPEN (pif, "w");
  if (NULL == pidfd)
  {
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_ERROR, "fopen", pif);
    GNUNET_free (pif);
    GNUNET_free_non_null (user);
    return GNUNET_SYSERR;
  }
  if (0 > FPRINTF (pidfd, "%u", pid))
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING, "fprintf", pif);
  GNUNET_break (0 == FCLOSE (pidfd));
  if ((NULL != user) && (0 < strlen (user)))
    GNUNET_DISK_file_change_owner (pif, user);
  GNUNET_free_non_null (user);
  GNUNET_free (pif);
  return GNUNET_OK;
}


/**
 * Task run during shutdown.  Stops the server/service.
 *
 * @param cls the `struct GNUNET_SERVICE_Context`
 * @param tc unused
 */
static void
shutdown_task (void *cls,
               const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_SERVICE_Context *service = cls;
  struct GNUNET_SERVER_Handle *server = service->server;

  service->shutdown_task = NULL;
  if (0 != (service->options & GNUNET_SERVICE_OPTION_SOFT_SHUTDOWN))
    GNUNET_SERVER_stop_listening (server);
  else
    GNUNET_SERVER_destroy (server);
}


/**
 * Initial task for the service.
 *
 * @param cls service context
 * @param tc unused
 */
static void
service_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_SERVICE_Context *sctx = cls;
  unsigned int i;

  if (0 != (GNUNET_SCHEDULER_REASON_SHUTDOWN & tc->reason))
    return;
  (void) GNUNET_SPEEDUP_start_ (sctx->cfg);
  GNUNET_RESOLVER_connect (sctx->cfg);
  if (NULL != sctx->lsocks)
    sctx->server
      = GNUNET_SERVER_create_with_sockets (&check_access, sctx, sctx->lsocks,
                                           sctx->timeout, sctx->require_found);
  else
    sctx->server
      = GNUNET_SERVER_create (&check_access, sctx, sctx->addrs, sctx->addrlens,
                              sctx->timeout, sctx->require_found);
  if (NULL == sctx->server)
  {
    if (NULL != sctx->addrs)
      for (i = 0; NULL != sctx->addrs[i]; i++)
        LOG (GNUNET_ERROR_TYPE_INFO,
             _("Failed to start `%s' at `%s'\n"),
             sctx->service_name, GNUNET_a2s (sctx->addrs[i], sctx->addrlens[i]));
    sctx->ret = GNUNET_SYSERR;
    return;
  }
#ifndef WINDOWS
  if (NULL != sctx->addrs)
    for (i = 0; NULL != sctx->addrs[i]; i++)
      if ((AF_UNIX == sctx->addrs[i]->sa_family)
          && ('\0' != ((const struct sockaddr_un *)sctx->addrs[i])->sun_path[0]))
        GNUNET_DISK_fix_permissions (((const struct sockaddr_un *)sctx->addrs[i])->sun_path,
                                     sctx->match_uid,
                                     sctx->match_gid);
#endif


  if (0 == (sctx->options & GNUNET_SERVICE_OPTION_MANUAL_SHUTDOWN))
  {
    /* install a task that will kill the server
     * process if the scheduler ever gets a shutdown signal */
    sctx->shutdown_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
                                                        &shutdown_task,
							sctx);
  }
  sctx->my_handlers = GNUNET_malloc (sizeof (defhandlers));
  memcpy (sctx->my_handlers, defhandlers, sizeof (defhandlers));
  i = 0;
  while (NULL != sctx->my_handlers[i].callback)
    sctx->my_handlers[i++].callback_cls = sctx;
  GNUNET_SERVER_add_handlers (sctx->server, sctx->my_handlers);
  if (-1 != sctx->ready_confirm_fd)
  {
    GNUNET_break (1 == WRITE (sctx->ready_confirm_fd, ".", 1));
    GNUNET_break (0 == CLOSE (sctx->ready_confirm_fd));
    sctx->ready_confirm_fd = -1;
    write_pid_file (sctx, getpid ());
  }
  if (NULL != sctx->addrs)
  {
    i = 0;
    while (NULL != sctx->addrs[i])
    {
      LOG (GNUNET_ERROR_TYPE_INFO, _("Service `%s' runs at %s\n"),
           sctx->service_name, GNUNET_a2s (sctx->addrs[i], sctx->addrlens[i]));
      i++;
    }
  }
  sctx->task (sctx->task_cls, sctx->server, sctx->cfg);
}


/**
 * Detach from terminal.
 *
 * @param sctx service context
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static int
detach_terminal (struct GNUNET_SERVICE_Context *sctx)
{
#ifndef MINGW
  pid_t pid;
  int nullfd;
  int filedes[2];

  if (0 != PIPE (filedes))
  {
    LOG_STRERROR (GNUNET_ERROR_TYPE_ERROR, "pipe");
    return GNUNET_SYSERR;
  }
  pid = fork ();
  if (pid < 0)
  {
    LOG_STRERROR (GNUNET_ERROR_TYPE_ERROR, "fork");
    return GNUNET_SYSERR;
  }
  if (0 != pid)
  {
    /* Parent */
    char c;

    GNUNET_break (0 == CLOSE (filedes[1]));
    c = 'X';
    if (1 != READ (filedes[0], &c, sizeof (char)))
      LOG_STRERROR (GNUNET_ERROR_TYPE_WARNING, "read");
    fflush (stdout);
    switch (c)
    {
    case '.':
      exit (0);
    case 'I':
      LOG (GNUNET_ERROR_TYPE_INFO, _("Service process failed to initialize\n"));
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
  nullfd = OPEN ("/dev/null", O_RDWR | O_APPEND);
  if (nullfd < 0)
    return GNUNET_SYSERR;
  /* set stdin/stdout to /dev/null */
  if ((dup2 (nullfd, 0) < 0) || (dup2 (nullfd, 1) < 0))
  {
    LOG_STRERROR (GNUNET_ERROR_TYPE_ERROR, "dup2");
    (void) CLOSE (nullfd);
    return GNUNET_SYSERR;
  }
  (void) CLOSE (nullfd);
  /* Detach from controlling terminal */
  pid = setsid ();
  if (-1 == pid)
    LOG_STRERROR (GNUNET_ERROR_TYPE_ERROR, "setsid");
  sctx->ready_confirm_fd = filedes[1];
#else
  /* FIXME: we probably need to do something else
   * elsewhere in order to fork the process itself... */
  FreeConsole ();
#endif
  return GNUNET_OK;
}


/**
 * Set user ID.
 *
 * @param sctx service context
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static int
set_user_id (struct GNUNET_SERVICE_Context *sctx)
{
  char *user;

  if (NULL == (user = get_user_name (sctx)))
    return GNUNET_OK;           /* keep */
#ifndef MINGW
  struct passwd *pws;

  errno = 0;
  pws = getpwnam (user);
  if (NULL == pws)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _("Cannot obtain information about user `%s': %s\n"), user,
         errno == 0 ? _("No such user") : STRERROR (errno));
    GNUNET_free (user);
    return GNUNET_SYSERR;
  }
  if ((0 != setgid (pws->pw_gid)) || (0 != setegid (pws->pw_gid)) ||
#if HAVE_INITGROUPS
      (0 != initgroups (user, pws->pw_gid)) ||
#endif
      (0 != setuid (pws->pw_uid)) || (0 != seteuid (pws->pw_uid)))
  {
    if ((0 != setregid (pws->pw_gid, pws->pw_gid)) ||
        (0 != setreuid (pws->pw_uid, pws->pw_uid)))
    {
      LOG (GNUNET_ERROR_TYPE_ERROR, _("Cannot change user/group to `%s': %s\n"),
           user, STRERROR (errno));
      GNUNET_free (user);
      return GNUNET_SYSERR;
    }
  }
#endif
  GNUNET_free (user);
  return GNUNET_OK;
}


/**
 * Delete the PID file that was created by our parent.
 *
 * @param sctx service context
 */
static void
pid_file_delete (struct GNUNET_SERVICE_Context *sctx)
{
  char *pif = get_pid_file_name (sctx);

  if (NULL == pif)
    return;                     /* no PID file */
  if (0 != UNLINK (pif))
    LOG_STRERROR_FILE (GNUNET_ERROR_TYPE_WARNING, "unlink", pif);
  GNUNET_free (pif);
}


/**
 * Run a standard GNUnet service startup sequence (initialize loggers
 * and configuration, parse options).
 *
 * @param argc number of command line arguments
 * @param argv command line arguments
 * @param service_name our service name
 * @param options service options
 * @param task main task of the service
 * @param task_cls closure for @a task
 * @return #GNUNET_SYSERR on error, #GNUNET_OK
 *         if we shutdown nicely
 */
int
GNUNET_SERVICE_run (int argc, char *const *argv,
                    const char *service_name,
                    enum GNUNET_SERVICE_Options options,
                    GNUNET_SERVICE_Main task,
                    void *task_cls)
{
#define HANDLE_ERROR do { GNUNET_break (0); goto shutdown; } while (0)

  int err;
  int ret;
  char *cfg_fn;
  char *opt_cfg_fn;
  char *loglev;
  char *logfile;
  int do_daemonize;
  unsigned int i;
  unsigned long long skew_offset;
  unsigned long long skew_variance;
  long long clock_offset;
  struct GNUNET_SERVICE_Context sctx;
  struct GNUNET_CONFIGURATION_Handle *cfg;
  const char *xdg;

  struct GNUNET_GETOPT_CommandLineOption service_options[] = {
    GNUNET_GETOPT_OPTION_CFG_FILE (&opt_cfg_fn),
    {'d', "daemonize", NULL,
     gettext_noop ("do daemonize (detach from terminal)"), 0,
     GNUNET_GETOPT_set_one, &do_daemonize},
    GNUNET_GETOPT_OPTION_HELP (NULL),
    GNUNET_GETOPT_OPTION_LOGLEVEL (&loglev),
    GNUNET_GETOPT_OPTION_LOGFILE (&logfile),
    GNUNET_GETOPT_OPTION_VERSION (PACKAGE_VERSION " " VCS_VERSION),
    GNUNET_GETOPT_OPTION_END
  };
  err = 1;
  do_daemonize = 0;
  logfile = NULL;
  loglev = NULL;
  opt_cfg_fn = NULL;
  xdg = getenv ("XDG_CONFIG_HOME");
  if (NULL != xdg)
    GNUNET_asprintf (&cfg_fn,
                     "%s%s%s",
                     xdg,
                     DIR_SEPARATOR_STR,
                     "gnunet.conf");
  else
    cfg_fn = GNUNET_strdup (GNUNET_DEFAULT_USER_CONFIG_FILE);
  memset (&sctx, 0, sizeof (sctx));
  sctx.options = options;
  sctx.ready_confirm_fd = -1;
  sctx.ret = GNUNET_OK;
  sctx.timeout = GNUNET_TIME_UNIT_FOREVER_REL;
  sctx.task = task;
  sctx.task_cls = task_cls;
  sctx.service_name = service_name;
  sctx.cfg = cfg = GNUNET_CONFIGURATION_create ();

  /* setup subsystems */
  ret = GNUNET_GETOPT_run (service_name, service_options, argc, argv);
  if (GNUNET_SYSERR == ret)
    goto shutdown;
  if (GNUNET_NO == ret)
  {
    err = 0;
    goto shutdown;
  }
  if (GNUNET_OK != GNUNET_log_setup (service_name, loglev, logfile))
    HANDLE_ERROR;
  if (NULL == opt_cfg_fn)
    opt_cfg_fn = GNUNET_strdup (cfg_fn);
  if (GNUNET_YES == GNUNET_DISK_file_test (opt_cfg_fn))
  {
    if (GNUNET_SYSERR == GNUNET_CONFIGURATION_load (cfg, opt_cfg_fn))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("Malformed configuration file `%s', exit ...\n"),
                  opt_cfg_fn);
      goto shutdown;
    }
  }
  else
  {
    if (GNUNET_SYSERR == GNUNET_CONFIGURATION_load (cfg, NULL))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("Malformed configuration, exit ...\n"));
      goto shutdown;
    }
    if (0 != strcmp (opt_cfg_fn, cfg_fn))
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Could not access configuration file `%s'\n"),
		  opt_cfg_fn);
  }
  if (GNUNET_OK != setup_service (&sctx))
    goto shutdown;
  if ((1 == do_daemonize) && (GNUNET_OK != detach_terminal (&sctx)))
    HANDLE_ERROR;
  if (GNUNET_OK != set_user_id (&sctx))
    goto shutdown;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Service `%s' runs with configuration from `%s'\n",
       service_name,
       opt_cfg_fn);
  if ((GNUNET_OK ==
       GNUNET_CONFIGURATION_get_value_number (sctx.cfg, "TESTING",
                                              "SKEW_OFFSET", &skew_offset)) &&
      (GNUNET_OK ==
       GNUNET_CONFIGURATION_get_value_number (sctx.cfg, "TESTING",
                                              "SKEW_VARIANCE", &skew_variance)))
  {
    clock_offset = skew_offset - skew_variance;
    GNUNET_TIME_set_offset (clock_offset);
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Skewing clock by %dll ms\n", clock_offset);
  }
  /* actually run service */
  err = 0;
  GNUNET_SCHEDULER_run (&service_task, &sctx);
  /* shutdown */
  if ((1 == do_daemonize) && (NULL != sctx.server))
    pid_file_delete (&sctx);
  GNUNET_free_non_null (sctx.my_handlers);

shutdown:
  if (-1 != sctx.ready_confirm_fd)
  {
    if (1 != WRITE (sctx.ready_confirm_fd, err ? "I" : "S", 1))
      LOG_STRERROR (GNUNET_ERROR_TYPE_WARNING, "write");
    GNUNET_break (0 == CLOSE (sctx.ready_confirm_fd));
  }
#if HAVE_MALLINFO
  {
    char *counter;

    if ( (GNUNET_YES ==
	  GNUNET_CONFIGURATION_have_value (sctx.cfg, service_name,
					   "GAUGER_HEAP")) &&
	 (GNUNET_OK ==
	  GNUNET_CONFIGURATION_get_value_string (sctx.cfg, service_name,
						 "GAUGER_HEAP",
						 &counter)) )
    {
      struct mallinfo mi;

      mi = mallinfo ();
      GAUGER (service_name, counter, mi.usmblks, "blocks");
      GNUNET_free (counter);
    }
  }
#endif
  GNUNET_SPEEDUP_stop_ ();
  GNUNET_CONFIGURATION_destroy (cfg);
  i = 0;
  if (NULL != sctx.addrs)
    while (NULL != sctx.addrs[i])
      GNUNET_free (sctx.addrs[i++]);
  GNUNET_free_non_null (sctx.addrs);
  GNUNET_free_non_null (sctx.addrlens);
  GNUNET_free_non_null (logfile);
  GNUNET_free_non_null (loglev);
  GNUNET_free (cfg_fn);
  GNUNET_free_non_null (opt_cfg_fn);
  GNUNET_free_non_null (sctx.v4_denied);
  GNUNET_free_non_null (sctx.v6_denied);
  GNUNET_free_non_null (sctx.v4_allowed);
  GNUNET_free_non_null (sctx.v6_allowed);

  return err ? GNUNET_SYSERR : sctx.ret;
}


/**
 * Run a service startup sequence within an existing
 * initialized system.
 *
 * @param service_name our service name
 * @param cfg configuration to use
 * @param options service options
 * @return NULL on error, service handle
 */
struct GNUNET_SERVICE_Context *
GNUNET_SERVICE_start (const char *service_name,
                      const struct GNUNET_CONFIGURATION_Handle *cfg,
		      enum GNUNET_SERVICE_Options options)
{
  int i;
  struct GNUNET_SERVICE_Context *sctx;

  sctx = GNUNET_new (struct GNUNET_SERVICE_Context);
  sctx->ready_confirm_fd = -1;  /* no daemonizing */
  sctx->ret = GNUNET_OK;
  sctx->timeout = GNUNET_TIME_UNIT_FOREVER_REL;
  sctx->service_name = service_name;
  sctx->cfg = cfg;
  sctx->options = options;

  /* setup subsystems */
  if (GNUNET_OK != setup_service (sctx))
  {
    GNUNET_SERVICE_stop (sctx);
    return NULL;
  }
  if (NULL != sctx->lsocks)
    sctx->server =
        GNUNET_SERVER_create_with_sockets (&check_access, sctx, sctx->lsocks,
                                           sctx->timeout, sctx->require_found);
  else
    sctx->server =
        GNUNET_SERVER_create (&check_access, sctx, sctx->addrs, sctx->addrlens,
                              sctx->timeout, sctx->require_found);

  if (NULL == sctx->server)
  {
    GNUNET_SERVICE_stop (sctx);
    return NULL;
  }
#ifndef WINDOWS
  if (NULL != sctx->addrs)
    for (i = 0; NULL != sctx->addrs[i]; i++)
      if ((AF_UNIX == sctx->addrs[i]->sa_family)
          && ('\0' != ((const struct sockaddr_un *)sctx->addrs[i])->sun_path[0]))
        GNUNET_DISK_fix_permissions (((const struct sockaddr_un *)sctx->addrs[i])->sun_path,
                                     sctx->match_uid,
                                     sctx->match_gid);
#endif
  sctx->my_handlers = GNUNET_malloc (sizeof (defhandlers));
  memcpy (sctx->my_handlers, defhandlers, sizeof (defhandlers));
  i = 0;
  while ((sctx->my_handlers[i].callback != NULL))
    sctx->my_handlers[i++].callback_cls = sctx;
  GNUNET_SERVER_add_handlers (sctx->server, sctx->my_handlers);
  return sctx;
}


/**
 * Obtain the server used by a service.  Note that the server must NOT
 * be destroyed by the caller.
 *
 * @param ctx the service context returned from the start function
 * @return handle to the server for this service, NULL if there is none
 */
struct GNUNET_SERVER_Handle *
GNUNET_SERVICE_get_server (struct GNUNET_SERVICE_Context *ctx)
{
  return ctx->server;
}


/**
 * Get the NULL-terminated array of listen sockets for this service.
 *
 * @param ctx service context to query
 * @return NULL if there are no listen sockets, otherwise NULL-terminated
 *              array of listen sockets.
 */
struct GNUNET_NETWORK_Handle *const*
GNUNET_SERVICE_get_listen_sockets (struct GNUNET_SERVICE_Context *ctx)
{
  return ctx->lsocks;
}


/**
 * Stop a service that was started with "GNUNET_SERVICE_start".
 *
 * @param sctx the service context returned from the start function
 */
void
GNUNET_SERVICE_stop (struct GNUNET_SERVICE_Context *sctx)
{
  unsigned int i;

#if HAVE_MALLINFO
  {
    char *counter;

    if ( (GNUNET_YES ==
	  GNUNET_CONFIGURATION_have_value (sctx->cfg, sctx->service_name,
					   "GAUGER_HEAP")) &&
	 (GNUNET_OK ==
	  GNUNET_CONFIGURATION_get_value_string (sctx->cfg, sctx->service_name,
						 "GAUGER_HEAP",
						 &counter)) )
    {
      struct mallinfo mi;

      mi = mallinfo ();
      GAUGER (sctx->service_name, counter, mi.usmblks, "blocks");
      GNUNET_free (counter);
    }
  }
#endif
  if (NULL != sctx->shutdown_task)
  {
    GNUNET_SCHEDULER_cancel (sctx->shutdown_task);
    sctx->shutdown_task = NULL;
  }
  if (NULL != sctx->server)
    GNUNET_SERVER_destroy (sctx->server);
  GNUNET_free_non_null (sctx->my_handlers);
  if (NULL != sctx->addrs)
  {
    i = 0;
    while (NULL != sctx->addrs[i])
      GNUNET_free (sctx->addrs[i++]);
    GNUNET_free (sctx->addrs);
  }
  GNUNET_free_non_null (sctx->addrlens);
  GNUNET_free_non_null (sctx->v4_denied);
  GNUNET_free_non_null (sctx->v6_denied);
  GNUNET_free_non_null (sctx->v4_allowed);
  GNUNET_free_non_null (sctx->v6_allowed);
  GNUNET_free (sctx);
}


/* end of service.c */
