/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

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
 * @file util/service.c
 * @brief functions related to starting services
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_configuration_lib.h"
#include "gnunet_crypto_lib.h"
#include "gnunet_directories.h"
#include "gnunet_disk_lib.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_os_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_server_lib.h"
#include "gnunet_service_lib.h"

/* ******************* access control ******************** */

/**
 * @brief IPV4 network in CIDR notation.
 */
struct IPv4NetworkSet
{
  struct in_addr network;
  struct in_addr netmask;
};

/**
 * @brief network in CIDR notation for IPV6.
 */
struct IPv6NetworkSet
{
  struct in6_addr network;
  struct in6_addr netmask;
};


/**
 * Parse a network specification. The argument specifies
 * a list of networks. The format is
 * <tt>[network/netmask;]*</tt> (no whitespace, must be terminated
 * with a semicolon). The network must be given in dotted-decimal
 * notation. The netmask can be given in CIDR notation (/16) or
 * in dotted-decimal (/255.255.0.0).
 * <p>
 * @param routeList a string specifying the forbidden networks
 * @return the converted list, NULL if the synatx is flawed
 */
static struct IPv4NetworkSet *
parse_ipv4_specification (const char *routeList)
{
  unsigned int count;
  unsigned int i;
  unsigned int j;
  unsigned int len;
  int cnt;
  unsigned int pos;
  unsigned int temps[8];
  int slash;
  struct IPv4NetworkSet *result;

  if (routeList == NULL)
    return NULL;
  len = strlen (routeList);
  if (len == 0)
    return NULL;
  count = 0;
  for (i = 0; i < len; i++)
    if (routeList[i] == ';')
      count++;
  result = GNUNET_malloc (sizeof (struct IPv4NetworkSet) * (count + 1));
  /* add termination */
  memset (result, 0, sizeof (struct IPv4NetworkSet) * (count + 1));
  i = 0;
  pos = 0;
  while (i < count)
    {
      cnt = sscanf (&routeList[pos],
                    "%u.%u.%u.%u/%u.%u.%u.%u;",
                    &temps[0],
                    &temps[1],
                    &temps[2],
                    &temps[3], &temps[4], &temps[5], &temps[6], &temps[7]);
      if (cnt == 8)
        {
          for (j = 0; j < 8; j++)
            if (temps[j] > 0xFF)
              {
                GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                            _("Invalid format for IP: `%s'\n"),
                            &routeList[pos]);
                GNUNET_free (result);
                return NULL;
              }
          result[i].network.s_addr
            =
            htonl ((temps[0] << 24) + (temps[1] << 16) + (temps[2] << 8) +
                   temps[3]);
          result[i].netmask.s_addr =
            htonl ((temps[4] << 24) + (temps[5] << 16) + (temps[6] << 8) +
                   temps[7]);
          while (routeList[pos] != ';')
            pos++;
          pos++;
          i++;
          continue;
        }
      /* try second notation */
      cnt = sscanf (&routeList[pos],
                    "%u.%u.%u.%u/%u;",
                    &temps[0], &temps[1], &temps[2], &temps[3], &slash);
      if (cnt == 5)
        {
          for (j = 0; j < 4; j++)
            if (temps[j] > 0xFF)
              {
                GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                            _("Invalid format for IP: `%s'\n"),
                            &routeList[pos]);
                GNUNET_free (result);
                return NULL;
              }
          result[i].network.s_addr
            =
            htonl ((temps[0] << 24) + (temps[1] << 16) + (temps[2] << 8) +
                   temps[3]);
          if ((slash <= 32) && (slash >= 0))
            {
              result[i].netmask.s_addr = 0;
              while (slash > 0)
                {
                  result[i].netmask.s_addr
                    = (result[i].netmask.s_addr >> 1) + 0x80000000;
                  slash--;
                }
              result[i].netmask.s_addr = htonl (result[i].netmask.s_addr);
              while (routeList[pos] != ';')
                pos++;
              pos++;
              i++;
              continue;
            }
          else
            {
              GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                          _
                          ("Invalid network notation ('/%d' is not legal in IPv4 CIDR)."),
                          slash);
              GNUNET_free (result);
              return NULL;      /* error */
            }
        }
      /* try third notation */
      slash = 32;
      cnt = sscanf (&routeList[pos],
                    "%u.%u.%u.%u;",
                    &temps[0], &temps[1], &temps[2], &temps[3]);
      if (cnt == 4)
        {
          for (j = 0; j < 4; j++)
            if (temps[j] > 0xFF)
              {
                GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                            _("Invalid format for IP: `%s'\n"),
                            &routeList[pos]);
                GNUNET_free (result);
                return NULL;
              }
          result[i].network.s_addr
            =
            htonl ((temps[0] << 24) + (temps[1] << 16) + (temps[2] << 8) +
                   temps[3]);
          result[i].netmask.s_addr = 0;
          while (slash > 0)
            {
              result[i].netmask.s_addr
                = (result[i].netmask.s_addr >> 1) + 0x80000000;
              slash--;
            }
          result[i].netmask.s_addr = htonl (result[i].netmask.s_addr);
          while (routeList[pos] != ';')
            pos++;
          pos++;
          i++;
          continue;
        }
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("Invalid format for IP: `%s'\n"), &routeList[pos]);
      GNUNET_free (result);
      return NULL;              /* error */
    }
  if (pos < strlen (routeList))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("Invalid format for IP: `%s'\n"), &routeList[pos]);
      GNUNET_free (result);
      return NULL;              /* oops */
    }
  return result;                /* ok */
}


/**
 * Parse a network specification. The argument specifies
 * a list of networks. The format is
 * <tt>[network/netmask;]*</tt> (no whitespace, must be terminated
 * with a semicolon). The network must be given in colon-hex
 * notation.  The netmask must be given in CIDR notation (/16) or
 * can be omitted to specify a single host.
 * <p>
 * @param routeListX a string specifying the forbidden networks
 * @return the converted list, NULL if the synatx is flawed
 */
static struct IPv6NetworkSet *
parse_ipv6_specification (const char *routeListX)
{
  unsigned int count;
  unsigned int i;
  unsigned int len;
  unsigned int pos;
  int start;
  int slash;
  int ret;
  char *routeList;
  struct IPv6NetworkSet *result;
  unsigned int bits;
  unsigned int off;
  int save;

  if (routeListX == NULL)
    return NULL;
  len = strlen (routeListX);
  if (len == 0)
    return NULL;
  routeList = GNUNET_strdup (routeListX);
  count = 0;
  for (i = 0; i < len; i++)
    if (routeList[i] == ';')
      count++;
  if (routeList[len - 1] != ';')
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _
                  ("Invalid network notation (does not end with ';': `%s')\n"),
                  routeList);
      GNUNET_free (routeList);
      return NULL;
    }

  result = GNUNET_malloc (sizeof (struct IPv6NetworkSet) * (count + 1));
  memset (result, 0, sizeof (struct IPv6NetworkSet) * (count + 1));
  i = 0;
  pos = 0;
  while (i < count)
    {
      start = pos;
      while (routeList[pos] != ';')
        pos++;
      slash = pos;
      while ((slash >= start) && (routeList[slash] != '/'))
        slash--;
      if (slash < start)
        {
          memset (&result[i].netmask, 0xFF, sizeof (struct in6_addr));
          slash = pos;
        }
      else
        {
          routeList[pos] = '\0';
          ret = inet_pton (AF_INET6,
                           &routeList[slash + 1], &result[i].netmask);
          if (ret <= 0)
            {
              save = errno;
              if ((1 != SSCANF (&routeList[slash + 1],
                                "%u", &bits)) || (bits >= 128))
                {
                  if (ret == 0)
                    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                                _("Wrong format `%s' for netmask\n"),
                                &routeList[slash + 1]);
                  else
                    {
                      errno = save;
                      GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR,
                                           "inet_pton");
                    }
                  GNUNET_free (result);
                  GNUNET_free (routeList);
                  return NULL;
                }
              off = 0;
              while (bits > 8)
                {
                  result[i].netmask.s6_addr[off++] = 0xFF;
                  bits -= 8;
                }
              while (bits > 0)
                {
                  result[i].netmask.s6_addr[off]
                    = (result[i].netmask.s6_addr[off] >> 1) + 0x80;
                  bits--;
                }
            }
        }
      routeList[slash] = '\0';
      ret = inet_pton (AF_INET6, &routeList[start], &result[i].network);
      if (ret <= 0)
        {
          if (ret == 0)
            GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                        _("Wrong format `%s' for network\n"),
                        &routeList[slash + 1]);
          else
            GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "inet_pton");
          GNUNET_free (result);
          GNUNET_free (routeList);
          return NULL;
        }
      pos++;
      i++;
    }
  GNUNET_free (routeList);
  return result;
}


/**
 * Check if the given IP address is in the list of IP addresses.
 *
 * @param list a list of networks
 * @param add the IP to check (in network byte order)
 * @return GNUNET_NO if the IP is not in the list, GNUNET_YES if it it is
 */
static int
check_ipv4_listed (const struct IPv4NetworkSet *list,
                   const struct in_addr *add)
{
  int i;

  i = 0;
  if (list == NULL)
    return GNUNET_NO;

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
 * @return GNUNET_NO if the IP is not in the list, GNUNET_YES if it it is
 */
static int
check_ipv6_listed (const struct IPv6NetworkSet *list,
                   const struct in6_addr *ip)
{
  unsigned int i;
  unsigned int j;
  struct in6_addr zero;

  if (list == NULL)
    return GNUNET_NO;

  memset (&zero, 0, sizeof (struct in6_addr));
  i = 0;
NEXT:
  while (memcmp (&zero, &list[i].network, sizeof (struct in6_addr)) != 0)
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
   * Scheduler for the server.
   */
  struct GNUNET_SCHEDULER_Handle *sched;

  /**
   * Address to bind to.
   */
  struct sockaddr *addr;

  /**
   * Name of our service.
   */
  const char *serviceName;

  /**
   * Main service-specific task to run.
   */
  GNUNET_SERVICE_Main task;

  /**
   * Closure for task.
   */
  void *task_cls;

  /**
   * IPv4 addresses that are not allowed to connect.
   */
  struct IPv4NetworkSet *v4_denied;

  /**
   * IPv6 addresses that are not allowed to connect.
   */
  struct IPv6NetworkSet *v6_denied;

  /**
   * IPv4 addresses that are allowed to connect (if not
   * set, all are allowed).
   */
  struct IPv4NetworkSet *v4_allowed;

  /**
   * IPv6 addresses that are allowed to connect (if not
   * set, all are allowed).
   */
  struct IPv6NetworkSet *v6_allowed;

  /**
   * My (default) message handlers.  Adjusted copy
   * of "defhandlers".
   */
  struct GNUNET_SERVER_MessageHandler *my_handlers;

  /**
   * Idle timeout for server.
   */
  struct GNUNET_TIME_Relative timeout;

  /**
   * Maximum buffer size for the server.
   */
  size_t maxbuf;

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
   * Can clients ask us to initiate a shutdown?
   */
  int allow_shutdown;

  /**
   * Length of addr.
   */
  socklen_t addrlen;

};


/* ****************** message handlers ****************** */

static size_t
write_test (void *cls, size_t size, void *buf)
{
  struct GNUNET_SERVER_Client *client = cls;
  struct GNUNET_MessageHeader *msg;

  if (size < sizeof (struct GNUNET_MessageHeader))
    {
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return 0;                 /* client disconnected */
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
handle_test (void *cls,
             struct GNUNET_SERVER_Client *client,
             const struct GNUNET_MessageHeader *message)
{
  /* simply bounce message back to acknowledge */
  if (NULL == GNUNET_SERVER_notify_transmit_ready (client,
                                                   sizeof (struct
                                                           GNUNET_MessageHeader),
                                                   GNUNET_TIME_UNIT_FOREVER_REL,
                                                   &write_test, client))
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
}


/**
 * Handler for SHUTDOWN message.
 *
 * @param cls closure (refers to service)
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_shutdown (void *cls,
                 struct GNUNET_SERVER_Client *client,
                 const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_SERVICE_Context *service = cls;
  if (!service->allow_shutdown)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _
                  ("Received shutdown request, but configured to ignore!\n"));
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              _("Initiating shutdown as requested by client.\n"));
  GNUNET_assert (service->sched != NULL);
  GNUNET_SCHEDULER_shutdown (service->sched);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Default handlers for all services.  Will be copied and the
 * "callback_cls" fields will be replaced with the specific service
 * struct.
 */
static const struct GNUNET_SERVER_MessageHandler defhandlers[] = {
  {&handle_test, NULL, GNUNET_MESSAGE_TYPE_TEST,
   sizeof (struct GNUNET_MessageHeader)},
  {&handle_shutdown, NULL, GNUNET_MESSAGE_TYPE_SHUTDOWN,
   sizeof (struct GNUNET_MessageHeader)},
  {NULL, NULL, 0, 0}
};



/* ****************** service core routines ************** */


/**
 * Check if access to the service is allowed from the given address.
 */
static int
check_access (void *cls, const struct sockaddr *addr, socklen_t addrlen)
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
      ret = ((sctx->v4_allowed == NULL) ||
             (check_ipv4_listed (sctx->v4_allowed,
                                 &i4->sin_addr)))
        && ((sctx->v4_denied == NULL) ||
            (!check_ipv4_listed (sctx->v4_denied, &i4->sin_addr)));
      break;
    case AF_INET6:
      GNUNET_assert (addrlen == sizeof (struct sockaddr_in6));
      i6 = (const struct sockaddr_in6 *) addr;
      ret = ((sctx->v6_allowed == NULL) ||
             (check_ipv6_listed (sctx->v6_allowed,
                                 &i6->sin6_addr)))
        && ((sctx->v6_denied == NULL) ||
            (!check_ipv6_listed (sctx->v6_denied, &i6->sin6_addr)));
      break;
    default:
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _("Unknown address family %d\n"), addr->sa_family);
      return GNUNET_SYSERR;
    }
  if (ret != GNUNET_OK)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _("Access from `%s' denied to service `%s'\n"),
                  GNUNET_a2s(addr, addrlen), sctx->serviceName);
    }
  return ret;
}


/**
 * Get the name of the file where we will
 * write the PID of the service.
 */
static char *
get_pid_file_name (struct GNUNET_SERVICE_Context *sctx)
{

  char *pif;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (sctx->cfg,
                                               sctx->serviceName,
                                               "PIDFILE", &pif))
    return NULL;
  return pif;
}


/**
 * Parse an IPv4 access control list.
 */
static int
process_acl4 (struct IPv4NetworkSet **ret,
              struct GNUNET_SERVICE_Context *sctx, const char *option)
{
  char *opt;

  if (!GNUNET_CONFIGURATION_have_value (sctx->cfg, sctx->serviceName, option))
    return GNUNET_OK;
  GNUNET_break (GNUNET_OK ==
                GNUNET_CONFIGURATION_get_value_string (sctx->cfg,
                                                       sctx->serviceName,
                                                       option, &opt));
  if (NULL == (*ret = parse_ipv4_specification (opt)))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _
                  ("Could not parse IPv4 network specification `%s' for `%s:%s'\n"),
                  opt, sctx->serviceName, option);
      GNUNET_free (opt);
      return GNUNET_SYSERR;
    }
  GNUNET_free (opt);
  return GNUNET_OK;
}


/**
 * Parse an IPv4 access control list.
 */
static int
process_acl6 (struct IPv6NetworkSet **ret,
              struct GNUNET_SERVICE_Context *sctx, const char *option)
{
  char *opt;
  if (!GNUNET_CONFIGURATION_have_value (sctx->cfg, sctx->serviceName, option))
    return GNUNET_OK;
  GNUNET_break (GNUNET_OK ==
                GNUNET_CONFIGURATION_get_value_string (sctx->cfg,
                                                       sctx->serviceName,
                                                       option, &opt));
  if (NULL == (*ret = parse_ipv6_specification (opt)))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _
                  ("Could not parse IPv6 network specification `%s' for `%s:%s'\n"),
                  opt, sctx->serviceName, option);
      GNUNET_free (opt);
      return GNUNET_SYSERR;
    }
  GNUNET_free (opt);
  return GNUNET_OK;
}


/**
 * Setup addr, addrlen, maxbuf, idle_timeout
 * based on configuration!
 *
 * Configuration must specify a "PORT".  It may
 * specify:
 * - TIMEOUT (after how many ms does an inactive service timeout);
 * - MAXBUF (maximum incoming message size supported)
 * - DISABLEV6 (disable support for IPv6, otherwise we use dual-stack)
 * - ALLOW_SHUTDOWN (allow clients to shutdown this service)
 * - BINDTO (hostname or IP address to bind to, otherwise we take everything)
 * - ACCEPT_FROM  (only allow connections from specified IPv4 subnets)
 * - ACCEPT_FROM6 (only allow connections from specified IPv6 subnets)
 * - REJECT_FROM  (disallow allow connections from specified IPv4 subnets)
 * - REJECT_FROM6 (disallow allow connections from specified IPv6 subnets)
 *
 * @return GNUNET_OK if configuration succeeded
 */
static int
setup_service (struct GNUNET_SERVICE_Context *sctx)
{
  unsigned long long maxbuf;
  struct GNUNET_TIME_Relative idleout;
  char *hostname;
  unsigned long long port;
  int disablev6;
  struct addrinfo hints;
  struct addrinfo *res;
  struct addrinfo *pos;
  int ret;
  int tolerant;
  struct GNUNET_NETWORK_Handle *desc;

  if (GNUNET_CONFIGURATION_have_value (sctx->cfg,
                                       sctx->serviceName, "TIMEOUT"))
    {
      if (GNUNET_OK !=
          GNUNET_CONFIGURATION_get_value_time (sctx->cfg,
					       sctx->serviceName,
					       "TIMEOUT", &idleout))
        return GNUNET_SYSERR;

      sctx->timeout = idleout;
    }
  else
    sctx->timeout = GNUNET_TIME_UNIT_FOREVER_REL;
  if (GNUNET_CONFIGURATION_have_value (sctx->cfg,
                                       sctx->serviceName, "MAXBUF"))
    {
      if (GNUNET_OK !=
          GNUNET_CONFIGURATION_get_value_number (sctx->cfg,
                                                 sctx->serviceName,
                                                 "MAXBUF", &maxbuf))
        return GNUNET_SYSERR;
    }
  else
    maxbuf = GNUNET_SERVER_MAX_MESSAGE_SIZE;
  if (GNUNET_CONFIGURATION_have_value (sctx->cfg,
                                       sctx->serviceName, "DISABLEV6"))
    {
      if (GNUNET_SYSERR ==
          (disablev6 = GNUNET_CONFIGURATION_get_value_yesno (sctx->cfg,
                                                             sctx->serviceName,
                                                             "DISABLEV6")))
        return GNUNET_SYSERR;
    }
  else
    disablev6 = GNUNET_NO;
  if (GNUNET_CONFIGURATION_have_value (sctx->cfg,
                                       sctx->serviceName, "ALLOW_SHUTDOWN"))
    {
      if (GNUNET_SYSERR ==
          (sctx->allow_shutdown =
           GNUNET_CONFIGURATION_get_value_yesno (sctx->cfg, sctx->serviceName,
                                                 "ALLOW_SHUTDOWN")))
        return GNUNET_SYSERR;
    }
  else
    sctx->allow_shutdown = GNUNET_NO;

  if (!disablev6)
    {
      /* probe IPv6 support */
      desc = GNUNET_NETWORK_socket_create (PF_INET6, SOCK_STREAM, 0);
      if (NULL == desc)
        {
          if ((errno == ENOBUFS) ||
              (errno == ENOMEM) || (errno == ENFILE) || (errno == EACCES))
            {
              GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "socket");
              return GNUNET_SYSERR;
            }
	  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		      _("Disabling IPv6 support for service `%s', failed to create IPv6 socket: %s\n"),
		      sctx->serviceName,
		      STRERROR (errno));
	  disablev6 = GNUNET_YES;
        }
      else
	{
	  GNUNET_break (GNUNET_OK == GNUNET_NETWORK_socket_close (desc));
	}
    }



  if (GNUNET_CONFIGURATION_have_value (sctx->cfg,
                                       sctx->serviceName, "TOLERANT"))
    {
      if (GNUNET_SYSERR ==
          (tolerant = GNUNET_CONFIGURATION_get_value_yesno (sctx->cfg,
                                                            sctx->serviceName,
                                                            "TOLERANT")))
        return GNUNET_SYSERR;
    }
  else
    tolerant = GNUNET_NO;
  sctx->require_found = tolerant ? GNUNET_NO : GNUNET_YES;


  if ((GNUNET_OK !=
       GNUNET_CONFIGURATION_get_value_number (sctx->cfg,
                                              sctx->serviceName,
                                              "PORT",
                                              &port)) || (port > 65535))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _
                  ("Require valid port number for service `%s' in configuration!\n"),
                  sctx->serviceName);
      return GNUNET_SYSERR;
    }
  if (GNUNET_CONFIGURATION_have_value (sctx->cfg,
                                       sctx->serviceName, "BINDTO"))
    {
      GNUNET_break (GNUNET_OK ==
                    GNUNET_CONFIGURATION_get_value_string (sctx->cfg,
                                                           sctx->serviceName,
                                                           "BINDTO",
                                                           &hostname));
    }
  else
    hostname = NULL;

  if (hostname != NULL)
    {
      memset (&hints, 0, sizeof (struct addrinfo));
      if (disablev6)
        hints.ai_family = AF_INET;
      if ((0 != (ret = getaddrinfo (hostname,
                                    NULL, &hints, &res))) || (res == NULL))
        {
          GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                      _("Failed to resolve `%s': %s\n"),
                      hostname, gai_strerror (ret));
          GNUNET_free (hostname);
          return GNUNET_SYSERR;
        }
      pos = res;
      while ((NULL != pos) &&
             (((disablev6) &&
               (pos->ai_family != AF_INET)) ||
              ((pos->ai_family != AF_INET) && (pos->ai_family != AF_INET6))))
        pos = pos->ai_next;
      if (pos == NULL)
        {
          GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                      _("Failed to find %saddress for `%s'.\n"),
		      disablev6 ? "IPv4 " : "", hostname);
          freeaddrinfo (res);
          GNUNET_free (hostname);
          return GNUNET_SYSERR;
        }
      GNUNET_free (hostname);
      if (pos->ai_family == AF_INET)
        {
          GNUNET_assert (pos->ai_addrlen == sizeof (struct sockaddr_in));
          sctx->addrlen = pos->ai_addrlen;
          sctx->addr = GNUNET_malloc (sctx->addrlen);
          memcpy (sctx->addr, res->ai_addr, sctx->addrlen);
          ((struct sockaddr_in *) sctx->addr)->sin_port = htons (port);
          GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                      _
                      ("Configured to bind to %s address; %s connections to this service will fail!\n"),
                      "IPv4", "IPv6");
        }
      else
        {
          GNUNET_assert (pos->ai_family == AF_INET6);
          GNUNET_assert (pos->ai_addrlen == sizeof (struct sockaddr_in6));
          sctx->addrlen = pos->ai_addrlen;
          sctx->addr = GNUNET_malloc (sctx->addrlen);
          memcpy (sctx->addr, res->ai_addr, sctx->addrlen);
          GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                      _
                      ("Configured to bind to %s address; %s connections to this service will fail!\n"),
                      "IPv6", "IPv4");
          ((struct sockaddr_in6 *) sctx->addr)->sin6_port = htons (port);
        }
      freeaddrinfo (res);
    }
  else
    {
      /* will bind against everything, just set port */
      if (disablev6)
        {
          /* V4-only */
          sctx->addrlen = sizeof (struct sockaddr_in);
          sctx->addr = GNUNET_malloc (sctx->addrlen);
#if HAVE_SOCKADDR_IN_SIN_LEN
          ((struct sockaddr_in *) sctx->addr)->sin_len = sctx->addrlen;
#endif
          ((struct sockaddr_in *) sctx->addr)->sin_family = AF_INET;
          ((struct sockaddr_in *) sctx->addr)->sin_port = htons (port);
          GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                      _
                      ("Configured to bind to %s address; %s connections to this service will fail!\n"),
                      "IPv4", "IPv6");
        }
      else
        {
          /* dual stack */
          sctx->addrlen = sizeof (struct sockaddr_in6);
          sctx->addr = GNUNET_malloc (sctx->addrlen);
#if HAVE_SOCKADDR_IN_SIN_LEN
          ((struct sockaddr_in6 *) sctx->addr)->sin6_len = sctx->addrlen;
#endif
          ((struct sockaddr_in6 *) sctx->addr)->sin6_family = AF_INET6;
          ((struct sockaddr_in6 *) sctx->addr)->sin6_port = htons (port);
        }
    }
  sctx->maxbuf = (size_t) maxbuf;
  if (sctx->maxbuf != maxbuf)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _
                  ("Value in configuration for `%s' and service `%s' too large!\n"),
                  "MAXBUF", sctx->serviceName);
      return GNUNET_SYSERR;
    }


  if ((GNUNET_OK !=
       process_acl4 (&sctx->v4_denied,
                     sctx,
                     "REJECT_FROM")) ||
      (GNUNET_OK !=
       process_acl4 (&sctx->v4_allowed,
                     sctx,
                     "ACCEPT_FROM")) ||
      (GNUNET_OK !=
       process_acl6 (&sctx->v6_denied,
                     sctx,
                     "REJECT_FROM6")) ||
      (GNUNET_OK != process_acl6 (&sctx->v6_allowed, sctx, "ACCEPT_FROM6")))
    return GNUNET_SYSERR;
  return GNUNET_OK;
}


/**
 * Get the name of the user that'll be used
 * to provide the service.
 */
static char *
get_user_name (struct GNUNET_SERVICE_Context *sctx)
{

  char *un;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (sctx->cfg,
                                               sctx->serviceName,
                                               "USERNAME", &un))
    return NULL;
  return un;
}

/**
 * Write PID file.
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
         as ours! */
      GNUNET_DISK_directory_create (rdir);
      if ((user != NULL) && (0 < strlen (user)))
        GNUNET_DISK_file_change_owner (rdir, user);
    }
  if (0 != ACCESS (rdir, W_OK | X_OK))
    {
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR, "access", rdir);
      GNUNET_free (rdir);
      GNUNET_free_non_null (user);
      GNUNET_free (pif);
      return GNUNET_SYSERR;
    }
  GNUNET_free (rdir);
  pidfd = FOPEN (pif, "w");
  if (pidfd == NULL)
    {
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR, "fopen", pif);
      GNUNET_free (pif);
      GNUNET_free_non_null (user);
      return GNUNET_SYSERR;
    }
  if (0 > FPRINTF (pidfd, "%u", pid))
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "fprintf", pif);
  GNUNET_break (0 == fclose (pidfd));
  if ((user != NULL) && (0 < strlen (user)))
    GNUNET_DISK_file_change_owner (pif, user);
  GNUNET_free_non_null (user);
  GNUNET_free (pif);
  return GNUNET_OK;
}


/**
 * Initial task for the service.
 */
static void
service_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_SERVICE_Context *sctx = cls;
  unsigned int i;

  sctx->sched = tc->sched;
  sctx->server = GNUNET_SERVER_create (tc->sched,
                                       &check_access,
                                       sctx,
                                       sctx->addr,
                                       sctx->addrlen,
                                       sctx->maxbuf,
                                       sctx->timeout, sctx->require_found);
  if (sctx->server == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
		  _("Failed to start `%s' at `%s'\n"),
		  sctx->serviceName, 
		  GNUNET_a2s (sctx->addr,
			      sctx->addrlen));
      sctx->ret = GNUNET_SYSERR;
      return;
    }
  sctx->my_handlers = GNUNET_malloc (sizeof (defhandlers));
  memcpy (sctx->my_handlers, defhandlers, sizeof (defhandlers));
  i = 0;
  while ((sctx->my_handlers[i].callback != NULL))
    sctx->my_handlers[i++].callback_cls = sctx;
  GNUNET_SERVER_add_handlers (sctx->server, sctx->my_handlers);
  if (sctx->ready_confirm_fd != -1)
    {
      GNUNET_break (1 == WRITE (sctx->ready_confirm_fd, ".", 1));
      GNUNET_break (0 == CLOSE (sctx->ready_confirm_fd));
      sctx->ready_confirm_fd = -1;
      write_pid_file (sctx, getpid ());
    }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
	      _("Service `%s' runs at %s\n"),
	      sctx->serviceName,
	      GNUNET_a2s (sctx->addr,
			  sctx->addrlen));
  sctx->task (sctx->task_cls, tc->sched, sctx->server, sctx->cfg);
}


/**
 * Detach from terminal.
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
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "pipe");
      return GNUNET_SYSERR;
    }
  pid = fork ();
  if (pid < 0)
    {
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "fork");
      return GNUNET_SYSERR;
    }
  if (pid != 0)
    {
      /* Parent */
      char c;

      GNUNET_break (0 == CLOSE (filedes[1]));
      c = 'X';
      if (1 != READ (filedes[0], &c, sizeof (char)))
        GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "read");
      fflush (stdout);
      switch (c)
        {
        case '.':
          exit (0);
        case 'I':
          GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                      _("Service process failed to initialize\n"));
          break;
        case 'S':
          GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                      _
                      ("Service process could not initialize server function\n"));
          break;
        case 'X':
          GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                      _("Service process failed to report status\n"));
          break;
        }
      exit (1);                 /* child reported error */
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
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "dup2");
      return GNUNET_SYSERR;
    }
  /* Detach from controlling terminal */
  pid = setsid ();
  if (pid == -1)
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "setsid");
  sctx->ready_confirm_fd = filedes[1];
#else
  /* FIXME: we probably need to do something else
     elsewhere in order to fork the process itself... */
  FreeConsole ();
#endif
  return GNUNET_OK;
}


/**
 * Set user ID.
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
  if (pws == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("Cannot obtain information about user `%s': %s\n"),
                  user, errno == 0 ? _("No such user") : STRERROR (errno));
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
          GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                      _("Cannot change user/group to `%s': %s\n"), user,
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
 * Delete the PID file that was created by our parent.
 */
static void
pid_file_delete (struct GNUNET_SERVICE_Context *sctx)
{
  char *pif = get_pid_file_name (sctx);
  if (pif == NULL)
    return;                     /* no PID file */
  if (0 != UNLINK (pif))
    GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING, "unlink", pif);
  GNUNET_free (pif);
}

/**
 * Run a standard GNUnet service startup sequence (initialize loggers
 * and configuration, parse options).
 *
 * @param argc number of command line arguments
 * @param argv command line arguments
 * @param serviceName our service name
 * @param task main task of the service
 * @param task_cls closure for task
 * @param term termination task of the service
 * @param term_cls closure for term
 * @return GNUNET_SYSERR on error, GNUNET_OK
 *         if we shutdown nicely
 */
int
GNUNET_SERVICE_run (int argc,
                    char *const *argv,
                    const char *serviceName,
                    GNUNET_SERVICE_Main task,
                    void *task_cls, GNUNET_SERVICE_Term term, void *term_cls)
{
  char *cfg_fn;
  char *loglev;
  char *logfile;
  int do_daemonize;
  struct GNUNET_SERVICE_Context sctx;
  struct GNUNET_CONFIGURATION_Handle *cfg;
  struct GNUNET_GETOPT_CommandLineOption service_options[] = {
    GNUNET_GETOPT_OPTION_CFG_FILE (&cfg_fn),
    {'d', "daemonize", NULL,
     gettext_noop ("do daemonize (detach from terminal)"), 0,
     GNUNET_GETOPT_set_one, &do_daemonize},
    GNUNET_GETOPT_OPTION_HELP (serviceName),
    GNUNET_GETOPT_OPTION_LOGLEVEL (&loglev),
    GNUNET_GETOPT_OPTION_LOGFILE (&logfile),
    GNUNET_GETOPT_OPTION_VERSION (PACKAGE_VERSION),
    GNUNET_GETOPT_OPTION_END
  };
  do_daemonize = 0;
  logfile = NULL;
  loglev = GNUNET_strdup ("WARNING");
  cfg_fn = GNUNET_strdup (GNUNET_DEFAULT_DAEMON_CONFIG_FILE);
  memset (&sctx, 0, sizeof (sctx));
  sctx.ready_confirm_fd = -1;
  sctx.ret = GNUNET_OK;
  sctx.timeout = GNUNET_TIME_UNIT_FOREVER_REL;
  sctx.maxbuf = GNUNET_SERVER_MAX_MESSAGE_SIZE;
  sctx.task = task;
  sctx.serviceName = serviceName;
  sctx.cfg = cfg = GNUNET_CONFIGURATION_create ();
  /* setup subsystems */
  if ((GNUNET_SYSERR ==
       GNUNET_GETOPT_run (serviceName,                         
                          service_options,
                          argc,
                          argv)) ||
      (GNUNET_OK !=
       GNUNET_log_setup (serviceName, loglev, logfile)) ||
      (GNUNET_OK !=
       GNUNET_CONFIGURATION_load (cfg, cfg_fn)) ||
      (GNUNET_OK !=
       setup_service (&sctx)) ||
      ((do_daemonize == 1) &&
       (GNUNET_OK != detach_terminal (&sctx))) ||
      (GNUNET_OK != set_user_id (&sctx)))
    {
      if (sctx.ready_confirm_fd != -1)
        {
          if (1 != WRITE (sctx.ready_confirm_fd, "I", 1))
            GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "write");
          GNUNET_break (0 == CLOSE (sctx.ready_confirm_fd));
        }
      GNUNET_CONFIGURATION_destroy (cfg);
      GNUNET_free_non_null (sctx.addr);
      GNUNET_free_non_null (logfile);
      GNUNET_free (loglev);
      GNUNET_free (cfg_fn);
      GNUNET_free_non_null (sctx.v4_denied);
      GNUNET_free_non_null (sctx.v6_denied);
      GNUNET_free_non_null (sctx.v4_allowed);
      GNUNET_free_non_null (sctx.v6_allowed);
      return GNUNET_SYSERR;
    }

  /* actually run service */
  GNUNET_SCHEDULER_run (&service_task, &sctx);
  if (sctx.ready_confirm_fd != -1)
    {
      if (1 != WRITE (sctx.ready_confirm_fd, "S", 1))
        GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "write");
      GNUNET_break (0 == CLOSE (sctx.ready_confirm_fd));
    }

  /* shutdown */
  if (term != NULL)
    term (term_cls, sctx.cfg);
  if ((do_daemonize == 1) && (sctx.server != NULL))
    pid_file_delete (&sctx);
  if (sctx.server != NULL)
    GNUNET_SERVER_destroy (sctx.server);
  GNUNET_free_non_null (sctx.my_handlers);
  GNUNET_CONFIGURATION_destroy (cfg);
  GNUNET_free_non_null (sctx.addr);
  GNUNET_free_non_null (logfile);
  GNUNET_free (loglev);
  GNUNET_free (cfg_fn);
  GNUNET_free_non_null (sctx.v4_denied);
  GNUNET_free_non_null (sctx.v6_denied);
  GNUNET_free_non_null (sctx.v4_allowed);
  GNUNET_free_non_null (sctx.v6_allowed);
  return sctx.ret;
}


/**
 * Run a service startup sequence within an existing
 * initialized system.
 *
 * @param serviceName our service name
 * @param sched scheduler to use
 * @param cfg configuration to use
 * @return NULL on error, service handle
 */
struct GNUNET_SERVICE_Context *
GNUNET_SERVICE_start (const char *serviceName,
                      struct GNUNET_SCHEDULER_Handle *sched,
                      const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  int i;
  struct GNUNET_SERVICE_Context *sctx;

  sctx = GNUNET_malloc (sizeof (struct GNUNET_SERVICE_Context));
  sctx->ready_confirm_fd = -1;  /* no daemonizing */
  sctx->ret = GNUNET_OK;
  sctx->timeout = GNUNET_TIME_UNIT_FOREVER_REL;
  sctx->maxbuf = GNUNET_SERVER_MAX_MESSAGE_SIZE;
  sctx->serviceName = serviceName;
  sctx->cfg = cfg;
  sctx->sched = sched;

  /* setup subsystems */
  if ((GNUNET_OK != setup_service (sctx)) ||
      (NULL == (sctx->server = GNUNET_SERVER_create (sched,
                                                     &check_access,
                                                     sctx,
                                                     sctx->addr,
                                                     sctx->addrlen,
                                                     sctx->maxbuf,
                                                     sctx->timeout,
                                                     sctx->require_found))))
    {
      GNUNET_SERVICE_stop (sctx);
      return NULL;
    }
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
 * Stop a service that was started with "GNUNET_SERVICE_start".
 *
 * @param sctx the service context returned from the start function
 */
void
GNUNET_SERVICE_stop (struct GNUNET_SERVICE_Context *sctx)
{
  if (NULL != sctx->server)
    GNUNET_SERVER_destroy (sctx->server);
  GNUNET_free_non_null (sctx->my_handlers);
  GNUNET_free_non_null (sctx->addr);
  GNUNET_free_non_null (sctx->v4_denied);
  GNUNET_free_non_null (sctx->v6_denied);
  GNUNET_free_non_null (sctx->v4_allowed);
  GNUNET_free_non_null (sctx->v6_allowed);
  GNUNET_free (sctx);
}


/* end of service.c */
