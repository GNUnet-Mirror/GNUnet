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
 * @file arm/gnunet-service-arm_interceptor.c
 * @brief listen to incoming connections from clients to services,
 * start services for which incoming an incoming connection occur,
 * and relay communication between the client and the service for
 * that first incoming connection.
 *
 * @author Safey Abdel Halim
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_service_lib.h"
#include "gnunet_configuration_lib.h"
#include "gnunet_constants.h"
#include "gnunet_client_lib.h"
#include "gnunet_container_lib.h"
#include "gnunet-service-arm.h"


#define DEBUG_SERVICE_MANAGER GNUNET_EXTRA_LOGGING

/**
 *
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
   * Name of the service being forwarded.
   */
  char *serviceName;

  /**
   *
   */
  struct sockaddr *service_addr;

  /**
   *
   */
  socklen_t service_addr_len;

  /**
   * Our listening socket.
   */
  struct GNUNET_NETWORK_Handle *listeningSocket;

  /**
   * Task doing the accepting.
   */
  GNUNET_SCHEDULER_TaskIdentifier acceptTask;
};


/**
 * Array with the names of the services started by default.
 */
static char **defaultServicesList;

/**
 * Size of the defaultServicesList array.
 */
static unsigned int numDefaultServices;

/**
 *
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 *
 */
static struct ServiceListeningInfo *serviceListeningInfoList_head;

/**
 *
 */
static struct ServiceListeningInfo *serviceListeningInfoList_tail;


/**
 * Put the default services represented by a space separated string into an array of strings
 *
 * @param services space separated string of default services
 */
static void
addDefaultServicesToList (const char *services)
{
  unsigned int i;
  const char *token;
  char *s;

  if (strlen (services) == 0)
    return;
  s = GNUNET_strdup (services);
  token = strtok (s, " ");
  while (NULL != token)
  {
    numDefaultServices++;
    token = strtok (NULL, " ");
  }
  GNUNET_free (s);

  defaultServicesList = GNUNET_malloc (numDefaultServices * sizeof (char *));
  i = 0;
  s = GNUNET_strdup (services);
  token = strtok (s, " ");
  while (NULL != token)
  {
    defaultServicesList[i++] = GNUNET_strdup (token);
    token = strtok (NULL, " ");
  }
  GNUNET_free (s);
  GNUNET_assert (i == numDefaultServices);
}

/**
 * Checks whether the serviceName is in the list of default services
 *
 * @param serviceName string to check its existance in the list
 * @return GNUNET_YES if the service is started by default
 */
static int
isInDefaultList (const char *serviceName)
{
  unsigned int i;

  for (i = 0; i < numDefaultServices; i++)
    if (strcmp (serviceName, defaultServicesList[i]) == 0)
      return GNUNET_YES;
  return GNUNET_NO;
}


/**
 *
 */
int
stop_listening (const char *serviceName)
{
  struct ServiceListeningInfo *pos;
  struct ServiceListeningInfo *next;
  int ret;

  ret = GNUNET_NO;
  next = serviceListeningInfoList_head;
  while (NULL != (pos = next))
  {
    next = pos->next;
    if ((serviceName != NULL) && (strcmp (pos->serviceName, serviceName) != 0))
      continue;
    if (pos->acceptTask != GNUNET_SCHEDULER_NO_TASK)
      GNUNET_SCHEDULER_cancel (pos->acceptTask);
    GNUNET_break (GNUNET_OK ==
                  GNUNET_NETWORK_socket_close (pos->listeningSocket));
    GNUNET_CONTAINER_DLL_remove (serviceListeningInfoList_head,
                                 serviceListeningInfoList_tail, pos);
    GNUNET_free (pos->serviceName);
    GNUNET_free (pos->service_addr);
    GNUNET_free (pos);
    ret = GNUNET_OK;
  }
  return ret;
}


/**
 * First connection has come to the listening socket associated with the service,
 * create the service in order to relay the incoming connection to it
 *
 * @param cls callback data, struct ServiceListeningInfo describing a listen socket
 * @param tc context
 */
static void
acceptConnection (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ServiceListeningInfo *sli = cls;
  struct ServiceListeningInfo *pos;
  struct ServiceListeningInfo *next;
  SOCKTYPE *lsocks;
  unsigned int ls;

  sli->acceptTask = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (GNUNET_SCHEDULER_REASON_SHUTDOWN & tc->reason))
    return;
  GNUNET_CONTAINER_DLL_remove (serviceListeningInfoList_head,
                               serviceListeningInfoList_tail, sli);
  lsocks = NULL;
  ls = 0;
  next = serviceListeningInfoList_head;
  while (NULL != (pos = next))
  {
    next = pos->next;
    if (0 == strcmp (pos->serviceName, sli->serviceName))
    {
      GNUNET_array_append (lsocks, ls,
                           GNUNET_NETWORK_get_fd (pos->listeningSocket));
      GNUNET_free (pos->listeningSocket);       /* deliberately no closing! */
      GNUNET_free (pos->service_addr);
      GNUNET_free (pos->serviceName);
      GNUNET_SCHEDULER_cancel (pos->acceptTask);
      GNUNET_CONTAINER_DLL_remove (serviceListeningInfoList_head,
                                   serviceListeningInfoList_tail, pos);
      GNUNET_free (pos);
    }
  }
  GNUNET_array_append (lsocks, ls,
                       GNUNET_NETWORK_get_fd (sli->listeningSocket));
  GNUNET_free (sli->listeningSocket);   /* deliberately no closing! */
  GNUNET_free (sli->service_addr);
#if WINDOWS
  GNUNET_array_append (lsocks, ls, INVALID_SOCKET);
#else
  GNUNET_array_append (lsocks, ls, -1);
#endif
  start_service (NULL, sli->serviceName, lsocks);
  ls = 0;
  while (lsocks[ls] != -1)
#if WINDOWS
    GNUNET_break (0 == closesocket (lsocks[ls++]));
#else
    GNUNET_break (0 == close (lsocks[ls++]));
#endif
  GNUNET_array_grow (lsocks, ls, 0);
  GNUNET_free (sli->serviceName);
  GNUNET_free (sli);
}


/**
 * Creating a listening socket for each of the service's addresses and
 * wait for the first incoming connection to it
 *
 * @param sa address associated with the service
 * @param addr_len length of sa
 * @param serviceName the name of the service in question
 */
static void
createListeningSocket (struct sockaddr *sa, socklen_t addr_len,
                       const char *serviceName)
{
  const static int on = 1;
  struct GNUNET_NETWORK_Handle *sock;
  struct ServiceListeningInfo *serviceListeningInfo;

  switch (sa->sa_family)
  {
  case AF_INET:
    sock = GNUNET_NETWORK_socket_create (PF_INET, SOCK_STREAM, 0);
    break;
  case AF_INET6:
    sock = GNUNET_NETWORK_socket_create (PF_INET6, SOCK_STREAM, 0);
    break;
  case AF_UNIX:
    if (strcmp (GNUNET_a2s (sa, addr_len), "@") == 0)   /* Do not bind to blank UNIX path! */
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
                serviceName, STRERROR (errno));
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

  if (GNUNET_NETWORK_socket_bind (sock, (const struct sockaddr *) sa, addr_len)
      != GNUNET_OK)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _
                ("Unable to bind listening socket for service `%s' to address `%s': %s\n"),
                serviceName, GNUNET_a2s (sa, addr_len), STRERROR (errno));
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
              serviceName, GNUNET_a2s (sa, addr_len));
  serviceListeningInfo = GNUNET_malloc (sizeof (struct ServiceListeningInfo));
  serviceListeningInfo->serviceName = GNUNET_strdup (serviceName);
  serviceListeningInfo->service_addr = sa;
  serviceListeningInfo->service_addr_len = addr_len;
  serviceListeningInfo->listeningSocket = sock;
  serviceListeningInfo->acceptTask =
      GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL, sock,
                                     &acceptConnection, serviceListeningInfo);
  GNUNET_CONTAINER_DLL_insert (serviceListeningInfoList_head,
                               serviceListeningInfoList_tail,
                               serviceListeningInfo);
}


/**
 * Callback function, checks whether the current tokens are representing a service,
 * gets its addresses and create listening socket for it.
 *
 * @param cls callback data, not used
 * @param section configuration section
 * @param option configuration option
 * @param value the option's value
 */
static void
checkPortNumberCB (void *cls, const char *section, const char *option,
                   const char *value)
{
  struct sockaddr **addrs;
  socklen_t *addr_lens;
  int ret;
  unsigned int i;

  if ((strcasecmp (section, "arm") == 0) ||
      (strcasecmp (option, "AUTOSTART") != 0) ||
      (strcasecmp (value, "YES") != 0) ||
      (isInDefaultList (section) == GNUNET_YES))
    return;
  if (0 >=
      (ret =
       GNUNET_SERVICE_get_server_addresses (section, cfg, &addrs, &addr_lens)))
    return;
  /* this will free (or capture) addrs[i] */
  for (i = 0; i < ret; i++)
    createListeningSocket (addrs[i], addr_lens[i], section);
  GNUNET_free (addrs);
  GNUNET_free (addr_lens);
}


/**
 * Entry point to the Service Manager
 *
 * @param configurationHandle configuration to use to get services
 */
void
prepareServices (const struct GNUNET_CONFIGURATION_Handle *configurationHandle)
{
  char *defaultServicesString;

  cfg = configurationHandle;
  /* Split the default services into a list */
  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_get_value_string (cfg, "arm", "DEFAULTSERVICES",
                                             &defaultServicesString))
  {
    addDefaultServicesToList (defaultServicesString);
    GNUNET_free (defaultServicesString);
  }
  /* Spot the services from the configuration and create a listening
   * socket for each */
  GNUNET_CONFIGURATION_iterate (cfg, &checkPortNumberCB, NULL);
}

/* end of gnunet-service-arm_interceptor.c */
