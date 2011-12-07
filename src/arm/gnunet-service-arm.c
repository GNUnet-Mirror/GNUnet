/*
     This file is part of GNUnet.
     (C) 2009, 2010 Christian Grothoff (and other contributing authors)

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
 *
 * TODO:
 * - need to test auto-restart code on configuration changes;
 * - should refine restart code to check if *relevant* parts of the
 *   configuration were changed (anything in the section for the service)
 * - should have a way to specify dependencies between services and
 *   manage restarts of groups of services
 *
 * + install handler for disconnecting clients!?
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_protocols.h"
#include "arm.h"


/**
 * Check for configuration file changes every 5s.
 */
#define MAINT_FREQUENCY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)

/**
 * Threshold after which exponential backoff shouldn't increase (in ms); 30m
 */
#define EXPONENTIAL_BACKOFF_THRESHOLD (1000 * 60 * 30)

/**
 * List of our services.
 */
struct ServiceList;


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
   * Last time the config of this service was
   * modified.
   */
  time_t mtime;

  /**
   * Process exponential backoff time
   */
  struct GNUNET_TIME_Relative backoff;

  /**
   * Absolute time at which the process is scheduled to restart in case of death
   */
  struct GNUNET_TIME_Absolute restartAt;

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
static struct ServiceListeningInfo *serviceListeningInfoList_head;

/**
 *
 */
static struct ServiceListeningInfo *serviceListeningInfoList_tail;


/**
 * Pipe used to communicate shutdown via signal.
 */
static struct GNUNET_DISK_PipeHandle *sigpipe;

/**
 * Reading end of the signal pipe.
 */
static const struct GNUNET_DISK_FileHandle *pr;

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
 * @param lsocks -1 terminated list of listen sockets to pass (systemd style), or NULL
 */
static void
start_process (struct ServiceList *sl, const SOCKTYPE *lsocks)
{
  char *loprefix;
  char *options;
  char *optpos;
  char *optend;
  const char *next;
  int use_debug;
  char b;
  char *val;

  /* start service */
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
            GNUNET_CONFIGURATION_get_value_string (cfg, "PATHS", optpos + 1,
                                                   &val))
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

#if DEBUG_ARM
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Starting service `%s' using binary `%s' and configuration `%s'\n",
              sl->name, sl->binary, sl->config);
#endif
  if (GNUNET_YES == use_debug)
    sl->proc =
        do_start_process (lsocks, loprefix, sl->binary, "-c", sl->config, "-L",
                          "DEBUG", options, NULL);
  else
    sl->proc =
        do_start_process (lsocks, loprefix, sl->binary, "-c", sl->config,
                          options, NULL);
  if (sl->proc == NULL)
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("Failed to start service `%s'\n"),
                sl->name);
  else
    GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Starting service `%s'\n"), sl->name);
  GNUNET_free (loprefix);
  GNUNET_free (options);
}


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
static int
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
  uint16_t *res = cls;
  struct GNUNET_MessageHeader *msg;

  if (buf == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("Could not send status result to client\n"));
    return 0;                   /* error, not much we can do */
  }
#if DEBUG_ARM
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending status response %u to client\n",
              (unsigned int) *res);
#endif
  GNUNET_assert (size >= sizeof (struct GNUNET_MessageHeader));
  msg = buf;
  msg->size = htons (sizeof (struct GNUNET_MessageHeader));
  msg->type = htons (*res);
  GNUNET_free (res);
  return sizeof (struct GNUNET_MessageHeader);
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
               uint16_t result)
{
  uint16_t *res;

  if (NULL == client)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                _("Not sending status result to client: no client known\n"));
    return;
  }
#if DEBUG_ARM
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Telling client that service `%s' is now %s\n", name,
              result == GNUNET_MESSAGE_TYPE_ARM_IS_DOWN ? "down" : "up");
#endif
  res = GNUNET_malloc (sizeof (uint16_t));
  *res = result;
  GNUNET_SERVER_notify_transmit_ready (client,
                                       sizeof (struct GNUNET_MessageHeader),
                                       GNUNET_TIME_UNIT_FOREVER_REL,
                                       &write_result, res);
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
  struct ServiceList *pos;

  pos = running_head;
  while (pos != NULL)
  {
    if (0 == strcmp (pos->name, name))
      return pos;
    pos = pos->next;
  }
  return NULL;
}


/**
 * Start the specified service.
 *
 * @param client who is asking for this
 * @param servicename name of the service to start
 * @param lsocks -1 terminated list of listen sockets to pass (systemd style), or NULL
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
static int
start_service (struct GNUNET_SERVER_Client *client, const char *servicename,
               const SOCKTYPE *lsocks)
{
  struct ServiceList *sl;
  char *binary;
  char *config;
  struct stat sbuf;

  if (GNUNET_YES == in_shutdown)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                _("ARM is shutting down, service `%s' not started.\n"),
                servicename);
    signal_result (client, servicename, GNUNET_MESSAGE_TYPE_ARM_IS_DOWN);
    return GNUNET_SYSERR;
  }
  sl = find_service (servicename);
  if (sl != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, _("Service `%s' already running.\n"),
                servicename);
    signal_result (client, servicename, GNUNET_MESSAGE_TYPE_ARM_IS_UP);
    return GNUNET_SYSERR;
  }
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg, servicename, "BINARY",
                                             &binary))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("Binary implementing service `%s' not known!\n"),
                servicename);
    signal_result (client, servicename, GNUNET_MESSAGE_TYPE_ARM_IS_DOWN);
    return GNUNET_SYSERR;
  }
  if ((GNUNET_OK !=
       GNUNET_CONFIGURATION_get_value_filename (cfg, servicename, "CONFIG",
                                                &config)) ||
      (0 != STAT (config, &sbuf)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("Configuration file `%s' for service `%s' not known!\n"),
                config, servicename);
    signal_result (client, servicename, GNUNET_MESSAGE_TYPE_ARM_IS_DOWN);
    GNUNET_free (binary);
    GNUNET_free_non_null (config);
    return GNUNET_SYSERR;
  }
  (void) stop_listening (servicename);
  sl = GNUNET_malloc (sizeof (struct ServiceList));
  sl->name = GNUNET_strdup (servicename);
  sl->binary = binary;
  sl->config = config;
  sl->mtime = sbuf.st_mtime;
  sl->backoff = GNUNET_TIME_UNIT_MILLISECONDS;
  sl->restartAt = GNUNET_TIME_UNIT_FOREVER_ABS;
  GNUNET_CONTAINER_DLL_insert (running_head, running_tail, sl);
  start_process (sl, lsocks);
  if (NULL != client)
    signal_result (client, servicename, GNUNET_MESSAGE_TYPE_ARM_IS_UP);
  return GNUNET_OK;
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
static void
prepare_services (const struct GNUNET_CONFIGURATION_Handle *configurationHandle)
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



/**
 * If the configuration file changes, restart tasks that depended on that
 * option.
 *
 * @param cls closure, NULL if we need to self-restart
 * @param tc context
 */
static void
config_change_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ServiceList *pos;
  struct stat sbuf;

  pos = running_head;
  while (pos != NULL)
  {
    /* FIXME: this test for config change may be a bit too coarse grained */
    if ((0 == STAT (pos->config, &sbuf)) && (pos->mtime < sbuf.st_mtime) &&
        (pos->proc != NULL))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  _
                  ("Restarting service `%s' due to configuration file change.\n"));
      if (0 != GNUNET_OS_process_kill (pos->proc, SIGTERM))
        GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "kill");
      else
        pos->backoff = GNUNET_TIME_UNIT_MILLISECONDS;
    }
    pos = pos->next;
  }
}


/**
 * Remove and free an entry in the service list.
 *
 * @param pos entry to free
 */
static void
free_service (struct ServiceList *pos)
{
  GNUNET_CONTAINER_DLL_remove (running_head, running_tail, pos);
  GNUNET_free_non_null (pos->config);
  GNUNET_free_non_null (pos->binary);
  GNUNET_free (pos->name);
  GNUNET_free (pos);
}


/**
 * Stop the specified service.
 *
 * @param client who is asking for this
 * @param servicename name of the service to stop
 */
static void
stop_service (struct GNUNET_SERVER_Client *client, const char *servicename)
{
  struct ServiceList *pos;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Preparing to stop `%s'\n"),
              servicename);
  pos = find_service (servicename);
  if (pos == NULL)
  {
    if (GNUNET_OK == stop_listening (servicename))
      signal_result (client, servicename, GNUNET_MESSAGE_TYPE_ARM_IS_DOWN);
    else
      signal_result (client, servicename, GNUNET_MESSAGE_TYPE_ARM_IS_UNKNOWN);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  if (pos->killing_client != NULL)
  {
    /* killing already in progress */
#if DEBUG_ARM
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Service `%s' is already down\n",
                servicename);
#endif
    signal_result (client, servicename, GNUNET_MESSAGE_TYPE_ARM_IS_DOWN);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }

  if (GNUNET_YES == in_shutdown)
  {
#if DEBUG_ARM
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Termination request already sent to `%s' (since ARM is in shutdown).\n",
                servicename);
#endif
    signal_result (client, servicename, GNUNET_MESSAGE_TYPE_ARM_IS_DOWN);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  if (pos->proc == NULL)
  {
    /* process is in delayed restart, simply remove it! */
    free_service (pos);
    signal_result (client, servicename, GNUNET_MESSAGE_TYPE_ARM_IS_DOWN);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
#if DEBUG_ARM
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending kill signal to service `%s', waiting for process to die.\n",
              servicename);
#endif
  if (0 != GNUNET_OS_process_kill (pos->proc, SIGTERM))
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "kill");
  pos->killing_client = client;
  GNUNET_SERVER_client_keep (client);
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
  start_service (client, servicename, NULL);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
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
  stop_service (client, servicename);
}


/**
 * Remove all entries for tasks that are not running
 * (proc = NULL) from the running list (they will no longer
 * be restarted since we are shutting down).
 */
static void
clean_up_running ()
{
  struct ServiceList *pos;
  struct ServiceList *next;

  next = running_head;
  while (NULL != (pos = next))
  {
    next = pos->next;
    if (pos->proc == NULL)
      free_service (pos);
  }
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

#if DEBUG_ARM
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, _("Stopping all services\n"));
#endif
  if (GNUNET_SCHEDULER_NO_TASK != child_restart_task)
  {
    GNUNET_SCHEDULER_cancel (child_restart_task);
    child_restart_task = GNUNET_SCHEDULER_NO_TASK;
  }
  in_shutdown = GNUNET_YES;
  stop_listening (NULL);
  pos = running_head;
  while (NULL != pos)
  {
    nxt = pos->next;
    if (pos->proc != NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Stopping service `%s'\n", pos->name);
      if (0 != GNUNET_OS_process_kill (pos->proc, SIGTERM))
        GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "kill");
    }
    else
    {
      free_service (pos);
    }
    pos = nxt;
  }
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
delayed_restart_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ServiceList *pos;
  struct GNUNET_TIME_Relative lowestRestartDelay;

  child_restart_task = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;
  GNUNET_assert (GNUNET_NO == in_shutdown);
  lowestRestartDelay = GNUNET_TIME_UNIT_FOREVER_REL;

  /* check for services that need to be restarted due to
   * configuration changes or because the last restart failed */
  pos = running_head;
  while (pos != NULL)
  {
    if (pos->proc == NULL)
    {
      if (GNUNET_TIME_absolute_get_remaining (pos->restartAt).rel_value == 0)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Restarting service `%s'.\n"),
                    pos->name);
        start_process (pos, NULL);
      }
      else
      {
        lowestRestartDelay =
            GNUNET_TIME_relative_min (lowestRestartDelay,
                                      GNUNET_TIME_absolute_get_remaining
                                      (pos->restartAt));
      }
    }
    pos = pos->next;
  }
  if (lowestRestartDelay.rel_value != GNUNET_TIME_UNIT_FOREVER_REL.rel_value)
  {
#if DEBUG_ARM
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Will restart process in %llums\n",
                (unsigned long long) lowestRestartDelay.rel_value);
#endif
    child_restart_task =
        GNUNET_SCHEDULER_add_delayed (lowestRestartDelay, &delayed_restart_task,
                                      NULL);
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
  const char *statstr;
  int statcode;
  int ret;
  char c[16];
  enum GNUNET_OS_ProcessStatusType statusType;
  unsigned long statusCode;

  child_death_task = GNUNET_SCHEDULER_NO_TASK;
  if (0 == (tc->reason & GNUNET_SCHEDULER_REASON_READ_READY))
  {
    /* shutdown scheduled us, ignore! */
    child_death_task =
        GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL, pr,
                                        &maint_child_death, NULL);
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
      continue;
    if ((GNUNET_SYSERR ==
         (ret = GNUNET_OS_process_status (pos->proc, &statusType, &statusCode)))
        || ((ret == GNUNET_NO) || (statusType == GNUNET_OS_PROCESS_STOPPED) ||
            (statusType == GNUNET_OS_PROCESS_RUNNING)))
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
      GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Service `%s' stopped\n"),
                  pos->name);
      signal_result (pos->killing_client, pos->name,
                     GNUNET_MESSAGE_TYPE_ARM_IS_DOWN);
      GNUNET_SERVER_receive_done (pos->killing_client, GNUNET_OK);
      GNUNET_SERVER_client_drop (pos->killing_client);
      free_service (pos);
      continue;
    }
    if (GNUNET_YES != in_shutdown)
    {
      if (0 == (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
        GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                    _
                    ("Service `%s' terminated with status %s/%d, will try to restart it!\n"),
                    pos->name, statstr, statcode);
      /* schedule restart */
      pos->restartAt = GNUNET_TIME_relative_to_absolute (pos->backoff);
      if (pos->backoff.rel_value < EXPONENTIAL_BACKOFF_THRESHOLD)
        pos->backoff = GNUNET_TIME_relative_multiply (pos->backoff, 2);
      if (GNUNET_SCHEDULER_NO_TASK != child_restart_task)
        GNUNET_SCHEDULER_cancel (child_restart_task);
      child_restart_task =
          GNUNET_SCHEDULER_add_with_priority (GNUNET_SCHEDULER_PRIORITY_IDLE,
                                              &delayed_restart_task, NULL);
    }
#if DEBUG_ARM
    else
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Service `%s' terminated with status %s/%d\n", pos->name,
                  statstr, statcode);
#endif
  }
  child_death_task =
      GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL, pr,
                                      &maint_child_death, NULL);
  if (GNUNET_YES == in_shutdown)
    clean_up_running ();
  if ((NULL == running_head) && (GNUNET_YES == in_shutdown))
    do_shutdown ();
}


static size_t
transmit_shutdown_ack (void *cls, size_t size, void *buf)
{
  struct GNUNET_SERVER_Client *client = cls;
  struct GNUNET_MessageHeader *msg;

  if (size < sizeof (struct GNUNET_MessageHeader))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                _("Failed to transmit shutdown ACK.\n"));
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return 0;                   /* client disconnected */
  }

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Transmitting shutdown ACK.\n"));

  /* Make the connection flushing for the purpose of ACK transmitting,
   * needed on W32 to ensure that the message is even received, harmless
   * on other platforms... */
  GNUNET_break (GNUNET_OK == GNUNET_SERVER_client_disable_corking (client));
  msg = (struct GNUNET_MessageHeader *) buf;
  msg->type = htons (GNUNET_MESSAGE_TYPE_ARM_SHUTDOWN_ACK);
  msg->size = htons (sizeof (struct GNUNET_MessageHeader));
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
  GNUNET_SERVER_client_drop (client);
  return sizeof (struct GNUNET_MessageHeader);
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
  GNUNET_SERVER_client_keep (client);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              _("Initiating shutdown as requested by client.\n"));
  GNUNET_SERVER_notify_transmit_ready (client,
                                       sizeof (struct GNUNET_MessageHeader),
                                       GNUNET_TIME_UNIT_FOREVER_REL,
                                       &transmit_shutdown_ack, client);
  GNUNET_SERVER_client_persist_ (client);
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Signal handler called for SIGCHLD.  Triggers the
 * respective handler by writing to the trigger pipe.
 */
static void
sighandler_child_death ()
{
  static char c;
  int old_errno = errno;        /* back-up errno */

  GNUNET_break (1 ==
                GNUNET_DISK_file_write (GNUNET_DISK_pipe_handle
                                        (sigpipe, GNUNET_DISK_PIPE_END_WRITE),
                                        &c, sizeof (c)));
  errno = old_errno;            /* restore errno */
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
  char *pos;

  cfg = c;
  server = serv;
  GNUNET_assert (serv != NULL);
  pr = GNUNET_DISK_pipe_handle (sigpipe, GNUNET_DISK_PIPE_END_READ);
  GNUNET_assert (pr != NULL);
  GNUNET_SERVER_ignore_shutdown (serv, GNUNET_YES);
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &shutdown_task,
                                NULL);
  child_death_task =
      GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL, pr,
                                      &maint_child_death, NULL);

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg, "ARM", "GLOBAL_PREFIX",
                                             &prefix_command))
    prefix_command = GNUNET_strdup ("");
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg, "ARM", "GLOBAL_POSTFIX",
                                             &final_option))
    final_option = GNUNET_strdup ("");
  /* start default services... */
  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_get_value_string (cfg, "ARM", "DEFAULTSERVICES",
                                             &defaultservices))
  {
#if DEBUG_ARM
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Starting default services `%s'\n",
                defaultservices);
#endif
    if (0 < strlen (defaultservices))
    {
      pos = strtok (defaultservices, " ");
      while (pos != NULL)
      {
        start_service (NULL, pos, NULL);
        pos = strtok (NULL, " ");
      }
    }
    GNUNET_free (defaultservices);
  }
  else
  {
#if DEBUG_ARM
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "No default services configured.\n");
#endif
  }

  /* create listening sockets for future services */
  prepare_services (cfg);

  /* process client requests */
  GNUNET_SERVER_add_handlers (server, handlers);

  /* manage services */
  GNUNET_SCHEDULER_add_with_priority (GNUNET_SCHEDULER_PRIORITY_IDLE,
                                      &config_change_task, NULL);
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

  sigpipe = GNUNET_DISK_pipe (GNUNET_NO, GNUNET_NO, GNUNET_NO);
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
