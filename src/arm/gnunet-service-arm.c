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
 * @file arm/gnunet-service-arm.c
 * @brief the automated restart manager service
 * @author Christian Grothoff
 *
 * TODO:
 * - multiple start-stop requests with RC>1 can result
 *   in UP/DOWN signals based on "pending" that are inaccurate...
 *   => have list of clients waiting for a resolution instead of
 *      giving instant (but incorrect) replies
 * - code could go into restart-loop for a service
 *   if service crashes instantly -- need exponential back-off
 * - need to test auto-restart code on configuration changes;
 * - should refine restart code to check if *relevant* parts of the
 *   configuration were changed (anything in the section for the service)
 * - should have a way to specify dependencies between services and
 *   manage restarts of groups of services
 */
#include "platform.h"
#include "gnunet_client_lib.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_os_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_service_lib.h"
#include "arm.h"


/**
 * Run maintenance every second.
 */
#define MAINT_FREQUENCY GNUNET_TIME_UNIT_SECONDS

/**
 * How long do we wait until we decide that a service
 * did not start?
 */
#define CHECK_TIMEOUT GNUNET_TIME_UNIT_MINUTES

struct ServiceList;

typedef void (*CleanCallback) (void *cls, struct ServiceList * pos);

/**
 * List of our services.
 */
struct ServiceList
{
  /**
   * This is a linked list.
   */
  struct ServiceList *next;

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
   * Function to call upon kill completion (waitpid), NULL
   * if we should simply restart the process.
   */
  CleanCallback kill_continuation;

  /**
   * Closure for kill_continuation.
   */
  void *kill_continuation_cls;

  /**
   * Process ID of the child.
   */
  pid_t pid;

  /**
   * Last time the config of this service was
   * modified.
   */
  time_t mtime;

  /**
   * Reference counter (counts how many times we've been
   * asked to start the service).  We only actually stop
   * it once rc hits zero.
   */
  unsigned int rc;

};

/**
 * List of running services.
 */
static struct ServiceList *running;

/**
 * Our configuration
 */
static struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Our scheduler.
 */
static struct GNUNET_SCHEDULER_Handle *sched;

/**
 * Command to prepend to each actual command.
 */
static char *prefix_command;


static size_t
write_result (void *cls, size_t size, void *buf)
{
  uint16_t *res = cls;
  struct GNUNET_MessageHeader *msg;

  if (buf == NULL)
    return 0;                   /* error, not much we can do */
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
 * @return NULL if it was not found
 */
static void
signal_result (struct GNUNET_SERVER_Client *client,
               const char *name, uint16_t result)
{
  uint16_t *res;

#if DEBUG_ARM
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Telling client that service `%s' is now %s\n",
              name,
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
 * Find the process with the given PID in the
 * given list.
 *
 * @return NULL if it was not found
 */
static struct ServiceList *
find_pid (pid_t pid)
{
  struct ServiceList *pos;

  pos = running;
  while (pos != NULL)
    {
      if (pos->pid == pid)
        return pos;
      pos = pos->next;
    }
  return NULL;
}


/**
 * Find the process with the given service
 * name in the given list, remove it and return it.
 *
 * @return NULL if it was not found
 */
static struct ServiceList *
find_name (const char *name)
{
  struct ServiceList *pos;
  struct ServiceList *prev;

  pos = running;
  prev = NULL;
  while (pos != NULL)
    {
      if (0 == strcmp (pos->name, name))
        {
          if (prev == NULL)
            running = pos->next;
          else
            prev->next = pos->next;
          pos->next = NULL;
          return pos;
        }
      prev = pos;
      pos = pos->next;
    }
  return NULL;
}


static void
free_entry (struct ServiceList *pos)
{
  GNUNET_free_non_null (pos->config);
  GNUNET_free_non_null (pos->binary);
  GNUNET_free (pos->name);
  GNUNET_free (pos);
}




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
  char **argv;
  unsigned int argv_size;
  char *lopos;
  char *optpos;
  const char *firstarg;
  int use_debug;

  /* start service */
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg,
                                             sl->name, "PREFIX", &loprefix))
    loprefix = GNUNET_strdup (prefix_command);
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg,
                                             sl->name, "OPTIONS", &options))
    options = GNUNET_strdup ("");
  use_debug = GNUNET_CONFIGURATION_get_value_yesno (cfg, sl->name, "DEBUG");

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Starting service `%s'\n"), sl->name);
#if DEBUG_ARM
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Starting service `%s' using binary `%s' and configuration `%s'\n",
              sl->name, sl->binary, sl->config);
#endif
  argv_size = 6;
  if (use_debug)
    argv_size += 2;
  lopos = loprefix;
  while ('\0' != *lopos)
    {
      if (*lopos == ' ')
        argv_size++;
      lopos++;
    }
  optpos = options;
  while ('\0' != *optpos)
    {
      if (*optpos == ' ')
        argv_size++;
      optpos++;
    }
  firstarg = NULL;
  argv = GNUNET_malloc (argv_size * sizeof (char *));
  argv_size = 0;
  lopos = loprefix;

  while ('\0' != *lopos)
    {
      while (*lopos == ' ')
        lopos++;
      if (*lopos == '\0')
        continue;
      if (argv_size == 0)
        firstarg = lopos;
      argv[argv_size++] = lopos;
      while (('\0' != *lopos) && (' ' != *lopos))
        lopos++;
      if ('\0' == *lopos)
        continue;
      *lopos = '\0';
      lopos++;
    }
  if (argv_size == 0)
    firstarg = sl->binary;
  argv[argv_size++] = sl->binary;
  argv[argv_size++] = "-c";
  argv[argv_size++] = sl->config;
  if (GNUNET_YES == use_debug)
    {
      argv[argv_size++] = "-L";
      argv[argv_size++] = "DEBUG";
    }
  optpos = options;
  while ('\0' != *optpos)
    {
      while (*optpos == ' ')
        optpos++;
      if (*optpos == '\0')
        continue;
      argv[argv_size++] = optpos;
      while (('\0' != *optpos) && (' ' != *optpos))
        optpos++;
      if ('\0' == *optpos)
        continue;
      *optpos = '\0';
      optpos++;
    }
  argv[argv_size++] = NULL;
  sl->pid = GNUNET_OS_start_process_v (firstarg, argv);
  GNUNET_free (argv);
  GNUNET_free (loprefix);
  GNUNET_free (options);
}


/**
 * Start the specified service.
 */
static void
start_service (struct GNUNET_SERVER_Client *client, const char *servicename)
{
  struct ServiceList *sl;
  char *binary;
  char *config;
  struct stat sbuf;
  sl = find_name (servicename);
  if (sl != NULL)
    {
      /* already running, just increment RC */
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  _("Service `%s' already running.\n"), servicename);
      sl->rc++;
      sl->next = running;
      running = sl;
      signal_result (client, servicename, GNUNET_MESSAGE_TYPE_ARM_IS_UP);
      return;
    }
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg,
                                             servicename, "BINARY", &binary))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _("Binary implementing service `%s' not known!\n"),
                  servicename);
      signal_result (client, servicename, GNUNET_MESSAGE_TYPE_ARM_IS_DOWN);
      return;
    }
  if ((GNUNET_OK !=
       GNUNET_CONFIGURATION_get_value_filename (cfg,
                                                servicename,
                                                "CONFIG",
                                                &config)) ||
      (0 != STAT (config, &sbuf)))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _("Configuration file `%s' for service `%s' not known!\n"),
                  config, servicename);
      signal_result (client, servicename, GNUNET_MESSAGE_TYPE_ARM_IS_DOWN);
      GNUNET_free (binary);
      GNUNET_free (config);
      return;
    }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              _("Preparing to start `%s'\n"), servicename);
  sl = GNUNET_malloc (sizeof (struct ServiceList));
  sl->name = GNUNET_strdup (servicename);
  sl->next = running;
  sl->rc = 1;
  sl->binary = binary;
  sl->config = config;
  sl->mtime = sbuf.st_mtime;
  running = sl;
  start_process (sl);
  signal_result (client, servicename, GNUNET_MESSAGE_TYPE_ARM_IS_UP);
}


static void
free_and_signal (void *cls, struct ServiceList *pos)
{
  struct GNUNET_SERVER_Client *client = cls;
  /* find_name will remove "pos" from the list! */
  GNUNET_assert (pos == find_name (pos->name));
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Service `%s' stopped\n", pos->name);
  signal_result (client, pos->name, GNUNET_MESSAGE_TYPE_ARM_IS_DOWN);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
  GNUNET_SERVER_client_drop (client);
  free_entry (pos);
}


/**
 * Stop the specified service.
 */
static void
stop_service (struct GNUNET_SERVER_Client *client, const char *servicename)
{
  struct ServiceList *pos;
  struct GNUNET_CLIENT_Connection *sc;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Preparing to stop `%s'\n", servicename);
  pos = find_name (servicename);
  if ((pos != NULL) && (pos->kill_continuation != NULL))
    {
      /* killing already in progress */
      signal_result (client, servicename, GNUNET_MESSAGE_TYPE_ARM_IS_DOWN);
      return;
    }
  if ((pos != NULL) && (pos->rc > 1))
    {
      /* RC>1, just decrement RC */
      pos->rc--;
      pos->next = running;
      running = pos;
      signal_result (client, servicename, GNUNET_MESSAGE_TYPE_ARM_IS_UP);
      GNUNET_SERVER_receive_done (client, GNUNET_OK);
      return;
    }
  if (pos != NULL)
    {
      if (0 != PLIBC_KILL (pos->pid, SIGTERM))
        GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "kill");
      pos->next = running;
      running = pos;
      pos->kill_continuation = &free_and_signal;
      pos->kill_continuation_cls = client;
      GNUNET_SERVER_client_keep (client);
    }
  else
    {
      sc = GNUNET_CLIENT_connect (sched, servicename, cfg);
      GNUNET_CLIENT_service_shutdown (sc);
      GNUNET_CLIENT_disconnect (sc);
      signal_result (client, servicename, GNUNET_MESSAGE_TYPE_ARM_IS_DOWN);
      GNUNET_SERVER_receive_done (client, GNUNET_OK);
    }
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
handle_start (void *cls,
              struct GNUNET_SERVER_Client *client,
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
  start_service (client, servicename);
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
handle_stop (void *cls,
             struct GNUNET_SERVER_Client *client,
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
 * Background task doing maintenance.
 *
 * @param cls closure
 * @param tc context
 */
static void
maint (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ServiceList *pos;
  pid_t pid;
  int status;
  const char *statstr;
  int statcode;
  struct stat sbuf;

  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Stopping all services\n"));
      while (NULL != (pos = running))
        {
          running = pos->next;
          if (0 != PLIBC_KILL (pos->pid, SIGTERM))
            GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "kill");
          if (pos->pid != waitpid (pos->pid, NULL, 0))
            GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "waitpid");
          free_entry (pos);
        }
      return;
    }
  GNUNET_SCHEDULER_add_delayed (tc->sched,
                                GNUNET_YES,
                                GNUNET_SCHEDULER_PRIORITY_IDLE,
                                GNUNET_SCHEDULER_NO_PREREQUISITE_TASK,
                                MAINT_FREQUENCY, &maint, cfg);

  /* check for services that died (WAITPID) */
  while (0 < (pid = waitpid (0, &status, WNOHANG)))
    {
      if (WIFSTOPPED (status) || WIFCONTINUED (status))
        continue;
      pos = find_pid (pid);
      if (pos == NULL)
        {
          /* we killed the service */
          continue;
        }
      if (WIFEXITED (status))
        {
          statstr = _( /* process termination method */ "exit");
          statcode = WEXITSTATUS (status);
        }
      else if (WTERMSIG (status))
        {
          statstr = _( /* process termination method */ "signal");
          statcode = WTERMSIG (status);
        }
      else
        {
          statstr = _( /* process termination method */ "unknown");
          statcode = 0;
        }
      if (NULL != pos->kill_continuation)
        {
          pos->kill_continuation (pos->kill_continuation_cls, pos);
        }
      else
        {
          GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                      _
                      ("Service `%s' terminated with status %s/%d, will try to restart it!\n"),
                      pos->name, statstr, statcode);
          /* schedule restart */
          pos->pid = 0;
        }
    }

  /* check for services that need to be restarted due to
     configuration changes or because the last restart failed */
  pos = running;
  while (pos != NULL)
    {
      if ((0 == STAT (pos->config, &sbuf)) && (pos->mtime < sbuf.st_mtime))
        {
          GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                      _
                      ("Restarting service `%s' due to configuration file change.\n"));
          if (0 != PLIBC_KILL (pos->pid, SIGTERM))
            GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "kill");
        }
      if (pos->pid == 0)
        {
          GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                      _("Restarting service `%s'.\n"), pos->name);
          /* FIXME: should have some exponentially
             increasing timer to avoid tight restart loops */
          start_process (pos);
        }
      pos = pos->next;
    }
}


/**
 * List of handlers for the messages understood by this
 * service.
 */
static struct GNUNET_SERVER_MessageHandler handlers[] = {
  {&handle_start, NULL, GNUNET_MESSAGE_TYPE_ARM_START, 0},
  {&handle_stop, NULL, GNUNET_MESSAGE_TYPE_ARM_STOP, 0},
  {NULL, NULL, 0, 0}
};


/**
 * Process arm requests.
 *
 * @param cls closure
 * @param s scheduler to use
 * @param server the initialized server
 * @param c configuration to use
 */
static void
run (void *cls,
     struct GNUNET_SCHEDULER_Handle *s,
     struct GNUNET_SERVER_Handle *server,
     struct GNUNET_CONFIGURATION_Handle *c)
{
  char *defaultservices;
  char *pos;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "Starting...\n");
  cfg = c;
  sched = s;
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg,
                                             "ARM",
                                             "GLOBAL_PREFIX",
                                             &prefix_command))
    prefix_command = GNUNET_strdup ("");
  /* start default services... */
  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_get_value_string (cfg,
                                             "ARM",
                                             "DEFAULTSERVICES",
                                             &defaultservices))
    {
#if DEBUG_ARM
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Starting default services `%s'\n", defaultservices);
#endif
      pos = strtok (defaultservices, " ");
      while (pos != NULL)
        {
          start_service (NULL, pos);
          pos = strtok (NULL, " ");
        }
      GNUNET_free (defaultservices);
    }
  else
    {
#if DEBUG_ARM
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "No default services configured.\n");
#endif
    }

  /* process client requests */
  GNUNET_SERVER_add_handlers (server, handlers);

  /* manage services */
  GNUNET_SCHEDULER_add_delayed (sched,
                                GNUNET_YES,
                                GNUNET_SCHEDULER_PRIORITY_IDLE,
                                GNUNET_SCHEDULER_NO_PREREQUISITE_TASK,
                                MAINT_FREQUENCY, &maint, NULL);
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
  return (GNUNET_OK ==
          GNUNET_SERVICE_run (argc,
                              argv, "arm", &run, NULL, NULL, NULL)) ? 0 : 1;
}

/* end of gnunet-service-arm.c */
