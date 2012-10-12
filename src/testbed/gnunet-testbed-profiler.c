/*
     This file is part of GNUnet.
     (C) 2011, 2012 Christian Grothoff (and other contributing authors)

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
 * @file testbed/gnunet-testbed-profiler.c
 * @brief Profiling driver for the testbed.
 * @author Sree Harsha Totakura <sreeharsha@totakura.in> 
 */

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_testbed_service.h"
#include "testbed_api_hosts.h"

/**
 * Generic loggins shorthand
 */
#define LOG(kind,...)                                           \
  GNUNET_log_from (kind, "testbed-api-testbed", __VA_ARGS__)

/**
 * DLL of operations
 */
struct DLLOperation
{
  /**
   * The testbed operation handle
   */
  struct GNUNET_TESTBED_Operation *op;

  /**
   * Closure
   */
  void *cls;

  /**
   * The next pointer for DLL
   */
  struct DLLOperation *next;

  /**
   * The prev pointer for DLL
   */
  struct DLLOperation *prev;
};


/**
 * An array of hosts loaded from the hostkeys file
 */
static struct GNUNET_TESTBED_Host **hosts;

/**
 * The array of peers; we fill this as the peers are given to us by the testbed
 */
static struct GNUNET_TESTBED_Peer **peers;

/**
 * Operation handle
 */
static struct GNUNET_TESTBED_Operation *op;

/**
 * Host registration handle
 */
static struct GNUNET_TESTBED_HostRegistrationHandle *reg_handle;

/**
 * Handle to the master controller process
 */
struct GNUNET_TESTBED_ControllerProc *mc_proc;

/**
 * Handle to the master controller
 */
struct GNUNET_TESTBED_Controller *mc;

/**
 * Handle to global configuration
 */
struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Abort task identifier
 */
static GNUNET_SCHEDULER_TaskIdentifier abort_task;

/**
 * Host registration task identifier
 */
static GNUNET_SCHEDULER_TaskIdentifier register_hosts_task;

/**
 * Global event mask for all testbed events
 */
uint64_t event_mask;

/**
 * Current peer id
 */
unsigned int peer_id;

/**
 * Number of peers to be started by the profiler
 */
static unsigned int num_peers;

/**
 * Number of hosts in the hosts array
 */
static unsigned int num_hosts;

/**
 * Global testing status
 */
static int result;


/**
 * Shutdown nicely
 *
 * @param cls NULL
 * @param tc the task context
 */
static void
do_shutdown (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  unsigned int nhost;

  if (GNUNET_SCHEDULER_NO_TASK != abort_task)
    GNUNET_SCHEDULER_cancel (abort_task);
  if (GNUNET_SCHEDULER_NO_TASK != register_hosts_task)
    GNUNET_SCHEDULER_cancel (register_hosts_task);
  GNUNET_free_non_null (peers);
  if (NULL != reg_handle)
    GNUNET_TESTBED_cancel_registration (reg_handle);
  for (nhost = 0; nhost < num_hosts; nhost++)
    if (NULL != hosts[nhost])
      GNUNET_TESTBED_host_destroy (hosts[nhost]);
  GNUNET_free_non_null (hosts);
  if (NULL != mc_proc)
    GNUNET_TESTBED_controller_stop (mc_proc);
  if (NULL != cfg)
    GNUNET_CONFIGURATION_destroy (cfg);
  GNUNET_SCHEDULER_shutdown ();	/* Stop scheduler to shutdown testbed run */  
}


/**
 * abort task to run on test timed out
 *
 * @param cls NULL
 * @param tc the task context
 */
static void
do_abort (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Aborting\n");
  abort_task = GNUNET_SCHEDULER_NO_TASK;
  result = GNUNET_SYSERR;
  GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
}


/**
 * Controller event callback
 *
 * @param cls NULL
 * @param event the controller event
 */
static void
controller_event_cb (void *cls,
                     const struct GNUNET_TESTBED_EventInformation *event)
{

  switch (event->type)
  {
  case GNUNET_TESTBED_ET_PEER_START:
    GNUNET_assert (NULL == peers[peer_id]);
    GNUNET_assert (NULL != event->details.peer_start.peer);
    peers[peer_id++] = event->details.peer_start.peer;
    break;
  case GNUNET_TESTBED_ET_PEER_STOP:
    GNUNET_assert (NULL != op);
    GNUNET_TESTBED_operation_done (op);
    GNUNET_assert (peers[0] == event->details.peer_stop.peer);
    GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
    break;
  default:
    GNUNET_assert (0);
  }
}


/**
 * Task to register all hosts available in the global host list
 *
 * @param cls NULL
 * @param tc the scheduler task context
 */
static void
register_hosts (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Callback which will be called to after a host registration succeeded or failed
 *
 * @param cls the closure
 * @param emsg the error message; NULL if host registration is successful
 */
static void
host_registration_completion (void *cls, const char *emsg)
{
  reg_handle = NULL;
  if (NULL != emsg)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         _("Host registration failed for a host. Error: %s\n"), emsg);
    GNUNET_SCHEDULER_cancel (abort_task);
    abort_task = GNUNET_SCHEDULER_add_now (&do_abort, NULL);
    return;
  }
  register_hosts_task = GNUNET_SCHEDULER_add_now (&register_hosts, NULL);
}


/**
 * Task to register all hosts available in the global host list
 *
 * @param cls NULL
 * @param tc the scheduler task context
 */
static void
register_hosts (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  static unsigned int reg_host;

  register_hosts_task = GNUNET_SCHEDULER_NO_TASK;
  if (reg_host == num_hosts)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "All hosts successfully registered\n");
    /* Start peer create task */
  }
  reg_handle = GNUNET_TESTBED_register_host (mc, hosts[reg_host++],
                                             host_registration_completion,
                                             NULL);
}


/**
 * Callback to signal successfull startup of the controller process
 *
 * @param cls the closure from GNUNET_TESTBED_controller_start()
 * @param cfg the configuration with which the controller has been started;
 *          NULL if status is not GNUNET_OK
 * @param status GNUNET_OK if the startup is successfull; GNUNET_SYSERR if not,
 *          GNUNET_TESTBED_controller_stop() shouldn't be called in this case
 */
static void
status_cb (void *cls, const struct GNUNET_CONFIGURATION_Handle *config, int status)
{
  GNUNET_SCHEDULER_cancel (abort_task);
  if (GNUNET_OK != status)
  {
    mc_proc = NULL;
    abort_task = GNUNET_SCHEDULER_add_now (&do_abort, NULL);
    return;
  }
  event_mask = 0;
  event_mask |= (1LL << GNUNET_TESTBED_ET_PEER_START);
  event_mask |= (1LL << GNUNET_TESTBED_ET_PEER_STOP);
  event_mask |= (1LL << GNUNET_TESTBED_ET_CONNECT);
  event_mask |= (1LL << GNUNET_TESTBED_ET_DISCONNECT);
  mc = GNUNET_TESTBED_controller_connect (config, hosts[0], event_mask,
                                          &controller_event_cb, NULL);
  if (NULL == mc)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         _("Unable to connect to master controller -- Check config\n"));
    abort_task = GNUNET_SCHEDULER_add_now (&do_abort, NULL);
    return;
  }
  register_hosts_task = GNUNET_SCHEDULER_add_now (&register_hosts, NULL);
  abort_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
                                             &do_abort, NULL);
}


/**
 * Main function that will be run by the scheduler.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param cfg configuration
 */
static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *config)
{
  unsigned int nhost;

  if (NULL == args[0])
  {
    fprintf (stderr, _("No hosts-file specified on command line\n"));
    return;
  }
  if (0 == num_peers)
  {
    result = GNUNET_OK;
    return;
  }
  num_hosts = GNUNET_TESTBED_hosts_load_from_file (args[0], &hosts);
  if (0 == num_hosts)
  {
    fprintf (stderr, _("No hosts loaded. Need atleast one host\n"));
    return;
  }
  for (nhost = 0; nhost < num_hosts; nhost++)
  {
    if (GNUNET_YES != GNUNET_TESTBED_is_host_habitable (hosts[nhost]))
    {
      fprintf (stderr, _("Host %s cannot start testbed\n"),
                         GNUNET_TESTBED_host_get_hostname_ (hosts[nhost]));
      break;
    }
  }
  if (num_hosts != nhost)
  {
    fprintf (stderr, _("Exiting\n"));
    GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
    return;
  }
  cfg = GNUNET_CONFIGURATION_dup (config);
  mc_proc = 
      GNUNET_TESTBED_controller_start (GNUNET_TESTBED_host_get_hostname_ 
                                       (hosts[0]),
                                       hosts[0],
                                       cfg,
                                       status_cb,
                                       NULL);
  abort_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                    (GNUNET_TIME_UNIT_SECONDS, 5), &do_abort,
                                    NULL);
}


/**
 * Main function.
 *
 * @return 0 on success
 */
int
main (int argc, char *const *argv)
{
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    { 'n', "num-peers", "COUNT",
      gettext_noop ("create COUNT number of peers"),
      GNUNET_YES, &GNUNET_GETOPT_set_uint, &num_peers },
    { 'n', "num-peers", "COUNT",
      gettext_noop ("create COUNT number of peers"),
      GNUNET_YES, &GNUNET_GETOPT_set_uint, &num_peers },
    GNUNET_GETOPT_OPTION_END
  };
  int ret;

  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;
  
  result = GNUNET_SYSERR;
  ret =
      GNUNET_PROGRAM_run (argc, argv, "gnunet-testbed-profiler [OPTIONS] hosts-file",
                          _("Profiler for testbed"),
                          options, &run, NULL);
  if (GNUNET_OK != ret)
    return ret;
  if (GNUNET_OK != result)
    return 1;
  return 0;
}
