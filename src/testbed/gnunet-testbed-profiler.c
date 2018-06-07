/*
     This file is part of GNUnet.
     Copyright (C) 2008--2013 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.
*/

/**
 * @file testbed/gnunet-testbed-profiler.c
 * @brief Profiling driver for the testbed.
 * @author Sree Harsha Totakura <sreeharsha@totakura.in>
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testbed_service.h"
#include "testbed_api_hosts.h"

/**
 * Generic loggins shorthand
 */
#define LOG(kind,...)                                           \
  GNUNET_log (kind, __VA_ARGS__)


/**
 * Handle to global configuration
 */
struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Peer linking - topology operation
 */
struct GNUNET_TESTBED_Operation *topology_op;

/**
 * Name of the file with the hosts to run the test over (configuration option).
 * It will be NULL if ENABLE_LL is set
 */
static char *hosts_file;

/**
 * Abort task identifier
 */
static struct GNUNET_SCHEDULER_Task *abort_task;

/**
 * Global event mask for all testbed events
 */
uint64_t event_mask;

/**
 * Number of peers to be started by the profiler
 */
static unsigned int num_peers;

/**
 * Number of timeout failures to tolerate
 */
static unsigned int num_cont_fails;

/**
 * Continuous failures during overlay connect operations
 */
static unsigned int cont_fails;

/**
 * Links which are successfully established
 */
static unsigned int established_links;

/**
 * Links which are not successfully established
 */
static unsigned int failed_links;

/**
 * Global testing status
 */
static int result;

/**
 * Are we running non interactively
 */
static int noninteractive;


/**
 * Shutdown nicely
 *
 * @param cls NULL
 */
static void
do_shutdown (void *cls)
{
  if (NULL != abort_task)
  {
    GNUNET_SCHEDULER_cancel (abort_task);
    abort_task = NULL;
  }
  if (NULL != cfg)
  {
    GNUNET_CONFIGURATION_destroy (cfg);
    cfg = NULL;
  }
}


/**
 * abort task to run on test timed out
 *
 * @param cls NULL
 */
static void
do_abort (void *cls)
{
  abort_task = NULL;
  LOG (GNUNET_ERROR_TYPE_WARNING,
       "Aborting\n");
  result = GNUNET_SYSERR;
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Function to print summary about how many overlay links we have made and how
 * many failed
 */
static void
print_overlay_links_summary ()
{
  static int printed_already;

  if (GNUNET_YES == printed_already)
    return;
  printed_already = GNUNET_YES;
  printf ("%u links succeeded\n", established_links);
  printf ("%u links failed due to timeouts\n", failed_links);
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
  case GNUNET_TESTBED_ET_OPERATION_FINISHED:
    /* Control reaches here when a peer linking operation fails */
    if (NULL != event->details.operation_finished.emsg)
    {
      printf ("F");
      fflush (stdout);
      failed_links++;
      if (++cont_fails > num_cont_fails)
      {
        printf ("\nAborting due to very high failure rate\n");
        print_overlay_links_summary ();
	GNUNET_SCHEDULER_shutdown ();
        return;
      }
    }
    break;
  case GNUNET_TESTBED_ET_CONNECT:
  {
    if (0 != cont_fails)
      cont_fails--;
    if (0 == established_links)
      printf ("Establishing links. Please wait\n");
    printf (".");
    fflush (stdout);
    established_links++;
  }
    break;
  default:
    GNUNET_break (0);
  }
}


/**
 * Signature of a main function for a testcase.
 *
 * @param cls closure
 * @param h the run handle
 * @param num_peers number of peers in 'peers'
 * @param peers handle to peers run in the testbed
 * @param links_succeeded the number of overlay link connection attempts that
 *          succeeded
 * @param links_failed the number of overlay link
 */
static void
test_run (void *cls,
          struct GNUNET_TESTBED_RunHandle *h,
          unsigned int num_peers, struct GNUNET_TESTBED_Peer **peers,
          unsigned int links_succeeded,
          unsigned int links_failed)
{
  result = GNUNET_OK;
  fprintf (stdout, "\n");
  print_overlay_links_summary ();
  GNUNET_SCHEDULER_add_shutdown (&do_shutdown, NULL);
  if (noninteractive)
  {
    GNUNET_SCHEDULER_cancel (abort_task);
    abort_task = NULL;
    return;
  }
#if (!ENABLE_SUPERMUC)
  fprintf (stdout, "Testbed running, waiting for keystroke to shut down\n");
  fflush (stdout);
  (void) getc (stdin);
#endif
  fprintf (stdout, "Shutting down. Please wait\n");
  fflush (stdout);
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Main function that will be run by the scheduler.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param config configuration
 */
static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *config)
{
  if (0 == num_peers)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR, _("Exiting as the number of peers is %u\n"),
         num_peers);
    return;
  }
  cfg = GNUNET_CONFIGURATION_dup (config);
  event_mask = 0;
  event_mask |= (1LL << GNUNET_TESTBED_ET_CONNECT);
  event_mask |= (1LL << GNUNET_TESTBED_ET_OPERATION_FINISHED);
  GNUNET_TESTBED_run (hosts_file, cfg, num_peers, event_mask,
		      &controller_event_cb, NULL,
		      &test_run, NULL);
  abort_task =
      GNUNET_SCHEDULER_add_shutdown (&do_abort,
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
  struct GNUNET_GETOPT_CommandLineOption options[] = {

    GNUNET_GETOPT_option_uint ('p',
                                   "num-peers",
                                   "COUNT",
                                   gettext_noop ("create COUNT number of peers"),
                                   &num_peers),

    GNUNET_GETOPT_option_uint ('e',
                                   "num-errors",
                                   "COUNT",
                                   gettext_noop ("tolerate COUNT number of continious timeout failures"),
                                   &num_cont_fails),

    GNUNET_GETOPT_option_flag ('n',
                                  "non-interactive",
                                  gettext_noop ("run profiler in non-interactive mode where upon "
                                                "testbed setup the profiler does not wait for a "
                                                "keystroke but continues to run until a termination "
                                                "signal is received"),
                                  &noninteractive),

#if !ENABLE_SUPERMUC
    GNUNET_GETOPT_option_string ('H',
                                 "hosts",
                                 "FILENAME",
                                 gettext_noop ("name of the file with the login information for the testbed"),
                                 &hosts_file),
#endif
    GNUNET_GETOPT_OPTION_END
  };
  const char *binaryHelp = "gnunet-testbed-profiler [OPTIONS]";
  int ret;

  unsetenv ("XDG_DATA_HOME");
  unsetenv ("XDG_CONFIG_HOME");
  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;
  result = GNUNET_SYSERR;
  ret =
      GNUNET_PROGRAM_run (argc, argv, "gnunet-testbed-profiler", binaryHelp,
                          options, &run, NULL);
  GNUNET_free ((void *) argv);
  if (GNUNET_OK != ret)
    return ret;
  if (GNUNET_OK != result)
    return 1;
  return 0;
}
