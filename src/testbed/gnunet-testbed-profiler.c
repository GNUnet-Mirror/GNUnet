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
 * Abort task identifier
 */
static GNUNET_SCHEDULER_TaskIdentifier abort_task;

/**
 * Shutdown task identifier
 */
static GNUNET_SCHEDULER_TaskIdentifier shutdown_task;

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
 * Shutdown nicely
 *
 * @param cls NULL
 * @param tc the task context
 */
static void
do_shutdown (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  shutdown_task = GNUNET_SCHEDULER_NO_TASK;
  if (GNUNET_SCHEDULER_NO_TASK != abort_task)
    GNUNET_SCHEDULER_cancel (abort_task);
  if (NULL != cfg)
    GNUNET_CONFIGURATION_destroy (cfg);
  GNUNET_SCHEDULER_shutdown (); /* Stop scheduler to shutdown testbed run */
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
  LOG (GNUNET_ERROR_TYPE_WARNING, "Aborting\n");
  abort_task = GNUNET_SCHEDULER_NO_TASK;
  result = GNUNET_SYSERR;
  if (GNUNET_SCHEDULER_NO_TASK != shutdown_task)
    GNUNET_SCHEDULER_cancel (shutdown_task);
  shutdown_task = GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
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
        GNUNET_SCHEDULER_cancel (abort_task);
        abort_task = GNUNET_SCHEDULER_add_now (&do_abort, NULL);
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
 * @param num_peers number of peers in 'peers'
 * @param peers handle to peers run in the testbed
 */
static void
test_run (void *cls, unsigned int num_peers, struct GNUNET_TESTBED_Peer **peers)
{
  result = GNUNET_OK;
  fprintf (stdout, "\n");
  print_overlay_links_summary ();
  fprintf (stdout, "Testbed running, waiting for keystroke to shut down\n");
  fflush (stdout);
  (void) getc (stdin);
  fprintf (stdout, "Shutting down. Please wait\n");
  fflush (stdout);
  shutdown_task = GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
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
  cfg = GNUNET_CONFIGURATION_dup (config);
  event_mask = 0;
  event_mask |= (1LL << GNUNET_TESTBED_ET_CONNECT);
  event_mask |= (1LL << GNUNET_TESTBED_ET_OPERATION_FINISHED);
  GNUNET_TESTBED_run (args[0], cfg, num_peers, event_mask, controller_event_cb,
                      NULL, &test_run, NULL);
  abort_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &do_abort,
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
    {'p', "num-peers", "COUNT",
     gettext_noop ("create COUNT number of peers"),
     GNUNET_YES, &GNUNET_GETOPT_set_uint, &num_peers},
    {'e', "num-errors", "COUNT",
     gettext_noop ("tolerate COUNT number of continious timeout failures"),
     GNUNET_YES, &GNUNET_GETOPT_set_uint, &num_cont_fails},
    GNUNET_GETOPT_OPTION_END
  };
  int ret;

  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;
  result = GNUNET_SYSERR;
  ret =
      GNUNET_PROGRAM_run (argc, argv,
                          "gnunet-testbed-profiler [OPTIONS] hosts-file",
                          _("Profiler for testbed"), options, &run, NULL);
  GNUNET_free ((void *) argv);
  if (GNUNET_OK != ret)
    return ret;
  if (GNUNET_OK != result)
    return 1;
  return 0;
}
