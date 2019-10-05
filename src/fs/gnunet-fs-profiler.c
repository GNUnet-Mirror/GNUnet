/*
     This file is part of GNUnet.
     Copyright (C) 2012 GNUnet e.V.

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

     SPDX-License-Identifier: AGPL3.0-or-later
 */

/**
 * @file fs/gnunet-fs-profiler.c
 * @brief tool to benchmark/profile file-sharing
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testbed_service.h"

/**
 * Final status code.
 */
static int ret;

/**
 * Data file with the hosts for the testbed.
 */
static char *host_filename;

/**
 * Number of peers to run in the experiment.
 */
static unsigned int num_peers;

/**
 * After how long do we abort the test?
 */
static struct GNUNET_TIME_Relative timeout;

/**
 * Handle to the task run during termination.
 */
static struct GNUNET_SCHEDULER_Task *terminate_taskid;


/**
 * Function called after we've collected the statistics.
 *
 * @param cls NULL
 * @param op the operation that has been finished
 * @param emsg error message in case the operation has failed; will be NULL if
 *          operation has executed successfully.
 */
static void
shutdown_task (void *cls,
               struct GNUNET_TESTBED_Operation *op,
               const char *emsg)
{
  if (NULL != emsg)
    fprintf (stderr,
             "Error collecting statistics: %s\n",
             emsg);
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Callback function to process statistic values from all peers.
 * Prints them out.
 *
 * @param cls closure
 * @param peer the peer the statistic belong to
 * @param subsystem name of subsystem that created the statistic
 * @param name the name of the datum
 * @param value the current value
 * @param is_persistent GNUNET_YES if the value is persistent, GNUNET_NO if not
 * @return GNUNET_OK to continue, GNUNET_SYSERR to abort iteration
 */
static int
process_stats (void *cls,
               const struct GNUNET_TESTBED_Peer *peer,
               const char *subsystem,
               const char *name,
               uint64_t value,
               int is_persistent)
{
  fprintf (stdout,
           "%p-%s: %s = %llu\n",
           peer,
           subsystem,
           name,
           (unsigned long long) value);
  return GNUNET_OK;
}


/**
 * Task run on shutdown to terminate.  Triggers printing out
 * all statistics.
 *
 * @param cls NULL
 */
static void
terminate_task (void *cls)
{
  if (NULL != terminate_taskid)
  {
    GNUNET_SCHEDULER_cancel (terminate_taskid);
    terminate_taskid = NULL;
  }
  GNUNET_TESTBED_get_statistics (0, NULL,
                                 NULL, NULL,
                                 &process_stats,
                                 &shutdown_task,
                                 NULL);
}


/**
 * Task run on timeout to terminate.  Triggers printing out
 * all statistics.
 *
 * @param cls NULL
 */
static void
timeout_task (void *cls)
{
  terminate_taskid = NULL;
  GNUNET_SCHEDULER_shutdown ();
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
 * @param links_failed the number of overlay link connection attempts that
 *          failed
 */
static void
test_master (void *cls,
             struct GNUNET_TESTBED_RunHandle *h,
             unsigned int num_peers,
             struct GNUNET_TESTBED_Peer **peers,
             unsigned int links_succeeded,
             unsigned int links_failed)
{
  // const struct GNUNET_CONFIGURATION_Handle *cfg = cls;
  // FIXME: enable clients to signal 'completion' before timeout;
  // in that case, run the 'terminate_task' "immediately"

  if (0 != timeout.rel_value_us)
    terminate_taskid = GNUNET_SCHEDULER_add_delayed (timeout,
                                                     &timeout_task,
                                                     NULL);
  GNUNET_SCHEDULER_add_shutdown (&terminate_task,
                                 NULL);
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
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  GNUNET_TESTBED_run (host_filename,
                      cfg,
                      num_peers,
                      0, NULL, NULL,
                      &test_master, (void *) cfg);
}


/**
 * Program to run a file-sharing testbed.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_option_uint ('n',
                               "num-peers",
                               "COUNT",
                               gettext_noop (
                                 "run the experiment with COUNT peers"),
                               &num_peers),

    GNUNET_GETOPT_option_string ('H',
                                 "hosts",
                                 "HOSTFILE",
                                 gettext_noop (
                                   "specifies name of a file with the HOSTS the testbed should use"),
                                 &host_filename),

    GNUNET_GETOPT_option_relative_time ('t',
                                        "timeout",
                                        "DELAY",
                                        gettext_noop (
                                          "automatically terminate experiment after DELAY"),
                                        &timeout),

    GNUNET_GETOPT_OPTION_END
  };

  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;

  ret = (GNUNET_OK ==
         GNUNET_PROGRAM_run (argc, argv, "gnunet-fs-profiler",
                             gettext_noop (
                               "run a testbed to measure file-sharing performance"),
                             options, &run,
                             NULL)) ? ret : 1;
  GNUNET_free ((void*) argv);
  return ret;
}

/* end of gnunet-fs-profiler.c */
