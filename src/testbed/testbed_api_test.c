/*
      This file is part of GNUnet
      (C) 2008--2012 Christian Grothoff (and other contributing authors)

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
 * @file testbed/testbed_api_test.c
 * @brief high-level test function
 * @author Christian Grothoff
 * @author Sree Harsha Totakura
 */
#include "platform.h"
#include "gnunet_testbed_service.h"


/**
 * Context information for test run
 */
struct TestRunContext
{
  /**
   * Test master callback
   */
  GNUNET_TESTBED_TestMaster test_master;

  /**
   * Closure for test master
   */
  void *test_master_cls;

  /**
   * Number of peers to start
   */
  unsigned int num_peers;

  /**
   * counter for loading peers
   */
  unsigned int peer_cnt;

  /**
   * Followed by peers list
   */
  struct GNUNET_TESTBED_Peer *peers[0];
};


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
  struct TestRunContext *rc = cls;

  if (rc->peer_cnt == rc->num_peers)
    return;
  GNUNET_assert (GNUNET_TESTBED_ET_PEER_START == event->type);
  GNUNET_assert (NULL == rc->peers[rc->peer_cnt]);
  GNUNET_assert (NULL != event->details.peer_start.peer);
  rc->peers[rc->peer_cnt++] = event->details.peer_start.peer;
}


/**
 * Task to be executed when peers are ready
 *
 * @param cls NULL
 * @param tc the task context
 */
static void
master_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct TestRunContext *rc = cls;

  GNUNET_assert (rc->peer_cnt == rc->num_peers);
  rc->test_master (rc->test_master_cls, rc->num_peers, rc->peers);
}


/**
 * Main run function.
 *
 * @param cls NULL
 * @param args arguments passed to GNUNET_PROGRAM_run
 * @param cfgfile the path to configuration file
 * @param cfg the configuration file handle
 */
static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *config)
{
  struct TestRunContext *rc = cls;

  GNUNET_TESTBED_run (NULL, config, rc->num_peers, 0, &controller_event_cb, rc,
                      &master_task, rc);
}


/**
 * Convenience method for running a "simple" test on the local system
 * with a single call from 'main'.  Underlay and overlay topology are
 * configured using the "UNDERLAY" and "OVERLAY" options in the
 * "[testbed]" section of the configuration (with possible options
 * given in "UNDERLAY_XXX" and/or "OVERLAY_XXX").
 *
 * The test is to be terminated using a call to
 * "GNUNET_SCHEDULER_shutdown".  If starting the test fails,
 * the program is stopped without 'master' ever being run.
 *
 * NOTE: this function should be called from 'main', NOT from
 * within a GNUNET_SCHEDULER-loop.  This function will initialze
 * the scheduler loop, the testbed and then pass control to
 * 'master'.
 *
 * @param testname name of the testcase (to configure logging, etc.)
 * @param cfg_filename configuration filename to use
 *              (for testbed, controller and peers)
 * @param num_peers number of peers to start
 * @param test_master task to run once the test is ready
 * @param test_master_cls closure for 'task'.
 */
void
GNUNET_TESTBED_test_run (const char *testname, const char *cfg_filename,
                         unsigned int num_peers,
                         GNUNET_TESTBED_TestMaster test_master,
                         void *test_master_cls)
{
  char *argv2[] = {
    NULL,
    "-c",
    NULL,
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  struct TestRunContext *rc;

  argv2[0] = GNUNET_strdup (testname);
  argv2[2] = GNUNET_strdup (cfg_filename);
  GNUNET_assert (NULL != test_master);
  GNUNET_assert (num_peers > 0);
  rc = GNUNET_malloc (sizeof (struct TestRunContext) +
                      (num_peers * sizeof (struct GNUNET_TESTBED_Peer *)));
  rc->test_master = test_master;
  rc->test_master_cls = test_master_cls;
  rc->num_peers = num_peers;
  (void) GNUNET_PROGRAM_run ((sizeof (argv2) / sizeof (char *)) - 1, argv2,
                             testname, "nohelp", options, &run, rc);
  GNUNET_free (rc);
  GNUNET_free (argv2[0]);
  GNUNET_free (argv2[2]);
}

/* end of testbed_api_test.c */
