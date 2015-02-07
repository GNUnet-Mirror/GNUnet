/*
  This file is part of GNUnet
  Copyright (C) 2008--2013 Christian Grothoff (and other contributing authors)

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
 * @file testbed/test_testbed_api_testbed_run.c
 * @brief Test cases for testing high-level testbed management
 * @author Sree Harsha Totakura <sreeharsha@totakura.in>
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testbed_service.h"

/**
 * Number of peers we want to start
 */
#define NUM_PEERS 5

/**
 * The array of peers; we fill this as the peers are given to us by the testbed
 */
static struct GNUNET_TESTBED_Peer *peers[NUM_PEERS];

/**
 * Operation handle
 */
static struct GNUNET_TESTBED_Operation *op;

/**
 * Abort task identifier
 */
static struct GNUNET_SCHEDULER_Task * abort_task;

/**
 * Current peer id
 */
static unsigned int peer_id;

/**
 * Testing result
 */
static int result;

/**
 * Should we wait forever after testbed is initialized?
 */
static int wait_forever;


/**
 * Shutdown nicely
 *
 * @param cls NULL
 * @param tc the task context
 */
static void
do_shutdown (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  if (NULL != abort_task)
    GNUNET_SCHEDULER_cancel (abort_task);
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
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Test timedout -- Aborting\n");
  abort_task = NULL;
  (void) GNUNET_SCHEDULER_add_now (&do_shutdown, NULL);
}


/**
 * Signature of a main function for a testcase.
 *
 * @param cls closure
 * @param h the run handle
 * @param num_peers number of peers in 'peers'
 * @param peers_ handle to peers run in the testbed
 * @param links_succeeded the number of overlay link connection attempts that
 *          succeeded
 * @param links_failed the number of overlay link connection attempts that
 *          failed
 */
static void
test_master (void *cls,
             struct GNUNET_TESTBED_RunHandle *h,
             unsigned int num_peers,
             struct GNUNET_TESTBED_Peer **peers_,
             unsigned int links_succeeded,
             unsigned int links_failed)
{
  result = GNUNET_OK;
  if (GNUNET_YES == wait_forever)
  {
    if (NULL == abort_task)
      return;                   /* abort already scheduled */
    GNUNET_SCHEDULER_cancel (abort_task);
    abort_task = NULL;
    (void) GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
                                         &do_shutdown, NULL);
    return;
  }
  GNUNET_assert (NULL != peers[0]);
  op = GNUNET_TESTBED_peer_stop (NULL, peers[0], NULL, NULL);
  GNUNET_assert (NULL != op);
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
  uint64_t event_mask;

  event_mask = 0;
  event_mask |= (1LL << GNUNET_TESTBED_ET_PEER_START);
  event_mask |= (1LL << GNUNET_TESTBED_ET_PEER_STOP);
  GNUNET_TESTBED_run (NULL, config, NUM_PEERS, event_mask, &controller_event_cb,
                      NULL, &test_master, NULL);
  abort_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                    (GNUNET_TIME_UNIT_SECONDS, 300), &do_abort,
                                    NULL);
}


/**
 * Main function
 */
int
main (int argc, char **argv)
{
  char *argv2[] = {
    "test_testbed_api_testbed_run",
    "-c", NULL,
    NULL
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  char *testname;
  char *config_filename;
  int ret;

  if (NULL == (testname = strrchr (argv[0], (int) '_')))
  {
    GNUNET_break (0);
    return 1;
  }
  testname++;
  testname = GNUNET_strdup (testname);
#ifdef MINGW
  {
    char *period;

    /* check and remove .exe extension */
    period = strrchr (testname, (int) '.');
    if (NULL != period)
      *period = '\0';
    else
      GNUNET_break (0);         /* Windows with no .exe? */
  }
#endif
  if (0 == strcmp ("waitforever", testname))
    wait_forever = GNUNET_YES;
  if ( (GNUNET_YES != wait_forever) && (0 != strcmp ("run", testname)) )
  {
    GNUNET_asprintf (&config_filename, "test_testbed_api_testbed_run_%s.conf",
                     testname);
  }
  else
    config_filename = GNUNET_strdup ("test_testbed_api.conf");
  GNUNET_free (testname);
  argv2[2] = config_filename;
  result = GNUNET_SYSERR;
  ret =
      GNUNET_PROGRAM_run ((sizeof (argv2) / sizeof (char *)) - 1, argv2,
                          "test_testbed_api_testbed_run", "nohelp", options,
                          &run, NULL);
  GNUNET_free (config_filename);
  if ((GNUNET_OK != ret) || (GNUNET_OK != result))
    return 1;
  return 0;
}

/* end of test_testbed_api_testbed_run.c */
